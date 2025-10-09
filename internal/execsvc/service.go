package execsvc

import (
	"bytes"
	"context"
	"fmt"
	"math"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/terateams/ExecMCP/internal/audit"
	"github.com/terateams/ExecMCP/internal/common"
	"github.com/terateams/ExecMCP/internal/config"
	"github.com/terateams/ExecMCP/internal/logging"
	"github.com/terateams/ExecMCP/internal/security"
	"github.com/terateams/ExecMCP/internal/ssh"
)

// Service 命令执行服务
type Service struct {
	config         *config.Config
	logger         logging.Logger
	sshManager     ssh.Manager
	filtersByGroup map[string]*security.Filter
	hostSecurity   map[string]*config.SecurityConfig
	hostIndex      map[string]*config.SSHHost
	audit          audit.Logger
}

func buildSecurityCaches(cfg *config.Config, logger logging.Logger, auditLogger audit.Logger) (map[string]*security.Filter, map[string]*config.SecurityConfig, map[string]*config.SSHHost, error) {
	filtersByGroup := make(map[string]*security.Filter)
	for i := range cfg.Security {
		sec := &cfg.Security[i]
		filtersByGroup[sec.Group] = security.NewFilter(sec, logger, auditLogger)
	}

	defaultGroup := cfg.DefaultSecurityGroup()
	hostSecurity := make(map[string]*config.SecurityConfig)
	hostIndex := make(map[string]*config.SSHHost)

	for i := range cfg.SSHHosts {
		host := &cfg.SSHHosts[i]

		if host.SecurityGroup == "" {
			host.SecurityGroup = defaultGroup
		}
		host.Type = strings.ToLower(strings.TrimSpace(host.Type))
		if host.Type == "" {
			host.Type = "linux"
		}
		host.ScriptTags = normalizeTags(host.ScriptTags)
		if len(host.ScriptTags) == 0 {
			host.ScriptTags = []string{"default"}
		}

		secCfg, ok := cfg.SecurityByGroup(host.SecurityGroup)
		if !ok {
			return nil, nil, nil, fmt.Errorf("主机 %s 引用未定义的 security_group '%s'", host.ID, host.SecurityGroup)
		}
		hostSecurity[host.ID] = secCfg
		hostIndex[host.ID] = host
	}

	return filtersByGroup, hostSecurity, hostIndex, nil
}

// ExecResult 执行结果
type ExecResult struct {
	ExitCode   int    `json:"exit_code"`
	Stdout     string `json:"stdout"`
	Stderr     string `json:"stderr"`
	Truncated  bool   `json:"truncated"`
	DurationMs int64  `json:"duration_ms"`
}

// ExecRequest 执行请求
type ExecRequest struct {
	HostID  string      `json:"host_id"`
	Command string      `json:"command"`
	Args    []string    `json:"args"`
	Options ExecOptions `json:"options"`
}

// ExecOptions 执行选项
type ExecOptions struct {
	CWD         string            `json:"cwd"`
	UseShell    bool              `json:"use_shell"`
	TimeoutSec  int               `json:"timeout_sec"`
	Env         map[string]string `json:"env"`
	Stream      bool              `json:"stream"`
	MergeStderr bool              `json:"merge_stderr"`
	EnablePTY   bool              `json:"enable_pty"`
}

// ScriptRequest 脚本执行请求
type ScriptRequest struct {
	HostID     string                 `json:"host_id"`
	ScriptName string                 `json:"script_name"`
	Parameters map[string]interface{} `json:"parameters"`
	Options    ExecOptions            `json:"options"`
}

// NewService 创建新的命令执行服务
func NewService(cfg *config.Config, logger logging.Logger, auditLogger audit.Logger) (*Service, error) {
	if auditLogger == nil {
		auditLogger = audit.NewNoopLogger()
	}
	filtersByGroup, hostSecurity, hostIndex, err := buildSecurityCaches(cfg, logger, auditLogger)
	if err != nil {
		return nil, err
	}

	service := &Service{
		config:         cfg,
		logger:         logger,
		sshManager:     ssh.NewManager(cfg, logger),
		filtersByGroup: filtersByGroup,
		hostSecurity:   hostSecurity,
		hostIndex:      hostIndex,
		audit:          auditLogger,
	}

	logger.Info("命令执行服务初始化完成",
		"security_groups", len(filtersByGroup),
		"hosts", len(hostIndex))

	return service, nil
}

// ExecuteCommand 执行命令
func (s *Service) ExecuteCommand(ctx context.Context, req ExecRequest) (*ExecResult, error) {
	ctx, _ = audit.EnsureContext(ctx)
	startTime := time.Now()

	// 记录执行上下文，便于审计与排查问题
	s.logger.Info("开始执行命令",
		"host_id", req.HostID,
		"command", req.Command,
		"args", req.Args,
		"use_shell", req.Options.UseShell)

	filter, secCfg, err := s.filterForHost(req.HostID)
	if err != nil {
		s.logger.Error("无法获取主机安全配置",
			"host_id", req.HostID,
			"error", err)
		return nil, common.WrapError("安全检查失败", err)
	}

	s.logAudit(ctx, audit.Event{
		Category: "exec_command",
		Type:     "command_requested",
		HostID:   req.HostID,
		Target:   req.Command,
		Outcome:  audit.OutcomeUnknown,
		Severity: audit.SeverityInfo,
		Metadata: map[string]interface{}{
			"args":        append([]string(nil), req.Args...),
			"use_shell":   req.Options.UseShell,
			"cwd":         req.Options.CWD,
			"timeout_sec": req.Options.TimeoutSec,
			"stream":      req.Options.Stream,
			"enable_pty":  req.Options.EnablePTY,
		},
	})

	// 1. 安全过滤：所有入口统一走安全策略，确保命令、参数和工作目录符合配置
	securityReq := security.ExecRequest{
		HostID:  req.HostID,
		Command: req.Command,
		Args:    req.Args,
		Options: security.ExecOptions{
			CWD:         req.Options.CWD,
			UseShell:    req.Options.UseShell,
			TimeoutSec:  req.Options.TimeoutSec,
			Env:         req.Options.Env,
			Stream:      req.Options.Stream,
			MergeStderr: req.Options.MergeStderr,
			EnablePTY:   req.Options.EnablePTY,
		},
	}

	if err := filter.Check(ctx, securityReq); err != nil {
		s.logger.Error("命令被安全过滤拒绝",
			"host_id", req.HostID,
			"command", req.Command,
			"error", err)
		return nil, common.WrapError("安全检查失败", err)
	}

	// 2. 获取 SSH 会话：通过连接管理器拿到复用的 SSH 会话，失败直接终止
	session, err := s.sshManager.GetSession(req.HostID)
	if err != nil {
		s.logger.Error("获取 SSH 会话失败",
			"host_id", req.HostID,
			"error", err)
		s.logAudit(ctx, audit.Event{
			Category: "exec_command",
			Type:     "session_error",
			HostID:   req.HostID,
			Target:   req.Command,
			Outcome:  audit.OutcomeError,
			Severity: audit.SeverityHigh,
			Reason:   err.Error(),
		})
		return nil, common.SSHError("获取会话", req.HostID, err)
	}
	defer s.sshManager.ReleaseSession(req.HostID, session)

	// 3. 执行命令
	output, err := session.ExecuteCommand(req.Command, req.Args, req.Options.EnablePTY)
	if err != nil {
		s.logger.Error("命令执行失败",
			"host_id", req.HostID,
			"command", req.Command,
			"error", err)
		s.logAudit(ctx, audit.Event{
			Category: "exec_command",
			Type:     "execution_error",
			HostID:   req.HostID,
			Target:   req.Command,
			Outcome:  audit.OutcomeError,
			Severity: audit.SeverityHigh,
			Reason:   err.Error(),
			Metadata: map[string]interface{}{
				"args": append([]string(nil), req.Args...),
			},
		})
		return nil, common.SSHError("命令执行", req.HostID, err)
	}

	// 4. 处理输出截断：避免单个命令输出过大拖垮上层调用者
	maxOutput := secCfg.MaxOutputBytes
	truncated := false
	originalLen := len(output)
	if int64(originalLen) > maxOutput {
		output = output[:maxOutput]
		truncated = true
		s.logger.Warn("输出被截断",
			"host_id", req.HostID,
			"command", req.Command,
			"original_size", originalLen,
			"max_size", maxOutput)
	}

	result := &ExecResult{
		ExitCode:   0, // 成功路径下默认视为 0，失败场景会在上方直接返回 error
		Stdout:     output,
		Stderr:     "",
		Truncated:  truncated,
		DurationMs: time.Since(startTime).Milliseconds(),
	}

	s.logger.Info("命令执行完成",
		"host_id", req.HostID,
		"exit_code", result.ExitCode,
		"duration_ms", result.DurationMs,
		"truncated", result.Truncated)

	s.logAudit(ctx, audit.Event{
		Category: "exec_command",
		Type:     "command_completed",
		HostID:   req.HostID,
		Target:   req.Command,
		Outcome:  audit.OutcomeSuccess,
		Severity: audit.SeverityInfo,
		Metadata: map[string]interface{}{
			"duration_ms": result.DurationMs,
			"exit_code":   result.ExitCode,
			"truncated":   result.Truncated,
			"output_size": len(result.Stdout),
			"enable_pty":  req.Options.EnablePTY,
		},
	})

	return result, nil
}

// ExecuteScript 执行脚本
func (s *Service) ExecuteScript(ctx context.Context, req ScriptRequest) (*ExecResult, error) {
	ctx, _ = audit.EnsureContext(ctx)
	startTime := time.Now()

	// 脚本执行同样先记录关键信息，便于追踪具体业务脚本
	s.logger.Info("开始执行脚本",
		"host_id", req.HostID,
		"script_name", req.ScriptName,
		"parameters", req.Parameters)

	host, err := s.hostForID(req.HostID)
	if err != nil {
		s.logAudit(ctx, audit.Event{
			Category: "exec_script",
			Type:     "host_missing",
			HostID:   req.HostID,
			Target:   req.ScriptName,
			Outcome:  audit.OutcomeDenied,
			Severity: audit.SeverityMedium,
			Reason:   err.Error(),
		})
		return nil, err
	}

	var paramKeys []string
	for key := range req.Parameters {
		paramKeys = append(paramKeys, key)
	}

	s.logAudit(ctx, audit.Event{
		Category: "exec_script",
		Type:     "script_requested",
		HostID:   req.HostID,
		Target:   req.ScriptName,
		Outcome:  audit.OutcomeUnknown,
		Severity: audit.SeverityInfo,
		Metadata: map[string]interface{}{
			"parameter_keys": paramKeys,
			"timeout_sec":    req.Options.TimeoutSec,
		},
	})

	// 查找脚本配置：脚本必须在配置文件中明确定义
	scriptConfig := s.findScriptConfig(req.ScriptName)
	if scriptConfig == nil {
		s.logAudit(ctx, audit.Event{
			Category: "exec_script",
			Type:     "script_missing",
			HostID:   req.HostID,
			Target:   req.ScriptName,
			Outcome:  audit.OutcomeDenied,
			Severity: audit.SeverityMedium,
			Reason:   "script definition not found",
		})
		return nil, fmt.Errorf("脚本 '%s' 不存在", req.ScriptName)
	}

	if !isHostAllowedForScript(host.ID, scriptConfig.AllowedHosts) {
		reason := fmt.Sprintf("host '%s' not allowed", host.ID)
		s.logger.Warn("脚本执行被 allowed_hosts 限制",
			"host_id", host.ID,
			"script_name", scriptConfig.Name,
			"allowed_hosts", scriptConfig.AllowedHosts)
		s.logAudit(ctx, audit.Event{
			Category: "exec_script",
			Type:     "host_not_allowed",
			HostID:   host.ID,
			Target:   scriptConfig.Name,
			Outcome:  audit.OutcomeDenied,
			Severity: audit.SeverityMedium,
			Reason:   reason,
			Metadata: map[string]interface{}{
				"allowed_hosts": append([]string(nil), scriptConfig.AllowedHosts...),
			},
		})
		return nil, fmt.Errorf("脚本 '%s' 不允许在主机 '%s' 上执行", scriptConfig.Name, host.ID)
	}

	if !hostAllowsScriptTag(host.ScriptTags, scriptConfig.Tag) {
		s.logger.Warn("脚本执行被标签限制",
			"host_id", host.ID,
			"script_name", scriptConfig.Name,
			"script_tag", scriptConfig.Tag,
			"host_tags", host.ScriptTags)
		s.logAudit(ctx, audit.Event{
			Category: "exec_script",
			Type:     "script_tag_denied",
			HostID:   host.ID,
			Target:   scriptConfig.Name,
			Outcome:  audit.OutcomeDenied,
			Severity: audit.SeverityMedium,
			Reason:   "script tag not allowed",
			Metadata: map[string]interface{}{
				"script_tag": scriptConfig.Tag,
				"host_tags":  append([]string(nil), host.ScriptTags...),
			},
		})
		return nil, fmt.Errorf("脚本 '%s' 标签 '%s' 未获主机 '%s' 授权", scriptConfig.Name, scriptConfig.Tag, host.ID)
	}

	// 合并用户参数与默认值，确保模板渲染阶段数据齐全
	mergedParams := s.applyDefaultValues(scriptConfig, req.Parameters)

	// 使用安全模板引擎渲染脚本，自动处理 shell 注入风险
	command, err := s.renderTemplate(scriptConfig.Template, mergedParams, scriptConfig.UseShell)
	if err != nil {
		s.logAudit(ctx, audit.Event{
			Category: "exec_script",
			Type:     "render_error",
			HostID:   req.HostID,
			Target:   req.ScriptName,
			Outcome:  audit.OutcomeError,
			Severity: audit.SeverityHigh,
			Reason:   err.Error(),
		})
		return nil, common.WrapError("模板渲染失败", err)
	}

	// 预留校验逻辑：未来可在此扩展类型、范围等校验
	if err := s.validateParameters(scriptConfig, mergedParams); err != nil {
		s.logAudit(ctx, audit.Event{
			Category: "exec_script",
			Type:     "validation_failed",
			HostID:   req.HostID,
			Target:   req.ScriptName,
			Outcome:  audit.OutcomeDenied,
			Severity: audit.SeverityMedium,
			Reason:   err.Error(),
		})
		return nil, common.ValidationError("脚本参数", err.Error())
	}

	// 构建执行请求 - 使用脚本配置中的选项，确保行为与声明保持一致
	var execReq ExecRequest

	if scriptConfig.UseShell {
		// 对于 shell 脚本，统一由 /bin/sh 执行渲染后的命令字符串
		execReq = ExecRequest{
			HostID:  req.HostID,
			Command: "sh",
			Args:    []string{"-c", command},
			Options: ExecOptions{
				CWD:         scriptConfig.WorkingDir,
				UseShell:    false, // 嵌套 shell 反而危险，因此保持 false
				TimeoutSec:  req.Options.TimeoutSec,
				Env:         req.Options.Env,
				Stream:      req.Options.Stream,
				MergeStderr: req.Options.MergeStderr,
				EnablePTY:   req.Options.EnablePTY,
			},
		}
	} else {
		// 对于非 shell 命令，直接执行
		execReq = ExecRequest{
			HostID:  req.HostID,
			Command: command,
			Args:    []string{},
			Options: ExecOptions{
				CWD:         scriptConfig.WorkingDir,
				UseShell:    scriptConfig.UseShell,
				TimeoutSec:  req.Options.TimeoutSec,
				Env:         req.Options.Env,
				Stream:      req.Options.Stream,
				MergeStderr: req.Options.MergeStderr,
				EnablePTY:   req.Options.EnablePTY,
			},
		}
	}

	// 如果脚本配置有超时设置，使用脚本的超时而不是请求的超时
	if scriptConfig.TimeoutSec > 0 {
		execReq.Options.TimeoutSec = scriptConfig.TimeoutSec
	}

	// 执行命令
	result, err := s.ExecuteCommand(ctx, execReq)
	if err != nil {
		s.logAudit(ctx, audit.Event{
			Category: "exec_script",
			Type:     "execution_error",
			HostID:   req.HostID,
			Target:   req.ScriptName,
			Outcome:  audit.OutcomeError,
			Severity: audit.SeverityHigh,
			Reason:   err.Error(),
		})
		return nil, err
	}

	durationMs := time.Since(startTime).Milliseconds()

	s.logger.Info("脚本执行完成",
		"host_id", req.HostID,
		"script_name", req.ScriptName,
		"exit_code", result.ExitCode,
		"duration_ms", durationMs)

	s.logAudit(ctx, audit.Event{
		Category: "exec_script",
		Type:     "script_completed",
		HostID:   req.HostID,
		Target:   req.ScriptName,
		Outcome:  audit.OutcomeSuccess,
		Severity: audit.SeverityInfo,
		Metadata: map[string]interface{}{
			"duration_ms": durationMs,
			"exit_code":   result.ExitCode,
		},
	})

	return result, nil
}

func (s *Service) logAudit(ctx context.Context, event audit.Event) {
	if s.audit == nil || !s.audit.Enabled() {
		return
	}
	s.audit.LogEvent(ctx, event)
}

// findScriptConfig 查找脚本配置
func (s *Service) findScriptConfig(scriptName string) *config.ScriptConfig {
	for i := range s.config.Scripts {
		script := &s.config.Scripts[i]
		if script.Name == scriptName {
			return script
		}
	}
	return nil
}

func (s *Service) filterForHost(hostID string) (*security.Filter, *config.SecurityConfig, error) {
	secCfg, ok := s.hostSecurity[hostID]
	if !ok {
		return nil, nil, fmt.Errorf("主机 '%s' 未配置", hostID)
	}
	filter, ok := s.filtersByGroup[secCfg.Group]
	if !ok {
		return nil, nil, fmt.Errorf("安全组 '%s' 未配置", secCfg.Group)
	}
	return filter, secCfg, nil
}

func (s *Service) hostForID(hostID string) (*config.SSHHost, error) {
	host, ok := s.hostIndex[hostID]
	if !ok {
		return nil, fmt.Errorf("主机 '%s' 未配置", hostID)
	}
	return host, nil
}

func isHostAllowedForScript(hostID string, patterns []string) bool {
	if len(patterns) == 0 {
		return false
	}
	for _, pattern := range patterns {
		p := strings.TrimSpace(pattern)
		if p == "" {
			continue
		}
		if p == "*" {
			return true
		}
		matched, err := filepath.Match(p, hostID)
		if err == nil && matched {
			return true
		}
	}
	return false
}

func hostAllowsScriptTag(hostTags []string, scriptTag string) bool {
	normalizedTag := strings.TrimSpace(strings.ToLower(scriptTag))
	if normalizedTag == "" {
		return true
	}
	for _, tag := range hostTags {
		clean := strings.TrimSpace(strings.ToLower(tag))
		if clean == "*" || clean == normalizedTag {
			return true
		}
	}
	return false
}

func normalizeTags(tags []string) []string {
	if len(tags) == 0 {
		return tags
	}
	result := make([]string, 0, len(tags))
	seen := make(map[string]struct{}, len(tags))
	for _, tag := range tags {
		clean := strings.TrimSpace(strings.ToLower(tag))
		if clean == "" {
			continue
		}
		if _, exists := seen[clean]; exists {
			continue
		}
		seen[clean] = struct{}{}
		result = append(result, clean)
	}
	return result
}

// renderTemplate 使用 text/template 渲染脚本命令。
// 如果脚本需要通过 shell 执行，模板内的默认变量一律会被 shellQuote 包裹，
// 这样就算用户参数里带有 `;`、`&&` 等特殊字符也不会被注入。
// 同时提供 raw()/shellQuote() 辅助函数，方便在特殊场景下自行决定转义策略。
func (s *Service) renderTemplate(templateStr string, params map[string]interface{}, useShell bool) (string, error) {
	if templateStr == "" {
		return "", fmt.Errorf("模板内容为空")
	}

	sanitized := make(map[string]string, len(params))
	raw := make(map[string]string, len(params))

	for key, value := range params {
		strVal := fmt.Sprintf("%v", value)
		raw[key] = strVal
		if useShell {
			sanitized[key] = shellQuote(strVal)
		} else {
			sanitized[key] = strVal
		}
	}

	funcMap := template.FuncMap{
		"raw": func(key string) string {
			return raw[key]
		},
		"shellQuote": shellQuote,
	}

	tmpl, err := template.New("script").Funcs(funcMap).Parse(templateStr)
	if err != nil {
		return "", common.WrapError("解析模板失败", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, sanitized); err != nil {
		return "", common.WrapError("模板渲染失败", err)
	}

	return buf.String(), nil
}

// applyDefaultValues 应用默认值并合并参数
func (s *Service) applyDefaultValues(scriptConfig *config.ScriptConfig, params map[string]interface{}) map[string]interface{} {
	merged := make(map[string]interface{})

	// 首先复制传入的参数
	for k, v := range params {
		merged[k] = v
	}

	// 然后应用默认值（对于缺失的参数）
	for _, param := range scriptConfig.Parameters {
		if _, exists := merged[param.Name]; !exists && param.Default != nil {
			merged[param.Name] = param.Default
		}
	}

	return merged
}

// validateParameters 验证参数
func (s *Service) validateParameters(scriptConfig *config.ScriptConfig, params map[string]interface{}) error {
	for _, def := range scriptConfig.Parameters {
		value, exists := params[def.Name]
		if !exists {
			if def.Required {
				return fmt.Errorf("缺少必需参数 '%s'", def.Name)
			}
			continue
		}

		var coerced interface{}
		switch strings.ToLower(def.Type) {
		case "string":
			str, ok := value.(string)
			if !ok {
				return fmt.Errorf("参数 '%s' 类型错误，期望 string", def.Name)
			}
			coerced = str
		case "integer":
			parsed, err := coerceToInt(value)
			if err != nil {
				return fmt.Errorf("参数 '%s' 类型错误，%v", def.Name, err)
			}
			coerced = parsed
		case "float":
			parsed, err := coerceToFloat(value)
			if err != nil {
				return fmt.Errorf("参数 '%s' 类型错误，%v", def.Name, err)
			}
			coerced = parsed
		case "boolean", "bool":
			parsed, err := coerceToBool(value)
			if err != nil {
				return fmt.Errorf("参数 '%s' 类型错误，%v", def.Name, err)
			}
			coerced = parsed
		default:
			return fmt.Errorf("参数 '%s' 使用了不支持的类型 '%s'", def.Name, def.Type)
		}

		if def.Validation != "" {
			strVal := fmt.Sprintf("%v", coerced)
			re, err := regexp.Compile(def.Validation)
			if err != nil {
				return fmt.Errorf("参数 '%s' 的验证规则无效: %v", def.Name, err)
			}
			if !re.MatchString(strVal) {
				return fmt.Errorf("参数 '%s' 未通过验证规则", def.Name)
			}
		}

		params[def.Name] = coerced
	}

	return nil
}

func coerceToInt(value interface{}) (int64, error) {
	switch v := value.(type) {
	case int:
		return int64(v), nil
	case int8:
		return int64(v), nil
	case int16:
		return int64(v), nil
	case int32:
		return int64(v), nil
	case int64:
		return v, nil
	case float32:
		return coerceToInt(float64(v))
	case float64:
		if math.Mod(v, 1) != 0 {
			return 0, fmt.Errorf("值 %v 不是整数", v)
		}
		return int64(v), nil
	case string:
		trimmed := strings.TrimSpace(v)
		if trimmed == "" {
			return 0, fmt.Errorf("值为空")
		}
		n, err := strconv.ParseInt(trimmed, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("无法解析整数: %v", err)
		}
		return n, nil
	default:
		return 0, fmt.Errorf("无法转换为整数")
	}
}

func coerceToFloat(value interface{}) (float64, error) {
	switch v := value.(type) {
	case float32:
		return float64(v), nil
	case float64:
		return v, nil
	case int:
		return float64(v), nil
	case int8:
		return float64(v), nil
	case int16:
		return float64(v), nil
	case int32:
		return float64(v), nil
	case int64:
		return float64(v), nil
	case string:
		trimmed := strings.TrimSpace(v)
		if trimmed == "" {
			return 0, fmt.Errorf("值为空")
		}
		n, err := strconv.ParseFloat(trimmed, 64)
		if err != nil {
			return 0, fmt.Errorf("无法解析浮点数: %v", err)
		}
		return n, nil
	default:
		return 0, fmt.Errorf("无法转换为浮点数")
	}
}

func coerceToBool(value interface{}) (bool, error) {
	switch v := value.(type) {
	case bool:
		return v, nil
	case string:
		trimmed := strings.TrimSpace(strings.ToLower(v))
		if trimmed == "" {
			return false, fmt.Errorf("值为空")
		}
		parsed, err := strconv.ParseBool(trimmed)
		if err != nil {
			return false, fmt.Errorf("无法解析布尔值: %v", err)
		}
		return parsed, nil
	default:
		return false, fmt.Errorf("无法转换为布尔值")
	}
}

// shellQuote 将任意参数包裹成安全的单引号表达式，并对内部单引号进行 POSIX 兼容的转义，
// 用于生成 `sh -c` 等命令的参数，确保字符串永远被视作字面量。
func shellQuote(value string) string {
	if value == "" {
		return "''"
	}

	escaped := strings.ReplaceAll(value, "'", "'\"'\"'")
	return "'" + escaped + "'"
}
