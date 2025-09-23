package execsvc

import (
	"bytes"
	"context"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/terateams/ExecMCP/internal/common"
	"github.com/terateams/ExecMCP/internal/config"
	"github.com/terateams/ExecMCP/internal/logging"
	"github.com/terateams/ExecMCP/internal/security"
	"github.com/terateams/ExecMCP/internal/ssh"
)

// Service 命令执行服务
type Service struct {
	config     *config.Config
	logger     logging.Logger
	sshManager ssh.Manager
	filter     *security.Filter
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
}

// ScriptRequest 脚本执行请求
type ScriptRequest struct {
	HostID     string                 `json:"host_id"`
	ScriptName string                 `json:"script_name"`
	Parameters map[string]interface{} `json:"parameters"`
	Options    ExecOptions            `json:"options"`
}

// NewService 创建新的命令执行服务
func NewService(cfg *config.Config, logger logging.Logger) (*Service, error) {
	service := &Service{
		config:     cfg,
		logger:     logger,
		sshManager: ssh.NewManager(cfg, logger),
		filter:     security.NewFilter(&cfg.Security),
	}

	logger.Info("命令执行服务初始化完成")

	return service, nil
}

// ExecuteCommand 执行命令
func (s *Service) ExecuteCommand(ctx context.Context, req ExecRequest) (*ExecResult, error) {
	startTime := time.Now()

	// 记录执行上下文，便于审计与排查问题
	s.logger.Info("开始执行命令",
		"host_id", req.HostID,
		"command", req.Command,
		"args", req.Args,
		"use_shell", req.Options.UseShell)

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
		},
	}

	if err := s.filter.Check(securityReq); err != nil {
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
		return nil, common.SSHError("获取会话", req.HostID, err)
	}
	defer s.sshManager.ReleaseSession(req.HostID, session)

	// 3. 执行命令
	output, err := session.ExecuteCommand(req.Command, req.Args)
	if err != nil {
		s.logger.Error("命令执行失败",
			"host_id", req.HostID,
			"command", req.Command,
			"error", err)
		return nil, common.SSHError("命令执行", req.HostID, err)
	}

	// 4. 处理输出截断：避免单个命令输出过大拖垮上层调用者
	maxOutput := s.config.Security.MaxOutputBytes
	truncated := false
	if int64(len(output)) > maxOutput {
		output = output[:maxOutput]
		truncated = true
		s.logger.Warn("输出被截断",
			"host_id", req.HostID,
			"command", req.Command,
			"original_size", len(output),
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

	return result, nil
}

// ExecuteScript 执行脚本
func (s *Service) ExecuteScript(ctx context.Context, req ScriptRequest) (*ExecResult, error) {
	startTime := time.Now()

	// 脚本执行同样先记录关键信息，便于追踪具体业务脚本
	s.logger.Info("开始执行脚本",
		"host_id", req.HostID,
		"script_name", req.ScriptName,
		"parameters", req.Parameters)

	// 查找脚本配置：脚本必须在配置文件中明确定义
	scriptConfig := s.findScriptConfig(req.ScriptName)
	if scriptConfig == nil {
		return nil, fmt.Errorf("脚本 '%s' 不存在", req.ScriptName)
	}

	// 合并用户参数与默认值，确保模板渲染阶段数据齐全
	mergedParams := s.applyDefaultValues(scriptConfig, req.Parameters)

	// 使用安全模板引擎渲染脚本，自动处理 shell 注入风险
	command, err := s.renderTemplate(scriptConfig.Template, mergedParams, scriptConfig.UseShell)
	if err != nil {
		return nil, common.WrapError("模板渲染失败", err)
	}

	// 预留校验逻辑：未来可在此扩展类型、范围等校验
	if err := s.validateParameters(scriptConfig, mergedParams); err != nil {
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
		return nil, err
	}

	s.logger.Info("脚本执行完成",
		"host_id", req.HostID,
		"script_name", req.ScriptName,
		"exit_code", result.ExitCode,
		"duration_ms", time.Since(startTime).Milliseconds())

	return result, nil
}

// findScriptConfig 查找脚本配置
func (s *Service) findScriptConfig(scriptName string) *config.ScriptConfig {
	for _, script := range s.config.Scripts {
		if script.Name == scriptName {
			return &script
		}
	}
	return nil
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
