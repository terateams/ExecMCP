package execsvc

import (
	"context"
	"fmt"
	"time"

	"github.com/your-username/ExecMCP/internal/config"
	"github.com/your-username/ExecMCP/internal/logging"
	"github.com/your-username/ExecMCP/internal/security"
	"github.com/your-username/ExecMCP/internal/ssh"
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

	s.logger.Info("开始执行命令",
		"host_id", req.HostID,
		"command", req.Command,
		"args", req.Args,
		"use_shell", req.Options.UseShell)

	// 1. 安全过滤
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
		return nil, fmt.Errorf("安全检查失败: %w", err)
	}

	// 2. 获取 SSH 会话
	session, err := s.sshManager.GetSession(req.HostID)
	if err != nil {
		s.logger.Error("获取 SSH 会话失败",
			"host_id", req.HostID,
			"error", err)
		return nil, fmt.Errorf("获取 SSH 会话失败: %w", err)
	}
	defer s.sshManager.ReleaseSession(req.HostID, session)

	// 3. 执行命令
	output, err := session.ExecuteCommand(req.Command, req.Args)
	if err != nil {
		s.logger.Error("命令执行失败",
			"host_id", req.HostID,
			"command", req.Command,
			"error", err)
		return nil, fmt.Errorf("命令执行失败: %w", err)
	}

	// 4. 处理输出截断
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
		ExitCode:   0, // Mock SSH 会话总是返回成功
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

	s.logger.Info("开始执行脚本",
		"host_id", req.HostID,
		"script_name", req.ScriptName,
		"parameters", req.Parameters)

	// 查找脚本配置
	scriptConfig := s.findScriptConfig(req.ScriptName)
	if scriptConfig == nil {
		return nil, fmt.Errorf("脚本 '%s' 不存在", req.ScriptName)
	}

	// 应用默认值并合并参数
	mergedParams := s.applyDefaultValues(scriptConfig, req.Parameters)

	// 渲染脚本模板
	command, err := s.renderTemplate(scriptConfig.Template, mergedParams)
	if err != nil {
		return nil, fmt.Errorf("模板渲染失败: %w", err)
	}

	// 验证参数
	if err := s.validateParameters(scriptConfig, mergedParams); err != nil {
		return nil, fmt.Errorf("参数验证失败: %w", err)
	}

	// 构建执行请求 - 使用脚本配置中的选项
	var execReq ExecRequest

	if scriptConfig.UseShell {
		// 对于 shell 脚本，使用 sh 作为命令，脚本内容作为参数
		execReq = ExecRequest{
			HostID:  req.HostID,
			Command: "sh",
			Args:    []string{"-c", command},
			Options: ExecOptions{
				CWD:         scriptConfig.WorkingDir,
				UseShell:    false, // 不需要额外的 shell 包装，因为我们直接调用 sh
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

// renderTemplate 渲染模板
func (s *Service) renderTemplate(template string, params map[string]interface{}) (string, error) {
	// TODO: 实现安全的模板渲染
	// 1. 参数验证和转义
	// 2. 替换模板中的占位符
	// 3. 返回渲染后的命令

	// 临时实现：简单的字符串替换
	result := template
	for key, value := range params {
		placeholder := "{{" + key + "}}"
		result = replaceAll(result, placeholder, fmt.Sprintf("%v", value))
	}

	return result, nil
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
	// TODO: 实现参数验证
	// 1. 检查必需参数
	// 2. 验证参数类型
	// 3. 应用正则验证
	// 4. 设置默认值

	return nil
}

// replaceAll 简单的字符串替换
func replaceAll(s, old, new string) string {
	result := s
	for {
		pos := findSubstring(result, old)
		if pos == -1 {
			break
		}
		result = result[:pos] + new + result[pos+len(old):]
	}
	return result
}

// findSubstring 查找子字符串位置
func findSubstring(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
