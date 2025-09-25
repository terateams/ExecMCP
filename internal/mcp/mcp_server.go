package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/terateams/ExecMCP/internal/audit"
	"github.com/terateams/ExecMCP/internal/config"
	"github.com/terateams/ExecMCP/internal/execsvc"
	"github.com/terateams/ExecMCP/internal/logging"
	"github.com/terateams/ExecMCP/internal/security"
	"github.com/terateams/ExecMCP/internal/ssh"
)

// MCPServer MCP 服务器
type MCPServer struct {
	config        *config.Config
	logger        logging.Logger
	audit         audit.Logger
	server        *server.MCPServer
	sseServer     *server.SSEServer
	execService   *execsvc.Service
	sshManager    ssh.Manager
	tempApprovals *temporaryApprovalCache
}

type remoteAddrContextKey struct{}

// NewMCPServer 创建新的 MCP 服务器
func NewMCPServer(cfg *config.Config, logger logging.Logger, auditLogger audit.Logger) (*MCPServer, error) {
	if auditLogger == nil {
		auditLogger = audit.NewNoopLogger()
	}
	// 创建 SSH 管理器
	sshManager := ssh.NewManager(cfg, logger)

	// 创建执行服务
	execService, err := execsvc.NewService(cfg, logger, auditLogger)
	if err != nil {
		return nil, fmt.Errorf("创建执行服务失败: %w", err)
	}

	// 创建 MCP 服务器
	mcpServer := server.NewMCPServer(
		"ExecMCP",
		"1.0.0",
		server.WithLogging(),
	)

	mcp := &MCPServer{
		config:        cfg,
		logger:        logger,
		audit:         auditLogger,
		server:        mcpServer,
		execService:   execService,
		sshManager:    sshManager,
		tempApprovals: newTemporaryApprovalCache(logger, auditLogger),
	}

	// 注册工具
	mcp.registerTools()

	// 创建 SSE 服务器
	baseURL := fmt.Sprintf("http://%s", cfg.Server.BindAddr)
	// Convert 127.0.0.1 to localhost for better client compatibility
	if cfg.Server.BindAddr == "127.0.0.1:8081" {
		baseURL = "http://localhost:8081"
	}
	mcp.sseServer = server.NewSSEServer(
		mcpServer,
		server.WithBaseURL(baseURL),
		server.WithStaticBasePath("/mcp"),
		server.WithSSEContextFunc(func(ctx context.Context, r *http.Request) context.Context {
			ip := remoteIPFromRequest(r)
			if ip != "" {
				ctx = context.WithValue(ctx, remoteAddrContextKey{}, ip)
			}
			return ctx
		}),
	)

	logger.Info("MCP 服务器初始化完成",
		"ssh_hosts_count", len(cfg.SSHHosts),
		"scripts_count", len(cfg.Scripts))

	return mcp, nil
}

// registerTools 注册 MCP 工具
func (m *MCPServer) registerTools() {
	execCommandTool := mcp.NewTool("exec_command",
		mcp.WithDescription("Execute a command on remote host"),
		mcp.WithString("host_id",
			mcp.Required(),
			mcp.Description("The unique identifier of the remote host on which the command should run"),
		),
		mcp.WithString("command",
			mcp.Required(),
			mcp.Description("Executable name (no arguments); pass flags/parameters via the args array"),
		),

		mcp.WithArray("args",
			mcp.Description("Optional array of command arguments to pass to the command"),
			mcp.WithStringItems(mcp.Description("Command argument")),
		),
		mcp.WithBoolean("use_shell",
			mcp.Description("Whether to execute the command through a shell (default: false)"),
		),
		mcp.WithBoolean("enable_pty",
			mcp.Description("Whether to request a pseudo-terminal (PTY) for the command; defaults to server policy"),
		),
		mcp.WithString("working_dir",
			mcp.Description("Working directory to execute the command in (optional)"),
		),
		mcp.WithNumber("timeout_sec",
			mcp.Description("Timeout in seconds for command execution (default: 30)"),
		),
		mcp.WithString("auth_token",
			mcp.Description("Server auth token (if configured)"),
		),
	)
	m.server.AddTool(execCommandTool, m.handleExecCommand)

	// 注册 exec_script 工具
	execScriptTool := mcp.NewTool("exec_script",
		mcp.WithDescription("Execute a predefined script"),
		mcp.WithString("host_id",
			mcp.Required(),
			mcp.Description("The unique identifier of the remote host on which the script should run"),
		),
		mcp.WithString("script_name",
			mcp.Required(),
			mcp.Description("The name of the predefined script to execute"),
		),
		mcp.WithObject("parameters",
			mcp.Description("Key-value pairs of script parameters (optional)"),
		),
		mcp.WithNumber("timeout_sec",
			mcp.Description("Timeout in seconds for script execution (default: 30)"),
		),
		mcp.WithBoolean("enable_pty",
			mcp.Description("Whether to request a pseudo-terminal (PTY) when executing the script"),
		),
		mcp.WithString("auth_token",
			mcp.Description("Server auth token (if configured)"),
		),
	)
	m.server.AddTool(execScriptTool, m.handleExecScript)

	// 注册 list_commands 工具
	listCommandsTool := mcp.NewTool("list_commands",
		mcp.WithDescription("List available commands and scripts"),
		mcp.WithString("type",
			mcp.Description("Type of items to list: 'all', 'commands', or 'scripts' (default: 'all')"),
			mcp.WithStringEnumItems([]string{"all", "commands", "scripts"}),
		),
		mcp.WithString("auth_token",
			mcp.Description("Server auth token (if configured)"),
		),
	)
	m.server.AddTool(listCommandsTool, m.handleListCommands)

	// 注册 test_connection 工具
	testConnectionTool := mcp.NewTool("test_connection",
		mcp.WithDescription("Test SSH connection to a remote host"),
		mcp.WithString("host_id",
			mcp.Required(),
			mcp.Description("The unique identifier of the remote host to test connection for"),
		),
		mcp.WithString("auth_token",
			mcp.Description("Server auth token (if configured)"),
		),
	)
	m.server.AddTool(testConnectionTool, m.handleTestConnection)

	// 注册 list_hosts 工具
	listHostsTool := mcp.NewTool("list_hosts",
		mcp.WithDescription("List all configured SSH hosts"),
		mcp.WithString("auth_token",
			mcp.Description("Server auth token (if configured)"),
		),
	)
	m.server.AddTool(listHostsTool, m.handleListHosts)

	// 注册 approve_command 工具
	approveCommandTool := mcp.NewTool("approve_command",
		mcp.WithDescription("Temporarily approve a command for the invoking client"),
		mcp.WithString("command",
			mcp.Required(),
			mcp.Description("Command name (exact match) to temporarily allow"),
		),
		mcp.WithNumber("duration_sec",
			mcp.Description("Approval lifetime in seconds (default: 600)"),
		),
		mcp.WithNumber("max_uses",
			mcp.Description("Maximum times the approval can be used before expiry (default: 1, 0 = unlimited)"),
		),
		mcp.WithString("notes",
			mcp.Description("Optional notes or ticket reference for auditing"),
		),
		mcp.WithString("auth_token",
			mcp.Description("Server auth token (if configured)"),
		),
	)
	m.server.AddTool(approveCommandTool, m.handleApproveCommand)
}

// Start 启动 MCP 服务器
func (m *MCPServer) Start(ctx context.Context) error {
	m.logger.Info("启动 MCP SSE 服务器", "address", m.config.Server.BindAddr)

	// 启动 SSE 服务器
	go func() {
		if err := m.sseServer.Start(m.config.Server.BindAddr); err != nil && err != http.ErrServerClosed {
			m.logger.Error("SSE 服务器启动失败", "error", err)
		}
	}()

	// 等待上下文取消
	<-ctx.Done()
	m.logger.Info("正在停止 MCP 服务器...")

	// 优雅关闭
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := m.sseServer.Shutdown(shutdownCtx); err != nil {
		m.logger.Error("SSE 服务器关闭失败", "error", err)
		return err
	}

	return nil
}

// Stop 停止 MCP 服务器
func (m *MCPServer) Stop() error {
	if m.sseServer != nil {
		return m.sseServer.Shutdown(context.Background())
	}
	return nil
}

// 处理工具调用
func (m *MCPServer) handleExecCommand(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	ctx = m.withAuditContext(ctx, "exec_command", req)
	if err := m.checkAuth(ctx, req); err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	identity := m.buildClientIdentity(ctx, req)
	if identity.IsValid() {
		if provider := newTemporaryApprovalProvider(m.tempApprovals, identity.Key()); provider != nil {
			ctx = security.WithTemporaryApproval(ctx, provider)
			m.logger.Debug("为请求注入临时批准上下文", "identity", identity.Key(), "ip", identity.IP, "client_id", identity.ClientID)
		}
	}
	hostID := mcp.ParseString(req, "host_id", "")
	command := mcp.ParseString(req, "command", "")

	if hostID == "" || command == "" {
		missing := []string{}
		if hostID == "" {
			missing = append(missing, "host_id")
		}
		if command == "" {
			missing = append(missing, "command")
		}
		m.logAudit(ctx, audit.Event{
			Category: "exec_command",
			Type:     "invalid_request",
			Outcome:  audit.OutcomeDenied,
			Severity: audit.SeverityLow,
			Reason:   "missing required fields",
			Metadata: map[string]interface{}{"missing": missing},
		})
		return mcp.NewToolResultError("host_id and command are required"), nil
	}

	if strings.ContainsAny(command, " \t\r\n") {
		m.logAudit(ctx, audit.Event{
			Category: "exec_command",
			Type:     "invalid_request",
			Outcome:  audit.OutcomeDenied,
			Severity: audit.SeverityLow,
			Reason:   "command contains whitespace",
			Metadata: map[string]interface{}{
				"command": command,
			},
		})
		return mcp.NewToolResultError("command must contain only the executable name; provide parameters via the args array"), nil
	}

	args := mcp.ParseArgument(req, "args", []interface{}{})
	var argsStr []string
	if argsSlice, ok := args.([]interface{}); ok {
		for _, arg := range argsSlice {
			if argStr, ok := arg.(string); ok {
				argsStr = append(argsStr, argStr)
			}
		}
	}

	defaultPTY := m.config.Security.EnablePTY
	useShell := mcp.ParseBoolean(req, "use_shell", false)
	enablePTY := mcp.ParseBoolean(req, "enable_pty", defaultPTY)
	workingDir := mcp.ParseString(req, "working_dir", "")
	timeoutSec := mcp.ParseArgument(req, "timeout_sec", 30.0)
	timeout := int(timeoutSec.(float64))

	m.logger.Info("收到命令执行请求", "host_id", hostID, "command", command, "args", argsStr, "use_shell", useShell, "enable_pty", enablePTY)

	result, err := m.execService.ExecuteCommand(ctx, execsvc.ExecRequest{
		HostID:  hostID,
		Command: command,
		Args:    argsStr,
		Options: execsvc.ExecOptions{
			UseShell:   useShell,
			EnablePTY:  enablePTY,
			CWD:        workingDir,
			TimeoutSec: timeout,
		},
	})

	if err != nil {
		m.logger.Error("命令执行失败", "error", err)
		return mcp.NewToolResultError(fmt.Sprintf("Command execution failed: %v", err)), nil
	}

	response := map[string]interface{}{
		"host_id":     hostID,
		"command":     command,
		"args":        argsStr,
		"exit_code":   result.ExitCode,
		"stdout":      result.Stdout,
		"stderr":      result.Stderr,
		"success":     result.ExitCode == 0,
		"duration_ms": result.DurationMs,
		"truncated":   result.Truncated,
	}

	responseJson, _ := json.MarshalIndent(response, "", "  ")
	return mcp.NewToolResultText(string(responseJson)), nil
}

func (m *MCPServer) handleExecScript(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	ctx = m.withAuditContext(ctx, "exec_script", req)
	if err := m.checkAuth(ctx, req); err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	hostID := mcp.ParseString(req, "host_id", "")
	scriptName := mcp.ParseString(req, "script_name", "")

	if hostID == "" || scriptName == "" {
		missing := []string{}
		if hostID == "" {
			missing = append(missing, "host_id")
		}
		if scriptName == "" {
			missing = append(missing, "script_name")
		}
		m.logAudit(ctx, audit.Event{
			Category: "exec_script",
			Type:     "invalid_request",
			Outcome:  audit.OutcomeDenied,
			Severity: audit.SeverityLow,
			Reason:   "missing required fields",
			Metadata: map[string]interface{}{"missing": missing},
		})
		return mcp.NewToolResultError("host_id and script_name are required"), nil
	}

	if strings.ContainsAny(scriptName, " \t\r\n") {
		m.logAudit(ctx, audit.Event{
			Category: "exec_script",
			Type:     "invalid_request",
			Outcome:  audit.OutcomeDenied,
			Severity: audit.SeverityLow,
			Reason:   "script_name contains whitespace",
			Metadata: map[string]interface{}{
				"script_name": scriptName,
			},
		})
		return mcp.NewToolResultError("script_name must match a configured script; pass arguments via the parameters map"), nil
	}

	paramsAny := mcp.ParseArgument(req, "parameters", map[string]interface{}{})
	parameters, _ := paramsAny.(map[string]interface{})
	timeoutSec := mcp.ParseArgument(req, "timeout_sec", 30.0)
	timeout := int(timeoutSec.(float64))
	enablePTY := mcp.ParseBoolean(req, "enable_pty", m.config.Security.EnablePTY)

	m.logger.Info("收到脚本执行请求", "host_id", hostID, "script_name", scriptName, "parameters", parameters, "enable_pty", enablePTY)

	result, err := m.execService.ExecuteScript(ctx, execsvc.ScriptRequest{
		HostID:     hostID,
		ScriptName: scriptName,
		Parameters: parameters,
		Options: execsvc.ExecOptions{
			TimeoutSec: timeout,
			EnablePTY:  enablePTY,
		},
	})

	if err != nil {
		m.logger.Error("脚本执行失败", "error", err)
		return mcp.NewToolResultError(fmt.Sprintf("Script execution failed: %v", err)), nil
	}

	response := map[string]interface{}{
		"host_id":     hostID,
		"script_name": scriptName,
		"parameters":  parameters,
		"exit_code":   result.ExitCode,
		"stdout":      result.Stdout,
		"stderr":      result.Stderr,
		"success":     result.ExitCode == 0,
		"duration_ms": result.DurationMs,
		"truncated":   result.Truncated,
	}

	responseJson, _ := json.MarshalIndent(response, "", "  ")
	return mcp.NewToolResultText(string(responseJson)), nil
}

func (m *MCPServer) handleListCommands(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	ctx = m.withAuditContext(ctx, "list_commands", req)
	if err := m.checkAuth(ctx, req); err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	listType := mcp.ParseString(req, "type", "all")

	sec := m.config.Security
	var allowedCommands []string
	if len(sec.AllowlistExact) > 0 {
		allowedCommands = append(allowedCommands, fmt.Sprintf("allowlist_exact: %s", strings.Join(sec.AllowlistExact, ", ")))
	}
	if len(sec.AllowlistRegex) > 0 {
		allowedCommands = append(allowedCommands, fmt.Sprintf("allowlist_regex: %s", strings.Join(sec.AllowlistRegex, ", ")))
	}
	if len(sec.AllowShellFor) > 0 {
		allowedCommands = append(allowedCommands, fmt.Sprintf("allow_shell_for: %s", strings.Join(sec.AllowShellFor, ", ")))
	}

	response := map[string]interface{}{
		"type":       listType,
		"queried_at": time.Now().Format(time.RFC3339),
		"security_notes": []string{
			"所有命令都经过安全过滤器检查",
			"禁止危险命令如 rm, dd, shutdown 等",
			"支持参数级别的正则表达式过滤",
			"可配置工作目录限制",
		},
	}

	if listType == "all" || listType == "commands" {
		response["allowed_commands"] = allowedCommands
		if len(sec.DenylistExact) > 0 {
			response["denylist_exact"] = append([]string(nil), sec.DenylistExact...)
		}
		if len(sec.DenylistRegex) > 0 {
			response["denylist_regex"] = append([]string(nil), sec.DenylistRegex...)
		}
		response["default_shell"] = sec.DefaultShell
	}

	if listType == "all" || listType == "scripts" {
		var scripts []map[string]interface{}
		for _, script := range m.config.Scripts {
			scriptInfo := map[string]interface{}{
				"name":          script.Name,
				"description":   script.Description,
				"timeout_sec":   script.TimeoutSec,
				"use_shell":     script.UseShell,
				"working_dir":   script.WorkingDir,
				"allowed_hosts": script.AllowedHosts,
			}

			var params []map[string]interface{}
			for _, param := range script.Parameters {
				paramInfo := map[string]interface{}{
					"name":        param.Name,
					"type":        param.Type,
					"required":    param.Required,
					"default":     param.Default,
					"description": param.Description,
					"validation":  param.Validation,
				}
				params = append(params, paramInfo)
			}
			scriptInfo["parameters"] = params
			scripts = append(scripts, scriptInfo)
		}
		response["scripts"] = scripts
	}

	responseJson, _ := json.MarshalIndent(response, "", "  ")
	return mcp.NewToolResultText(string(responseJson)), nil
}

func (m *MCPServer) handleTestConnection(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	ctx = m.withAuditContext(ctx, "test_connection", req)
	if err := m.checkAuth(ctx, req); err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	hostID := mcp.ParseString(req, "host_id", "")

	if hostID == "" {
		m.logAudit(ctx, audit.Event{
			Category: "test_connection",
			Type:     "invalid_request",
			Outcome:  audit.OutcomeDenied,
			Severity: audit.SeverityLow,
			Reason:   "missing host_id",
		})
		return mcp.NewToolResultError("host_id is required"), nil
	}

	m.logger.Info("收到连接测试请求", "host_id", hostID)

	err := m.sshManager.HealthCheck(hostID)
	if err != nil {
		m.logger.Error("连接测试失败", "host_id", hostID, "error", err)
		m.logAudit(ctx, audit.Event{
			Category: "test_connection",
			Type:     "connection_failed",
			Outcome:  audit.OutcomeError,
			Severity: audit.SeverityMedium,
			Reason:   err.Error(),
			Metadata: map[string]interface{}{"host_id": hostID},
		})
		return mcp.NewToolResultError(fmt.Sprintf("Connection test failed: %v", err)), nil
	}

	// 查找主机配置
	var hostConfig *config.SSHHost
	for _, host := range m.config.SSHHosts {
		if host.ID == hostID {
			hostConfig = &host
			break
		}
	}

	if hostConfig == nil {
		m.logAudit(ctx, audit.Event{
			Category: "test_connection",
			Type:     "unknown_host",
			Outcome:  audit.OutcomeDenied,
			Severity: audit.SeverityMedium,
			Reason:   fmt.Sprintf("host not configured: %s", hostID),
		})
		return mcp.NewToolResultError(fmt.Sprintf("Host configuration not found: %s", hostID)), nil
	}

	response := map[string]interface{}{
		"success":   true,
		"host_id":   hostID,
		"status":    "connected",
		"tested_at": time.Now().Format(time.RFC3339),
		"notes":     []string{"SSH 连接正常"},
	}

	responseJson, _ := json.MarshalIndent(response, "", "  ")
	return mcp.NewToolResultText(string(responseJson)), nil
}

func (m *MCPServer) handleListHosts(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	ctx = m.withAuditContext(ctx, "list_hosts", req)
	if err := m.checkAuth(ctx, req); err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	m.logger.Info("收到主机列表请求")

	var hosts []map[string]interface{}
	for _, host := range m.config.SSHHosts {
		hostInfo := map[string]interface{}{
			"id":                  host.ID,
			"auth_type":           host.AuthMethod,
			"connect_timeout_sec": host.ConnectTimeout,
			"keepalive_sec":       host.KeepaliveSec,
			"max_sessions":        host.MaxSessions,
		}

		hosts = append(hosts, hostInfo)
	}

	response := map[string]interface{}{
		"hosts":      hosts,
		"count":      len(hosts),
		"queried_at": time.Now().Format(time.RFC3339),
		"notes": []string{
			"所有配置的 SSH 主机列表",
			"可以使用 test_connection 工具测试连接",
			"使用 exec_command 工具执行命令",
		},
	}

	responseJson, _ := json.MarshalIndent(response, "", "  ")
	return mcp.NewToolResultText(string(responseJson)), nil
}

func (m *MCPServer) handleApproveCommand(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	ctx = m.withAuditContext(ctx, "approve_command", req)
	if err := m.checkAuth(ctx, req); err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	identity := m.buildClientIdentity(ctx, req)
	command := strings.TrimSpace(mcp.ParseString(req, "command", ""))

	if command == "" {
		m.logAudit(ctx, audit.Event{
			Category: "temporary_approval",
			Type:     "approve_command_failed",
			Outcome:  audit.OutcomeDenied,
			Severity: audit.SeverityMedium,
			Reason:   "missing command",
		})
		return mcp.NewToolResultError("command is required"), nil
	}

	duration := parseIntArgument(mcp.ParseArgument(req, "duration_sec", 600.0))
	if duration <= 0 {
		duration = 600
	}
	maxUses := parseIntArgument(mcp.ParseArgument(req, "max_uses", 1.0))
	if maxUses < 0 {
		maxUses = 0
	}
	notes := strings.TrimSpace(mcp.ParseString(req, "notes", ""))

	if !identity.IsValid() {
		m.logAudit(ctx, audit.Event{
			Category: "temporary_approval",
			Type:     "approve_command_failed",
			Outcome:  audit.OutcomeDenied,
			Severity: audit.SeverityMedium,
			Reason:   "unable to infer client identity",
		})
		return mcp.NewToolResultError("could not infer client identity from request"), nil
	}
	identityKey := identity.Key()

	noteFields := map[string]any{
		"client_ip": identity.IP,
		"client_id": identity.ClientID,
	}
	if notes != "" {
		noteFields["notes"] = notes
	}

	approvedBy := extractActorFromRequest(req)
	entry := m.tempApprovals.approve(identityKey, command, time.Duration(duration)*time.Second, maxUses, approvedBy, noteFields)

	m.logAudit(ctx, audit.Event{
		Category: "temporary_approval",
		Type:     "approve_command",
		Outcome:  audit.OutcomeSuccess,
		Severity: audit.SeverityInfo,
		Actor:    approvedBy,
		Target:   command,
		Metadata: map[string]interface{}{
			"client_ip":        identity.IP,
			"client_id":        identity.ClientID,
			"expires_at":       entry.expiresAt.Format(time.RFC3339),
			"max_uses":         entry.maxUses,
			"notes":            notes,
			"identity_key":     identityKey,
			"duration_seconds": duration,
		},
	})

	response := map[string]any{
		"identity":         identityKey,
		"client_ip":        identity.IP,
		"client_id":        identity.ClientID,
		"command":          command,
		"expires_at":       entry.expiresAt.Format(time.RFC3339),
		"max_uses":         entry.maxUses,
		"uses_consumed":    entry.useCount,
		"duration_seconds": duration,
	}
	if notes != "" {
		response["notes"] = notes
	}

	responseJSON, _ := json.MarshalIndent(response, "", "  ")
	return mcp.NewToolResultText(string(responseJSON)), nil
}

func (m *MCPServer) checkAuth(ctx context.Context, req mcp.CallToolRequest) error {
	expected := strings.TrimSpace(m.config.Server.AuthToken)
	if expected == "" {
		return nil
	}

	provided := strings.TrimSpace(req.GetString("auth_token", ""))

	if provided == "" && req.Params.Meta != nil && req.Params.Meta.AdditionalFields != nil {
		if v, ok := req.Params.Meta.AdditionalFields["auth_token"].(string); ok {
			provided = strings.TrimSpace(v)
		}
	}

	if provided == "" && req.Header != nil {
		if authHeader := strings.TrimSpace(req.Header.Get("Authorization")); authHeader != "" {
			const bearer = "bearer "
			lower := strings.ToLower(authHeader)
			if strings.HasPrefix(lower, bearer) {
				provided = strings.TrimSpace(authHeader[len(bearer):])
			}
		}
	}

	if provided == "" {
		m.logAudit(ctx, audit.Event{
			Category: "auth",
			Type:     "auth_failed",
			Outcome:  audit.OutcomeDenied,
			Severity: audit.SeverityHigh,
			Reason:   "missing auth token",
			Metadata: map[string]interface{}{"has_token": false},
		})
		return fmt.Errorf("unauthorized: missing auth token")
	}
	if provided != expected {
		m.logAudit(ctx, audit.Event{
			Category: "auth",
			Type:     "auth_failed",
			Outcome:  audit.OutcomeDenied,
			Severity: audit.SeverityHigh,
			Reason:   "invalid auth token",
			Metadata: map[string]interface{}{"has_token": true},
		})
		return fmt.Errorf("unauthorized: invalid auth token")
	}
	return nil
}

func (m *MCPServer) withAuditContext(ctx context.Context, toolName string, req mcp.CallToolRequest) context.Context {
	ctx, reqID := audit.EnsureContext(ctx)
	fields := audit.ContextFields{
		RequestID: reqID,
		Actor:     extractActorFromRequest(req),
		Tool:      toolName,
		SourceIP:  extractSourceIPFromRequest(req),
	}
	return audit.WithContext(ctx, fields)
}

func (m *MCPServer) logAudit(ctx context.Context, event audit.Event) {
	if m.audit == nil || !m.audit.Enabled() {
		return
	}
	m.audit.LogEvent(ctx, event)
}

func extractActorFromRequest(req mcp.CallToolRequest) string {
	if meta := req.Params.Meta; meta != nil && meta.AdditionalFields != nil {
		for _, key := range []string{"actor", "user", "username", "client", "source"} {
			if value, ok := meta.AdditionalFields[key]; ok {
				if str, ok := value.(string); ok {
					if trimmed := strings.TrimSpace(str); trimmed != "" {
						return trimmed
					}
				}
			}
		}
	}
	if req.Header != nil {
		keys := []string{"X-Actor", "X-Client-Id", "X-Requester", "User-Agent"}
		for _, key := range keys {
			if value := strings.TrimSpace(req.Header.Get(key)); value != "" {
				return value
			}
		}
	}
	return "unknown"
}

func extractSourceIPFromRequest(req mcp.CallToolRequest) string {
	if req.Header == nil {
		return ""
	}
	if forwarded := strings.TrimSpace(req.Header.Get("X-Forwarded-For")); forwarded != "" {
		parts := strings.Split(forwarded, ",")
		if len(parts) > 0 {
			if ip := strings.TrimSpace(parts[0]); ip != "" {
				return ip
			}
		}
	}
	keys := []string{"X-Real-IP", "X-Client-IP"}
	for _, key := range keys {
		if value := strings.TrimSpace(req.Header.Get(key)); value != "" {
			return value
		}
	}
	return ""
}

func (m *MCPServer) buildClientIdentity(ctx context.Context, req mcp.CallToolRequest) clientIdentity {
	ip := ""
	if ctx != nil {
		if value := ctx.Value(remoteAddrContextKey{}); value != nil {
			if v, ok := value.(string); ok {
				ip = v
			}
		}
	}
	if ip == "" {
		ip = extractSourceIPFromRequest(req)
	}
	ip = sanitizeClientIPInput(ip)
	clientID := extractClientIdentifier(req)
	return clientIdentity{
		IP:       normalizeIP(ip),
		ClientID: clientID,
	}
}

func remoteIPFromRequest(r *http.Request) string {
	if r == nil {
		return ""
	}
	if forwarded := r.Header.Get("X-Forwarded-For"); strings.TrimSpace(forwarded) != "" {
		return sanitizeClientIPInput(forwarded)
	}
	if realIP := strings.TrimSpace(r.Header.Get("X-Real-IP")); realIP != "" {
		return realIP
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

func sanitizeClientIPInput(input string) string {
	input = strings.TrimSpace(input)
	if input == "" {
		return ""
	}
	parts := strings.Split(input, ",")
	if len(parts) > 0 {
		input = strings.TrimSpace(parts[0])
	}
	return input
}

func parseIntArgument(value interface{}) int {
	switch v := value.(type) {
	case nil:
		return 0
	case float64:
		return int(v)
	case float32:
		return int(v)
	case int:
		return v
	case int64:
		return int(v)
	case uint:
		return int(v)
	case uint64:
		return int(v)
	case string:
		if trimmed := strings.TrimSpace(v); trimmed != "" {
			if parsed, err := strconv.Atoi(trimmed); err == nil {
				return parsed
			}
		}
	case json.Number:
		if parsed, err := v.Int64(); err == nil {
			return int(parsed)
		}
	}
	return 0
}

func extractClientIdentifier(req mcp.CallToolRequest) string {
	if meta := req.Params.Meta; meta != nil && meta.AdditionalFields != nil {
		for _, key := range []string{"client_id", "clientId", "client", "actor", "user", "username"} {
			if value, ok := meta.AdditionalFields[key]; ok {
				if str, ok := value.(string); ok {
					if trimmed := strings.TrimSpace(str); trimmed != "" {
						return trimmed
					}
				}
			}
		}
	}
	if req.Header != nil {
		for _, key := range []string{"X-Client-Id", "X-Actor", "X-Requester"} {
			if value := strings.TrimSpace(req.Header.Get(key)); value != "" {
				return value
			}
		}
	}
	return ""
}
