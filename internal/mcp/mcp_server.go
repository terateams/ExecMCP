package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/terateams/ExecMCP/internal/config"
	"github.com/terateams/ExecMCP/internal/execsvc"
	"github.com/terateams/ExecMCP/internal/logging"
	"github.com/terateams/ExecMCP/internal/ssh"
)

// MCPServer MCP 服务器
type MCPServer struct {
	config      *config.Config
	logger      logging.Logger
	server      *server.MCPServer
	sseServer   *server.SSEServer
	execService *execsvc.Service
	sshManager  ssh.Manager
}

// NewMCPServer 创建新的 MCP 服务器
func NewMCPServer(cfg *config.Config, logger logging.Logger) (*MCPServer, error) {
	// 创建 SSH 管理器
	sshManager := ssh.NewManager(cfg, logger)

	// 创建执行服务
	execService, err := execsvc.NewService(cfg, logger)
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
		config:      cfg,
		logger:      logger,
		server:      mcpServer,
		execService: execService,
		sshManager:  sshManager,
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
			mcp.Description("The exact command string to execute on the remote host"),
		),
		mcp.WithArray("args",
			mcp.Description("Optional array of command arguments to pass to the command"),
			mcp.WithStringItems(mcp.Description("Command argument")),
		),
		mcp.WithBoolean("use_shell",
			mcp.Description("Whether to execute the command through a shell (default: false)"),
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
	if err := m.checkAuth(ctx, req); err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	hostID := mcp.ParseString(req, "host_id", "")
	command := mcp.ParseString(req, "command", "")

	if hostID == "" || command == "" {
		return mcp.NewToolResultError("host_id and command are required"), nil
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

	useShell := mcp.ParseBoolean(req, "use_shell", false)
	workingDir := mcp.ParseString(req, "working_dir", "")
	timeoutSec := mcp.ParseArgument(req, "timeout_sec", 30.0)
	timeout := int(timeoutSec.(float64))

	m.logger.Info("收到命令执行请求", "host_id", hostID, "command", command, "args", argsStr, "use_shell", useShell)

	result, err := m.execService.ExecuteCommand(ctx, execsvc.ExecRequest{
		HostID:  hostID,
		Command: command,
		Args:    argsStr,
		Options: execsvc.ExecOptions{
			UseShell:   useShell,
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
	if err := m.checkAuth(ctx, req); err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	hostID := mcp.ParseString(req, "host_id", "")
	scriptName := mcp.ParseString(req, "script_name", "")

	if hostID == "" || scriptName == "" {
		return mcp.NewToolResultError("host_id and script_name are required"), nil
	}

	paramsAny := mcp.ParseArgument(req, "parameters", map[string]interface{}{})
	parameters, _ := paramsAny.(map[string]interface{})
	timeoutSec := mcp.ParseArgument(req, "timeout_sec", 30.0)
	timeout := int(timeoutSec.(float64))

	m.logger.Info("收到脚本执行请求", "host_id", hostID, "script_name", scriptName, "parameters", parameters)

	result, err := m.execService.ExecuteScript(ctx, execsvc.ScriptRequest{
		HostID:     hostID,
		ScriptName: scriptName,
		Parameters: parameters,
		Options: execsvc.ExecOptions{
			TimeoutSec: timeout,
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
	if err := m.checkAuth(ctx, req); err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	listType := mcp.ParseString(req, "type", "all")

	allowedCommands := []string{
		"信息查询: whoami, hostname, uname, pwd, ls, date",
		"系统监控: top, htop, ps, df, du, free",
		"网络工具: ping, netstat, ss, curl, wget",
		"文件操作: cat, less, head, tail, grep, find",
		"进程管理: systemctl, service, kill, pkill",
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
	if err := m.checkAuth(ctx, req); err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	hostID := mcp.ParseString(req, "host_id", "")

	if hostID == "" {
		return mcp.NewToolResultError("host_id is required"), nil
	}

	m.logger.Info("收到连接测试请求", "host_id", hostID)

	err := m.sshManager.HealthCheck(hostID)
	if err != nil {
		m.logger.Error("连接测试失败", "host_id", hostID, "error", err)
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
		return fmt.Errorf("unauthorized: missing auth token")
	}
	if provided != expected {
		return fmt.Errorf("unauthorized: invalid auth token")
	}
	return nil
}
