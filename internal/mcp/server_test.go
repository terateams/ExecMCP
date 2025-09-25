package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	mcplib "github.com/mark3labs/mcp-go/mcp"

	"github.com/terateams/ExecMCP/internal/audit"
	"github.com/terateams/ExecMCP/internal/config"
	"github.com/terateams/ExecMCP/internal/logging"
	"github.com/terateams/ExecMCP/internal/testutils"
)

func TestNewMCPServer(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			BindAddr: "127.0.0.1:8080",
		},
		SSHHosts: []config.SSHHost{
			{
				ID:         "test-host",
				Addr:       "localhost:22",
				User:       "testuser",
				AuthMethod: "password",
				Password:   "testpass",
			},
		},
	}

	logger := logging.NewLogger(cfg.Logging)

	server, err := NewMCPServer(cfg, logger, audit.NewNoopLogger())
	if err != nil {
		t.Fatalf("期望创建服务器成功，但得到错误: %v", err)
	}

	if server == nil {
		t.Fatal("期望返回服务器实例，但得到 nil")
	}

	if server.config != cfg {
		t.Error("期望配置被正确设置")
	}

	if server.logger != logger {
		t.Error("期望日志记录器被正确设置")
	}

	if server.server == nil {
		t.Error("期望 MCP 服务器被正确创建")
	}

	if server.sseServer == nil {
		t.Error("期望 SSE 服务器被正确创建")
	}

	if server.execService == nil {
		t.Error("期望执行服务被正确创建")
	}

	if server.sshManager == nil {
		t.Error("期望 SSH 管理器被正确创建")
	}
}

func TestMCPServer_StartAndStop(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			BindAddr: "127.0.0.1:0", // 使用 0 端口让系统分配
		},
		SSHHosts: []config.SSHHost{
			{
				ID:         "test-host",
				Addr:       "localhost:22",
				User:       "testuser",
				AuthMethod: "password",
				Password:   "testpass",
			},
		},
	}

	logger := logging.NewLogger(cfg.Logging)
	server, err := NewMCPServer(cfg, logger, audit.NewNoopLogger())
	if err != nil {
		t.Fatalf("期望创建服务器成功，但得到错误: %v", err)
	}

	// 创建上下文并在短时间后取消
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// 启动服务器
	startErr := make(chan error, 1)
	go func() {
		startErr <- server.Start(ctx)
	}()

	// 等待服务器启动或失败
	select {
	case err := <-startErr:
		if err != nil {
			t.Errorf("服务器启动失败: %v", err)
		}
	case <-time.After(200 * time.Millisecond):
		// 服务器应该已经启动，现在测试停止
	}

	// 停止服务器
	if err := server.Stop(); err != nil {
		t.Errorf("服务器停止失败: %v", err)
	}
}

func TestHandleExecCommandRejectsMixedCommandAndArgs(t *testing.T) {
	mcpServer := &MCPServer{
		config: &config.Config{},
		logger: logging.NewLogger(config.LoggingConfig{}),
		audit:  audit.NewNoopLogger(),
	}

	req := mcplib.CallToolRequest{
		Params: mcplib.CallToolParams{
			Arguments: map[string]any{
				"host_id": "test-host",
				"command": "docker ps -a",
			},
		},
	}

	result, err := mcpServer.handleExecCommand(context.Background(), req)
	if err != nil {
		t.Fatalf("期望返回工具错误结果，但得到执行错误: %v", err)
	}
	if result == nil {
		t.Fatal("期望返回错误结果，但得到 nil")
	}
	if !result.IsError {
		t.Fatal("期望 result 标记为错误，但 IsError=false")
	}
	if len(result.Content) == 0 {
		t.Fatal("期望返回错误信息内容，但 Content 为空")
	}
	if text, ok := mcplib.AsTextContent(result.Content[0]); ok {
		if !strings.Contains(text.Text, "args") {
			t.Fatalf("期望错误消息提示使用 args，但得到: %s", text.Text)
		}
	}
}

func TestHandleExecScriptRejectsMixedScriptName(t *testing.T) {
	mcpServer := &MCPServer{
		config: &config.Config{},
		logger: logging.NewLogger(config.LoggingConfig{}),
		audit:  audit.NewNoopLogger(),
	}

	req := mcplib.CallToolRequest{
		Params: mcplib.CallToolParams{
			Arguments: map[string]any{
				"host_id":     "test-host",
				"script_name": "check_disk_usage --path=/",
			},
		},
	}

	result, err := mcpServer.handleExecScript(context.Background(), req)
	if err != nil {
		t.Fatalf("期望返回工具错误结果，但得到执行错误: %v", err)
	}
	if result == nil {
		t.Fatal("期望返回错误结果，但得到 nil")
	}
	if !result.IsError {
		t.Fatal("期望 result 标记为错误，但 IsError=false")
	}
	if len(result.Content) == 0 {
		t.Fatal("期望返回错误信息内容，但 Content 为空")
	}
	if text, ok := mcplib.AsTextContent(result.Content[0]); ok {
		if !strings.Contains(text.Text, "parameters") {
			t.Fatalf("期望错误消息提示使用 parameters，但得到: %s", text.Text)
		}
	}
}

func TestHandleListCommandsIncludesConfig(t *testing.T) {
	cfg := &config.Config{
		Security: config.SecurityConfig{
			DefaultShell:   true,
			AllowlistExact: []string{"ls", "docker"},
			AllowlistRegex: []string{"^systemctl$"},
			AllowShellFor:  []string{"bash"},
			DenylistExact:  []string{"rm"},
			DenylistRegex:  []string{".*sudo.*"},
		},
	}

	mcpServer := &MCPServer{
		config: cfg,
		logger: logging.NewLogger(config.LoggingConfig{}),
		audit:  audit.NewNoopLogger(),
	}

	req := mcplib.CallToolRequest{
		Params: mcplib.CallToolParams{
			Arguments: map[string]any{"type": "commands"},
		},
	}

	res, err := mcpServer.handleListCommands(context.Background(), req)
	if err != nil {
		t.Fatalf("期望无错误，结果得到: %v", err)
	}
	if res == nil || res.IsError {
		t.Fatalf("期望成功结果，得到: %+v", res)
	}

	var body map[string]any
	if err := json.Unmarshal([]byte(toolResultText(res)), &body); err != nil {
		t.Fatalf("解析返回 JSON 失败: %v", err)
	}

	allowedRaw, ok := body["allowed_commands"].([]any)
	if !ok {
		t.Fatalf("期望 allowed_commands 为数组，得到: %T", body["allowed_commands"])
	}

	joined := make([]string, len(allowedRaw))
	for i, v := range allowedRaw {
		joined[i], _ = v.(string)
	}
	joinedStr := strings.Join(joined, "|")
	for _, expected := range []string{"allowlist_exact: ls, docker", "allowlist_regex: ^systemctl$", "allow_shell_for: bash"} {
		if !strings.Contains(joinedStr, expected) {
			t.Fatalf("期望 allowed_commands 包含 %q，实际: %s", expected, joinedStr)
		}
	}

	if value, ok := body["denylist_exact"].([]any); !ok || len(value) == 0 || value[0] != "rm" {
		t.Fatalf("期望 denylist_exact 包含 rm，实际: %v", body["denylist_exact"])
	}
	if value, ok := body["denylist_regex"].([]any); !ok || len(value) == 0 || value[0] != ".*sudo.*" {
		t.Fatalf("期望 denylist_regex 包含 .*sudo.*，实际: %v", body["denylist_regex"])
	}
	if val, ok := body["default_shell"].(bool); !ok || !val {
		t.Fatalf("期望 default_shell=true，实际: %v", body["default_shell"])
	}
}

func TestCheckAuth_AuditOnFailure(t *testing.T) {
	recorder := testutils.NewRecordingAuditLogger()
	mcpServer := &MCPServer{
		config: &config.Config{Server: config.ServerConfig{AuthToken: "secret"}},
		logger: logging.NewLogger(config.LoggingConfig{}),
		audit:  recorder,
	}

	ctx := audit.WithContext(context.Background(), audit.ContextFields{RequestID: "test"})
	err := mcpServer.checkAuth(ctx, mcplib.CallToolRequest{})
	if err == nil {
		t.Fatal("期望校验失败但成功了")
	}

	events := recorder.Events()
	if len(events) != 1 {
		t.Fatalf("期望记录一条审计日志，得到 %d", len(events))
	}
	if events[0].Type != "auth_failed" {
		t.Errorf("期望事件类型为 auth_failed，得到 %s", events[0].Type)
	}
	if events[0].Outcome != audit.OutcomeDenied {
		t.Errorf("期望事件 Outcome=denied，得到 %s", events[0].Outcome)
	}
}

func TestMCPServer_SSLEndpoint(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			BindAddr: "127.0.0.1:0",
		},
		SSHHosts: []config.SSHHost{
			{
				ID:         "test-host",
				Addr:       "localhost:22",
				User:       "testuser",
				AuthMethod: "password",
				Password:   "testpass",
			},
		},
	}

	logger := logging.NewLogger(cfg.Logging)
	server, err := NewMCPServer(cfg, logger, audit.NewNoopLogger())
	if err != nil {
		t.Fatalf("期望创建服务器成功，但得到错误: %v", err)
	}

	recorder := httptest.NewRecorder()
	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, "/mcp/sse", nil).WithContext(ctx)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		server.sseServer.ServeHTTP(recorder, req)
	}()

	// 等待 SSE 处理器写入初始响应后再关闭
	time.Sleep(10 * time.Millisecond)
	cancel()
	wg.Wait()

	resp := recorder.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("期望状态码 200，但得到 %d", resp.StatusCode)
	}

	if contentType := resp.Header.Get("Content-Type"); contentType != "text/event-stream" {
		t.Errorf("期望 Content-Type 为 text/event-stream，但得到 %s", contentType)
	}
}

func TestMCPServer_ToolsList(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			BindAddr: "127.0.0.1:0",
		},
		SSHHosts: []config.SSHHost{
			{
				ID:         "test-host",
				Addr:       "localhost:22",
				User:       "testuser",
				AuthMethod: "password",
				Password:   "testpass",
			},
		},
		Scripts: []config.ScriptConfig{
			{
				Name:        "test-script",
				Description: "测试脚本",
				Template:    "echo 'test'",
			},
		},
	}

	logger := logging.NewLogger(cfg.Logging)
	server, err := NewMCPServer(cfg, logger, audit.NewNoopLogger())
	if err != nil {
		t.Fatalf("期望创建服务器成功，但得到错误: %v", err)
	}

	// 检查工具是否正确注册
	tools := server.server.ListTools()
	if len(tools) != 6 {
		t.Errorf("期望有 6 个工具，但得到 %d", len(tools))
	}

	// 检查工具名称
	expectedTools := map[string]bool{
		"exec_command":    false,
		"exec_script":     false,
		"list_commands":   false,
		"test_connection": false,
		"list_hosts":      false,
		"approve_command": false,
	}

	for name := range tools {
		if _, exists := expectedTools[name]; exists {
			expectedTools[name] = true
		}
	}

	for name, found := range expectedTools {
		if !found {
			t.Errorf("期望工具 %s 被注册", name)
		}
	}
}

func TestMCPServer_InvalidConfig(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			BindAddr: "", // 空地址
		},
	}

	logger := logging.NewLogger(cfg.Logging)
	server, err := NewMCPServer(cfg, logger, audit.NewNoopLogger())

	// 即使配置有问题，服务器也应该能创建（因为 SSE 服务器会在 Start 时才绑定端口）
	if err != nil {
		t.Fatalf("期望即使配置有问题也能创建服务器，但得到错误: %v", err)
	}

	if server == nil {
		t.Fatal("期望返回服务器实例，但得到 nil")
	}
}

func TestMCPServer_MissingSSHHosts(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			BindAddr: "127.0.0.1:0",
		},
		SSHHosts: []config.SSHHost{}, // 空 SSH 主机列表
	}

	logger := logging.NewLogger(cfg.Logging)
	server, err := NewMCPServer(cfg, logger, audit.NewNoopLogger())

	if err != nil {
		t.Fatalf("期望即使没有 SSH 主机也能创建服务器，但得到错误: %v", err)
	}

	if server == nil {
		t.Fatal("期望返回服务器实例，但得到 nil")
	}

	// 应该仍然能注册工具
	tools := server.server.ListTools()
	if len(tools) != 6 {
		t.Errorf("期望有 6 个工具，但得到 %d", len(tools))
	}
}

func TestMCPServer_SSEServerCreation(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			BindAddr: "127.0.0.1:8080",
		},
	}

	logger := logging.NewLogger(cfg.Logging)
	server, err := NewMCPServer(cfg, logger, audit.NewNoopLogger())

	if err != nil {
		t.Fatalf("期望创建服务器成功，但得到错误: %v", err)
	}

	if server.sseServer == nil {
		t.Fatal("期望 SSE 服务器被创建")
	}

	// 检查 SSE 服务器配置
	if server.sseServer == nil {
		t.Fatal("期望 SSE 服务器不为 nil")
	}
}

func TestHandleApproveCommandStoresApproval(t *testing.T) {
	logger := logging.NewLogger(config.LoggingConfig{})
	m := &MCPServer{
		config:        &config.Config{},
		logger:        logger,
		audit:         audit.NewNoopLogger(),
		tempApprovals: newTemporaryApprovalCache(logger, audit.NewNoopLogger()),
	}

	req := mcplib.CallToolRequest{
		Params: mcplib.CallToolParams{
			Arguments: map[string]any{
				"command":      "uname",
				"duration_sec": 120,
				"max_uses":     2,
				"notes":        "ticket-123",
			},
		},
	}

	ctx := context.WithValue(context.Background(), remoteAddrContextKey{}, "192.0.2.10")
	res, err := m.handleApproveCommand(ctx, req)
	if err != nil {
		t.Fatalf("期望批准成功，得到错误: %v", err)
	}
	if res == nil || res.IsError {
		t.Fatalf("期望返回成功结果，得到: %+v", res)
	}

	identityKey := buildIdentityKey("192.0.2.10", "")
	m.tempApprovals.mu.RLock()
	entry := m.tempApprovals.entries[identityKey]["uname"]
	m.tempApprovals.mu.RUnlock()
	if entry == nil {
		t.Fatalf("期望缓存中存在批准记录，但未找到")
	}
	if entry.maxUses != 2 {
		t.Fatalf("期望 maxUses=2，实际 %d", entry.maxUses)
	}
	if entry.useCount != 0 {
		t.Fatalf("期望 useCount 初始为 0，实际 %d", entry.useCount)
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(toolResultText(res)), &payload); err != nil {
		t.Fatalf("解析响应失败: %v", err)
	}
	if payload["identity"] != identityKey {
		t.Fatalf("期望响应 identity 为 %s，实际 %v", identityKey, payload["identity"])
	}
	if payload["command"] != "uname" {
		t.Fatalf("期望响应 command=uname，实际 %v", payload["command"])
	}
}

func TestBuildClientIdentityPrefersContextIP(t *testing.T) {
	m := &MCPServer{}
	req := mcplib.CallToolRequest{
		Header: http.Header{
			"X-Forwarded-For": []string{"198.51.100.5"},
		},
		Params: mcplib.CallToolParams{
			Meta: &mcplib.Meta{AdditionalFields: map[string]any{"client_id": "meta-client"}},
		},
	}

	ctx := context.WithValue(context.Background(), remoteAddrContextKey{}, "203.0.113.9:443")
	identity := m.buildClientIdentity(ctx, req)

	if identity.IP != "203.0.113.9" {
		t.Fatalf("期望优先使用上下文中的 IP, 实际 %s", identity.IP)
	}
	if identity.ClientID != "meta-client" {
		t.Fatalf("期望从 _meta 读取 client_id，实际 %s", identity.ClientID)
	}
}

func TestMCPServer_ContextCancellation(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			BindAddr: "127.0.0.1:0",
		},
	}

	logger := logging.NewLogger(cfg.Logging)
	server, err := NewMCPServer(cfg, logger, audit.NewNoopLogger())

	if err != nil {
		t.Fatalf("期望创建服务器成功，但得到错误: %v", err)
	}

	// 测试上下文取消
	ctx, cancel := context.WithCancel(context.Background())

	// 立即取消上下文
	cancel()

	// 服务器应该能够处理取消
	err = server.Start(ctx)
	if err != nil {
		// 上下文取消不一定是错误
		t.Logf("服务器处理上下文取消: %v", err)
	}
}

func TestMCPServer_MultipleStartStop(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			BindAddr: "127.0.0.1:0",
		},
	}

	logger := logging.NewLogger(cfg.Logging)
	server, err := NewMCPServer(cfg, logger, audit.NewNoopLogger())

	if err != nil {
		t.Fatalf("期望创建服务器成功，但得到错误: %v", err)
	}

	// 多次启动和停止服务器
	for i := 0; i < 3; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)

		startErr := make(chan error, 1)
		go func() {
			startErr <- server.Start(ctx)
		}()

		select {
		case err := <-startErr:
			t.Logf("启动 %d 结果: %v", i+1, err)
		case <-time.After(100 * time.Millisecond):
			// 正常情况
		}

		cancel()

		if err := server.Stop(); err != nil {
			t.Logf("停止 %d 结果: %v", i+1, err)
		}
	}
}

func TestMCPServer_ToolHandlersExist(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			BindAddr: "127.0.0.1:0",
		},
	}

	logger := logging.NewLogger(cfg.Logging)
	server, err := NewMCPServer(cfg, logger, audit.NewNoopLogger())

	if err != nil {
		t.Fatalf("期望创建服务器成功，但得到错误: %v", err)
	}

	// 测试工具处理器函数是否存在
	tools := server.server.ListTools()

	for name, tool := range tools {
		if tool.Handler == nil {
			t.Errorf("工具 %s 的处理器为 nil", name)
		}
	}
}

func TestMCPServer_AuthTokenRequired(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			BindAddr:  "127.0.0.1:0",
			AuthToken: "secret-token",
		},
		SSHHosts: []config.SSHHost{
			{
				ID:         "test-host",
				Addr:       "localhost:22",
				User:       "testuser",
				AuthMethod: "password",
				Password:   "testpass",
			},
		},
	}

	logger := logging.NewLogger(cfg.Logging)
	server, err := NewMCPServer(cfg, logger, audit.NewNoopLogger())
	if err != nil {
		t.Fatalf("期望创建服务器成功，但得到错误: %v", err)
	}

	makeReq := func(args map[string]any, header http.Header) mcplib.CallToolRequest {
		return mcplib.CallToolRequest{
			Header: header,
			Params: mcplib.CallToolParams{Arguments: args},
		}
	}

	assertError := func(res *mcplib.CallToolResult, msg string) {
		if res == nil || !res.IsError {
			t.Fatalf("%s: 应返回错误", msg)
		}
		if text := toolResultText(res); !strings.Contains(text, msg) {
			t.Fatalf("%s: 期望错误消息包含 '%s'，实际: %s", msg, msg, text)
		}
	}

	res, _ := server.handleListHosts(context.Background(), makeReq(map[string]any{}, http.Header{}))
	assertError(res, "missing auth token")

	res, _ = server.handleListHosts(context.Background(), makeReq(map[string]any{"auth_token": "wrong"}, http.Header{}))
	assertError(res, "invalid auth token")

	header := http.Header{}
	header.Set("Authorization", "Bearer secret-token")
	res, _ = server.handleListHosts(context.Background(), makeReq(map[string]any{}, header))
	if res == nil || res.IsError {
		t.Fatalf("提供正确 token 应通过认证")
	}
}

func toolResultText(res *mcplib.CallToolResult) string {
	if res == nil || len(res.Content) == 0 {
		return ""
	}
	if text, ok := res.Content[0].(mcplib.TextContent); ok {
		return text.Text
	}
	return ""
}
