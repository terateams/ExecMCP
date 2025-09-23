package mcp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/terateams/ExecMCP/internal/config"
	"github.com/terateams/ExecMCP/internal/logging"
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

	server, err := NewMCPServer(cfg, logger)
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
	server, err := NewMCPServer(cfg, logger)
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
	server, err := NewMCPServer(cfg, logger)
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
	server, err := NewMCPServer(cfg, logger)
	if err != nil {
		t.Fatalf("期望创建服务器成功，但得到错误: %v", err)
	}

	// 检查工具是否正确注册
	tools := server.server.ListTools()
	if len(tools) != 5 {
		t.Errorf("期望有 5 个工具，但得到 %d", len(tools))
	}

	// 检查工具名称
	expectedTools := map[string]bool{
		"exec_command":    false,
		"exec_script":     false,
		"list_commands":   false,
		"test_connection": false,
		"list_hosts":      false,
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
	server, err := NewMCPServer(cfg, logger)

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
	server, err := NewMCPServer(cfg, logger)

	if err != nil {
		t.Fatalf("期望即使没有 SSH 主机也能创建服务器，但得到错误: %v", err)
	}

	if server == nil {
		t.Fatal("期望返回服务器实例，但得到 nil")
	}

	// 应该仍然能注册工具
	tools := server.server.ListTools()
	if len(tools) != 5 {
		t.Errorf("期望有 5 个工具，但得到 %d", len(tools))
	}
}

func TestMCPServer_SSEServerCreation(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			BindAddr: "127.0.0.1:8080",
		},
	}

	logger := logging.NewLogger(cfg.Logging)
	server, err := NewMCPServer(cfg, logger)

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

func TestMCPServer_ContextCancellation(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			BindAddr: "127.0.0.1:0",
		},
	}

	logger := logging.NewLogger(cfg.Logging)
	server, err := NewMCPServer(cfg, logger)

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
	server, err := NewMCPServer(cfg, logger)

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
	server, err := NewMCPServer(cfg, logger)

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
