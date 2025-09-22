package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/your-username/ExecMCP/internal/config"
	"github.com/your-username/ExecMCP/internal/logging"
	"github.com/your-username/ExecMCP/internal/mcp"
)

func main() {
	// 解析命令行参数
	var configPath string
	flag.StringVar(&configPath, "c", "config.test.yaml", "配置文件路径")
	flag.Parse()

	// 加载配置
	cfg, err := config.Load(configPath)
	if err != nil {
		log.Fatalf("配置加载失败: %v", err)
	}

	// 初始化日志
	logger := logging.NewLogger(cfg.Logging)
	logger.Info("ExecMCP 服务器启动中...", "version", "1.0.0")

	// 创建上下文
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 初始化 MCP 服务器
	mcpServer, err := mcp.NewMCPServer(cfg, logger)
	if err != nil {
		logger.Fatal("MCP 服务器初始化失败", "error", err)
	}

	// 启动服务器
	go func() {
		logger.Info("启动 MCP 服务器", "address", cfg.Server.BindAddr)
		if err := mcpServer.Start(ctx); err != nil {
			logger.Error("MCP 服务器启动失败", "error", err)
			cancel()
		}
	}()

	// 优雅关闭
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// 等待信号
	sig := <-sigChan
	logger.Info("接收到关闭信号，开始优雅关闭...", "signal", sig)

	// 取消上下文
	cancel()

	// 等待服务器关闭
	logger.Info("ExecMCP 服务器已关闭")
}