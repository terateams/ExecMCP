package execsvc

import (
	"path/filepath"
	"testing"

	"github.com/terateams/ExecMCP/internal/audit"
	"github.com/terateams/ExecMCP/internal/config"
	"github.com/terateams/ExecMCP/internal/logging"
	"github.com/terateams/ExecMCP/internal/ssh"
)

// testKnownHostsPath 指向仓库内的固定 known_hosts 文件，确保单测在无真实环境下也能通过校验。
var testKnownHostsPath = filepath.Join("..", "testdata", ".ssh", "known_hosts_test")

// newTestLogger 创建噪声最小的日志器，避免在测试输出中夹杂大量日志。
func newTestLogger() logging.Logger {
	return logging.NewLogger(config.LoggingConfig{
		Level:  "error",
		Format: "text",
		Output: "stdout",
	})
}

// newBaseTestConfig 构造一份安全默认配置，覆盖 SSH 主机、白名单及日志设置。
// 后续测试可以在此基础上按需修改，避免重复拼装配置。
func newBaseTestConfig() *config.Config {
	return &config.Config{
		Server: config.ServerConfig{
			BindAddr:       "127.0.0.1:8080",
			MaxConcurrent:  32,
			RequestTimeout: 30,
		},
		SSHHosts: []config.SSHHost{
			{
				ID:             "test-host",
				Addr:           "localhost:22",
				User:           "testuser",
				AuthMethod:     "private_key",
				PrivateKeyPath: "testdata/mock_id_rsa",
				KnownHosts:     testKnownHostsPath,
				MaxSessions:    4,
				Type:           "linux",
				Description:    "Test host",
				SecurityGroup:  "default",
				ScriptTags:     []string{"default"},
			},
		},
		Security: []config.SecurityConfig{
			{
				Group:           "default",
				DefaultShell:    false,
				AllowShellFor:   []string{"bash"},
				DenylistExact:   []string{"rm", "dd"},
				AllowlistExact:  []string{"echo", "ls", "pwd", "bash", "sh", "sleep"},
				AllowlistRegex:  []string{},
				WorkingDirAllow: []string{"/tmp", "."},
				MaxOutputBytes:  1024 * 1024,
			},
		},
		Logging: config.LoggingConfig{
			Level:  "error",
			Format: "text",
			Output: "stdout",
		},
	}
}

// newTestServiceWithConfig 使用 Mock SSH 管理器构造 Service，
// 通过 modify 回调让每个测试自由调整配置，同时保持安全过滤与日志实例一致。
func newTestServiceWithConfig(t *testing.T, modify func(cfg *config.Config)) *Service {
	t.Helper()

	cfg := newBaseTestConfig()
	if modify != nil {
		modify(cfg)
	}

	logger := newTestLogger()
	auditLogger := audit.NewNoopLogger()

	svc, err := NewService(cfg, logger, auditLogger)
	if err != nil {
		t.Fatalf("初始化测试 Service 失败: %v", err)
	}
	svc.sshManager = ssh.NewMockManager(cfg)
	return svc
}

// newTestStreamManager 与 newTestServiceWithConfig 类似，用于构造 StreamManager，
// 统一使用 mock 资源以便在本地、CI 等环境稳定运行。
func newTestStreamManager(t *testing.T, modify func(cfg *config.Config)) *StreamManager {
	t.Helper()

	cfg := newBaseTestConfig()
	if modify != nil {
		modify(cfg)
	}

	logger := newTestLogger()
	manager := ssh.NewMockManager(cfg)

	streamManager := NewStreamManagerWithManager(cfg, logger, manager)
	if streamManager == nil {
		t.Fatal("初始化 StreamManager 失败")
	}
	return streamManager
}
