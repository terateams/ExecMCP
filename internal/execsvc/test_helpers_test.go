package execsvc

import (
	"path/filepath"
	"testing"

	"github.com/terateams/ExecMCP/internal/config"
	"github.com/terateams/ExecMCP/internal/logging"
	"github.com/terateams/ExecMCP/internal/security"
	"github.com/terateams/ExecMCP/internal/ssh"
)

var testKnownHostsPath = filepath.Join("..", "testdata", ".ssh", "known_hosts_test")

func newTestLogger() logging.Logger {
	return logging.NewLogger(config.LoggingConfig{
		Level:  "error",
		Format: "text",
		Output: "stdout",
	})
}

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
			},
		},
		Security: config.SecurityConfig{
			DefaultShell:    false,
			AllowShellFor:   []string{"bash"},
			DenylistExact:   []string{"rm", "dd"},
			AllowlistExact:  []string{"echo", "ls", "pwd", "bash", "sh", "sleep"},
			AllowlistRegex:  []string{},
			WorkingDirAllow: []string{"/tmp", "."},
			MaxOutputBytes:  1024 * 1024,
		},
		Logging: config.LoggingConfig{
			Level:  "error",
			Format: "text",
			Output: "stdout",
		},
	}
}

func newTestServiceWithConfig(t *testing.T, modify func(cfg *config.Config)) *Service {
	t.Helper()

	cfg := newBaseTestConfig()
	if modify != nil {
		modify(cfg)
	}

	logger := newTestLogger()
	manager := ssh.NewMockManager(cfg)

	return &Service{
		config:     cfg,
		logger:     logger,
		sshManager: manager,
		filter:     security.NewFilter(&cfg.Security),
	}
}

func newTestStreamManager(t *testing.T, modify func(cfg *config.Config)) *StreamManager {
	t.Helper()

	cfg := newBaseTestConfig()
	if modify != nil {
		modify(cfg)
	}

	logger := newTestLogger()
	manager := ssh.NewMockManager(cfg)

	return &StreamManager{
		config:     cfg,
		logger:     logger,
		sshManager: manager,
		filter:     security.NewFilter(&cfg.Security),
	}
}
