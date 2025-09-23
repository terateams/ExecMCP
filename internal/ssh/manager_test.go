package ssh

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/terateams/ExecMCP/internal/config"
	"github.com/terateams/ExecMCP/internal/logging"
)

var testKnownHostsPath = filepath.Join("..", "..", "testdata", ".ssh", "known_hosts_test")

func TestNewManager(t *testing.T) {
	cfg := &config.Config{
		SSHHosts: []config.SSHHost{
			{
				ID:             "test-host",
				Addr:           "localhost:22",
				User:           "testuser",
				AuthMethod:     "private_key",
				PrivateKeyPath: "~/.ssh/id_rsa",
				KnownHosts:     testKnownHostsPath,
				MaxSessions:    4,
			},
		},
	}

	logger := logging.NewLogger(config.LoggingConfig{
		Level:  "info",
		Format: "text",
		Output: "stdout",
	})

	manager := NewManager(cfg, logger)
	if manager == nil {
		t.Fatal("期望创建管理器，但得到 nil")
	}

	// 验证返回的是 RealManager 类型
	realManager, ok := manager.(*RealManager)
	if !ok {
		t.Fatal("期望返回 RealManager 类型")
	}

	if realManager.config != cfg {
		t.Error("期望配置被正确设置")
	}

	if realManager.logger != logger {
		t.Error("期望日志器被正确设置")
	}
}

func TestRealManager_GetSession(t *testing.T) {
	cfg := &config.Config{
		SSHHosts: []config.SSHHost{
			{
				ID:             "test-host",
				Addr:           "localhost:22",
				User:           "testuser",
				AuthMethod:     "private_key",
				PrivateKeyPath: "~/.ssh/id_rsa",
				KnownHosts:     testKnownHostsPath,
				MaxSessions:    4,
			},
		},
	}

	logger := logging.NewLogger(config.LoggingConfig{
		Level:  "info",
		Format: "text",
		Output: "stdout",
	})

	manager := &RealManager{
		config:          cfg,
		logger:          logger,
		realConnections: make(map[string]*RealConnection),
	}

	// 初始化连接
	for _, host := range cfg.SSHHosts {
		manager.realConnections[host.ID] = &RealConnection{
			HostID:      host.ID,
			MaxSessions: host.MaxSessions,
			hostConfig:  host,
			logger:      logger,
		}
	}

	// 测试获取未配置的主机
	_, err := manager.GetSession("unknown-host")
	if err == nil {
		t.Fatal("期望获取未配置主机返回错误，但成功了")
	}

	// 测试获取已配置的主机（会尝试创建真实的SSH连接，可能会失败）
	// 在真实环境中，这需要有效的SSH服务器和认证
	_, err = manager.GetSession("test-host")
	// 这里我们只期望返回错误（因为没有真实的SSH服务器），但不是主机未配置的错误
	if err != nil {
		// 检查错误类型，应该是连接相关的错误，而不是主机未配置的错误
		if err.Error() == "主机 'test-host' 未配置" {
			t.Fatal("期望主机已配置，但返回主机未配置错误")
		}
		// 连接错误是预期的，因为我们没有运行真实的SSH服务器
	}
}

func TestRealManager_ReleaseSession(t *testing.T) {
	cfg := &config.Config{
		SSHHosts: []config.SSHHost{
			{
				ID:             "test-host",
				Addr:           "localhost:22",
				User:           "testuser",
				AuthMethod:     "private_key",
				PrivateKeyPath: "~/.ssh/id_rsa",
				KnownHosts:     testKnownHostsPath,
				MaxSessions:    4,
			},
		},
	}

	logger := logging.NewLogger(config.LoggingConfig{
		Level:  "info",
		Format: "text",
		Output: "stdout",
	})

	manager := &RealManager{
		config:          cfg,
		logger:          logger,
		realConnections: make(map[string]*RealConnection),
	}

	// 初始化连接
	for _, host := range cfg.SSHHosts {
		manager.realConnections[host.ID] = &RealConnection{
			HostID:      host.ID,
			MaxSessions: host.MaxSessions,
			hostConfig:  host,
			logger:      logger,
		}
	}

	// 测试释放 nil 会话（不应 panic）
	manager.ReleaseSession("test-host", nil)

	// 测试释放不存在的主机会话（不应 panic）
	manager.ReleaseSession("unknown-host", nil)
}

func TestRealManager_Close(t *testing.T) {
	cfg := &config.Config{
		SSHHosts: []config.SSHHost{
			{
				ID:             "test-host",
				Addr:           "localhost:22",
				User:           "testuser",
				AuthMethod:     "private_key",
				PrivateKeyPath: "~/.ssh/id_rsa",
				KnownHosts:     testKnownHostsPath,
				MaxSessions:    4,
			},
		},
	}

	logger := logging.NewLogger(config.LoggingConfig{
		Level:  "info",
		Format: "text",
		Output: "stdout",
	})

	manager := &RealManager{
		config:          cfg,
		logger:          logger,
		realConnections: make(map[string]*RealConnection),
	}

	// 初始化连接
	for _, host := range cfg.SSHHosts {
		manager.realConnections[host.ID] = &RealConnection{
			HostID:      host.ID,
			MaxSessions: host.MaxSessions,
			hostConfig:  host,
			logger:      logger,
		}
	}

	// 关闭管理器
	manager.Close()

	if manager.realConnections != nil {
		t.Error("期望关闭后连接映射被清空")
	}
}

func TestRealManager_GetHostKeyCallback_RequiresKnownHosts(t *testing.T) {
	realLogger := logging.NewLogger(config.LoggingConfig{
		Level:  "info",
		Format: "text",
		Output: "stdout",
	})

	manager := &RealManager{logger: realLogger}

	_, err := manager.getHostKeyCallback(config.SSHHost{ID: "missing-known-hosts"})
	if err == nil {
		t.Fatal("未配置 known_hosts 时应返回错误")
	}
}

func TestRealManager_GetHostKeyCallback_WithValidKnownHosts(t *testing.T) {
	realLogger := logging.NewLogger(config.LoggingConfig{
		Level:  "info",
		Format: "text",
		Output: "stdout",
	})

	manager := &RealManager{logger: realLogger}

	callback, err := manager.getHostKeyCallback(config.SSHHost{ID: "test-host", KnownHosts: testKnownHostsPath})
	if err != nil {
		t.Fatalf("期望加载 known_hosts 成功，但得到错误: %v", err)
	}

	if callback == nil {
		t.Fatal("期望返回 host key 回调，但得到 nil")
	}
}

func TestRealManager_ConfigurePasswordSources(t *testing.T) {
	realLogger := logging.NewLogger(config.LoggingConfig{
		Level:  "info",
		Format: "text",
		Output: "stdout",
	})

	manager := &RealManager{logger: realLogger}

	sshConfig := &ssh.ClientConfig{}
	host := config.SSHHost{ID: "env-host", AuthMethod: "password", PasswordEnv: config.EnvTestPassword}
	os.Setenv(config.EnvTestPassword, "env-secret")
	defer os.Unsetenv(config.EnvTestPassword)

	if err := manager.configurePassword(sshConfig, host); err != nil {
		t.Fatalf("期望从环境变量加载密码成功，但得到错误: %v", err)
	}
	if len(sshConfig.Auth) == 0 {
		t.Fatal("期望配置 auth provider，但为空")
	}

	// 覆盖密码文件场景
	sshConfig = &ssh.ClientConfig{}
	passwordFile := t.TempDir() + "/password.txt"
	if err := os.WriteFile(passwordFile, []byte("file-secret\n"), 0o600); err != nil {
		t.Fatalf("写入密码文件失败: %v", err)
	}

	fileHost := config.SSHHost{ID: "file-host", AuthMethod: "password", PasswordFile: passwordFile}
	if err := manager.configurePassword(sshConfig, fileHost); err != nil {
		t.Fatalf("期望从密码文件加载成功，但得到错误: %v", err)
	}
	if len(sshConfig.Auth) == 0 {
		t.Fatal("期望配置 auth provider，但为空")
	}

	// 缺少密码来源应返回错误
	emptyHost := config.SSHHost{ID: "empty-host", AuthMethod: "password"}
	if err := manager.configurePassword(&ssh.ClientConfig{}, emptyHost); err == nil {
		t.Fatal("缺少密码来源时应返回错误")
	}
}

func TestRealManager_HealthCheck(t *testing.T) {
	cfg := &config.Config{
		SSHHosts: []config.SSHHost{
			{
				ID:             "test-host",
				Addr:           "localhost:22",
				User:           "testuser",
				AuthMethod:     "private_key",
				PrivateKeyPath: "~/.ssh/id_rsa",
				KnownHosts:     testKnownHostsPath,
				MaxSessions:    4,
			},
		},
	}

	logger := logging.NewLogger(config.LoggingConfig{
		Level:  "info",
		Format: "text",
		Output: "stdout",
	})

	manager := &RealManager{
		config:          cfg,
		logger:          logger,
		realConnections: make(map[string]*RealConnection),
	}

	// 初始化连接
	for _, host := range cfg.SSHHosts {
		manager.realConnections[host.ID] = &RealConnection{
			HostID:      host.ID,
			MaxSessions: host.MaxSessions,
			hostConfig:  host,
			logger:      logger,
		}
	}

	// 测试未配置主机的健康检查
	err := manager.HealthCheck("unknown-host")
	if err == nil {
		t.Fatal("期望未配置主机健康检查返回错误，但成功了")
	}

	// 测试已配置主机的健康检查（会尝试创建真实的SSH连接，可能会失败）
	// 在真实环境中，这需要有效的SSH服务器和认证
	err = manager.HealthCheck("test-host")
	// 这里我们期望返回错误（因为没有真实的SSH服务器），但不是主机未配置的错误
	if err != nil {
		// 检查错误类型，应该是连接相关的错误，而不是主机未配置的错误
		if err.Error() == "主机 'test-host' 未配置" {
			t.Fatal("期望主机已配置，但返回主机未配置错误")
		}
		// 连接错误是预期的，因为我们没有运行真实的SSH服务器
	}
}

func TestRealManager_ConcurrentAccess(t *testing.T) {
	cfg := &config.Config{
		SSHHosts: []config.SSHHost{
			{
				ID:             "test-host",
				Addr:           "localhost:22",
				User:           "testuser",
				AuthMethod:     "private_key",
				PrivateKeyPath: "~/.ssh/id_rsa",
				KnownHosts:     testKnownHostsPath,
				MaxSessions:    10,
			},
		},
	}

	logger := logging.NewLogger(config.LoggingConfig{
		Level:  "error", // 减少日志输出
		Format: "text",
		Output: "stdout",
	})

	manager := &RealManager{
		config:          cfg,
		logger:          logger,
		realConnections: make(map[string]*RealConnection),
	}

	// 初始化连接
	for _, host := range cfg.SSHHosts {
		manager.realConnections[host.ID] = &RealConnection{
			HostID:      host.ID,
			MaxSessions: host.MaxSessions,
			hostConfig:  host,
			logger:      logger,
		}
	}

	// 并发测试
	var wg sync.WaitGroup
	concurrentCount := 50

	for i := 0; i < concurrentCount; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			// 获取会话（会尝试创建真实的SSH连接，可能会失败）
			_, err := manager.GetSession("test-host")
			if err != nil {
				// 连接错误是预期的，因为我们没有运行真实的SSH服务器
				// 但我们不认为这是测试失败
				if err.Error() == "主机 'test-host' 未配置" {
					t.Errorf("并发获取会话失败 #%d: 主机未配置错误", id)
				}
				return
			}

			// 模拟使用会话
			time.Sleep(1 * time.Millisecond)

			// 由于SSH会话不能重复使用，我们不测试释放会话
		}(i)
	}

	wg.Wait()
}
