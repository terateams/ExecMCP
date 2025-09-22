package ssh

import (
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/your-username/ExecMCP/internal/config"
)

func TestNewMockManager(t *testing.T) {
	cfg := &config.Config{
		SSHHosts: []config.SSHHost{
			{
				ID:             "test-host",
				Addr:           "localhost:22",
				User:           "testuser",
				AuthMethod:     "private_key",
				PrivateKeyPath: "~/.ssh/id_rsa",
				KnownHosts:     "~/.ssh/known_hosts",
				MaxSessions:    4,
			},
		},
	}

	manager := NewMockManager(cfg)
	if manager == nil {
		t.Fatal("期望创建模拟管理器，但得到 nil")
	}

	mockManager, ok := manager.(*MockManager)
	if !ok {
		t.Fatal("期望返回 MockManager 类型")
	}

	if mockManager.config != cfg {
		t.Error("期望配置被正确设置")
	}

	if len(mockManager.hosts) != 1 {
		t.Errorf("期望有1个主机，但得到 %d", len(mockManager.hosts))
	}

	if _, exists := mockManager.hosts["test-host"]; !exists {
		t.Error("期望主机 'test-host' 存在")
	}
}

func TestMockManager_GetSession(t *testing.T) {
	cfg := &config.Config{
		SSHHosts: []config.SSHHost{
			{
				ID:             "test-host",
				Addr:           "localhost:22",
				User:           "testuser",
				AuthMethod:     "private_key",
				PrivateKeyPath: "~/.ssh/id_rsa",
				KnownHosts:     "~/.ssh/known_hosts",
				MaxSessions:    2,
			},
		},
	}

	manager := NewMockManager(cfg)

	// 测试获取会话
	session, err := manager.GetSession("test-host")
	if err != nil {
		t.Fatalf("期望获取会话成功，但得到错误: %v", err)
	}

	if session == nil {
		t.Fatal("期望返回会话对象，但得到 nil")
	}

	mockSession, ok := session.(*MockSession)
	if !ok {
		t.Fatal("期望返回 MockSession 类型")
	}

	if mockSession.closed {
		t.Error("期望会话处于开启状态")
	}

	// 测试获取未配置的主机
	_, err = manager.GetSession("unknown-host")
	if err == nil {
		t.Fatal("期望获取未配置主机返回错误，但成功了")
	}
}

func TestMockManager_GetSession_SessionReuse(t *testing.T) {
	cfg := &config.Config{
		SSHHosts: []config.SSHHost{
			{
				ID:             "test-host",
				Addr:           "localhost:22",
				User:           "testuser",
				AuthMethod:     "private_key",
				PrivateKeyPath: "~/.ssh/id_rsa",
				KnownHosts:     "~/.ssh/known_hosts",
				MaxSessions:    1,
			},
		},
	}

	manager := NewMockManager(cfg)

	// 获取第一个会话
	session1, err := manager.GetSession("test-host")
	if err != nil {
		t.Fatalf("期望获取第一个会话成功，但得到错误: %v", err)
	}

	// 释放第一个会话
	manager.ReleaseSession("test-host", session1)

	// 获取第二个会话，应该重用第一个
	session2, err := manager.GetSession("test-host")
	if err != nil {
		t.Fatalf("期望获取第二个会话成功，但得到错误: %v", err)
	}

	if session1 != session2 {
		t.Error("期望会话被重用，但得到了新的会话")
	}
}

func TestMockManager_SetFailConnect(t *testing.T) {
	cfg := &config.Config{
		SSHHosts: []config.SSHHost{
			{
				ID:             "test-host",
				Addr:           "localhost:22",
				User:           "testuser",
				AuthMethod:     "private_key",
				PrivateKeyPath: "~/.ssh/id_rsa",
				KnownHosts:     "~/.ssh/known_hosts",
				MaxSessions:    4,
			},
		},
	}

	manager := NewMockManager(cfg)
	mockManager := manager.(*MockManager)

	// 设置连接失败模式
	mockManager.SetFailConnect(true)

	// 尝试获取会话应该失败
	_, err := manager.GetSession("test-host")
	if err == nil {
		t.Fatal("期望连接失败模式下获取会话失败，但成功了")
	}
}

func TestMockManager_Close(t *testing.T) {
	cfg := &config.Config{
		SSHHosts: []config.SSHHost{
			{
				ID:             "test-host",
				Addr:           "localhost:22",
				User:           "testuser",
				AuthMethod:     "private_key",
				PrivateKeyPath: "~/.ssh/id_rsa",
				KnownHosts:     "~/.ssh/known_hosts",
				MaxSessions:    4,
			},
		},
	}

	manager := NewMockManager(cfg)
	mockManager := manager.(*MockManager)

	// 获取一个会话
	session, err := manager.GetSession("test-host")
	if err != nil {
		t.Fatalf("期望获取会话成功，但得到错误: %v", err)
	}

	// 关闭管理器
	manager.Close()

	if !mockManager.closed {
		t.Error("期望管理器被标记为关闭")
	}

	// 关闭后获取会话应该失败
	_, err = manager.GetSession("test-host")
	if err == nil {
		t.Fatal("期望关闭后获取会话失败，但成功了")
	}

	// 释放已关闭管理器的会话不应该 panic
	manager.ReleaseSession("test-host", session)
}

func TestMockManager_HealthCheck(t *testing.T) {
	cfg := &config.Config{
		SSHHosts: []config.SSHHost{
			{
				ID:             "test-host",
				Addr:           "localhost:22",
				User:           "testuser",
				AuthMethod:     "private_key",
				PrivateKeyPath: "~/.ssh/id_rsa",
				KnownHosts:     "~/.ssh/known_hosts",
				MaxSessions:    4,
			},
		},
	}

	manager := NewMockManager(cfg)

	// 先获取一个会话来建立连接
	_, err := manager.GetSession("test-host")
	if err != nil {
		t.Fatalf("期望获取会话成功，但得到错误: %v", err)
	}

	// 测试健康检查
	err = manager.HealthCheck("test-host")
	if err != nil {
		t.Fatalf("期望健康检查成功，但得到错误: %v", err)
	}

	// 测试未配置主机的健康检查
	err = manager.HealthCheck("unknown-host")
	if err == nil {
		t.Fatal("期望未配置主机健康检查返回错误，但成功了")
	}

	// 关闭后健康检查应该失败
	manager.Close()
	err = manager.HealthCheck("test-host")
	if err == nil {
		t.Fatal("期望关闭后健康检查失败，但成功了")
	}
}

func TestMockSession_ExecuteCommand(t *testing.T) {
	cfg := &config.Config{
		SSHHosts: []config.SSHHost{
			{
				ID:             "test-host",
				Addr:           "localhost:22",
				User:           "testuser",
				AuthMethod:     "private_key",
				PrivateKeyPath: "~/.ssh/id_rsa",
				KnownHosts:     "~/.ssh/known_hosts",
				MaxSessions:    4,
			},
		},
	}

	manager := NewMockManager(cfg)
	session, err := manager.GetSession("test-host")
	if err != nil {
		t.Fatalf("期望获取会话成功，但得到错误: %v", err)
	}

	mockSession := session.(*MockSession)

	// 测试执行命令
	output, err := mockSession.ExecuteCommand("echo", []string{"hello", "world"})
	if err != nil {
		t.Fatalf("期望执行命令成功，但得到错误: %v", err)
	}

	expectedOutput := "模拟输出: echo hello world\n"
	if output != expectedOutput {
		t.Errorf("期望输出 '%s'，但得到 '%s'", expectedOutput, output)
	}

	// 测试关闭会话后执行命令
	mockSession.Close()
	_, err = mockSession.ExecuteCommand("echo", []string{"test"})
	if err == nil {
		t.Fatal("期望关闭会话后执行命令失败，但成功了")
	}
}

func TestMockSession_Close(t *testing.T) {
	cfg := &config.Config{
		SSHHosts: []config.SSHHost{
			{
				ID:             "test-host",
				Addr:           "localhost:22",
				User:           "testuser",
				AuthMethod:     "private_key",
				PrivateKeyPath: "~/.ssh/id_rsa",
				KnownHosts:     "~/.ssh/known_hosts",
				MaxSessions:    4,
			},
		},
	}

	manager := NewMockManager(cfg)
	session, err := manager.GetSession("test-host")
	if err != nil {
		t.Fatalf("期望获取会话成功，但得到错误: %v", err)
	}

	mockSession := session.(*MockSession)

	// 关闭会话
	mockSession.Close()

	if !mockSession.closed {
		t.Error("期望会话被标记为关闭")
	}

	// 多次关闭不应该 panic
	mockSession.Close()
}

func TestMockManager_ConcurrentAccess(t *testing.T) {
	cfg := &config.Config{
		SSHHosts: []config.SSHHost{
			{
				ID:             "test-host",
				Addr:           "localhost:22",
				User:           "testuser",
				AuthMethod:     "private_key",
				PrivateKeyPath: "~/.ssh/id_rsa",
				KnownHosts:     "~/.ssh/known_hosts",
				MaxSessions:    10,
			},
		},
	}

	manager := NewMockManager(cfg)

	// 并发测试
	var wg sync.WaitGroup
	concurrentCount := 50

	for i := 0; i < concurrentCount; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			// 获取会话
			session, err := manager.GetSession("test-host")
			if err != nil {
				t.Errorf("并发获取会话失败 #%d: %v", id, err)
				return
			}

			// 模拟使用会话
			output, err := session.ExecuteCommand("echo", []string{"test", strconv.Itoa(id)})
			if err != nil {
				t.Errorf("并发执行命令失败 #%d: %v", id, err)
				return
			}

			if output == "" {
				t.Errorf("并发执行命令 #%d 返回空输出", id)
			}

			// 释放会话
			manager.ReleaseSession("test-host", session)
		}(i)
	}

	wg.Wait()
}

func TestMockSSHConnection_Close(t *testing.T) {
	conn := &MockSSHConnection{
		createdAt: time.Now(),
		lastUsed:  time.Now(),
		hostID:    "test-host",
		closed:    false,
	}

	// 关闭连接
	conn.Close()

	if !conn.closed {
		t.Error("期望连接被标记为关闭")
	}

	// 多次关闭不应该 panic
	conn.Close()
}
