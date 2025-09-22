package ssh

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/your-username/ExecMCP/internal/config"
	"github.com/your-username/ExecMCP/internal/logging"
)

// MockManager 模拟 SSH 连接管理器
type MockManager struct {
	config      *config.Config
	hosts       map[string]*MockHostManager
	logger      logging.Logger
	mu          sync.RWMutex
	closed      bool
	failConnect bool
}

// MockHostManager 模拟主机管理器
type MockHostManager struct {
	hostID      string
	config      config.SSHHost
	connections []*MockSSHConnection
	sessionPool chan *MockSession
	logger      logging.Logger
	mu          sync.Mutex
}

// MockSSHConnection 模拟 SSH 连接
type MockSSHConnection struct {
	createdAt time.Time
	lastUsed  time.Time
	hostID    string
	closed    bool
}

// MockSession 模拟 SSH 会话
type MockSession struct {
	connection *MockSSHConnection
	closed     bool
}

// NewMockManager 创建模拟 SSH 连接管理器（用于测试）
func NewMockManager(cfg *config.Config) Manager {
	return NewMockManagerInternal(cfg, logging.NewLogger(cfg.Logging))
}

// NewMockManagerInternal 创建模拟 SSH 管理器（内部方法）
func NewMockManagerInternal(cfg *config.Config, logger logging.Logger) *MockManager {
	manager := &MockManager{
		config: cfg,
		hosts:  make(map[string]*MockHostManager),
		logger: logger,
	}

	// 初始化主机管理器
	for _, host := range cfg.SSHHosts {
		manager.hosts[host.ID] = &MockHostManager{
			hostID:      host.ID,
			config:      host,
			connections: make([]*MockSSHConnection, 0),
			sessionPool: make(chan *MockSession, host.MaxSessions),
			logger:      manager.logger,
		}
	}

	manager.logger.Info("模拟 SSH 连接管理器初始化完成", "hosts_count", len(cfg.SSHHosts))
	return manager
}

// SetFailConnect 设置连接失败模式
func (m *MockManager) SetFailConnect(fail bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failConnect = fail
}

// GetSession 获取 SSH 会话
func (m *MockManager) GetSession(hostID string) (Session, error) {
	m.mu.RLock()
	if m.closed {
		m.mu.RUnlock()
		return nil, errors.New("SSH 管理器已关闭")
	}

	host, exists := m.hosts[hostID]
	m.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("主机 '%s' 未配置", hostID)
	}

	if m.failConnect {
		return nil, errors.New("模拟连接失败")
	}

	// 尝试从会话池获取会话
	select {
	case session := <-host.sessionPool:
		if !session.connection.closed {
			session.connection.lastUsed = time.Now()
			return session, nil
		}
	default:
		// 会话池为空，继续创建新会话
	}

	// 创建新的会话
	return host.createNewSession()
}

// ReleaseSession 释放 SSH 会话
func (m *MockManager) ReleaseSession(hostID string, session Session) {
	mockSession, ok := session.(*MockSession)
	if !ok {
		return
	}

	m.mu.RLock()
	if m.closed {
		m.mu.RUnlock()
		if mockSession != nil && !mockSession.closed {
			mockSession.Close()
		}
		return
	}

	host, exists := m.hosts[hostID]
	m.mu.RUnlock()

	if !exists {
		if mockSession != nil && !mockSession.closed {
			mockSession.Close()
		}
		return
	}

	host.releaseSession(mockSession)
}

// Close 关闭所有连接
func (m *MockManager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return
	}

	m.closed = true

	// 关闭所有主机连接
	for _, host := range m.hosts {
		host.Close()
	}

	m.logger.Info("模拟 SSH 连接管理器已关闭")
}

// HealthCheck 执行健康检查
func (m *MockManager) HealthCheck(hostID string) error {
	m.mu.RLock()
	if m.closed {
		m.mu.RUnlock()
		return errors.New("SSH 管理器已关闭")
	}

	host, exists := m.hosts[hostID]
	m.mu.RUnlock()

	if !exists {
		return fmt.Errorf("主机 '%s' 未配置", hostID)
	}

	return host.healthCheck()
}

// createNewSession 创建新的模拟 SSH 会话
func (h *MockHostManager) createNewSession() (*MockSession, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	// 查找可用的连接
	var connection *MockSSHConnection
	for _, conn := range h.connections {
		if !conn.closed && time.Since(conn.lastUsed) < 5*time.Minute {
			connection = conn
			break
		}
	}

	// 如果没有可用连接，创建新连接
	if connection == nil {
		conn := &MockSSHConnection{
			createdAt: time.Now(),
			lastUsed:  time.Now(),
			hostID:    h.hostID,
			closed:    false,
		}
		h.connections = append(h.connections, conn)
		connection = conn
	}

	// 创建会话
	session := &MockSession{
		connection: connection,
		closed:     false,
	}

	h.logger.Debug("创建新的模拟 SSH 会话", "host_id", h.hostID)
	return session, nil
}

// releaseSession 释放会话
func (h *MockHostManager) releaseSession(session *MockSession) {
	if session == nil || session.closed {
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	// 尝试将会话放回池中
	select {
	case h.sessionPool <- session:
		session.connection.lastUsed = time.Now()
		h.logger.Debug("会话已放回池中", "host_id", h.hostID)
	default:
		// 池已满，关闭会话
		session.Close()
		h.logger.Debug("会话池已满，关闭会话", "host_id", h.hostID)
	}
}

// Close 关闭主机所有连接
func (h *MockHostManager) Close() {
	h.mu.Lock()
	defer h.mu.Unlock()

	// 关闭所有会话
	close(h.sessionPool)
	for session := range h.sessionPool {
		if session != nil && !session.closed {
			session.Close()
		}
	}

	// 关闭所有连接
	for _, conn := range h.connections {
		if !conn.closed {
			conn.Close()
		}
	}

	h.connections = nil
	h.logger.Info("主机连接已关闭", "host_id", h.hostID)
}

// healthCheck 执行健康检查
func (h *MockHostManager) healthCheck() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if len(h.connections) == 0 {
		return errors.New("没有可用的连接")
	}

	// 检查第一个连接的健康状态
	conn := h.connections[0]
	if conn.closed {
		return errors.New("连接已关闭")
	}

	h.logger.Debug("模拟健康检查通过", "host_id", h.hostID)
	return nil
}

// Close 关闭连接
func (c *MockSSHConnection) Close() {
	if c.closed {
		return
	}
	c.closed = true
}

// Close 关闭会话
func (s *MockSession) Close() {
	if s.closed {
		return
	}
	s.closed = true
}

// ExecuteCommand 在会话中执行命令
func (s *MockSession) ExecuteCommand(command string, args []string) (string, error) {
	if s.closed {
		return "", errors.New("会话已关闭")
	}

	// 构建完整命令
	cmd := command
	if len(args) > 0 {
		for _, arg := range args {
			cmd += " " + arg
		}
	}

	// 模拟少量执行时间
	if command == "echo" && len(args) > 0 {
		// 为特定命令添加延迟，便于测试
		time.Sleep(1 * time.Millisecond)
	}

	// 模拟命令执行
	return "模拟输出: " + cmd + "\n", nil
}
