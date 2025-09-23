package ssh

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/terateams/ExecMCP/internal/common"
	"github.com/terateams/ExecMCP/internal/config"
	"github.com/terateams/ExecMCP/internal/logging"
)

// Manager SSH 连接管理器接口
type Manager interface {
	GetSession(hostID string) (Session, error)
	ReleaseSession(hostID string, session Session)
	Close()
	HealthCheck(hostID string) error
}

// Session SSH 会话接口
type Session interface {
	ExecuteCommand(command string, args []string) (string, error)
	Close()
}

// NewManager 创建 SSH 连接管理器
func NewManager(cfg *config.Config, logger logging.Logger) Manager {
	manager := &RealManager{
		config:          cfg,
		logger:          logger,
		realConnections: make(map[string]*RealConnection),
		mu:              sync.RWMutex{},
	}

	// 初始化主机连接
	for _, host := range cfg.SSHHosts {
		maxSessions := host.MaxSessions
		if maxSessions <= 0 {
			maxSessions = 4 // 默认值
		}
		manager.realConnections[host.ID] = &RealConnection{
			HostID:      host.ID,
			MaxSessions: maxSessions,
			hostConfig:  host,
			logger:      logger,
		}
	}

	logger.Info("真实 SSH 连接管理器初始化完成", "hosts_count", len(cfg.SSHHosts))
	return manager
}

// RealManager 真实 SSH 连接管理器
type RealManager struct {
	config *config.Config
	logger logging.Logger

	realConnections map[string]*RealConnection
	mu              sync.RWMutex
}

// RealConnection 真实 SSH 连接
type RealConnection struct {
	HostID       string
	Client       *ssh.Client
	LastUsed     time.Time
	SessionCount int
	MaxSessions  int
	mu           sync.Mutex
	closed       bool
	hostConfig   config.SSHHost
	logger       logging.Logger
}

// RealSession 真实 SSH 会话
type RealSession struct {
	connection *RealConnection
	session    *ssh.Session
	closed     bool
}

// NewRealManager 创建真实 SSH 管理器
func NewRealManager(cfg *config.Config, logger logging.Logger) (*RealManager, error) {
	manager := &RealManager{
		config:          cfg,
		logger:          logger,
		realConnections: make(map[string]*RealConnection),
	}

	// 初始化主机连接
	for _, host := range cfg.SSHHosts {
		manager.realConnections[host.ID] = &RealConnection{
			HostID:      host.ID,
			MaxSessions: host.MaxSessions,
			hostConfig:  host,
			logger:      logger,
		}
	}

	logger.Info("真实 SSH 连接管理器初始化完成", "hosts_count", len(cfg.SSHHosts))
	return manager, nil
}

// GetSession 获取 SSH 会话
func (m *RealManager) GetSession(hostID string) (Session, error) {
	m.mu.RLock()
	conn, exists := m.realConnections[hostID]
	m.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("主机 '%s' 未配置", hostID)
	}

	// SSH会话不能重复使用，每次都创建新会话
	return m.createNewSession(conn)
}

// createNewSession 创建新的SSH会话
func (m *RealManager) createNewSession(conn *RealConnection) (Session, error) {
	conn.mu.Lock()
	defer conn.mu.Unlock()

	if conn.closed {
		return nil, fmt.Errorf("连接已关闭")
	}

	// 如果SSH客户端未初始化，先建立连接
	if conn.Client == nil {
		client, err := m.createSSHClient(conn.hostConfig)
		if err != nil {
			return nil, common.SSHError("创建客户端", conn.hostConfig.ID, err)
		}
		conn.Client = client
	}

	// 创建新的SSH会话
	session, err := conn.Client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("创建SSH会话失败: %w", err)
	}

	// 设置会话模式（不需要PTY，直接执行命令）

	realSession := &RealSession{
		connection: conn,
		session:    session,
		closed:     false,
	}

	conn.SessionCount++
	conn.LastUsed = time.Now()

	m.logger.Debug("创建新SSH会话", "host_id", conn.HostID, "session_count", conn.SessionCount)
	return realSession, nil
}

// createSSHClient 创建SSH客户端连接
func (m *RealManager) createSSHClient(hostConfig config.SSHHost) (*ssh.Client, error) {
	// 配置主机密钥校验
	hostKeyCallback, err := m.getHostKeyCallback(hostConfig)
	if err != nil {
		return nil, fmt.Errorf("加载 known_hosts 失败: %w", err)
	}

	// 构建SSH配置
	sshConfig := &ssh.ClientConfig{
		User:            hostConfig.User,
		HostKeyCallback: hostKeyCallback,
		Timeout:         time.Duration(hostConfig.ConnectTimeout) * time.Second,
	}

	// 根据认证方式配置
	var authErr error
	switch hostConfig.AuthMethod {
	case "private_key":
		authErr = m.configurePrivateKey(sshConfig, hostConfig)
	case "password":
		authErr = m.configurePassword(sshConfig, hostConfig)
	default:
		return nil, fmt.Errorf("不支持的认证方式: %s", hostConfig.AuthMethod)
	}

	if authErr != nil {
		return nil, fmt.Errorf("配置认证失败: %w", authErr)
	}

	// 解析主机地址
	addr := hostConfig.Addr
	if !strings.Contains(addr, ":") {
		addr += ":22"
	}

	// 建立SSH连接
	m.logger.Info("正在建立SSH连接", "host_id", hostConfig.ID, "address", addr, "user", hostConfig.User)
	client, err := ssh.Dial("tcp", addr, sshConfig)
	if err != nil {
		return nil, common.SSHError("建立连接", hostConfig.ID, err)
	}

	m.logger.Info("SSH连接建立成功", "host_id", hostConfig.ID)
	return client, nil
}

// getHostKeyCallback 严格要求提供 known_hosts 文件，不再容忍 InsecureIgnoreHostKey，
// 以免生产环境被中间人攻击。任何加载失败都会返回错误并写入日志。
func (m *RealManager) getHostKeyCallback(hostConfig config.SSHHost) (ssh.HostKeyCallback, error) {
	if strings.TrimSpace(hostConfig.KnownHosts) == "" {
		m.logger.Error("未配置 known_hosts 文件，拒绝建立 SSH 连接", "host_id", hostConfig.ID)
		return nil, fmt.Errorf("未配置 known_hosts 文件")
	}

	// 创建known_hosts验证回调
	callback, err := knownhosts.New(hostConfig.KnownHosts)
	if err != nil {
		m.logger.Error("加载 known_hosts 文件失败", "host_id", hostConfig.ID, "path", hostConfig.KnownHosts, "error", err)
		return nil, fmt.Errorf("无法加载 known_hosts 文件 '%s': %w", hostConfig.KnownHosts, err)
	}

	return callback, nil
}

// configurePrivateKey 配置私钥认证
func (m *RealManager) configurePrivateKey(sshConfig *ssh.ClientConfig, hostConfig config.SSHHost) error {
	if hostConfig.PrivateKeyPath == "" {
		return fmt.Errorf("私钥路径未配置")
	}

	// 展开用户目录路径
	keyPath := os.ExpandEnv(hostConfig.PrivateKeyPath)
	if strings.HasPrefix(keyPath, "~") {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("获取用户目录失败: %w", err)
		}
		keyPath = filepath.Join(home, keyPath[1:])
	}

	// 读取私钥文件
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("读取私钥文件失败: %w", err)
	}

	// 解析私钥
	signer, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		// 尝试解析带密码的私钥
		if _, ok := err.(*ssh.PassphraseMissingError); ok {
			return fmt.Errorf("私钥需要密码，当前不支持")
		}
		return fmt.Errorf("解析私钥失败: %w", err)
	}

	sshConfig.Auth = append(sshConfig.Auth, ssh.PublicKeys(signer))
	// 避免在日志中暴露完整的私钥路径，仅记录文件名
	keyName := filepath.Base(keyPath)
	m.logger.Debug("配置私钥认证成功", "host_id", hostConfig.ID, "key_file", keyName)
	return nil
}

// configurePassword 配置密码认证
func (m *RealManager) configurePassword(sshConfig *ssh.ClientConfig, hostConfig config.SSHHost) error {
	password := strings.TrimSpace(hostConfig.Password)
	if password == "" {
		if envKey := strings.TrimSpace(hostConfig.PasswordEnv); envKey != "" {
			password = os.Getenv(envKey)
			if strings.TrimSpace(password) == "" {
				return fmt.Errorf("从环境变量读取密码失败")
			}
		} else if filePath := strings.TrimSpace(hostConfig.PasswordFile); filePath != "" {
			data, err := os.ReadFile(filePath)
			if err != nil {
				return fmt.Errorf("读取密码文件失败: %w", err)
			}
			password = strings.TrimSpace(string(data))
			if password == "" {
				return fmt.Errorf("密码文件内容为空")
			}
		} else {
			return fmt.Errorf("密码未配置")
		}
	}

	sshConfig.Auth = append(sshConfig.Auth, ssh.Password(password))
	m.logger.Debug("配置密码认证成功", "host_id", hostConfig.ID)
	return nil
}

// ReleaseSession 释放 SSH 会话
func (m *RealManager) ReleaseSession(hostID string, session Session) {
	m.mu.RLock()
	conn, exists := m.realConnections[hostID]
	m.mu.RUnlock()

	if !exists {
		m.logger.Warn("尝试释放不存在的连接的会话", "host_id", hostID)
		return
	}

	if session != nil {
		// SSH会话一旦使用过就不能重复使用，直接关闭
		session.Close()
		conn.mu.Lock()
		conn.SessionCount--
		conn.LastUsed = time.Now()
		conn.mu.Unlock()
		m.logger.Debug("SSH会话已关闭", "host_id", hostID)
	}
}

// Close 关闭所有连接
func (m *RealManager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for hostID, conn := range m.realConnections {
		conn.mu.Lock()
		conn.closed = true

		// 关闭SSH客户端
		if conn.Client != nil {
			conn.Client.Close()
		}

		conn.mu.Unlock()
		m.logger.Info("关闭 SSH 连接", "host_id", hostID)
	}

	m.realConnections = nil
	m.logger.Info("所有SSH连接已关闭")
}

// HealthCheck 执行健康检查
func (m *RealManager) HealthCheck(hostID string) error {
	m.mu.RLock()
	conn, exists := m.realConnections[hostID]
	m.mu.RUnlock()

	if !exists {
		return fmt.Errorf("主机 '%s' 未配置", hostID)
	}

	// 检查连接是否已建立
	if conn.Client == nil {
		// 尝试建立连接
		conn.mu.Lock()
		defer conn.mu.Unlock()

		if conn.closed {
			return fmt.Errorf("连接已关闭")
		}

		client, err := m.createSSHClient(conn.hostConfig)
		if err != nil {
			return fmt.Errorf("建立连接失败: %w", err)
		}

		conn.Client = client
		conn.LastUsed = time.Now()
		m.logger.Info("健康检查时建立了新连接", "host_id", hostID)
		return nil
	}

	// 测试连接是否仍然活跃
	conn.mu.Lock()
	defer conn.mu.Unlock()

	if conn.closed {
		return fmt.Errorf("连接已关闭")
	}

	// 发送keepalive请求
	_, _, err := conn.Client.SendRequest("keepalive@golang.org", true, nil)
	if err != nil {
		// 连接可能已断开，关闭旧连接
		conn.Client.Close()
		conn.Client = nil
		return fmt.Errorf("连接已断开: %w", err)
	}

	m.logger.Debug("连接健康检查通过", "host_id", hostID)
	return nil
}

// ExecuteCommand 执行命令
func (s *RealSession) ExecuteCommand(command string, args []string) (string, error) {
	if s.closed {
		return "", fmt.Errorf("会话已关闭")
	}
	if s.session == nil {
		return "", fmt.Errorf("SSH会话未初始化")
	}

	// 构建完整命令
	cmd := command
	for _, arg := range args {
		cmd += " " + arg
	}

	// 创建脱敏的命令用于日志记录
	sanitizedCmd := s.sanitizeCommandForLogging(cmd)
	s.connection.logger.Debug("执行SSH命令", "host_id", s.connection.HostID, "command", sanitizedCmd)

	// 执行命令并捕获输出
	var stdout, stderr bytes.Buffer
	session := s.session

	session.Stdout = &stdout
	session.Stderr = &stderr

	// 执行命令
	err := session.Run(cmd)
	if err != nil {
		s.connection.logger.Error("命令执行失败",
			"host_id", s.connection.HostID,
			"command", sanitizedCmd,
			"error", err,
			"stderr_length", stderr.Len())
		return "", fmt.Errorf("命令执行失败: %w", err)
	}

	// 合并stdout和stderr
	result := stdout.String()
	if stderr.Len() > 0 {
		result += "\n" + stderr.String()
	}

	s.connection.logger.Debug("命令执行成功",
		"host_id", s.connection.HostID,
		"command", sanitizedCmd,
		"output_length", len(result))

	return result, nil
}

// sanitizeCommandForLogging 对命令进行脱敏处理，避免在日志中暴露敏感参数
func (s *RealSession) sanitizeCommandForLogging(cmd string) string {
	// 将命令按空格分割，但保留引号内的内容
	words := strings.Fields(cmd)
	if len(words) == 0 {
		return cmd
	}

	// 敏感参数关键词列表
	sensitiveParams := []string{
		"--password", "-p", "--passwd", "--pwd",
		"--token", "--auth-token", "--bearer",
		"--secret", "--key", "--auth", "--authorization",
		"--private-key", "--passphrase", "--credentials",
	}

	// 敏感值检测关键词
	sensitiveValueKeywords := []string{
		"password", "passwd", "pwd", "token", "secret", "key", "auth",
		"bearer", "credentials", "passphrase", "private",
	}

	var sanitized []string
	sanitized = append(sanitized, words[0]) // 保留命令名

	for i := 1; i < len(words); i++ {
		word := strings.ToLower(words[i])
		originalWord := words[i]

		// 检查是否是敏感参数名
		isSensitiveParam := false
		for _, param := range sensitiveParams {
			if word == strings.ToLower(param) {
				isSensitiveParam = true
				break
			}
			// 检查参数=值格式，如 --password=value
			if strings.HasPrefix(word, strings.ToLower(param)+"=") {
				// 分离参数名和值
				parts := strings.SplitN(originalWord, "=", 2)
				if len(parts) == 2 {
					sanitized = append(sanitized, parts[0]+"=[REDACTED]")
					isSensitiveParam = false // 已处理，不再作为独立参数处理
					break
				}
			}
		}

		if isSensitiveParam {
			sanitized = append(sanitized, originalWord) // 保留参数名
			// 检查下一个参数是否是值
			if i+1 < len(words) && !strings.HasPrefix(words[i+1], "-") {
				sanitized = append(sanitized, "[REDACTED]") // 替换敏感值
				i++ // 跳过下一个单词
			}
		} else {
			// 检查是否已处理过参数=值格式
			alreadyProcessed := false
			for _, param := range sensitiveParams {
				if strings.HasPrefix(word, strings.ToLower(param)+"=") {
					alreadyProcessed = true
					break
				}
			}

			if !alreadyProcessed {
				// 检查当前词是否包含敏感关键词
				containsSensitive := false
				for _, keyword := range sensitiveValueKeywords {
					if strings.Contains(word, keyword) {
						containsSensitive = true
						break
					}
				}

				if containsSensitive {
					sanitized = append(sanitized, "[REDACTED]")
				} else {
					sanitized = append(sanitized, originalWord)
				}
			}
		}
	}

	return strings.Join(sanitized, " ")
}

// Close 关闭会话
func (s *RealSession) Close() {
	if s.closed {
		return
	}

	s.closed = true
	if s.session != nil {
		s.session.Close()
		s.session = nil
	}

	s.connection.logger.Debug("SSH会话已关闭", "host_id", s.connection.HostID)
}
