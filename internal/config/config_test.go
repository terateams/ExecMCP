package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_ValidConfig(t *testing.T) {
	// 创建临时配置文件
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.yaml")

	configContent := `
server:
  bind_addr: "127.0.0.1:8080"
  log_level: "debug"
  max_concurrent: 16
  request_timeout_sec: 60
  auth_token: "test-token"

ssh_hosts:
  - id: "test-host"
    addr: "localhost:22"
    user: "testuser"
    auth_method: "private_key"
    private_key_path: "~/.ssh/id_rsa"
    known_hosts: "~/.ssh/known_hosts"
    max_sessions: 4

security:
  default_shell: false
  allow_shell_for: ["bash", "sh"]
  denylist_exact: ["rm", "dd"]
  allowlist_exact: ["ls", "cat"]
  working_dir_allow: ["/tmp"]
  max_output_bytes: 512000
  rate_limit_per_min: 100

scripts:
  - name: "test-script"
    description: "Test script"
    prompt: "This is a test script"
    template: "echo 'Hello {name}'"
    parameters:
      - name: "name"
        type: "string"
        required: true
        default: "World"
        description: "Name parameter"
    allowed_hosts: ["*"]
    timeout_sec: 10
    use_shell: true

logging:
  level: "info"
  format: "json"
  output: "stdout"
  max_size: "100MB"
  max_backups: 3
  max_age: 7
`

	err := os.WriteFile(configPath, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("创建测试配置文件失败: %v", err)
	}

	// 测试配置加载
	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("配置加载失败: %v", err)
	}

	// 验证服务器配置
	if cfg.Server.BindAddr != "127.0.0.1:8080" {
		t.Errorf("期望 BindAddr 为 '127.0.0.1:8080'，但得到 '%s'", cfg.Server.BindAddr)
	}
	if cfg.Server.LogLevel != "debug" {
		t.Errorf("期望 LogLevel 为 'debug'，但得到 '%s'", cfg.Server.LogLevel)
	}
	if cfg.Server.MaxConcurrent != 16 {
		t.Errorf("期望 MaxConcurrent 为 16，但得到 %d", cfg.Server.MaxConcurrent)
	}
	if cfg.Server.RequestTimeout != 60 {
		t.Errorf("期望 RequestTimeout 为 60，但得到 %d", cfg.Server.RequestTimeout)
	}

	// 验证 SSH 主机配置
	if len(cfg.SSHHosts) != 1 {
		t.Fatalf("期望 1 个 SSH 主机配置，但得到 %d", len(cfg.SSHHosts))
	}

	host := cfg.SSHHosts[0]
	if host.ID != "test-host" {
		t.Errorf("期望 HostID 为 'test-host'，但得到 '%s'", host.ID)
	}
	if host.Addr != "localhost:22" {
		t.Errorf("期望 Addr 为 'localhost:22'，但得到 '%s'", host.Addr)
	}
	if host.AuthMethod != "private_key" {
		t.Errorf("期望 AuthMethod 为 'private_key'，但得到 '%s'", host.AuthMethod)
	}

	// 验证安全配置
	if cfg.Security.DefaultShell {
		t.Error("期望 DefaultShell 为 false")
	}
	if len(cfg.Security.AllowShellFor) != 2 {
		t.Errorf("期望 AllowShellFor 有 2 个元素，但得到 %d", len(cfg.Security.AllowShellFor))
	}
	if len(cfg.Security.DenylistExact) != 2 {
		t.Errorf("期望 DenylistExact 有 2 个元素，但得到 %d", len(cfg.Security.DenylistExact))
	}

	// 验证脚本配置
	if len(cfg.Scripts) != 1 {
		t.Fatalf("期望 1 个脚本配置，但得到 %d", len(cfg.Scripts))
	}

	script := cfg.Scripts[0]
	if script.Name != "test-script" {
		t.Errorf("期望脚本名称为 'test-script'，但得到 '%s'", script.Name)
	}
	if script.Template != "echo 'Hello {name}'" {
		t.Errorf("期望模板为 'echo 'Hello {name}''，但得到 '%s'", script.Template)
	}
	if len(script.Parameters) != 1 {
		t.Errorf("期望 1 个参数，但得到 %d", len(script.Parameters))
	}

	// 验证日志配置
	if cfg.Logging.Level != "info" {
		t.Errorf("期望日志级别为 'info'，但得到 '%s'", cfg.Logging.Level)
	}
	if cfg.Logging.Format != "json" {
		t.Errorf("期望日志格式为 'json'，但得到 '%s'", cfg.Logging.Format)
	}
}

func TestLoad_ConfigDefaults(t *testing.T) {
	// 创建最小配置文件
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.yaml")

	configContent := `
server:
  bind_addr: "127.0.0.1:8080"

ssh_hosts:
  - id: "test-host"
    addr: "localhost:22"
    user: "testuser"
    auth_method: "private_key"
    private_key_path: "~/.ssh/id_rsa"
`

	err := os.WriteFile(configPath, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("创建测试配置文件失败: %v", err)
	}

	// 测试配置加载
	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("配置加载失败: %v", err)
	}

	// 验证默认值
	if cfg.Server.LogLevel != "info" {
		t.Errorf("期望默认 LogLevel 为 'info'，但得到 '%s'", cfg.Server.LogLevel)
	}
	if cfg.Server.MaxConcurrent != 32 {
		t.Errorf("期望默认 MaxConcurrent 为 32，但得到 %d", cfg.Server.MaxConcurrent)
	}
	if cfg.Server.RequestTimeout != 30 {
		t.Errorf("期望默认 RequestTimeout 为 30，但得到 %d", cfg.Server.RequestTimeout)
	}
	if cfg.Security.MaxOutputBytes != 1024*1024 {
		t.Errorf("期望默认 MaxOutputBytes 为 1MB，但得到 %d", cfg.Security.MaxOutputBytes)
	}
	if cfg.Security.RateLimitPerMin != 120 {
		t.Errorf("期望默认 RateLimitPerMin 为 120，但得到 %d", cfg.Security.RateLimitPerMin)
	}
	if cfg.Logging.Level != "info" {
		t.Errorf("期望默认日志级别为 'info'，但得到 '%s'", cfg.Logging.Level)
	}
}

func TestLoad_InvalidConfig(t *testing.T) {
	// 测试无效配置文件
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.yaml")

	testCases := []struct {
		name          string
		configContent string
		expectedError string
	}{
		{
			name: "缺少SSH主机",
			configContent: `
server:
  bind_addr: "127.0.0.1:8080"
`,
			expectedError: "配置验证失败: 至少需要配置一个 SSH 主机",
		},
		{
			name: "主机缺少ID",
			configContent: `
server:
  bind_addr: "127.0.0.1:8080"
ssh_hosts:
  - addr: "localhost:22"
    user: "testuser"
`,
			expectedError: "配置验证失败: 第 1 个 SSH 主机缺少 ID",
		},
		{
			name: "主机缺少地址",
			configContent: `
server:
  bind_addr: "127.0.0.1:8080"
ssh_hosts:
  - id: "test-host"
    user: "testuser"
`,
			expectedError: "配置验证失败: 主机 test-host 缺少地址",
		},
		{
			name: "主机缺少用户名",
			configContent: `
server:
  bind_addr: "127.0.0.1:8080"
ssh_hosts:
  - id: "test-host"
    addr: "localhost:22"
`,
			expectedError: "配置验证失败: 主机 test-host 缺少用户名",
		},
		{
			name: "主机缺少认证方式",
			configContent: `
server:
  bind_addr: "127.0.0.1:8080"
ssh_hosts:
  - id: "test-host"
    addr: "localhost:22"
    user: "testuser"
`,
			expectedError: "配置验证失败: 主机 test-host 缺少认证方式",
		},
		{
			name: "私钥认证但缺少私钥路径",
			configContent: `
server:
  bind_addr: "127.0.0.1:8080"
ssh_hosts:
  - id: "test-host"
    addr: "localhost:22"
    user: "testuser"
    auth_method: "private_key"
`,
			expectedError: "配置验证失败: 主机 test-host 使用私钥认证但缺少私钥路径",
		},
		{
			name: "密码认证但缺少密码来源",
			configContent: `
server:
  bind_addr: "127.0.0.1:8080"
ssh_hosts:
  - id: "test-host"
    addr: "localhost:22"
    user: "testuser"
    auth_method: "password"
`,
			expectedError: "配置验证失败: 主机 test-host 使用密码认证但缺少密码来源",
		},
		{
			name: "脚本缺少名称",
			configContent: `
server:
  bind_addr: "127.0.0.1:8080"
ssh_hosts:
  - id: "test-host"
    addr: "localhost:22"
    user: "testuser"
    auth_method: "private_key"
    private_key_path: "~/.ssh/id_rsa"
scripts:
  - template: "echo hello"
`,
			expectedError: "配置验证失败: 第 1 个脚本缺少名称",
		},
		{
			name: "脚本缺少模板",
			configContent: `
server:
  bind_addr: "127.0.0.1:8080"
ssh_hosts:
  - id: "test-host"
    addr: "localhost:22"
    user: "testuser"
    auth_method: "private_key"
    private_key_path: "~/.ssh/id_rsa"
scripts:
  - name: "test-script"
`,
			expectedError: "配置验证失败: 脚本 test-script 缺少模板",
		},
		{
			name: "脚本缺少提示信息",
			configContent: `
server:
  bind_addr: "127.0.0.1:8080"
ssh_hosts:
  - id: "test-host"
    addr: "localhost:22"
    user: "testuser"
    auth_method: "private_key"
    private_key_path: "~/.ssh/id_rsa"
scripts:
  - name: "test-script"
    template: "echo hello"
`,
			expectedError: "配置验证失败: 脚本 test-script 缺少提示信息",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := os.WriteFile(configPath, []byte(tc.configContent), 0644)
			if err != nil {
				t.Fatalf("创建测试配置文件失败: %v", err)
			}

			_, err = Load(configPath)
			if err == nil {
				t.Fatal("期望配置加载失败，但成功了")
			}

			if err.Error() != tc.expectedError {
				t.Errorf("期望错误信息为 '%s'，但得到 '%s'", tc.expectedError, err.Error())
			}
		})
	}
}

func TestLoad_FileNotFound(t *testing.T) {
	_, err := Load("/nonexistent/config.yaml")
	if err == nil {
		t.Fatal("期望配置文件不存在时失败，但成功了")
	}

	expectedError := "读取配置文件失败"
	if err.Error()[:len(expectedError)] != expectedError {
		t.Errorf("期望错误以 '%s' 开头，但得到 '%s'", expectedError, err.Error())
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.yaml")

	// 创建无效的 YAML
	invalidYAML := `
server:
  bind_addr: "127.0.0.1:8080"
  log_level: "debug"
  max_concurrent: 16
    invalid yaml structure
ssh_hosts:
  - id: "test-host"
    addr: "localhost:22"
`

	err := os.WriteFile(configPath, []byte(invalidYAML), 0644)
	if err != nil {
		t.Fatalf("创建测试配置文件失败: %v", err)
	}

	_, err = Load(configPath)
	if err == nil {
		t.Fatal("期望无效 YAML 解析失败，但成功了")
	}

	expectedError := "解析配置文件失败"
	if err.Error()[:len(expectedError)] != expectedError {
		t.Errorf("期望错误以 '%s' 开头，但得到 '%s'", expectedError, err.Error())
	}
}

func TestExpandPaths(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.yaml")

	configContent := `
server:
  bind_addr: "127.0.0.1:8080"
ssh_hosts:
  - id: "test-host"
    addr: "localhost:22"
    user: "testuser"
    auth_method: "private_key"
    private_key_path: "~/.ssh/id_rsa"
    known_hosts: "~/.ssh/known_hosts"
`

	err := os.WriteFile(configPath, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("创建测试配置文件失败: %v", err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("配置加载失败: %v", err)
	}

	host := cfg.SSHHosts[0]
	homeDir, _ := os.UserHomeDir()
	expectedKeyPath := filepath.Join(homeDir, ".ssh", "id_rsa")
	expectedKnownHostsPath := filepath.Join(homeDir, ".ssh", "known_hosts")

	if host.PrivateKeyPath != expectedKeyPath {
		t.Errorf("期望私钥路径为 '%s'，但得到 '%s'", expectedKeyPath, host.PrivateKeyPath)
	}
	if host.KnownHosts != expectedKnownHostsPath {
		t.Errorf("期望 known_hosts 路径为 '%s'，但得到 '%s'", expectedKnownHostsPath, host.KnownHosts)
	}
}

func BenchmarkLoad(b *testing.B) {
	tempDir := b.TempDir()
	configPath := filepath.Join(tempDir, "config.yaml")

	configContent := `
server:
  bind_addr: "127.0.0.1:8080"
  log_level: "debug"
  max_concurrent: 16
  request_timeout_sec: 60

ssh_hosts:
  - id: "test-host"
    addr: "localhost:22"
    user: "testuser"
    auth_method: "private_key"
    private_key_path: "~/.ssh/id_rsa"
    known_hosts: "~/.ssh/known_hosts"
    max_sessions: 4

security:
  default_shell: false
  allow_shell_for: ["bash", "sh"]
  denylist_exact: ["rm", "dd", "mkfs"]
  allowlist_exact: ["ls", "cat", "grep", "find"]
  working_dir_allow: ["/tmp", "/var/log"]
  max_output_bytes: 1048576

scripts:
  - name: "test-script"
    description: "Test script"
    prompt: "This is a test script"
    template: "echo 'Hello {name}'"
    parameters:
      - name: "name"
        type: "string"
        required: true
        default: "World"
        description: "Name parameter"
    allowed_hosts: ["*"]
    timeout_sec: 10
    use_shell: true

logging:
  level: "info"
  format: "json"
  output: "stdout"
`

	err := os.WriteFile(configPath, []byte(configContent), 0644)
	if err != nil {
		b.Fatalf("创建测试配置文件失败: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := Load(configPath)
		if err != nil {
			b.Fatalf("基准测试失败: %v", err)
		}
	}
}
