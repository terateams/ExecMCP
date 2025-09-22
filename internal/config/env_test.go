package config

import (
	"os"
	"testing"
)

func TestApplyEnvOverrides_ServerConfig(t *testing.T) {
	// 设置环境变量
	testEnvVars := map[string]string{
		"EXECMCP_SERVER_BIND_ADDR":           "0.0.0.0:8080",
		"EXECMCP_SERVER_LOG_LEVEL":           "debug",
		"EXECMCP_SERVER_MAX_CONCURRENT":      "64",
		"EXECMCP_SERVER_REQUEST_TIMEOUT_SEC": "60",
		"EXECMCP_SERVER_AUTH_TOKEN":          "test-token",
	}

	// 保存原始环境变量
	originalEnv := make(map[string]string)
	for key, value := range testEnvVars {
		originalEnv[key] = os.Getenv(key)
		os.Setenv(key, value)
	}

	// 测试后恢复环境变量
	defer func() {
		for key, value := range originalEnv {
			if value == "" {
				os.Unsetenv(key)
			} else {
				os.Setenv(key, value)
			}
		}
	}()

	config := &Config{}
	applyEnvOverrides(config)

	// 验证环境变量覆盖
	if config.Server.BindAddr != "0.0.0.0:8080" {
		t.Errorf("期望 BindAddr = '0.0.0.0:8080', 得到 '%s'", config.Server.BindAddr)
	}
	if config.Server.LogLevel != "debug" {
		t.Errorf("期望 LogLevel = 'debug', 得到 '%s'", config.Server.LogLevel)
	}
	if config.Server.MaxConcurrent != 64 {
		t.Errorf("期望 MaxConcurrent = 64, 得到 %d", config.Server.MaxConcurrent)
	}
	if config.Server.RequestTimeout != 60 {
		t.Errorf("期望 RequestTimeout = 60, 得到 %d", config.Server.RequestTimeout)
	}
	if config.Server.AuthToken != "test-token" {
		t.Errorf("期望 AuthToken = 'test-token', 得到 '%s'", config.Server.AuthToken)
	}
}

func TestApplyEnvOverrides_SecurityConfig(t *testing.T) {
	testEnvVars := map[string]string{
		"EXECMCP_SECURITY_DEFAULT_SHELL":      "true",
		"EXECMCP_SECURITY_MAX_OUTPUT_BYTES":   "2048000",
		"EXECMCP_SECURITY_ENABLE_PTY":         "true",
		"EXECMCP_SECURITY_RATE_LIMIT_PER_MIN": "240",
	}

	originalEnv := make(map[string]string)
	for key, value := range testEnvVars {
		originalEnv[key] = os.Getenv(key)
		os.Setenv(key, value)
	}

	defer func() {
		for key, value := range originalEnv {
			if value == "" {
				os.Unsetenv(key)
			} else {
				os.Setenv(key, value)
			}
		}
	}()

	config := &Config{}
	applyEnvOverrides(config)

	if !config.Security.DefaultShell {
		t.Error("期望 DefaultShell = true")
	}
	if config.Security.MaxOutputBytes != 2048000 {
		t.Errorf("期望 MaxOutputBytes = 2048000, 得到 %d", config.Security.MaxOutputBytes)
	}
	if !config.Security.EnablePTY {
		t.Error("期望 EnablePTY = true")
	}
	if config.Security.RateLimitPerMin != 240 {
		t.Errorf("期望 RateLimitPerMin = 240, 得到 %d", config.Security.RateLimitPerMin)
	}
}

func TestApplyEnvOverrides_LoggingConfig(t *testing.T) {
	testEnvVars := map[string]string{
		"EXECMCP_LOGGING_LEVEL":       "warn",
		"EXECMCP_LOGGING_FORMAT":      "text",
		"EXECMCP_LOGGING_OUTPUT":      "file",
		"EXECMCP_LOGGING_FILE_PATH":   "/var/log/execmcp.log",
		"EXECMCP_LOGGING_MAX_SIZE":    "100MB",
		"EXECMCP_LOGGING_MAX_BACKUPS": "10",
		"EXECMCP_LOGGING_MAX_AGE":     "30",
	}

	originalEnv := make(map[string]string)
	for key, value := range testEnvVars {
		originalEnv[key] = os.Getenv(key)
		os.Setenv(key, value)
	}

	defer func() {
		for key, value := range originalEnv {
			if value == "" {
				os.Unsetenv(key)
			} else {
				os.Setenv(key, value)
			}
		}
	}()

	config := &Config{}
	applyEnvOverrides(config)

	if config.Logging.Level != "warn" {
		t.Errorf("期望 Level = 'warn', 得到 '%s'", config.Logging.Level)
	}
	if config.Logging.Format != "text" {
		t.Errorf("期望 Format = 'text', 得到 '%s'", config.Logging.Format)
	}
	if config.Logging.Output != "file" {
		t.Errorf("期望 Output = 'file', 得到 '%s'", config.Logging.Output)
	}
	if config.Logging.FilePath != "/var/log/execmcp.log" {
		t.Errorf("期望 FilePath = '/var/log/execmcp.log', 得到 '%s'", config.Logging.FilePath)
	}
	if config.Logging.MaxSize != "100MB" {
		t.Errorf("期望 MaxSize = '100MB', 得到 '%s'", config.Logging.MaxSize)
	}
	if config.Logging.MaxBackups != 10 {
		t.Errorf("期望 MaxBackups = 10, 得到 %d", config.Logging.MaxBackups)
	}
	if config.Logging.MaxAge != 30 {
		t.Errorf("期望 MaxAge = 30, 得到 %d", config.Logging.MaxAge)
	}
}

func TestApplyEnvOverrides_SSHHost(t *testing.T) {
	// 测试添加新的SSH主机
	os.Setenv("EXECMCP_SSH_HOST", "test-host:192.168.1.100:root:password:secret123")
	defer os.Unsetenv("EXECMCP_SSH_HOST")

	config := &Config{
		SSHHosts: []SSHHost{
			{
				ID:         "existing-host",
				Addr:       "localhost:22",
				User:       "user",
				AuthMethod: "private_key",
			},
		},
	}

	applyEnvOverrides(config)

	// 验证新主机被添加
	found := false
	for _, host := range config.SSHHosts {
		if host.ID == "test-host" {
			found = true
			if host.Addr != "192.168.1.100" {
				t.Errorf("期望 Addr = '192.168.1.100', 得到 '%s'", host.Addr)
			}
			if host.User != "root" {
				t.Errorf("期望 User = 'root', 得到 '%s'", host.User)
			}
			if host.AuthMethod != "password" {
				t.Errorf("期望 AuthMethod = 'password', 得到 '%s'", host.AuthMethod)
			}
			if host.Password != "secret123" {
				t.Errorf("期望 Password = 'secret123', 得到 '%s'", host.Password)
			}
			break
		}
	}

	if !found {
		t.Error("期望找到新添加的SSH主机 'test-host'")
	}

	// 验证现有主机仍然存在
	foundExisting := false
	for _, host := range config.SSHHosts {
		if host.ID == "existing-host" {
			foundExisting = true
			break
		}
	}

	if !foundExisting {
		t.Error("期望现有主机 'existing-host' 仍然存在")
	}

	// 测试替换现有主机
	os.Setenv("EXECMCP_SSH_HOST", "existing-host:192.168.1.200:admin:private_key:/path/to/key")
	defer os.Unsetenv("EXECMCP_SSH_HOST")

	config = &Config{
		SSHHosts: []SSHHost{
			{
				ID:         "existing-host",
				Addr:       "localhost:22",
				User:       "user",
				AuthMethod: "private_key",
			},
		},
	}

	applyEnvOverrides(config)

	// 验证主机被替换
	replacedHost := config.SSHHosts[0]
	if replacedHost.ID != "existing-host" {
		t.Errorf("期望 ID = 'existing-host', 得到 '%s'", replacedHost.ID)
	}
	if replacedHost.Addr != "192.168.1.200" {
		t.Errorf("期望 Addr = '192.168.1.200', 得到 '%s'", replacedHost.Addr)
	}
	if replacedHost.User != "admin" {
		t.Errorf("期望 User = 'admin', 得到 '%s'", replacedHost.User)
	}
	if replacedHost.PrivateKeyPath != "/path/to/key" {
		t.Errorf("期望 PrivateKeyPath = '/path/to/key', 得到 '%s'", replacedHost.PrivateKeyPath)
	}
}

func TestApplyEnvOverrides_SecurityRules(t *testing.T) {
	testEnvVars := map[string]string{
		"EXECMCP_SECURITY_DENYLIST_EXACT":    "rm,dd,shutdown",
		"EXECMCP_SECURITY_ALLOWLIST_EXACT":   "echo,ls,pwd",
		"EXECMCP_SECURITY_WORKING_DIR_ALLOW": "/tmp,/var/log",
		"EXECMCP_SECURITY_ALLOW_SHELL_FOR":   "bash,zsh",
	}

	originalEnv := make(map[string]string)
	for key, value := range testEnvVars {
		originalEnv[key] = os.Getenv(key)
		os.Setenv(key, value)
	}

	defer func() {
		for key, value := range originalEnv {
			if value == "" {
				os.Unsetenv(key)
			} else {
				os.Setenv(key, value)
			}
		}
	}()

	config := &Config{
		Security: SecurityConfig{
			DenylistExact:   []string{"existing-deny"},
			AllowlistExact:  []string{"existing-allow"},
			WorkingDirAllow: []string{"/existing"},
			AllowShellFor:   []string{"existing-shell"},
		},
	}

	applyEnvOverrides(config)

	// 验证新的规则被追加
	expectedDenylist := []string{"existing-deny", "rm", "dd", "shutdown"}
	if !equalStringSlices(config.Security.DenylistExact, expectedDenylist) {
		t.Errorf("期望 DenylistExact = %v, 得到 %v", expectedDenylist, config.Security.DenylistExact)
	}

	expectedAllowlist := []string{"existing-allow", "echo", "ls", "pwd"}
	if !equalStringSlices(config.Security.AllowlistExact, expectedAllowlist) {
		t.Errorf("期望 AllowlistExact = %v, 得到 %v", expectedAllowlist, config.Security.AllowlistExact)
	}

	expectedWorkingDirs := []string{"/existing", "/tmp", "/var/log"}
	if !equalStringSlices(config.Security.WorkingDirAllow, expectedWorkingDirs) {
		t.Errorf("期望 WorkingDirAllow = %v, 得到 %v", expectedWorkingDirs, config.Security.WorkingDirAllow)
	}

	expectedShellAllow := []string{"existing-shell", "bash", "zsh"}
	if !equalStringSlices(config.Security.AllowShellFor, expectedShellAllow) {
		t.Errorf("期望 AllowShellFor = %v, 得到 %v", expectedShellAllow, config.Security.AllowShellFor)
	}
}

func TestApplyEnvOverrides_InvalidValues(t *testing.T) {
	// 测试无效的环境变量值
	testEnvVars := map[string]string{
		"EXECMCP_SERVER_MAX_CONCURRENT":     "invalid",
		"EXECMCP_SECURITY_DEFAULT_SHELL":    "not-a-boolean",
		"EXECMCP_SECURITY_MAX_OUTPUT_BYTES": "invalid",
		"EXECMCP_LOGGING_MAX_BACKUPS":       "invalid",
	}

	originalEnv := make(map[string]string)
	for key, value := range testEnvVars {
		originalEnv[key] = os.Getenv(key)
		os.Setenv(key, value)
	}

	defer func() {
		for key, value := range originalEnv {
			if value == "" {
				os.Unsetenv(key)
			} else {
				os.Setenv(key, value)
			}
		}
	}()

	config := &Config{
		Server: ServerConfig{
			MaxConcurrent: 32,
		},
		Security: SecurityConfig{
			DefaultShell:   false,
			MaxOutputBytes: 1024,
		},
		Logging: LoggingConfig{
			MaxBackups: 5,
		},
	}

	// 确保不会因为无效值而panic
	applyEnvOverrides(config)

	// 验证无效值不会覆盖现有配置
	if config.Server.MaxConcurrent != 32 {
		t.Errorf("期望 MaxConcurrent 保持原值 32, 得到 %d", config.Server.MaxConcurrent)
	}
	if config.Security.DefaultShell != false {
		t.Errorf("期望 DefaultShell 保持原值 false, 得到 %t", config.Security.DefaultShell)
	}
	if config.Security.MaxOutputBytes != 1024 {
		t.Errorf("期望 MaxOutputBytes 保持原值 1024, 得到 %d", config.Security.MaxOutputBytes)
	}
	if config.Logging.MaxBackups != 5 {
		t.Errorf("期望 MaxBackups 保持原值 5, 得到 %d", config.Logging.MaxBackups)
	}
}

func TestApplyEnvOverrides_NoEnvVars(t *testing.T) {
	// 确保没有测试相关的环境变量
	envVars := []string{
		"EXECMCP_SERVER_BIND_ADDR",
		"EXECMCP_SECURITY_DEFAULT_SHELL",
		"EXECMCP_LOGGING_LEVEL",
		"EXECMCP_SSH_HOST",
	}

	originalEnv := make(map[string]string)
	for _, key := range envVars {
		originalEnv[key] = os.Getenv(key)
		os.Unsetenv(key)
	}

	defer func() {
		for key, value := range originalEnv {
			if value == "" {
				os.Unsetenv(key)
			} else {
				os.Setenv(key, value)
			}
		}
	}()

	config := &Config{
		Server: ServerConfig{
			BindAddr: "original-value",
		},
		Security: SecurityConfig{
			DefaultShell: false,
		},
		Logging: LoggingConfig{
			Level: "original-level",
		},
		SSHHosts: []SSHHost{
			{
				ID: "original-host",
			},
		},
	}

	applyEnvOverrides(config)

	// 验证配置保持不变
	if config.Server.BindAddr != "original-value" {
		t.Errorf("期望 BindAddr 保持原值 'original-value', 得到 '%s'", config.Server.BindAddr)
	}
	if config.Security.DefaultShell != false {
		t.Errorf("期望 DefaultShell 保持原值 false, 得到 %t", config.Security.DefaultShell)
	}
	if config.Logging.Level != "original-level" {
		t.Errorf("期望 Level 保持原值 'original-level', 得到 '%s'", config.Logging.Level)
	}
	if len(config.SSHHosts) != 1 || config.SSHHosts[0].ID != "original-host" {
		t.Errorf("期望 SSHHosts 保持原值，得到 %v", config.SSHHosts)
	}
}

// equalStringSlices 比较两个字符串切片是否相等
func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
