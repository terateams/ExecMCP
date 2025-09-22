package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config 主配置结构
type Config struct {
	Server   ServerConfig   `yaml:"server"`
	SSHHosts []SSHHost      `yaml:"ssh_hosts"`
	Security SecurityConfig `yaml:"security"`
	Scripts  []ScriptConfig `yaml:"scripts"`
	Logging  LoggingConfig  `yaml:"logging"`
}

// ServerConfig 服务器配置
type ServerConfig struct {
	BindAddr       string `yaml:"bind_addr"`
	LogLevel       string `yaml:"log_level"`
	MaxConcurrent  int    `yaml:"max_concurrent"`
	RequestTimeout int    `yaml:"request_timeout_sec"`
	AuthToken      string `yaml:"auth_token"`
}

// SSHHost SSH主机配置
type SSHHost struct {
	ID             string `yaml:"id"`
	Addr           string `yaml:"addr"`
	User           string `yaml:"user"`
	AuthMethod     string `yaml:"auth_method"`
	PrivateKeyPath string `yaml:"private_key_path"`
	Password       string `yaml:"password"`
	KnownHosts     string `yaml:"known_hosts"`
	ConnectTimeout int    `yaml:"connect_timeout_sec"`
	KeepaliveSec   int    `yaml:"keepalive_sec"`
	MaxSessions    int    `yaml:"max_sessions"`
}

// SecurityConfig 安全配置
type SecurityConfig struct {
	DefaultShell    bool     `yaml:"default_shell"`
	AllowShellFor   []string `yaml:"allow_shell_for"`
	DenylistExact   []string `yaml:"denylist_exact"`
	DenylistRegex   []string `yaml:"denylist_regex"`
	ArgDenyRegex    []string `yaml:"arg_deny_regex"`
	AllowlistExact  []string `yaml:"allowlist_exact"`
	AllowlistRegex  []string `yaml:"allowlist_regex"`
	WorkingDirAllow []string `yaml:"working_dir_allow"`
	MaxOutputBytes  int64    `yaml:"max_output_bytes"`
	EnablePTY       bool     `yaml:"enable_pty"`
	RateLimitPerMin int      `yaml:"rate_limit_per_min"`
}

// ScriptConfig 脚本配置
type ScriptConfig struct {
	Name         string            `yaml:"name"`
	Description  string            `yaml:"description"`
	Prompt       string            `yaml:"prompt"`
	Template     string            `yaml:"template"`
	Parameters   []ScriptParameter `yaml:"parameters"`
	AllowedHosts []string          `yaml:"allowed_hosts"`
	TimeoutSec   int               `yaml:"timeout_sec"`
	UseShell     bool              `yaml:"use_shell"`
	WorkingDir   string            `yaml:"working_dir"`
}

// ScriptParameter 脚本参数定义
type ScriptParameter struct {
	Name        string      `yaml:"name"`
	Type        string      `yaml:"type"`
	Required    bool        `yaml:"required"`
	Default     interface{} `yaml:"default"`
	Description string      `yaml:"description"`
	Validation  string      `yaml:"validation"`
}

// LoggingConfig 日志配置
type LoggingConfig struct {
	Level      string `yaml:"level"`
	Format     string `yaml:"format"`
	Output     string `yaml:"output"`
	FilePath   string `yaml:"file_path"`
	MaxSize    string `yaml:"max_size"`
	MaxBackups int    `yaml:"max_backups"`
	MaxAge     int    `yaml:"max_age"`
}

// Load 加载配置文件
func Load(path string) (*Config, error) {
	// 读取配置文件
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件失败: %w", err)
	}

	// 解析 YAML
	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("解析配置文件失败: %w", err)
	}

	// 设置默认值
	setDefaults(&config)

	// 应用环境变量覆盖
	applyEnvOverrides(&config)

	// 验证配置
	if err := validate(&config); err != nil {
		return nil, fmt.Errorf("配置验证失败: %w", err)
	}

	// 展开路径中的 ~
	expandPaths(&config)

	return &config, nil
}

// setDefaults 设置默认值
func setDefaults(config *Config) {
	if config.Server.BindAddr == "" {
		config.Server.BindAddr = "127.0.0.1:7458"
	}
	if config.Server.LogLevel == "" {
		config.Server.LogLevel = "info"
	}
	if config.Server.MaxConcurrent == 0 {
		config.Server.MaxConcurrent = 32
	}
	if config.Server.RequestTimeout == 0 {
		config.Server.RequestTimeout = 30
	}
	if config.Security.MaxOutputBytes == 0 {
		config.Security.MaxOutputBytes = 1024 * 1024 // 1MB
	}
	if config.Security.RateLimitPerMin == 0 {
		config.Security.RateLimitPerMin = 120
	}
	if config.Logging.Level == "" {
		config.Logging.Level = "info"
	}
	if config.Logging.Format == "" {
		config.Logging.Format = "json"
	}
	if config.Logging.Output == "" {
		config.Logging.Output = "stdout"
	}
}

// validate 验证配置
func validate(config *Config) error {
	if len(config.SSHHosts) == 0 {
		return fmt.Errorf("至少需要配置一个 SSH 主机")
	}

	for i, host := range config.SSHHosts {
		if host.ID == "" {
			return fmt.Errorf("第 %d 个 SSH 主机缺少 ID", i+1)
		}
		if host.Addr == "" {
			return fmt.Errorf("主机 %s 缺少地址", host.ID)
		}
		if host.User == "" {
			return fmt.Errorf("主机 %s 缺少用户名", host.ID)
		}
		if host.AuthMethod == "" {
			return fmt.Errorf("主机 %s 缺少认证方式", host.ID)
		}
		if host.AuthMethod == "private_key" && host.PrivateKeyPath == "" {
			return fmt.Errorf("主机 %s 使用私钥认证但缺少私钥路径", host.ID)
		}
		if host.AuthMethod == "password" && host.Password == "" {
			return fmt.Errorf("主机 %s 使用密码认证但缺少密码", host.ID)
		}
	}

	// 验证脚本配置
	for i, script := range config.Scripts {
		if script.Name == "" {
			return fmt.Errorf("第 %d 个脚本缺少名称", i+1)
		}
		if script.Template == "" {
			return fmt.Errorf("脚本 %s 缺少模板", script.Name)
		}
		if script.Prompt == "" {
			return fmt.Errorf("脚本 %s 缺少提示信息", script.Name)
		}
	}

	return nil
}

// expandPaths 展开路径中的 ~
func expandPaths(config *Config) {
	for i := range config.SSHHosts {
		host := &config.SSHHosts[i]
		host.PrivateKeyPath = expandPath(host.PrivateKeyPath)
		host.KnownHosts = expandPath(host.KnownHosts)
	}
}

// expandPath 展开路径中的 ~
func expandPath(path string) string {
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err == nil {
			return filepath.Join(home, path[2:])
		}
	}
	return path
}

// applyEnvOverrides 应用环境变量覆盖
func applyEnvOverrides(config *Config) {
	// 服务器配置环境变量
	if addr := os.Getenv("EXECMCP_SERVER_BIND_ADDR"); addr != "" {
		config.Server.BindAddr = addr
	}
	if level := os.Getenv("EXECMCP_SERVER_LOG_LEVEL"); level != "" {
		config.Server.LogLevel = level
	}
	if max := os.Getenv("EXECMCP_SERVER_MAX_CONCURRENT"); max != "" {
		if val, err := strconv.Atoi(max); err == nil {
			config.Server.MaxConcurrent = val
		}
	}
	if timeout := os.Getenv("EXECMCP_SERVER_REQUEST_TIMEOUT_SEC"); timeout != "" {
		if val, err := strconv.Atoi(timeout); err == nil {
			config.Server.RequestTimeout = val
		}
	}
	if token := os.Getenv("EXECMCP_SERVER_AUTH_TOKEN"); token != "" {
		config.Server.AuthToken = token
	}

	// 安全配置环境变量
	if shell := os.Getenv("EXECMCP_SECURITY_DEFAULT_SHELL"); shell != "" {
		if val, err := strconv.ParseBool(shell); err == nil {
			config.Security.DefaultShell = val
		}
	}
	if maxOutput := os.Getenv("EXECMCP_SECURITY_MAX_OUTPUT_BYTES"); maxOutput != "" {
		if val, err := strconv.ParseInt(maxOutput, 10, 64); err == nil {
			config.Security.MaxOutputBytes = val
		}
	}
	if pty := os.Getenv("EXECMCP_SECURITY_ENABLE_PTY"); pty != "" {
		if val, err := strconv.ParseBool(pty); err == nil {
			config.Security.EnablePTY = val
		}
	}
	if rateLimit := os.Getenv("EXECMCP_SECURITY_RATE_LIMIT_PER_MIN"); rateLimit != "" {
		if val, err := strconv.Atoi(rateLimit); err == nil {
			config.Security.RateLimitPerMin = val
		}
	}

	// 日志配置环境变量
	if level := os.Getenv("EXECMCP_LOGGING_LEVEL"); level != "" {
		config.Logging.Level = level
	}
	if format := os.Getenv("EXECMCP_LOGGING_FORMAT"); format != "" {
		config.Logging.Format = format
	}
	if output := os.Getenv("EXECMCP_LOGGING_OUTPUT"); output != "" {
		config.Logging.Output = output
	}
	if filePath := os.Getenv("EXECMCP_LOGGING_FILE_PATH"); filePath != "" {
		config.Logging.FilePath = filePath
	}
	if maxSize := os.Getenv("EXECMCP_LOGGING_MAX_SIZE"); maxSize != "" {
		config.Logging.MaxSize = maxSize
	}
	if maxBackups := os.Getenv("EXECMCP_LOGGING_MAX_BACKUPS"); maxBackups != "" {
		if val, err := strconv.Atoi(maxBackups); err == nil {
			config.Logging.MaxBackups = val
		}
	}
	if maxAge := os.Getenv("EXECMCP_LOGGING_MAX_AGE"); maxAge != "" {
		if val, err := strconv.Atoi(maxAge); err == nil {
			config.Logging.MaxAge = val
		}
	}

	// 动态添加SSH主机配置
	if sshHost := os.Getenv("EXECMCP_SSH_HOST"); sshHost != "" {
		// 解析SSH主机配置，格式: id:addr:user:auth_method[:private_key_path|:password]
		parts := strings.Split(sshHost, ":")
		if len(parts) >= 4 {
			newHost := SSHHost{
				ID:         parts[0],
				Addr:       parts[1],
				User:       parts[2],
				AuthMethod: parts[3],
			}

			if len(parts) > 4 {
				if parts[3] == "private_key" {
					newHost.PrivateKeyPath = parts[4]
				} else if parts[3] == "password" {
					newHost.Password = parts[4]
				}
			}

			// 检查是否已存在相同ID的主机，如果存在则替换
			found := false
			for i, host := range config.SSHHosts {
				if host.ID == newHost.ID {
					config.SSHHosts[i] = newHost
					found = true
					break
				}
			}

			// 如果不存在则添加
			if !found {
				config.SSHHosts = append(config.SSHHosts, newHost)
			}
		}
	}

	// 动态添加安全规则
	if denylist := os.Getenv("EXECMCP_SECURITY_DENYLIST_EXACT"); denylist != "" {
		config.Security.DenylistExact = append(config.Security.DenylistExact, strings.Split(denylist, ",")...)
	}
	if allowlist := os.Getenv("EXECMCP_SECURITY_ALLOWLIST_EXACT"); allowlist != "" {
		config.Security.AllowlistExact = append(config.Security.AllowlistExact, strings.Split(allowlist, ",")...)
	}
	if workingDirs := os.Getenv("EXECMCP_SECURITY_WORKING_DIR_ALLOW"); workingDirs != "" {
		config.Security.WorkingDirAllow = append(config.Security.WorkingDirAllow, strings.Split(workingDirs, ",")...)
	}
	if shellAllow := os.Getenv("EXECMCP_SECURITY_ALLOW_SHELL_FOR"); shellAllow != "" {
		config.Security.AllowShellFor = append(config.Security.AllowShellFor, strings.Split(shellAllow, ",")...)
	}
}
