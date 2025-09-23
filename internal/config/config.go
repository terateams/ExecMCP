// Package config 提供 ExecMCP 服务器的配置管理功能
// 支持从 YAML 文件加载配置，应用环境变量覆盖，并提供配置验证
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config 主配置结构体，包含 ExecMCP 服务器的所有配置项
// 这是整个配置系统的根结构，通过 YAML 文件进行配置
type Config struct {
	Server   ServerConfig   `yaml:"server"`    // 服务器基本配置
	SSHHosts []SSHHost      `yaml:"ssh_hosts"` // SSH 主机连接配置列表
	Security SecurityConfig `yaml:"security"`  // 安全过滤和访问控制配置
	Scripts  []ScriptConfig `yaml:"scripts"`   // 预定义脚本配置
	Logging  LoggingConfig  `yaml:"logging"`   // 日志记录配置
}

// ServerConfig 服务器基本配置
// 定义 MCP 服务器的网络绑定、并发限制、超时等基本参数
type ServerConfig struct {
	BindAddr       string `yaml:"bind_addr"`        // 服务器监听地址，格式为 "host:port"
	LogLevel       string `yaml:"log_level"`        // 日志级别：debug, info, warn, error
	MaxConcurrent  int    `yaml:"max_concurrent"`   // 最大并发请求数，超过限制的请求将被排队或拒绝
	RequestTimeout int    `yaml:"request_timeout_sec"` // 单个请求的超时时间（秒）
	AuthToken      string `yaml:"auth_token"`       // 认证令牌，用于客户端身份验证
}

// SSHHost SSH 主机连接配置
// 定义远程主机的连接信息、认证方式和连接参数
type SSHHost struct {
	ID             string `yaml:"id"`                 // 主机唯一标识符，用于在请求中指定目标主机
	Addr           string `yaml:"addr"`               // 主机地址，格式为 "host:port"
	User           string `yaml:"user"`               // SSH 登录用户名
	AuthMethod     string `yaml:"auth_method"`        // 认证方式：private_key 或 password
	PrivateKeyPath string `yaml:"private_key_path"`   // 私钥文件路径（支持 ~ 展开）
	Password       string `yaml:"password"`           // 登录密码（仅用于密码认证）
	KnownHosts     string `yaml:"known_hosts"`       // known_hosts 文件路径，用于主机密钥验证
	ConnectTimeout int    `yaml:"connect_timeout_sec"` // SSH 连接超时时间（秒）
	KeepaliveSec   int    `yaml:"keepalive_sec"`     // SSH keepalive 间隔时间（秒）
	MaxSessions    int    `yaml:"max_sessions"`      // 该主机的最大并发会话数
}

// SecurityConfig 安全过滤和访问控制配置
// 实现多层安全过滤机制，包括命令黑名单、白名单、参数验证等
type SecurityConfig struct {
	DefaultShell    bool     `yaml:"default_shell"`     // 默认是否使用 shell 执行命令（false=直接执行，更安全）
	AllowShellFor   []string `yaml:"allow_shell_for"`    // 允许使用 shell 的命令列表
	DenylistExact   []string `yaml:"denylist_exact"`    // 精确匹配的黑名单命令（如 rm, dd, mkfs 等）
	DenylistRegex   []string `yaml:"denylist_regex"`    // 正则表达式黑名单（阻止危险命令模式）
	ArgDenyRegex    []string `yaml:"arg_deny_regex"`     // 参数正则黑名单（阻止危险参数如 --force）
	AllowlistExact  []string `yaml:"allowlist_exact"`   // 精确匹配的白名单命令（允许的安全命令）
	AllowlistRegex  []string `yaml:"allowlist_regex"`   // 正则表达式白名单（允许的命令模式）
	WorkingDirAllow []string `yaml:"working_dir_allow"`  // 允许的工作目录列表（防止目录遍历攻击）
	MaxOutputBytes  int64    `yaml:"max_output_bytes"`   // 命令输出最大字节数（防止内存耗尽）
	EnablePTY       bool     `yaml:"enable_pty"`        // 是否启用伪终端（某些交互式命令需要）
	RateLimitPerMin int      `yaml:"rate_limit_per_min"` // 每分钟每个主机的请求限制
}

// ScriptConfig 预定义脚本配置
// 定义可重用的命令模板，支持参数替换和默认值
type ScriptConfig struct {
	Name         string            `yaml:"name"`          // 脚本唯一标识符
	Description  string            `yaml:"description"`   // 脚本功能描述
	Prompt       string            `yaml:"prompt"`        // 向用户显示的提示信息
	Template     string            `yaml:"template"`      // 命令模板，支持 {parameter} 占位符
	Parameters   []ScriptParameter `yaml:"parameters"`    // 脚本参数定义
	AllowedHosts []string          `yaml:"allowed_hosts"`  // 允许执行此脚本的主机列表（* 表示所有主机）
	TimeoutSec   int               `yaml:"timeout_sec"`   // 脚本执行超时时间（秒）
	UseShell     bool              `yaml:"use_shell"`     // 是否使用 shell 执行脚本
	WorkingDir   string            `yaml:"working_dir"`   // 脚本执行的工作目录
}

// ScriptParameter 脚本参数定义
// 定义脚本模板中可用的参数及其验证规则
type ScriptParameter struct {
	Name        string      `yaml:"name"`         // 参数名称，必须与模板中的占位符匹配
	Type        string      `yaml:"type"`         // 参数类型：string, integer, boolean, float
	Required    bool        `yaml:"required"`     // 是否为必需参数
	Default     interface{} `yaml:"default"`      // 参数默认值（可选）
	Description string      `yaml:"description"`  // 参数说明
	Validation  string      `yaml:"validation"`   // 参数验证正则表达式（可选）
}

// LoggingConfig 日志记录配置
// 控制日志的级别、格式、输出位置和轮转策略
type LoggingConfig struct {
	Level      string `yaml:"level"`       // 日志级别：debug, info, warn, error, fatal
	Format     string `yaml:"format"`      // 日志格式：json 或 text
	Output     string `yaml:"output"`      // 输出目标：stdout, stderr, file
	FilePath   string `yaml:"file_path"`   // 文件输出路径（当 output 为 file 时使用）
	MaxSize    string `yaml:"max_size"`    // 单个日志文件最大大小（如 100MB, 1GB）
	MaxBackups int    `yaml:"max_backups"` // 保留的旧日志文件数量
	MaxAge     int    `yaml:"max_age"`     // 日志文件保留天数
}

// Load 从指定路径加载配置文件并完成所有配置处理步骤
//
// 处理流程：
// 1. 读取 YAML 配置文件
// 2. 解析 YAML 内容到 Config 结构体
// 3. 设置各项配置的默认值
// 4. 应用环境变量覆盖（方便容器化部署）
// 5. 验证配置的完整性和正确性
// 6. 展开路径中的 ~ 为用户主目录
//
// 参数：
//   path - 配置文件的路径
//
// 返回值：
//   *Config - 解析完成的配置对象
//   error - 加载过程中的错误，包含详细的错误信息
func Load(path string) (*Config, error) {
	// 读取配置文件内容
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件失败: %w", err)
	}

	// 解析 YAML 内容到配置结构体
	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("解析配置文件失败: %w", err)
	}

	// 设置默认值，确保未配置的项有合理的默认值
	setDefaults(&config)

	// 应用环境变量覆盖，支持运行时配置调整
	applyEnvOverrides(&config)

	// 验证配置的完整性和正确性
	if err := validate(&config); err != nil {
		return nil, fmt.Errorf("配置验证失败: %w", err)
	}

	// 展开路径中的 ~ 为用户主目录路径
	expandPaths(&config)

	return &config, nil
}

// setDefaults 为配置项设置合理的默认值
// 确保即使用户未在配置文件中指定某些选项，系统也能正常运行
func setDefaults(config *Config) {
	// 服务器配置默认值
	if config.Server.BindAddr == "" {
		config.Server.BindAddr = "127.0.0.1:7458" // 默认监听本地端口 7458
	}
	if config.Server.LogLevel == "" {
		config.Server.LogLevel = "info" // 默认日志级别为 info
	}
	if config.Server.MaxConcurrent == 0 {
		config.Server.MaxConcurrent = 32 // 默认最大并发 32 个请求
	}
	if config.Server.RequestTimeout == 0 {
		config.Server.RequestTimeout = 30 // 默认请求超时 30 秒
	}

	// 安全配置默认值
	if config.Security.MaxOutputBytes == 0 {
		config.Security.MaxOutputBytes = 1024 * 1024 // 默认最大输出 1MB
	}
	if config.Security.RateLimitPerMin == 0 {
		config.Security.RateLimitPerMin = 120 // 默认每分钟 120 次请求
	}

	// 日志配置默认值
	if config.Logging.Level == "" {
		config.Logging.Level = "info" // 默认日志级别
	}
	if config.Logging.Format == "" {
		config.Logging.Format = "json" // 默认 JSON 格式，便于日志分析
	}
	if config.Logging.Output == "" {
		config.Logging.Output = "stdout" // 默认输出到标准输出
	}
}

// validate 验证配置的完整性和正确性
// 确保所有必需的配置项都已正确设置，避免运行时错误
func validate(config *Config) error {
	// 验证 SSH 主机配置
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

// expandPaths 展开所有 SSH 主机配置中的 ~ 路径
// 将 ~/path 格式的路径转换为完整的绝对路径
func expandPaths(config *Config) {
	for i := range config.SSHHosts {
		host := &config.SSHHosts[i]
		host.PrivateKeyPath = expandPath(host.PrivateKeyPath)
		host.KnownHosts = expandPath(host.KnownHosts)
	}
}

// expandPath 展开单个路径中的 ~ 为用户主目录
// 支持 ~/path 格式的路径，自动转换为用户主目录下的绝对路径
// 如果展开失败，返回原路径
func expandPath(path string) string {
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err == nil {
			return filepath.Join(home, path[2:])
		}
	}
	return path
}

// applyEnvOverrides 应用环境变量覆盖配置
// 支持通过环境变量动态调整配置，便于容器化部署和运行时配置
// 环境变量命名规则：EXECMCP_<SECTION>_<KEY>，全部大写，用下划线分隔
func applyEnvOverrides(config *Config) {
	// 服务器配置环境变量覆盖
	// 格式：EXECMCP_SERVER_<CONFIG_KEY>
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

	// 安全配置环境变量覆盖
	// 格式：EXECMCP_SECURITY_<CONFIG_KEY>
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

	// 日志配置环境变量覆盖
	// 格式：EXECMCP_LOGGING_<CONFIG_KEY>
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
	// 支持通过环境变量动态添加SSH主机，格式：id:addr:user:auth_method[:private_key_path|:password]
	// 示例：EXECMCP_SSH_HOST="server1:192.168.1.100:ubuntu:private_key:/path/to/key"
	if sshHost := os.Getenv("EXECMCP_SSH_HOST"); sshHost != "" {
		parts := strings.Split(sshHost, ":")
		if len(parts) >= 4 {
			newHost := SSHHost{
				ID:         parts[0],
				Addr:       parts[1],
				User:       parts[2],
				AuthMethod: parts[3],
			}

			// 处理认证信息（第5部分）
			if len(parts) > 4 {
				if parts[3] == "private_key" {
					newHost.PrivateKeyPath = parts[4]
				} else if parts[3] == "password" {
					newHost.Password = parts[4]
				}
			}

			// 检查是否已存在相同ID的主机，如果存在则替换，否则添加
			found := false
			for i, host := range config.SSHHosts {
				if host.ID == newHost.ID {
					config.SSHHosts[i] = newHost
					found = true
					break
				}
			}

			// 如果不存在则添加到列表末尾
			if !found {
				config.SSHHosts = append(config.SSHHosts, newHost)
			}
		}
	}

	// 动态添加安全规则
	// 支持通过环境变量扩展安全规则列表，多个值用逗号分隔
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
