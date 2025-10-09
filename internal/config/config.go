// Package config 提供 ExecMCP 服务器的配置管理功能
// 支持从 YAML 文件加载配置，应用环境变量覆盖，并提供配置验证
package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/terateams/ExecMCP/internal/common"
	"gopkg.in/yaml.v3"
)

// Config 主配置结构体，包含 ExecMCP 服务器的所有配置项
// 这是整个配置系统的根结构，通过 YAML 文件进行配置
type Config struct {
	Server           ServerConfig       `yaml:"server"`             // 服务器基本配置
	SSHHosts         []SSHHost          `yaml:"ssh_hosts"`          // SSH 主机连接配置列表
	SSHHostIncludes  []string           `yaml:"ssh_hosts_includes"` // 外部 SSH 主机配置文件
	Security         []SecurityConfig   `yaml:"security"`           // 安全过滤和访问控制配置（按组划分）
	SecurityIncludes []string           `yaml:"security_includes"`  // 外部安全策略配置文件
	Scripts          []ScriptConfig     `yaml:"scripts"`            // 预定义脚本配置
	ScriptIncludes   []string           `yaml:"scripts_includes"`   // 外部脚本配置文件
	Logging          LoggingConfig      `yaml:"logging"`            // 日志记录配置
	Audit            AuditLoggingConfig `yaml:"audit_logging"`      // 安全审计日志配置
	// 以下字段为运行时索引，加速 host / security_group 查询
	securityIndex map[string]*SecurityConfig `yaml:"-"`
	hostIndex     map[string]*SSHHost        `yaml:"-"`
}

// ServerConfig 服务器基本配置
// 定义 MCP 服务器的网络绑定、并发限制、超时等基本参数
type ServerConfig struct {
	BindAddr       string `yaml:"bind_addr"`           // 服务器监听地址，格式为 "host:port"
	PublicBaseURL  string `yaml:"public_base_url"`     // 对外暴露的基础 URL，用于客户端连接
	LogLevel       string `yaml:"log_level"`           // 日志级别：debug, info, warn, error
	MaxConcurrent  int    `yaml:"max_concurrent"`      // 最大并发请求数，超过限制的请求将被排队或拒绝
	RequestTimeout int    `yaml:"request_timeout_sec"` // 单个请求的超时时间（秒）
	AuthToken      string `yaml:"auth_token"`          // 认证令牌，用于客户端身份验证
}

// SSHHost SSH 主机连接配置
// 定义远程主机的连接信息、认证方式和连接参数
type SSHHost struct {
	ID             string   `yaml:"id"`                  // 主机唯一标识符，用于在请求中指定目标主机
	Addr           string   `yaml:"addr"`                // 主机地址，格式为 "host:port"
	User           string   `yaml:"user"`                // SSH 登录用户名
	AuthMethod     string   `yaml:"auth_method"`         // 认证方式：private_key 或 password
	PrivateKeyPath string   `yaml:"private_key_path"`    // 私钥文件路径（支持 ~ 展开）
	Password       string   `yaml:"password"`            // 登录密码（仅用于密码认证，建议仅在开发环境使用）
	PasswordEnv    string   `yaml:"password_env"`        // 保存密码的环境变量名称（优先级高于 password）
	PasswordFile   string   `yaml:"password_file"`       // 保存密码的文件路径（次优先级，支持 ~ 展开）
	KnownHosts     string   `yaml:"known_hosts"`         // known_hosts 文件路径，用于主机密钥验证
	ConnectTimeout int      `yaml:"connect_timeout_sec"` // SSH 连接超时时间（秒）
	KeepaliveSec   int      `yaml:"keepalive_sec"`       // SSH keepalive 间隔时间（秒）
	MaxSessions    int      `yaml:"max_sessions"`        // 该主机的最大并发会话数
	Type           string   `yaml:"type"`                // 主机类型：linux, macos, routeros
	Description    string   `yaml:"description"`         // 主机描述信息，用于向客户端展示
	SecurityGroup  string   `yaml:"security_group"`      // 关联的安全策略分组
	ScriptTags     []string `yaml:"script_tags"`         // 允许执行脚本的标签列表
}

// SecurityConfig 安全过滤和访问控制配置
// 实现多层安全过滤机制，包括命令黑名单、白名单、参数验证等
type SecurityConfig struct {
	Group           string   `yaml:"group"`              // 安全策略分组名称
	DefaultShell    bool     `yaml:"default_shell"`      // 默认是否使用 shell 执行命令（false=直接执行，更安全）
	AllowShellFor   []string `yaml:"allow_shell_for"`    // 允许使用 shell 的命令列表
	DenylistExact   []string `yaml:"denylist_exact"`     // 精确匹配的黑名单命令（如 rm, dd, mkfs 等）
	DenylistRegex   []string `yaml:"denylist_regex"`     // 正则表达式黑名单（阻止危险命令模式）
	ArgDenyRegex    []string `yaml:"arg_deny_regex"`     // 参数正则黑名单（阻止危险参数如 --force）
	AllowlistExact  []string `yaml:"allowlist_exact"`    // 精确匹配的白名单命令（允许的安全命令）
	AllowlistRegex  []string `yaml:"allowlist_regex"`    // 正则表达式白名单（允许的命令模式）
	WorkingDirAllow []string `yaml:"working_dir_allow"`  // 允许的工作目录列表（防止目录遍历攻击）
	MaxOutputBytes  int64    `yaml:"max_output_bytes"`   // 命令输出最大字节数（防止内存耗尽）
	EnablePTY       bool     `yaml:"enable_pty"`         // 是否启用伪终端（某些交互式命令需要）
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
	AllowedHosts []string          `yaml:"allowed_hosts"` // 允许执行此脚本的主机列表（* 表示所有主机）
	TimeoutSec   int               `yaml:"timeout_sec"`   // 脚本执行超时时间（秒）
	UseShell     bool              `yaml:"use_shell"`     // 是否使用 shell 执行脚本
	WorkingDir   string            `yaml:"working_dir"`   // 脚本执行的工作目录
	Tag          string            `yaml:"tag"`           // 脚本标签，用于与主机 script_tags 匹配
}

// ScriptParameter 脚本参数定义
// 定义脚本模板中可用的参数及其验证规则
type ScriptParameter struct {
	Name        string      `yaml:"name"`        // 参数名称，必须与模板中的占位符匹配
	Type        string      `yaml:"type"`        // 参数类型：string, integer, boolean, float
	Required    bool        `yaml:"required"`    // 是否为必需参数
	Default     interface{} `yaml:"default"`     // 参数默认值（可选）
	Description string      `yaml:"description"` // 参数说明
	Validation  string      `yaml:"validation"`  // 参数验证正则表达式（可选）
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

// AuditLoggingConfig 安全审计日志配置
// 控制安全事件日志的输出位置和格式
type AuditLoggingConfig struct {
	Enabled  *bool  `yaml:"enabled"`   // 是否启用安全审计日志
	Format   string `yaml:"format"`    // 日志格式：json 或 text
	Output   string `yaml:"output"`    // 输出目标：stdout, stderr, file
	FilePath string `yaml:"file_path"` // 当 output 为 file 时的日志文件路径
}

// IsEnabled 返回是否启用安全审计日志，默认启用。
func (a *AuditLoggingConfig) IsEnabled() bool {
	if a == nil || a.Enabled == nil {
		return true
	}
	return *a.Enabled
}

// SetEnabled 显式设置安全审计日志开关。
func (a *AuditLoggingConfig) SetEnabled(v bool) {
	if a == nil {
		return
	}
	a.Enabled = &v
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
//
//	path - 配置文件的路径
//
// 返回值：
//
//	*Config - 解析完成的配置对象
//	error - 加载过程中的错误，包含详细的错误信息
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

	// 处理 includes 引用
	if err := applyIncludes(&config, filepath.Dir(path)); err != nil {
		return nil, fmt.Errorf("处理 includes 失败: %w", err)
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

	// 构建运行时索引，便于后续快速查询
	buildIndexes(&config)

	return &config, nil
}

// setDefaults 为配置项设置合理的默认值
// 确保即使用户未在配置文件中指定某些选项，系统也能正常运行
func setDefaults(config *Config) {
	// 服务器配置默认值
	if config.Server.BindAddr == "" {
		config.Server.BindAddr = "127.0.0.1:7458" // 默认监听本地端口 7458
	}
	if config.Server.PublicBaseURL == "" {
		config.Server.PublicBaseURL = DefaultPublicBaseURL(config.Server.BindAddr)
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
	if len(config.Security) == 0 {
		config.Security = append(config.Security, SecurityConfig{
			Group: "default",
		})
	}

	for i := range config.Security {
		sec := &config.Security[i]
		if sec.Group == "" {
			if i == 0 {
				sec.Group = "default"
			} else {
				sec.Group = fmt.Sprintf("group_%d", i)
			}
		}
		if sec.MaxOutputBytes == 0 {
			sec.MaxOutputBytes = 1024 * 1024 // 默认最大输出 1MB
		}
		if sec.RateLimitPerMin == 0 {
			sec.RateLimitPerMin = 120 // 默认每分钟 120 次请求
		}
	}

	defaultGroup := config.Security[0].Group

	for i := range config.SSHHosts {
		host := &config.SSHHosts[i]
		host.Type = strings.ToLower(strings.TrimSpace(host.Type))
		if host.Type == "" {
			host.Type = "linux"
		}
		if host.SecurityGroup == "" {
			host.SecurityGroup = defaultGroup
		}
		if len(host.ScriptTags) == 0 {
			host.ScriptTags = []string{"default"}
		}
	}

	for i := range config.Scripts {
		script := &config.Scripts[i]
		if script.Tag == "" {
			script.Tag = "default"
		}
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

	// 安全审计日志默认值
	if config.Audit.Format == "" {
		config.Audit.Format = "json"
	}
	if config.Audit.Output == "" {
		config.Audit.Output = "file"
	}
	if strings.EqualFold(config.Audit.Output, "file") && config.Audit.FilePath == "" {
		config.Audit.FilePath = "security_audit.log"
	}
}

// validate 验证配置的完整性和正确性
// 确保所有必需的配置项都已正确设置，避免运行时错误
func validate(config *Config) error {
	// 验证 SSH 主机配置
	if len(config.SSHHosts) == 0 {
		return fmt.Errorf("至少需要配置一个 SSH 主机")
	}
	if len(config.Security) == 0 {
		return fmt.Errorf("至少需要配置一个 security 组")
	}

	allowedHostTypes := map[string]struct{}{
		"linux":    {},
		"macos":    {},
		"routeros": {},
	}

	securityGroups := make(map[string]struct{}, len(config.Security))
	for i, sec := range config.Security {
		if strings.TrimSpace(sec.Group) == "" {
			return fmt.Errorf("第 %d 个 security 组缺少 group 字段", i+1)
		}
		if _, exists := securityGroups[sec.Group]; exists {
			return fmt.Errorf("security group '%s' 重复定义", sec.Group)
		}
		securityGroups[sec.Group] = struct{}{}
	}

	defaultGroup := config.Security[0].Group
	hostIDs := make(map[string]struct{}, len(config.SSHHosts))

	for i, host := range config.SSHHosts {
		if host.ID == "" {
			return fmt.Errorf("第 %d 个 SSH 主机缺少 ID", i+1)
		}
		if _, duplicate := hostIDs[host.ID]; duplicate {
			return fmt.Errorf("SSH 主机 ID '%s' 重复定义", host.ID)
		}
		hostIDs[host.ID] = struct{}{}
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
		if host.AuthMethod == "password" {
			if host.Password == "" && host.PasswordEnv == "" && host.PasswordFile == "" {
				return fmt.Errorf("主机 %s 使用密码认证但缺少密码来源", host.ID)
			}
		}

		hostType := strings.ToLower(strings.TrimSpace(host.Type))
		if hostType == "" {
			hostType = "linux"
		}
		if _, ok := allowedHostTypes[hostType]; !ok {
			return fmt.Errorf("主机 %s 使用不支持的类型 '%s'", host.ID, host.Type)
		}

		groupName := host.SecurityGroup
		if groupName == "" {
			groupName = defaultGroup
		}
		if _, exists := securityGroups[groupName]; !exists {
			return fmt.Errorf("主机 %s 引用未定义的 security_group '%s'", host.ID, host.SecurityGroup)
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
		if strings.TrimSpace(script.Tag) == "" {
			return fmt.Errorf("脚本 %s 缺少 tag 配置", script.Name)
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
		host.PasswordFile = expandPath(host.PasswordFile)
	}

	if strings.EqualFold(config.Logging.Output, "file") {
		config.Logging.FilePath = expandPath(config.Logging.FilePath)
	}
	if strings.EqualFold(config.Audit.Output, "file") {
		config.Audit.FilePath = expandPath(config.Audit.FilePath)
	}
}

// expandPath 展开单个路径中的 ~ 为用户主目录
// 支持 ~/path 格式的路径，自动转换为用户主目录下的绝对路径
// 如果展开失败，返回原路径
func expandPath(path string) string {
	return common.ExpandPath(path)
}

// applyEnvOverrides 应用环境变量覆盖配置
// 支持通过环境变量动态调整配置，便于容器化部署和运行时配置
// 环境变量命名规则：EXECMCP_<SECTION>_<KEY>，全部大写，用下划线分隔
func applyEnvOverrides(config *Config) {
	// 服务器配置环境变量覆盖
	applyServerEnvOverrides(config)

	// 安全配置环境变量覆盖
	applySecurityEnvOverrides(config)

	// 日志配置环境变量覆盖
	applyLoggingEnvOverrides(config)

	// 安全审计日志环境变量覆盖
	applyAuditLoggingEnvOverrides(config)

	// 动态添加SSH主机配置
	applyDynamicSSHHost(config)

	// 动态添加安全规则
	applyDynamicSecurityRules(config)
}

// applyServerEnvOverrides 应用服务器配置相关的环境变量覆盖
func applyServerEnvOverrides(config *Config) {
	// 格式：EXECMCP_SERVER_<CONFIG_KEY>
	setStringFromEnv(&config.Server.BindAddr, EnvServerBindAddr)
	setStringFromEnv(&config.Server.PublicBaseURL, EnvServerPublicBaseURL)
	setStringFromEnv(&config.Server.LogLevel, EnvServerLogLevel)
	setIntFromEnv(&config.Server.MaxConcurrent, EnvServerMaxConcurrent)
	setIntFromEnv(&config.Server.RequestTimeout, EnvServerRequestTimeoutSec)
	setStringFromEnv(&config.Server.AuthToken, EnvServerAuthToken)
}

// applySecurityEnvOverrides 应用安全配置相关的环境变量覆盖
func applySecurityEnvOverrides(config *Config) {
	sec := config.DefaultSecurityConfig()
	if sec == nil {
		return
	}
	// 格式：EXECMCP_SECURITY_<CONFIG_KEY>
	setBoolFromEnv(&sec.DefaultShell, EnvSecurityDefaultShell)
	setInt64FromEnv(&sec.MaxOutputBytes, EnvSecurityMaxOutputBytes)
	setBoolFromEnv(&sec.EnablePTY, EnvSecurityEnablePTY)
	setIntFromEnv(&sec.RateLimitPerMin, EnvSecurityRateLimitPerMin)
}

// applyLoggingEnvOverrides 应用日志配置相关的环境变量覆盖
func applyLoggingEnvOverrides(config *Config) {
	// 格式：EXECMCP_LOGGING_<CONFIG_KEY>
	setStringFromEnv(&config.Logging.Level, EnvLoggingLevel)
	setStringFromEnv(&config.Logging.Format, EnvLoggingFormat)
	setStringFromEnv(&config.Logging.Output, EnvLoggingOutput)
	setStringFromEnv(&config.Logging.FilePath, EnvLoggingFilePath)
	setStringFromEnv(&config.Logging.MaxSize, EnvLoggingMaxSize)
	setIntFromEnv(&config.Logging.MaxBackups, EnvLoggingMaxBackups)
	setIntFromEnv(&config.Logging.MaxAge, EnvLoggingMaxAge)
}

// applyAuditLoggingEnvOverrides 应用安全审计日志相关环境变量覆盖
func applyAuditLoggingEnvOverrides(config *Config) {
	setBoolPointerFromEnv(&config.Audit.Enabled, EnvAuditLoggingEnabled)
	setStringFromEnv(&config.Audit.Format, EnvAuditLoggingFormat)
	setStringFromEnv(&config.Audit.Output, EnvAuditLoggingOutput)
	setStringFromEnv(&config.Audit.FilePath, EnvAuditLoggingFilePath)
}

// applyDynamicSSHHost 通过环境变量动态添加SSH主机配置
// 支持格式：id:addr:user:auth_method[:private_key_path|:password]
// 示例：EXECMCP_SSH_HOST="server1:192.168.1.100:ubuntu:private_key:/path/to/key"
func applyDynamicSSHHost(config *Config) {
	if sshHost := common.GetEnv(EnvSSHHost, ""); sshHost != "" {
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

			newHost.Type = strings.ToLower(strings.TrimSpace(newHost.Type))
			if newHost.Type == "" {
				newHost.Type = "linux"
			}
			if newHost.SecurityGroup == "" {
				newHost.SecurityGroup = config.DefaultSecurityGroup()
				if newHost.SecurityGroup == "" {
					newHost.SecurityGroup = "default"
				}
			}
			if len(newHost.ScriptTags) == 0 {
				newHost.ScriptTags = []string{"default"}
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
}

// applyDynamicSecurityRules 通过环境变量动态添加安全规则
// 支持通过环境变量扩展安全规则列表，多个值用逗号分隔
func applyDynamicSecurityRules(config *Config) {
	sec := config.DefaultSecurityConfig()
	if sec == nil {
		return
	}
	appendStringSliceFromEnv(&sec.DenylistExact, EnvSecurityDenylistExact)
	appendStringSliceFromEnv(&sec.AllowlistExact, EnvSecurityAllowlistExact)
	appendStringSliceFromEnv(&sec.WorkingDirAllow, EnvSecurityWorkingDirAllow)
	appendStringSliceFromEnv(&sec.AllowShellFor, EnvSecurityAllowShellFor)
}

// setStringFromEnv 从环境变量设置字符串值
func setStringFromEnv(target *string, envKey string) {
	if value := common.GetEnv(envKey, ""); value != "" {
		*target = value
	}
}

// setIntFromEnv 从环境变量设置整数值
func setIntFromEnv(target *int, envKey string) {
	if val := common.GetEnvInt(envKey, 0); val != 0 {
		*target = val
	}
}

// DefaultPublicBaseURL derives a client-facing base URL from the provided bind address.
// It normalizes unspecified or loopback hosts to localhost to improve compatibility.
func DefaultPublicBaseURL(bindAddr string) string {
	host := "localhost"
	port := ""
	if bindAddr != "" {
		if h, p, err := net.SplitHostPort(bindAddr); err == nil {
			h = strings.TrimSpace(h)
			if h != "" {
				hostCandidate := normalizePublicHost(h)
				if hostCandidate != "" {
					host = hostCandidate
				}
			}
			port = strings.TrimSpace(p)
		} else {
			trimmed := strings.TrimSpace(bindAddr)
			if trimmed != "" {
				host = normalizePublicHost(trimmed)
			}
		}
	}
	hostPart := host
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		hostPart = "[" + host + "]"
	}
	if port != "" {
		return fmt.Sprintf("http://%s:%s", hostPart, port)
	}
	return fmt.Sprintf("http://%s", hostPart)
}

func normalizePublicHost(host string) string {
	lower := strings.ToLower(host)
	switch lower {
	case "", "0.0.0.0", "::", "[::]":
		return "localhost"
	case "127.0.0.1":
		return "localhost"
	}
	return host
}

// setInt64FromEnv 从环境变量设置int64值
func setInt64FromEnv(target *int64, envKey string) {
	if val := common.GetEnvInt64(envKey, 0); val != 0 {
		*target = val
	}
}

// setBoolFromEnv 从环境变量设置布尔值
func setBoolFromEnv(target *bool, envKey string) {
	*target = common.GetEnvBool(envKey, false)
}

// setBoolPointerFromEnv 从环境变量设置布尔指针值
func setBoolPointerFromEnv(target **bool, envKey string) {
	if target == nil {
		return
	}
	if value, exists := os.LookupEnv(envKey); exists {
		val := strings.EqualFold(value, "true") || value == "1"
		if *target == nil {
			*target = new(bool)
		}
		**target = val
	}
}

// appendStringSliceFromEnv 从环境变量追加字符串切片
func appendStringSliceFromEnv(target *[]string, envKey string) {
	if value := common.GetEnv(envKey, ""); value != "" {
		*target = append(*target, common.SplitCommaSeparated(value)...)
	}
}

// applyIncludes 处理配置文件中的 includes 扩展
func applyIncludes(cfg *Config, baseDir string) error {
	if err := appendSSHHostIncludes(cfg, baseDir); err != nil {
		return err
	}
	if err := appendSecurityIncludes(cfg, baseDir); err != nil {
		return err
	}
	if err := appendScriptIncludes(cfg, baseDir); err != nil {
		return err
	}
	return nil
}

func appendSSHHostIncludes(cfg *Config, baseDir string) error {
	if len(cfg.SSHHostIncludes) == 0 {
		return nil
	}
	included, err := loadSSHHosts(baseDir, cfg.SSHHostIncludes)
	if err != nil {
		return err
	}
	cfg.SSHHosts = append(cfg.SSHHosts, included...)
	return nil
}

func appendSecurityIncludes(cfg *Config, baseDir string) error {
	if len(cfg.SecurityIncludes) == 0 {
		return nil
	}
	included, err := loadSecurityConfigs(baseDir, cfg.SecurityIncludes)
	if err != nil {
		return err
	}
	cfg.Security = append(cfg.Security, included...)
	return nil
}

func appendScriptIncludes(cfg *Config, baseDir string) error {
	if len(cfg.ScriptIncludes) == 0 {
		return nil
	}
	included, err := loadScriptConfigs(baseDir, cfg.ScriptIncludes)
	if err != nil {
		return err
	}
	cfg.Scripts = append(cfg.Scripts, included...)
	return nil
}

func loadSSHHosts(baseDir string, includes []string) ([]SSHHost, error) {
	var result []SSHHost
	for _, inc := range includes {
		hosts := []SSHHost{}
		if err := loadIncludeFile(baseDir, inc, &hosts, "ssh_hosts", func(wrapper *includeWrapper) interface{} {
			return &wrapper.SSHHosts
		}); err != nil {
			return nil, fmt.Errorf("加载 ssh_hosts include '%s' 失败: %w", inc, err)
		}
		result = append(result, hosts...)
	}
	return result, nil
}

func loadSecurityConfigs(baseDir string, includes []string) ([]SecurityConfig, error) {
	var result []SecurityConfig
	for _, inc := range includes {
		secs := []SecurityConfig{}
		if err := loadIncludeFile(baseDir, inc, &secs, "security", func(wrapper *includeWrapper) interface{} {
			return &wrapper.Security
		}); err != nil {
			return nil, fmt.Errorf("加载 security include '%s' 失败: %w", inc, err)
		}
		result = append(result, secs...)
	}
	return result, nil
}

func loadScriptConfigs(baseDir string, includes []string) ([]ScriptConfig, error) {
	var result []ScriptConfig
	for _, inc := range includes {
		scripts := []ScriptConfig{}
		if err := loadIncludeFile(baseDir, inc, &scripts, "scripts", func(wrapper *includeWrapper) interface{} {
			return &wrapper.Scripts
		}); err != nil {
			return nil, fmt.Errorf("加载 scripts include '%s' 失败: %w", inc, err)
		}
		result = append(result, scripts...)
	}
	return result, nil
}

type includeWrapper struct {
	SSHHosts []SSHHost        `yaml:"ssh_hosts"`
	Security []SecurityConfig `yaml:"security"`
	Scripts  []ScriptConfig   `yaml:"scripts"`
}

func loadIncludeFile(baseDir, includePath string, target interface{}, wrapperKey string, selector func(*includeWrapper) interface{}) error {
	fullPath := includePath
	if !filepath.IsAbs(includePath) {
		fullPath = filepath.Join(baseDir, includePath)
	}

	data, err := os.ReadFile(fullPath)
	if err != nil {
		return err
	}

	if err := yaml.Unmarshal(data, target); err == nil {
		return nil
	}

	var wrapper includeWrapper
	if err := yaml.Unmarshal(data, &wrapper); err != nil {
		return err
	}

	selected := selector(&wrapper)
	switch dst := target.(type) {
	case *[]SSHHost:
		if hosts, ok := selected.(*[]SSHHost); ok {
			*dst = append(*dst, (*hosts)...)
			return nil
		}
	case *[]SecurityConfig:
		if secs, ok := selected.(*[]SecurityConfig); ok {
			*dst = append(*dst, (*secs)...)
			return nil
		}
	case *[]ScriptConfig:
		if scripts, ok := selected.(*[]ScriptConfig); ok {
			*dst = append(*dst, (*scripts)...)
			return nil
		}
	}

	return fmt.Errorf("include 文件 '%s' 缺少有效的 %s 配置", includePath, wrapperKey)
}

// DefaultSecurityConfig 返回默认的安全配置（第一个 security 组）
func (c *Config) DefaultSecurityConfig() *SecurityConfig {
	if len(c.Security) == 0 {
		return nil
	}
	return &c.Security[0]
}

// DefaultSecurityGroup 返回默认安全组名称
func (c *Config) DefaultSecurityGroup() string {
	if len(c.Security) == 0 {
		return ""
	}
	return c.Security[0].Group
}

// SecurityByGroup 根据 group 名称获取安全配置
func (c *Config) SecurityByGroup(group string) (*SecurityConfig, bool) {
	c.ensureIndexes()
	if group == "" {
		group = c.DefaultSecurityGroup()
	}
	sec, ok := c.securityIndex[group]
	return sec, ok
}

// SecurityForHost 返回指定主机对应的安全配置
func (c *Config) SecurityForHost(hostID string) (*SecurityConfig, bool) {
	c.ensureIndexes()
	host, ok := c.hostIndex[hostID]
	if !ok {
		return nil, false
	}
	return c.SecurityByGroup(host.SecurityGroup)
}

// HostByID 根据主机 ID 返回配置
func (c *Config) HostByID(hostID string) (*SSHHost, bool) {
	c.ensureIndexes()
	host, ok := c.hostIndex[hostID]
	return host, ok
}

func (c *Config) ensureIndexes() {
	if c.securityIndex == nil || c.hostIndex == nil {
		buildIndexes(c)
	}
}

func buildIndexes(c *Config) {
	c.securityIndex = make(map[string]*SecurityConfig, len(c.Security))
	for i := range c.Security {
		sec := &c.Security[i]
		c.securityIndex[sec.Group] = sec
	}

	c.hostIndex = make(map[string]*SSHHost, len(c.SSHHosts))
	for i := range c.SSHHosts {
		host := &c.SSHHosts[i]
		c.hostIndex[host.ID] = host
	}
}
