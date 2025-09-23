package config

// 本文件集中管理 ExecMCP 项目中使用的所有环境变量名称常量
// 避免在代码中硬编码环境变量名，提高可维护性和一致性

// ===== 服务器配置相关环境变量 =====

// EnvServerBindAddr 服务器绑定地址
const EnvServerBindAddr = "EXECMCP_SERVER_BIND_ADDR"

// EnvServerLogLevel 服务器日志级别
const EnvServerLogLevel = "EXECMCP_SERVER_LOG_LEVEL"

// EnvServerMaxConcurrent 最大并发连接数
const EnvServerMaxConcurrent = "EXECMCP_SERVER_MAX_CONCURRENT"

// EnvServerRequestTimeoutSec 请求超时时间（秒）
const EnvServerRequestTimeoutSec = "EXECMCP_SERVER_REQUEST_TIMEOUT_SEC"

// EnvServerAuthToken 认证令牌
const EnvServerAuthToken = "EXECMCP_SERVER_AUTH_TOKEN"

// ===== 安全配置相关环境变量 =====

// EnvSecurityDefaultShell 是否默认使用 Shell
const EnvSecurityDefaultShell = "EXECMCP_SECURITY_DEFAULT_SHELL"

// EnvSecurityMaxOutputBytes 最大输出字节数
const EnvSecurityMaxOutputBytes = "EXECMCP_SECURITY_MAX_OUTPUT_BYTES"

// EnvSecurityEnablePTY 是否启用 PTY
const EnvSecurityEnablePTY = "EXECMCP_SECURITY_ENABLE_PTY"

// EnvSecurityRateLimitPerMin 每分钟速率限制
const EnvSecurityRateLimitPerMin = "EXECMCP_SECURITY_RATE_LIMIT_PER_MIN"

// EnvSecurityDenylistExact 精确禁止的命令列表（逗号分隔）
const EnvSecurityDenylistExact = "EXECMCP_SECURITY_DENYLIST_EXACT"

// EnvSecurityAllowlistExact 精确允许的命令列表（逗号分隔）
const EnvSecurityAllowlistExact = "EXECMCP_SECURITY_ALLOWLIST_EXACT"

// EnvSecurityWorkingDirAllow 允许的工作目录列表（逗号分隔）
const EnvSecurityWorkingDirAllow = "EXECMCP_SECURITY_WORKING_DIR_ALLOW"

// EnvSecurityAllowShellFor 允许使用 Shell 的命令列表（逗号分隔）
const EnvSecurityAllowShellFor = "EXECMCP_SECURITY_ALLOW_SHELL_FOR"

// ===== 日志配置相关环境变量 =====

// EnvLoggingLevel 日志级别
const EnvLoggingLevel = "EXECMCP_LOGGING_LEVEL"

// EnvLoggingFormat 日志格式
const EnvLoggingFormat = "EXECMCP_LOGGING_FORMAT"

// EnvLoggingOutput 日志输出方式
const EnvLoggingOutput = "EXECMCP_LOGGING_OUTPUT"

// EnvLoggingFilePath 日志文件路径
const EnvLoggingFilePath = "EXECMCP_LOGGING_FILE_PATH"

// EnvLoggingMaxSize 日志文件最大大小
const EnvLoggingMaxSize = "EXECMCP_LOGGING_MAX_SIZE"

// EnvLoggingMaxBackups 日志备份文件数量
const EnvLoggingMaxBackups = "EXECMCP_LOGGING_MAX_BACKUPS"

// EnvLoggingMaxAge 日志文件最大保存天数
const EnvLoggingMaxAge = "EXECMCP_LOGGING_MAX_AGE"

// ===== 安全审计日志配置相关环境变量 =====

// EnvAuditLoggingEnabled 是否启用安全审计日志
const EnvAuditLoggingEnabled = "EXECMCP_AUDIT_LOGGING_ENABLED"

// EnvAuditLoggingFormat 安全审计日志格式
const EnvAuditLoggingFormat = "EXECMCP_AUDIT_LOGGING_FORMAT"

// EnvAuditLoggingOutput 安全审计日志输出方式
const EnvAuditLoggingOutput = "EXECMCP_AUDIT_LOGGING_OUTPUT"

// EnvAuditLoggingFilePath 安全审计日志文件路径
const EnvAuditLoggingFilePath = "EXECMCP_AUDIT_LOGGING_FILE_PATH"

// ===== SSH 主机配置相关环境变量 =====

// EnvSSHHost 动态添加或替换 SSH 主机
// 格式：id:addr:user:auth_method[:private_key_path|:password]
const EnvSSHHost = "EXECMCP_SSH_HOST"
