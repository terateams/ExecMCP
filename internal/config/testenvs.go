package config

// 本文件集中管理 ExecMCP 项目中测试专用的环境变量名称常量
// 这些环境变量仅用于测试环境，不会在生产环境中使用

// ===== 测试专用环境变量 =====

// EnvTestPassword 用于测试的密码环境变量
const EnvTestPassword = "EXECMCP_TEST_PASSWORD"

// EnvStagingPassword 用于预发布环境的密码环境变量
const EnvStagingPassword = "EXECMCP_STAGING_PASSWORD"

// EnvTestFatal 测试中是否触发 fatal 错误（用于日志测试）
const EnvTestFatal = "TEST_FATAL"




// ===== 工具/客户端相关环境变量 =====

// EnvMCPServerURL MCP 服务器 URL（用于测试客户端）
const EnvMCPServerURL = "EXECMCP_MCP_SERVER_URL"

// EnvMCPHostID MCP 主机 ID（用于测试客户端）
const EnvMCPHostID = "EXECMCP_MCP_HOST_ID"

// EnvMCPCommand MCP 命令（用于测试客户端）
const EnvMCPCommand = "EXECMCP_MCP_COMMAND"

// EnvMCPArgs MCP 命令参数（用于测试客户端）
const EnvMCPArgs = "EXECMCP_MCP_ARGS"

// EnvMCPUseShell 是否使用 Shell（用于测试客户端）
const EnvMCPUseShell = "EXECMCP_MCP_USE_SHELL"

// EnvMCPTimeout 超时时间（用于测试客户端）
const EnvMCPTimeout = "EXECMCP_MCP_TIMEOUT"

// EnvMCPListType 列表类型（用于测试客户端）
const EnvMCPListType = "EXECMCP_MCP_LIST_TYPE"

// EnvMCPScriptName 脚本名称（用于测试客户端）
const EnvMCPScriptName = "EXECMCP_MCP_SCRIPT_NAME"

// EnvMCPScriptParams 脚本参数（用于测试客户端）
const EnvMCPScriptParams = "EXECMCP_MCP_SCRIPT_PARAMS"