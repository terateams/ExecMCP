# ExecMCP

安全优先的 Go 语言 MCP (Model Context Protocol) 服务器，通过 SSH 为 Linux 主机提供安全的远程命令执行服务。

## ✨ 特性

### 🔒 安全优先

- **多层安全过滤**: 精确黑名单、正则表达式、参数验证
- **默认拒绝策略**: 所有命令需明确授权才能执行
- **无 Shell 默认**: 防止命令注入攻击
- **资源限制**: 输出大小、超时、并发控制
- **完整审计**: 所有操作记录和追踪

### 🚀 高性能

- **SSH 连接池**: 复用连接，提高性能
- **流式输出**: 实时返回命令执行结果
- **并发处理**: 支持多主机并发命令执行
- **异步处理**: 基于 goroutine 的高并发架构

### 🛠️ 易于集成

- **MCP 协议**: 标准化的 AI Agent 接口
- **SSE 传输**: 实时双向通信
- **配置驱动**: 灵活的 YAML 配置文件
- **结构化日志**: 便于监控和调试

## 📋 快速开始

### 安装要求

- Go 1.19+
- 远程 Linux 主机访问权限
- SSH 密钥或密码认证

### 下载和构建

```bash
# 克隆项目
git clone https://github.com/terateams/ExecMCP.git
cd ExecMCP

# 下载依赖
go mod tidy

# 构建项目
go build -o bin/mcpserver ./cmd/mcpserver
```

### 配置

创建 `config.yaml` 配置文件：

```yaml
server:
  bind_addr: "127.0.0.1:7458"
  log_level: "info"
  max_concurrent: 32
  request_timeout_sec: 30
  auth_token: "your-secret-token"

ssh_hosts:
  - id: "prod-1"
    addr: "10.0.0.11:22"
    user: "ubuntu"
    auth_method: "private_key"
    private_key_path: "~/.ssh/id_rsa"
    known_hosts: "~/.ssh/known_hosts"
    max_sessions: 8

security:
  default_shell: false
  allow_shell_for: ["bash", "sh"]
  denylist_exact: ["rm", "reboot", "shutdown", "halt", "poweroff", "mkfs", "dd"]
  allowlist_exact: ["ls", "cat", "tail", "head", "grep", "uname", "whoami", "uptime", "df", "du", "ps"]
  working_dir_allow: ["/home", "/var/log", "/tmp"]
  max_output_bytes: 1048576
  rate_limit_per_min: 120
```

### 运行服务器

```bash
# 开发模式
go run ./cmd/mcpserver --config ./config.yaml

# 生产模式
./bin/mcpserver --config ./config.yaml
```

### 健康检查

服务器启动后，应该看到类似日志：
```
INFO: SSE listening on 127.0.0.1:7458 ...
INFO: Configuration loaded successfully
INFO: Security filter initialized with 15 rules
```

## 🔧 MCP 工具

### exec_command

在指定主机上执行命令，支持安全过滤和流式输出。

```json
{
  "tool_name": "exec_command",
  "arguments": {
    "host_id": "prod-1",
    "command": "ls",
    "args": ["-la", "/var/log"],
    "options": {
      "cwd": "/var/log",
      "timeout_sec": 10,
      "stream": true
    }
  }
}
```

### exec_script (🆕 新功能)

执行预定义的脚本模板，支持参数替换和安全的模板渲染。AI Agent 可以通过配置的脚本名称执行预设的命令。

```json
{
  "tool_name": "exec_script",
  "arguments": {
    "host_id": "prod-1",
    "script_name": "check_disk_usage",
    "parameters": {
      "path": "/var/log",
      "threshold": 85
    },
    "options": {
      "timeout_sec": 30,
      "stream": true
    }
  }
}
```

### list_commands

返回允许执行的命令列表和模板。

```json
{
  "tool_name": "list_commands",
  "arguments": {}
}
```

### test_connection

测试指定主机的 SSH 连接状态。

```json
{
  "tool_name": "test_connection",
  "arguments": {
    "host_id": "prod-1"
  }
}
```

## 📜 脚本执行功能

### 概述

`exec_script` 工具支持在配置文件中预定义脚本模板，AI Agent 可以通过配置的脚本名称执行预设的命令，同时支持动态参数替换。

### 配置示例

```yaml
scripts:
  - name: "check_disk_usage"
    description: "检查磁盘使用情况，支持指定路径和阈值告警"
    prompt: "检查指定路径的磁盘使用情况，如果使用率超过阈值则告警"
    template: "df -h {path} | awk 'NR>1 && $5+0 > {threshold} {print $6 \": \" $5 \" 使用率过高\"}'"
    parameters:
      - name: "path"
        type: "string"
        required: true
        default: "/"
        description: "要检查的路径"
        validation: "^[a-zA-Z0-9/_-]+$"
      - name: "threshold"
        type: "integer"
        required: false
        default: 80
        description: "使用率阈值百分比"
        validation: "^[0-9]+$"
    allowed_hosts: ["*"]
    timeout_sec: 30
    use_shell: true
```

### 预定义脚本模板

项目提供了多个实用的脚本模板：

- **check_disk_usage**: 磁盘使用情况检查
- **find_large_files**: 查找大文件
- **check_system_load**: 系统负载检查
- **analyze_logs**: 日志分析
- **check_network_connections**: 网络连接检查

### AI 友好特性

- **Prompt 集成**: 每个脚本都有专门的 AI 提示信息
- **参数验证**: 自动验证参数格式和类型
- **默认值**: 支持参数默认值，减少配置复杂度
- **模板安全**: 安全的参数替换机制，防止注入攻击

### 使用场景

```bash
# 检查磁盘使用情况
./mcpserver --config config.yaml

# AI Agent 调用示例
{
  "tool_name": "exec_script",
  "arguments": {
    "host_id": "prod-1",
    "script_name": "analyze_logs",
    "parameters": {
      "log_file": "/var/log/app.log",
      "pattern": "ERROR",
      "hours": 24
    }
  }
}
```

## 🛡️ 安全机制

### 命令过滤

- **精确黑名单**: 直接阻止危险命令 (`rm`, `dd`, `mkfs`, `shutdown`)
- **正则表达式**: 阻止命令变体和注入攻击 (`.*;.*`, `^rm\.*`)
- **参数过滤**: 阻止危险参数 (`--no-preserve-root`, `--recursive`)
- **白名单**: 只允许明确授权的命令执行

### 资源控制

- **输出限制**: 防止内存耗尽 (`max_output_bytes`)
- **超时控制**: 防止长时间运行的命令 (`timeout_sec`)
- **并发限制**: 控制并发请求数量 (`max_concurrent`)
- **速率限制**: 防止滥用 (`rate_limit_per_min`)

### 连接安全

- **known_hosts 验证**: 防止 MITM 攻击
- **连接池管理**: 复用连接，提高性能
- **认证支持**: 支持 SSH 密钥和密码认证
- **会话限制**: 每主机的最大会话数限制

## 🔍 开发

### 项目结构

```
ExecMCP/
├── cmd/mcpserver/main.go          # 主程序入口
├── internal/
│   ├── config/config.go          # 配置解析
│   ├── ssh/manager.go            # SSH 连接管理
│   ├── execsvc/service.go        # 命令执行服务
│   ├── security/filter.go        # 安全过滤引擎
│   ├── mcp/server.go             # MCP 服务器集成
│   └── logging/logger.go         # 日志记录
├── develop/TODO_LIST.md           # 开发 TODO 清单
├── config.example.yaml            # 示例配置
└── README.md                     # 项目说明
```

### 运行测试

```bash
# 运行所有测试
go test ./...

# 运行安全测试（重点）
go test ./internal/security -v -race

# 运行特定测试
go test ./internal/execsvc -v

# 生成测试覆盖率报告
go test ./... -coverprofile=coverage.out
go tool cover -html=coverage.out
```

### 开发环境

```bash
# 安装开发依赖
go mod download

# 格式化代码
go fmt ./...

# 静态检查
go vet ./...

# 运行 linter (如果有安装)
golangci-lint run
```

## 📖 配置说明

### 服务器配置

```yaml
server:
  bind_addr: "127.0.0.1:7458"    # 监听地址
  log_level: "info"               # 日志级别
  max_concurrent: 32              # 最大并发数
  request_timeout_sec: 30         # 请求超时时间
  auth_token: ""                  # 认证令牌
```

### SSH 主机配置

```yaml
ssh_hosts:
  - id: "host-id"                 # 主机标识
    addr: "host:port"            # 主机地址
    user: "username"              # 用户名
    auth_method: "private_key"   # 认证方式
    private_key_path: "~/.ssh/id_rsa"  # 私钥路径
    known_hosts: "~/.ssh/known_hosts" # known_hosts 文件
    max_sessions: 8               # 最大会话数
```

### 安全配置

```yaml
security:
  default_shell: false            # 默认不使用 shell
  allow_shell_for: ["bash", "sh"] # 允许使用 shell 的命令
  denylist_exact: [...]          # 精确黑名单
  allowlist_exact: [...]         # 精确白名单
  working_dir_allow: [...]       # 允许的工作目录
  max_output_bytes: 1048576      # 最大输出字节数
  rate_limit_per_min: 120        # 速率限制
```

## 🚨 错误处理

### 错误类型

- `SECURITY_DENY`: 命令被安全规则阻止
- `TIMEOUT`: 命令执行超时
- `OUTPUT_TRUNCATED`: 输出超过大小限制
- `RATE_LIMITED`: 超过速率限制
- `SSH_CONNECT_ERROR`: SSH 连接失败
- `SSH_AUTH_ERROR`: SSH 认证失败
- `SSH_SESSION_ERROR`: SSH 会话错误

### 错误示例

```json
{
  "error": {
    "code": "SECURITY_DENY",
    "message": "command 'rm' is not allowed",
    "details": {
      "rule": "denylist_exact",
      "host_id": "prod-1",
      "command": "rm"
    }
  }
}
```

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

### 开发流程

1. Fork 项目
2. 创建功能分支 (`git checkout -b feature/amazing-feature`)
3. 提交更改 (`git commit -m 'Add amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 创建 Pull Request

### 代码规范

- 遵循 Go 语言标准代码风格
- 所有公共 API 都需要文档注释
- 安全相关的代码必须有充分的测试覆盖
- 提交前运行完整测试套件

## 📄 许可证

本项目采用 MIT 许可证 - 详见 [LICENSE](LICENSE) 文件。

## 🆘 支持

- 📧 Email: support@example.com
- 🐛 Issues: [GitHub Issues](https://github.com/terateams/ExecMCP/issues)
- 📖 文档: [Wiki](https://github.com/terateams/ExecMCP/wiki)

## 🔗 相关链接

- [MCP 协议文档](https://modelcontextprotocol.io/)
- [MCP-Go 库](https://github.com/mark3labs/mcp-go)
- [Go SSH 库](https://pkg.go.dev/golang.org/x/crypto/ssh)

---

**⚠️ 安全提示**: 本工具提供远程命令执行能力，请确保正确配置安全规则，仅允许可信的 AI Agent 访问。
