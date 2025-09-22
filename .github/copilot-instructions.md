# ExecMCP AI 编程指南

## 项目概述
ExecMCP 是基于 Go 的 MCP (Model Context Protocol) 服务器，通过 SSH 为 Linux 主机提供安全的远程命令执行。服务器通过 SSE (Server-Sent Events) 向 AI 代理暴露工具，实现远程命令执行，同时保持严格的安全控制。

## 架构与核心组件

### 核心结构
```
/cmd/mcpserver/main.go          # 程序入口
/internal/config/config.go      # YAML 配置解析
/internal/ssh/manager.go        # SSH 连接池管理
/internal/execsvc/service.go    # 命令执行逻辑与流式处理
/internal/security/filter.go    # 安全过滤引擎
/internal/mcp/server.go         # MCP-Go SSE 集成
/internal/logging/logger.go     # 结构化日志与审计
```

### 安全优先设计
- **默认全拒绝策略**: 命令必须明确加入白名单
- **默认禁用 shell**: 直接执行以防止注入攻击
- **多层过滤机制**: 精确拒绝 → 正则拒绝 → 白名单 → 路径验证
- **资源限制**: 输出大小限制、超时控制、速率限制
- **全审计**: 所有命令执行都记录上下文

## 关键依赖与模式

### 主要库
- `golang.org/x/crypto/ssh` - SSH 客户端实现
- `github.com/mark3labs/mcp-go` - MCP 协议与 SSE 传输
- 标准 Go 并发会话管理模式

### 安全过滤管道
```go
func (f *Filter) Check(req ExecRequest) error {
    // 1. 拒绝精确匹配 (rm, dd, mkfs, shutdown)
    // 2. 拒绝正则模式 (.*;.*, ^rm\.*, 危险参数)
    // 3. 检查白名单 (ls, cat, systemctl, 等)
    // 4. 验证工作目录白名单
    // 5. Shell 命令验证（如果 use_shell=true）
}
```

## MCP 工具接口

### exec_command
- **用途**: 在远程主机上执行带安全过滤的命令
- **关键参数**: `host_id`, `command`, `args[]`, `options{cwd, timeout, use_shell}`
- **流式传输**: 通过 SSE 实时输出，处理 stdout/stderr 合并
- **错误处理**: 分类错误 (SECURITY_DENY, TIMEOUT, SSH_ERROR)

### list_commands 与 test_connection
- 发现和健康检查的辅助工具
- 返回允许命令和主机连接状态的结构化数据

## 开发工作流

### 安全测试优先
```bash
# 首先实现的关键测试用例:
go test ./internal/security -v  # 拒绝危险命令
go test ./internal/execsvc -v  # 输出截断、超时
go test ./internal/ssh -v      # 连接处理、会话池
```

### 配置驱动的安全
- `config.yaml` 中的所有安全规则
- 主机定义与每主机连接限制
- 精确匹配和正则模式的独立白名单
- 工作目录路径限制

### 错误分类系统
- `SECURITY_DENY`: 被安全规则阻止
- `TIMEOUT`: 命令执行超时
- `OUTPUT_TRUNCATED`: 达到 max_output_bytes 限制
- `RATE_LIMITED`: 达到并发/速率限制
- `SSH_*_ERROR`: 连接/认证/会话失败

## 实现优先级

1. **配置解析与 SSH 连接管理** - 包含 known_hosts 验证
2. **安全过滤引擎** - TDD 风格实现，测试优先
3. **MCP-Go 集成** - 注册工具，基本请求/响应流
4. **流式输出处理** - 截断和超时终止
5. **审计日志与错误分类**
6. **并发限制与速率限制**

## 安全约定

### 命令执行
- 默认 `use_shell=false` - 仅直接执行
- 仅对 `allow_shell_for` 配置中的命令允许 Shell
- 通过正则阻止危险参数: `--no-preserve-root`, `--recursive`, `/dev/sd.*`
- 防止环境变量注入

### 路径限制
- 工作目录必须在 `working_dir_allow` 前缀内
- 任何上下文中都不允许相对路径遍历 (../)
- 文件操作限制在安全目录如 `/var/log`, `/tmp`

### 连接安全
- 强制执行 SSH known_hosts 验证（开发模式除外，但有警告）
- 连接池化与每主机会话限制
- SSH 故障的自动重连处理

## 测试策略

专注于安全边界:
- 拒绝危险命令: `rm`, `dd`, `mkfs`, `shutdown`, `reboot`
- 阻止 shell 注入: 非 shell 模式下的 `;`, `&&`, `||`, `>`, `>>`, `|`
- 验证路径遍历防护
- 测试 `max_output_bytes` 的输出截断
- 验证超时终止向远程进程发送 SIGKILL
- 并发请求处理不崩溃

## 构建与运行命令

```bash
# 开发
go run ./cmd/mcpserver --config ./config.yaml

# 专注安全的测试
go test ./internal/security -v -race
go test ./... -v -short  # 跳过集成测试

# 健康检查 - 服务器应记录 "SSE listening on 127.0.0.1:7458"
```

## 常见模式

- **错误包装**: 在错误消息中保留安全上下文
- **每请求一个 goroutine**: 每个 MCP 工具调用独立运行
- **上下文取消**: 超时和关闭时的正确清理
- **结构化日志**: JSON 格式，包含审计字段 (timestamp, host_id, command, result)
- **连接池**: 复用 SSH 客户端，管理会话生命周期

## 集成点

- **MCP SSE 传输**: 与 AI 代理的实时双向通信
- **SSH 会话管理**: 池化连接，优雅处理网络故障
- **审计管道**: 记录所有命令执行以供合规/调试
- **速率限制**: 全局和每主机请求节流