# CLAUDE.md

本文件为 Claude Code (claude.ai/code) 在此代码库中工作提供指导。

## 项目概述

ExecMCP 是一个安全优先的 Go 语言 MCP (Model Context Protocol) 服务器，通过 SSH 为 Linux 主机提供安全的远程命令执行。服务器通过 SSE (Server-Sent Events) 向 AI 代理暴露工具，具有严格的安全控制、命令过滤和审计日志功能。

## 架构设计

### 核心目录结构
```
/cmd/mcpserver/main.go          # 程序入口点
/internal/config/config.go      # YAML 配置解析
/internal/ssh/manager.go        # SSH 连接池和会话管理
/internal/execsvc/service.go    # 命令执行逻辑与流式处理
/internal/security/filter.go    # 多层安全过滤引擎
/internal/mcp/server.go         # MCP-Go SSE 传输集成
/internal/logging/logger.go     # 结构化日志和审计追踪
```

### 安全优先设计
- **默认拒绝策略**: 除非明确加入白名单，否则阻止所有命令
- **默认无shell**: 直接执行以防止注入攻击 (`use_shell=false`)
- **多层过滤**: 精确拒绝 → 正则拒绝 → 白名单 → 路径验证
- **资源限制**: 输出大小限制、超时控制、速率限制
- **完整审计**: 所有命令执行都记录上下文信息

## 开发命令

### 构建和运行
```bash
# 开发服务器
go run ./cmd/mcpserver --config ./config.yaml

# 测试 (首先关注安全边界)
go test ./internal/security -v -race      # 安全过滤器测试
go test ./internal/execsvc -v            # 执行服务测试
go test ./internal/ssh -v                # SSH 连接测试
go test ./... -v -short                  # 所有单元测试 (跳过集成测试)

# 健康检查 - 查看 "SSE listening on 127.0.0.1:7458"
```

### 关键依赖
- `golang.org/x/crypto/ssh` - SSH 客户端实现
- `github.com/mark3labs/mcp-go` - MCP 协议与 SSE 传输
- 标准 Go 并发模式，采用每请求一个 goroutine 的模型

## MCP 工具接口

### exec_command 工具
- **用途**: 在远程主机上执行带安全过滤的命令
- **参数**: `host_id`, `command`, `args[]`, `options{cwd, timeout, use_shell, stream}`
- **流式传输**: 通过 SSE 实时输出，处理 stdout/stderr 合并
- **错误类型**: SECURITY_DENY, TIMEOUT, SSH_ERROR, OUTPUT_TRUNCATED, RATE_LIMITED

### 辅助工具
- `list_commands`: 返回允许的命令模式供 AI 发现
- `test_connection`: 指定主机的 SSH 健康检查

## 安全实现

### 过滤管道
```go
func (f *Filter) Check(req ExecRequest) error {
    // 1. 阻止精确匹配 (rm, dd, mkfs, shutdown, reboot)
    // 2. 阻止正则模式 (.*;.*, ^rm\.*, 危险参数如 --no-preserve-root)
    // 3. 检查白名单 (ls, cat, systemctl 等)
    // 4. 验证工作目录是否在允许列表中
    // 5. Shell 命令验证 (如果 use_shell=true)
}
```

### 关键安全规则
- **Shell 限制**: 只允许 `allow_shell_for` 配置中的命令使用 shell
- **路径保护**: 工作目录必须在 `working_dir_allow` 前缀内
- **参数过滤**: 阻止危险参数如 `--recursive`, `--force`
- **输出限制**: 强制执行 `max_output_bytes` 以防止内存耗尽
- **连接安全**: 要求 known_hosts 验证 (开发模式会警告)

## 配置驱动的安全

`config.yaml` 文件定义了所有安全规则、主机连接和限制：
- SSH 主机定义和认证方法
- 命令允许/拒绝列表 (精确匹配和正则模式)
- 工作目录限制
- 资源限制 (超时、输出大小、并发数)
- 速率限制阈值

## 错误分类系统

- `SECURITY_DENY`: 被安全规则阻止
- `TIMEOUT`: 命令执行超时
- `OUTPUT_TRUNCATED`: 超过 max_output_bytes 限制
- `RATE_LIMITED`: 超过并发/速率限制
- `SSH_CONNECT_ERROR` / `SSH_AUTH_ERROR` / `SSH_SESSION_ERROR`: 连接失败

## 测试策略

专注于安全边界测试：
- 阻止危险命令: `rm`, `dd`, `mkfs`, `shutdown`, `reboot`
- 防止 shell 注入: 在非 shell 模式下的 `;`, `&&`, `||`, `>`, `>>`, `|`
- 验证路径遍历保护
- 测试在 `max_output_bytes` 处的输出截断
- 验证超时终止向远程进程发送 SIGKILL
- 并发请求处理不会导致崩溃

## 常见模式

- **错误包装**: 在错误消息中保留安全上下文
- **每请求一个 goroutine**: 每个 MCP 工具调用独立运行
- **上下文取消**: 在超时/关闭时正确清理
- **结构化日志**: JSON 格式，包含审计字段
- **连接池**: 复用 SSH 客户端，管理会话生命周期
- **审计追踪**: 记录时间戳、host_id、命令、参数、结果

## 集成点

- **MCP SSE 传输**: 与 AI 代理的实时双向通信
- **SSH 会话管理**: 连接池化，优雅处理网络故障
- **审计管道**: 记录所有命令执行以供合规/调试
- **速率限制**: 全局和每主机的请求节流

## 实现优先级

1. **配置解析和 SSH 连接管理** (包括 known_hosts 验证)
2. **安全过滤引擎** (TDD 方法，测试优先)
3. **MCP-Go 集成** (注册工具，基本请求/响应流)
4. **流式输出处理** (截断和超时终止)
5. **审计日志和错误分类**
6. **并发限制和速率限制**