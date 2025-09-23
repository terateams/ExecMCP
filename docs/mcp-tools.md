# MCP 工具接口

本文档详细说明了 ExecMCP 提供的 MCP (Model Context Protocol) 工具接口。

## 概述

ExecMCP 通过 MCP 协议向 AI 代理提供以下工具：

- `exec_command` - 执行安全过滤的命令
- `exec_script` - 执行预定义脚本
- `list_commands` - 查看可用命令
- `test_connection` - 测试主机连接
- `list_hosts` - 列出配置的主机

## 工具详细说明

### 1. exec_command

执行安全过滤的命令，支持实时流式输出。

#### 参数

```json
{
  "host_id": "string",           // 主机ID (必需)
  "command": "string",          // 要执行的命令 (必需)
  "args": ["string"],           // 命令参数 (可选)
  "options": {                  // 执行选项 (可选)
    "cwd": "string",            // 工作目录
    "timeout": "30s",           // 超时时间
    "use_shell": false,         // 是否使用shell
    "stream": true              // 是否流式输出
  }
}
```

#### 示例

```json
{
  "host_id": "prod-server-1",
  "command": "ls",
  "args": ["-la", "/tmp"],
  "options": {
    "cwd": "/tmp",
    "timeout": "30s",
    "use_shell": false,
    "stream": true
  }
}
```

#### 响应

```json
{
  "success": true,
  "output": "总用量 12\ndrwxrwxrwt 3 root root 4096 Jan 1 12:00 .\ndrwxr-xr-x 3 root root 4096 Jan 1 12:00 ..",
  "error": null,
  "exit_code": 0,
  "duration_ms": 150,
  "output_size": 128
}
```

#### 错误类型

- `SECURITY_DENY` - 命令被安全规则拒绝
- `TIMEOUT` - 命令执行超时
- `OUTPUT_TRUNCATED` - 输出被截断
- `RATE_LIMITED` - 请求被限流
- `SSH_CONNECT_ERROR` - SSH 连接错误
- `SSH_AUTH_ERROR` - SSH 认证错误
- `SSH_SESSION_ERROR` - SSH 会话错误

### 2. exec_script

执行预定义的脚本模板，支持参数替换。

#### 参数

```json
{
  "host_id": "string",           // 主机ID (必需)
  "script_name": "string",      // 脚本名称 (必需)
  "params": {                   // 脚本参数 (可选)
    "param1": "value1",
    "param2": "value2"
  },
  "options": {                  // 执行选项 (可选)
    "timeout": "300s",          // 超时时间
    "stream": true              // 是否流式输出
  }
}
```

#### 示例

```json
{
  "host_id": "prod-server-1",
  "script_name": "system-info",
  "params": {
    "format": "json"
  },
  "options": {
    "timeout": "60s",
    "stream": true
  }
}
```

#### 预定义脚本

**system-info**
```bash
#!/bin/bash
echo "=== 系统信息 ==="
echo "主机名: $(hostname)"
echo "内核版本: $(uname -a)"
echo "运行时间: $(uptime)"
```

**docker-status**
```bash
#!/bin/bash
echo "=== Docker 容器状态 ==="
docker ps -a
echo ""
echo "=== Docker 镜像列表 ==="
docker images
```

#### 响应

```json
{
  "success": true,
  "output": "=== 系统信息 ===\n主机名: prod-server-1\n内核版本: Linux 5.4.0...\n运行时间: 12:34:56 up 30 days",
  "error": null,
  "exit_code": 0,
  "duration_ms": 250,
  "output_size": 256
}
```

### 3. list_commands

列出可用的命令和脚本。

#### 参数

```json
{
  "host_id": "string"           // 主机ID (可选)
}
```

#### 示例

```json
{
  "host_id": "prod-server-1"
}
```

#### 响应

```json
{
  "commands": [
    {
      "name": "ls",
      "description": "列出文件和目录",
      "allowed": true,
      "requires_shell": false
    },
    {
      "name": "cat",
      "description": "查看文件内容",
      "allowed": true,
      "requires_shell": false
    }
  ],
  "scripts": [
    {
      "name": "system-info",
      "description": "获取系统信息",
      "allowed_params": {
        "format": {
          "type": "string",
          "default": "text",
          "enum": ["text", "json"]
        }
      }
    }
  ]
}
```

### 4. test_connection

测试指定主机的 SSH 连接。

#### 参数

```json
{
  "host_id": "string"           // 主机ID (必需)
}
```

#### 示例

```json
{
  "host_id": "prod-server-1"
}
```

#### 响应

```json
{
  "success": true,
  "message": "SSH 连接成功",
  "details": {
    "host": "192.168.1.100",
    "port": 22,
    "user": "admin",
    "auth_method": "private_key",
    "response_time_ms": 50
  }
}
```

#### 错误响应

```json
{
  "success": false,
  "message": "SSH 连接失败",
  "error": "SSH_AUTH_ERROR",
  "details": {
    "host": "192.168.1.100",
    "port": 22,
    "user": "admin",
    "error_message": "authentication failed"
  }
}
```

### 5. list_hosts

列出所有配置的主机。

#### 参数

```json
{}  // 无参数
```

#### 响应

```json
{
  "hosts": [
    {
      "id": "prod-server-1",
      "name": "生产服务器 1",
      "host": "192.168.1.100",
      "port": 22,
      "user": "admin",
      "status": "connected",
      "max_sessions": 5,
      "active_sessions": 2
    },
    {
      "id": "dev-server-1",
      "name": "开发服务器 1",
      "host": "192.168.1.101",
      "port": 22,
      "user": "developer",
      "status": "disconnected",
      "max_sessions": 3,
      "active_sessions": 0
    }
  ]
}
```

## 流式输出

### SSE 格式

启用流式输出时，服务器通过 Server-Sent Events (SSE) 实时发送输出：

```text
data: {"type": "output", "content": "第一行输出"}

data: {"type": "output", "content": "第二行输出"}

data: {"type": "error", "content": "错误信息"}

data: {"type": "status", "exit_code": 0, "duration_ms": 150}
```

### 消息类型

- `output` - 标准输出
- `error` - 错误输出
- `status` - 执行状态

## 认证

所有 MCP 请求都需要包含认证令牌：

### HTTP Header

```
Authorization: Bearer your-token
```

### Query Parameter

```
?token=your-token
```

## 错误处理

### 错误格式

```json
{
  "error": {
    "code": "SECURITY_DENY",
    "message": "命令被安全规则拒绝",
    "details": {
      "command": "rm -rf /",
      "rule": "exact_deny"
    }
  }
}
```

### 错误代码

| 代码 | 描述 | HTTP 状态码 |
|------|------|------------|
| `SECURITY_DENY` | 命令被安全规则拒绝 | 403 |
| `TIMEOUT` | 命令执行超时 | 408 |
| `OUTPUT_TRUNCATED` | 输出被截断 | 206 |
| `RATE_LIMITED` | 请求被限流 | 429 |
| `SSH_CONNECT_ERROR` | SSH 连接错误 | 502 |
| `SSH_AUTH_ERROR` | SSH 认证错误 | 401 |
| `SSH_SESSION_ERROR` | SSH 会话错误 | 500 |
| `INVALID_REQUEST` | 无效请求 | 400 |
| `INTERNAL_ERROR` | 内部错误 | 500 |

## 使用示例

### JavaScript/Node.js

```javascript
// 执行命令
const response = await fetch('http://localhost:7458/mcp/exec_command', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer your-token'
  },
  body: JSON.stringify({
    host_id: 'prod-server-1',
    command: 'ls',
    args: ['-la', '/tmp']
  })
});

const result = await response.json();
console.log(result);
```

### Python

```python
import requests

# 执行命令
response = requests.post(
    'http://localhost:7458/mcp/exec_command',
    headers={
        'Content-Type': 'application/json',
        'Authorization': 'Bearer your-token'
    },
    json={
        'host_id': 'prod-server-1',
        'command': 'ls',
        'args': ['-la', '/tmp']
    }
)

result = response.json()
print(result)
```

### curl

```bash
# 执行命令
curl -X POST http://localhost:7458/mcp/exec_command \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your-token" \
  -d '{
    "host_id": "prod-server-1",
    "command": "ls",
    "args": ["-la", "/tmp"]
  }'
```

## 性能考虑

### 1. 并发限制

- 全局并发限制：`max_concurrent_commands`
- 每主机并发限制：`max_sessions_per_host`
- 速率限制：`rate_limit_per_host`

### 2. 资源使用

- 输出限制：`max_output_bytes`
- 执行时间限制：`max_execution_time`
- 内存使用：流式输出减少内存占用

### 3. 网络优化

- 使用 SSE 减少网络请求
- 压缩大输出
- 连接复用

## 安全注意事项

1. **认证令牌**：定期轮换认证令牌
2. **命令过滤**：严格配置安全规则
3. **审计日志**：启用审计日志记录
4. **网络隔离**：限制访问 IP 地址
5. **输入验证**：验证所有输入参数

通过这些 MCP 工具接口，AI 代理可以安全地与远程主机交互，执行各种管理和监控任务。