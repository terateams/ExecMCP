# 安全机制

本文档详细说明了 ExecMCP 的安全机制和最佳实践。

## 安全架构

ExecMCP 采用多层安全架构，确保远程命令执行的安全性：

```
用户请求 → 认证层 → 授权层 → 过滤层 → 执行层 → 审计层
```

## 1. 认证机制

### 1.1 令牌认证

```yaml
server:
  auth_token: "your-secure-token"
```

- 所有 MCP 请求必须包含有效的认证令牌
- 令牌通过 `Authorization` 头部或查询参数传递
- 支持令牌轮换和撤销

### 1.2 SSH 认证

支持多种 SSH 认证方式：

```yaml
auth:
  # 私钥认证
  private_key:
    path: "/path/to/private/key"
    password: "optional-password"

  # 密码认证
  password: "password"

  # SSH Agent 认证
  agent: true
```

## 2. 命令过滤机制

### 2.1 多层过滤管道

命令过滤采用多层检查机制：

```go
func (f *Filter) Check(req ExecRequest) error {
    // 1. 精确拒绝检查
    if f.isExactDenied(req.Command) {
        return NewSecurityError("命令被精确拒绝")
    }

    // 2. 正则表达式拒绝检查
    if f.isRegexDenied(req.Command) {
        return NewSecurityError("命令被正则表达式拒绝")
    }

    // 3. 白名单检查
    if !f.isAllowed(req.Command) {
        return NewSecurityError("命令不在白名单中")
    }

    // 4. 路径验证
    if req.CWD != "" && !f.isPathAllowed(req.CWD) {
        return NewSecurityError("工作目录不被允许")
    }

    // 5. Shell 使用检查
    if req.UseShell && !f.isShellAllowed(req.Command) {
        return NewSecurityError("该命令不允许使用 shell")
    }

    return nil
}
```

### 2.2 精确拒绝列表

默认拒绝的危险命令：

```yaml
exact_deny:
  - "rm"           # 删除文件
  - "dd"           # 磁盘操作
  - "mkfs"         # 文件系统格式化
  - "shutdown"     # 关机
  - "reboot"       # 重启
  - "halt"         # 停止系统
  - "poweroff"     # 关闭电源
  - "init"         # 系统初始化
  - "telinit"      # 切换运行级别
  - "killall"      # 杀死所有进程
  - "pkill"        # 按名称杀死进程
```

### 2.3 正则表达式拒绝

防止命令注入和危险操作：

```yaml
regex_deny:
  - ".*;.*"                    # 命令分隔符
  - ".*&&.*"                   # 逻辑与
  - ".*\\|\\|.*"               # 逻辑或
  - ".*>.*"                    # 输出重定向
  - ".*>>.*"                   # 输出追加
  - ".*<.*"                    # 输入重定向
  - "rm\\s+-.*"                # rm 的危险参数
  - "chmod\\s+777"             # 设置完全权限
  - "chown\\s+.*"              # 改变所有者
  - "wget.*"                   # 文件下载
  - "curl.*"                   # 文件下载
  - "scp.*"                    # 文件传输
  - "rsync.*"                  # 文件同步
```

### 2.4 白名单机制

只允许明确授权的命令：

```yaml
allow:
  - "ls"           # 列出文件
  - "cat"          # 查看文件内容
  - "pwd"          # 当前目录
  - "whoami"       # 当前用户
  - "date"         # 日期时间
  - "uptime"       # 系统运行时间
  - "df"           # 磁盘使用情况
  - "du"           # 目录大小
  - "ps"           # 进程列表
  - "top"          # 系统监控
  - "htop"         # 增强系统监控
  - "systemctl"    # 系统服务管理
  - "journalctl"   # 系统日志
  - "docker"       # Docker 命令
  - "kubectl"      # Kubernetes 命令
  - "git"          # 版本控制
  - "npm"          # Node.js 包管理
  - "yarn"         # Node.js 包管理
  - "python"       # Python 解释器
  - "go"           # Go 语言工具
```

### 2.5 Shell 使用限制

只有特定命令可以使用 shell：

```yaml
allow_shell_for:
  - "systemctl"    # 需要复杂的参数处理
  - "journalctl"   # 需要复杂的参数处理
  - "docker"       # 需要复杂的参数处理
  - "kubectl"      # 需要复杂的参数处理
```

## 3. 资源限制

### 3.1 输出限制

```yaml
limits:
  max_output_bytes: 1048576      # 1MB 输出限制
```

- 防止命令输出过大导致内存耗尽
- 超过限制时自动截断输出
- 记录截断事件到审计日志

### 3.2 执行时间限制

```yaml
limits:
  max_execution_time: "300s"     # 5 分钟执行限制
```

- 防止长时间运行的命令
- 超时后自动终止进程
- 发送 SIGTERM，超时后发送 SIGKILL

### 3.3 并发限制

```yaml
limits:
  max_concurrent_commands: 10     # 全局并发限制
  rate_limit_per_host: 5         # 每主机速率限制
  rate_limit_global: 20          # 全局速率限制
```

- 防止系统过载
- 避免单个主机占用过多资源
- 实现请求节流

## 4. 路径安全

### 4.1 工作目录限制

```yaml
working_dir_allow:
  - "/tmp"           # 临时目录
  - "/home"          # 用户目录
  - "/var/log"       # 日志目录
  - "/opt"           # 可选软件目录
```

- 限制命令执行的工作目录
- 防止访问敏感系统目录
- 支持路径前缀匹配

### 4.2 路径验证机制

```go
func isPathPrefix(path, prefix string) bool {
    canonicalPrefix, err := canonicalizePath(prefix)
    if err != nil {
        return false
    }

    canonicalPath, err := canonicalizePath(path)
    if err != nil {
        return false
    }

    rel, err := filepath.Rel(canonicalPrefix, canonicalPath)
    if err != nil {
        return false
    }

    return !strings.HasPrefix(rel, "..")
}
```

## 5. 审计日志

### 5.1 审计事件

```yaml
audit:
  events:
    - "command_execute"           # 命令执行
    - "script_execute"            # 脚本执行
    - "security_violation"        # 安全违规
    - "connection_error"         # 连接错误
    - "authentication_error"     # 认证错误
```

### 5.2 审计日志格式

```json
{
  "timestamp": "2024-01-01T12:00:00Z",
  "level": "info",
  "event": "command_execute",
  "request_id": "uuid-here",
  "host_id": "prod-server-1",
  "command": "ls -la",
  "args": ["-la"],
  "cwd": "/tmp",
  "user": "admin",
  "result": "success",
  "duration_ms": 150,
  "output_size": 1024,
  "client_ip": "192.168.1.100"
}
```

## 6. 错误处理

### 6.1 安全错误分类

```go
type SecurityErrorType string

const (
    SECURITY_DENY          SecurityErrorType = "security_deny"
    TIMEOUT                SecurityErrorType = "timeout"
    OUTPUT_TRUNCATED       SecurityErrorType = "output_truncated"
    RATE_LIMITED           SecurityErrorType = "rate_limited"
    SSH_CONNECT_ERROR      SecurityErrorType = "ssh_connect_error"
    SSH_AUTH_ERROR         SecurityErrorType = "ssh_auth_error"
    SSH_SESSION_ERROR      SecurityErrorType = "ssh_session_error"
)
```

### 6.2 错误信息处理

- 不泄露敏感信息
- 提供足够的信息用于调试
- 记录详细的错误上下文到日志

## 7. 最佳实践

### 7.1 配置安全

1. **使用强密码和密钥**
   ```yaml
   # 推荐：使用 SSH 密钥认证
   auth:
     private_key:
       path: "/path/to/private/key"
   ```

2. **限制命令白名单**
   ```yaml
   # 只允许必要的命令
   allow:
     - "ls"
     - "cat"
     - "pwd"
   ```

3. **启用审计日志**
   ```yaml
   audit:
     enabled: true
     log_file: "/var/log/execmcp/audit.log"
   ```

### 7.2 运维安全

1. **定期轮换认证令牌**
2. **监控审计日志**
3. **更新安全规则**
4. **备份配置文件**

### 7.3 网络安全

1. **使用防火墙限制访问**
2. **启用 SSL/TLS 加密**
3. **限制访问 IP 地址**
4. **监控网络流量**

## 8. 安全测试

### 8.1 测试用例

```go
func TestSecurityFilter(t *testing.T) {
    tests := []struct {
        name    string
        command string
        wantErr bool
    }{
        {"危险命令", "rm -rf /", true},
        {"命令注入", "ls; rm -rf /", true},
        {"允许命令", "ls -la", false},
        {"Shell 使用", "docker run", false},
    }

    for _, tt := range tests {
        // 测试逻辑
    }
}
```

### 8.2 渗透测试

定期进行安全测试：

- 命令注入测试
- 路径遍历测试
- 资源耗尽测试
- 权限提升测试

## 9. 应急响应

### 9.1 安全事件处理

1. **立即停止服务**
2. **保存审计日志**
3. **分析事件原因**
4. **修复安全漏洞**
5. **恢复服务**

### 9.2 事件响应流程

```yaml
incident_response:
  detection:
    - "异常命令执行"
    - "多次认证失败"
    - "大量输出截断"
  response:
    - "自动阻止 IP"
    - "发送警报"
    - "记录事件"
  recovery:
    - "分析日志"
    - "修复漏洞"
    - "恢复服务"
```

通过这些安全机制，ExecMCP 确保了远程命令执行的安全性，同时保持了易用性和灵活性。