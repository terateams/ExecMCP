# 配置指南

本文档提供了 ExecMCP 的完整配置说明。

## 配置文件结构

ExecMCP 使用 YAML 格式的配置文件，支持环境变量覆盖。主配置文件通常为 `config.yaml`。

## 基本配置

```yaml
# 服务器配置
server:
  listen: "127.0.0.1:7458"    # 监听地址和端口
  auth_token: "your-token"     # 认证令牌

# 日志配置
logging:
  level: "info"                # 日志级别: debug, info, warn, error
  format: "json"              # 日志格式: json, text
  output: "stdout"            # 输出位置: stdout, file
  file:                       # 当 output 为 file 时的配置
    path: "/var/log/execmcp.log"
    max_size: 100            # MB
    max_age: 30              # 天
    max_backups: 7
    compress: true
```

## SSH 主机配置

```yaml
# SSH 主机配置
ssh:
  # 全局 SSH 设置
  global:
    timeout: "30s"                    # 连接超时
    keep_alive_interval: "30s"        # 保活间隔
    max_sessions_per_host: 5          # 每个主机最大会话数
    known_hosts_file: "~/.ssh/known_hosts"

  # 主机定义
  hosts:
    - id: "prod-server-1"
      name: "生产服务器 1"
      host: "192.168.1.100"
      port: 22
      user: "admin"

      # 认证方式（选择一种）
      auth:
        private_key:
          path: "/path/to/private/key"
          password: ""               # 私钥密码（可选）
        # 或者使用密码认证
        password: ""
        # 或者使用 SSH agent
        agent: true

      # 连接限制
      connection:
        timeout: "30s"
        keep_alive_interval: "30s"
        max_sessions: 5
```

## 安全配置

```yaml
# 安全配置
security:
  # 命令过滤规则
  command_filter:
    # 精确拒绝的命令
    exact_deny:
      - "rm"
      - "dd"
      - "mkfs"
      - "shutdown"
      - "reboot"
      - "halt"
      - "poweroff"
      - "init"
      - "telinit"
      - "killall"
      - "pkill"

    # 正则表达式拒绝的命令
    regex_deny:
      - ".*;.*"                    # 防止命令链
      - ".*&&.*"                   # 防止逻辑与
      - ".*\\|\\|.*"               # 防止逻辑或
      - ".*>.*"                    # 防止输出重定向
      - ".*>>.*"                   # 防止输出追加
      - "rm\\s+-.*"                # 防止 rm 的危险参数
      - "chmod\\s+777"             # 防止设置完全权限

    # 允许的命令
    allow:
      - "ls"
      - "cat"
      - "pwd"
      - "whoami"
      - "date"
      - "uptime"
      - "df"
      - "du"
      - "ps"
      - "top"
      - "htop"
      - "systemctl"
      - "journalctl"
      - "docker"
      - "kubectl"
      - "git"
      - "npm"
      - "yarn"
      - "python"
      - "go"

    # 允许使用 shell 的命令
    allow_shell_for:
      - "systemctl"
      - "journalctl"
      - "docker"
      - "kubectl"

  # 工作目录限制
  working_dir_allow:
    - "/tmp"
    - "/home"
    - "/var/log"
    - "/opt"

  # 资源限制
  limits:
    max_output_bytes: 1048576      # 最大输出字节数 (1MB)
    max_execution_time: "300s"     # 最大执行时间 (5分钟)
    max_concurrent_commands: 10     # 最大并发命令数
    rate_limit_per_host: 5         # 每主机速率限制 (每秒)
    rate_limit_global: 20          # 全局速率限制 (每秒)
```

## 脚本配置

```yaml
# 脚本配置
scripts:
  - name: "system-info"
    description: "获取系统信息"
    template: |
      #!/bin/bash
      echo "=== 系统信息 ==="
      echo "主机名: $(hostname)"
      echo "内核版本: $(uname -a)"
      echo "运行时间: $(uptime)"
      echo "内存使用:"
      free -h
      echo "磁盘使用:"
      df -h
    allowed_params:
      format:
        type: "string"
        default: "text"
        enum: ["text", "json"]

  - name: "docker-status"
    description: "检查 Docker 容器状态"
    template: |
      #!/bin/bash
      echo "=== Docker 容器状态 ==="
      docker ps -a
      echo ""
      echo "=== Docker 镜像列表 ==="
      docker images
    allowed_params:
      filter:
        type: "string"
        default: ""
        description: "容器名称过滤器"
```

## 审计配置

```yaml
# 审计配置
audit:
  enabled: true                    # 启用审计
  log_file: "/var/log/execmcp/audit.log"
  log_level: "info"               # 审计日志级别
  max_file_size: 100              # MB
  max_files: 10
  compress: true
  include_params: true            # 是否包含参数
  include_output: false          # 是否包含输出（可能包含敏感信息）

  # 审计事件
  events:
    - "command_execute"
    - "script_execute"
    - "security_violation"
    - "connection_error"
    - "authentication_error"
```

## 环境变量覆盖

ExecMCP 支持通过环境变量覆盖配置文件中的设置：

```bash
# 服务器配置
export EXECMCP_SERVER_LISTEN="0.0.0.0:7458"
export EXECMCP_SERVER_AUTH_TOKEN="your-token"

# 日志配置
export EXECMCP_LOGGING_LEVEL="debug"
export EXECMCP_LOGGING_FORMAT="json"

# SSH 主机密码（安全方式）
export EXECMCP_SSH_HOSTS_0_PASSWORD="your-password"
```

## 配置验证

ExecMCP 在启动时会验证配置文件的有效性：

- 检查 YAML 语法
- 验证必需的配置项
- 检查 SSH 连接参数
- 验证安全规则配置

## 最佳实践

1. **安全性**
   - 使用强密码和 SSH 密钥
   - 限制允许的命令
   - 启用审计日志
   - 定期轮换认证令牌

2. **性能**
   - 合理设置连接池大小
   - 配置适当的超时时间
   - 启用日志压缩

3. **监控**
   - 启用审计日志
   - 设置日志轮转
   - 监控系统资源使用

## 示例配置

参考 `config.example.yaml` 文件获取完整的配置示例。