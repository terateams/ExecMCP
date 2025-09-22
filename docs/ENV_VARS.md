# ExecMCP 环境变量配置

ExecMCP 支持通过环境变量覆盖配置文件中的设置，这提供了更灵活的部署和配置管理方式。

## 环境变量命名规范

所有环境变量都使用 `EXECMCP_` 前缀，后跟配置路径的大写形式，用下划线分隔。

## 支持的环境变量

### 服务器配置

| 环境变量 | 配置路径 | 类型 | 说明 |
|---------|---------|------|------|
| `EXECMCP_SERVER_BIND_ADDR` | `server.bind_addr` | 字符串 | 服务器绑定地址 |
| `EXECMCP_SERVER_LOG_LEVEL` | `server.log_level` | 字符串 | 服务器日志级别 |
| `EXECMCP_SERVER_MAX_CONCURRENT` | `server.max_concurrent` | 整数 | 最大并发连接数 |
| `EXECMCP_SERVER_REQUEST_TIMEOUT_SEC` | `server.request_timeout_sec` | 整数 | 请求超时时间（秒） |
| `EXECMCP_SERVER_AUTH_TOKEN` | `server.auth_token` | 字符串 | 认证令牌 |

### 安全配置

| 环境变量 | 配置路径 | 类型 | 说明 |
|---------|---------|------|------|
| `EXECMCP_SECURITY_DEFAULT_SHELL` | `security.default_shell` | 布尔值 | 是否默认使用 Shell |
| `EXECMCP_SECURITY_MAX_OUTPUT_BYTES` | `security.max_output_bytes` | 整数 | 最大输出字节数 |
| `EXECMCP_SECURITY_ENABLE_PTY` | `security.enable_pty` | 布尔值 | 是否启用 PTY |
| `EXECMCP_SECURITY_RATE_LIMIT_PER_MIN` | `security.rate_limit_per_min` | 整数 | 每分钟速率限制 |

### 日志配置

| 环境变量 | 配置路径 | 类型 | 说明 |
|---------|---------|------|------|
| `EXECMCP_LOGGING_LEVEL` | `logging.level` | 字符串 | 日志级别 |
| `EXECMCP_LOGGING_FORMAT` | `logging.format` | 字符串 | 日志格式 |
| `EXECMCP_LOGGING_OUTPUT` | `logging.output` | 字符串 | 日志输出方式 |
| `EXECMCP_LOGGING_FILE_PATH` | `logging.file_path` | 字符串 | 日志文件路径 |
| `EXECMCP_LOGGING_MAX_SIZE` | `logging.max_size` | 字符串 | 日志文件最大大小 |
| `EXECMCP_LOGGING_MAX_BACKUPS` | `logging.max_backups` | 整数 | 日志备份文件数量 |
| `EXECMCP_LOGGING_MAX_AGE` | `logging.max_age` | 整数 | 日志文件最大保存天数 |

### SSH 主机配置

| 环境变量 | 格式 | 说明 |
|---------|------|------|
| `EXECMCP_SSH_HOST` | `id:addr:user:auth_method[:auth_value]` | 动态添加或替换 SSH 主机 |

**SSH 主机格式说明：**
- `id`: 主机唯一标识符
- `addr`: 主机地址（格式：host:port）
- `user`: SSH 用户名
- `auth_method`: 认证方式（`private_key` 或 `password`）
- `auth_value`: 可选，认证值（私钥路径或密码）

**示例：**
```bash
# 添加密码认证的主机
export EXECMCP_SSH_HOST="prod-server:192.168.1.100:root:password:secret123"

# 添加私钥认证的主机
export EXECMCP_SSH_HOST="dev-server:192.168.1.101:developer:private_key:/home/user/.ssh/id_rsa"
```

### 安全规则配置

| 环境变量 | 配置路径 | 类型 | 说明 |
|---------|---------|------|------|
| `EXECMCP_SECURITY_DENYLIST_EXACT` | `security.denylist_exact` | 逗号分隔列表 | 精确禁止的命令列表 |
| `EXECMCP_SECURITY_ALLOWLIST_EXACT` | `security.allowlist_exact` | 逗号分隔列表 | 精确允许的命令列表 |
| `EXECMCP_SECURITY_WORKING_DIR_ALLOW` | `security.working_dir_allow` | 逗号分隔列表 | 允许的工作目录列表 |
| `EXECMCP_SECURITY_ALLOW_SHELL_FOR` | `security.allow_shell_for` | 逗号分隔列表 | 允许使用 Shell 的命令 |

## 使用示例

### 基本配置覆盖

```bash
# 设置服务器绑定地址和日志级别
export EXECMCP_SERVER_BIND_ADDR="0.0.0.0:8080"
export EXECMCP_SERVER_LOG_LEVEL="debug"

# 设置安全配置
export EXECMCP_SECURITY_MAX_OUTPUT_BYTES="5242880"  # 5MB
export EXECMCP_SECURITY_ENABLE_PTY="true"

# 设置日志配置
export EXECMCP_LOGGING_LEVEL="warn"
export EXECMCP_LOGGING_FORMAT="text"
export EXECMCP_LOGGING_OUTPUT="file"
export EXECMCP_LOGGING_FILE_PATH="/var/log/execmcp.log"
```

### Docker 部署示例

```bash
docker run -d \
  -e EXECMCP_SERVER_BIND_ADDR="0.0.0.0:8080" \
  -e EXECMCP_SERVER_AUTH_TOKEN="your-secret-token" \
  -e EXECMCP_SSH_HOST="production:prod.example.com:22:admin:password:${ADMIN_PASSWORD}" \
  -e EXECMCP_SECURITY_MAX_OUTPUT_BYTES="10485760" \
  -e EXECMCP_LOGGING_LEVEL="info" \
  -v /config:/config \
  execmcp:latest
```

### Kubernetes 部署示例

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: execmcp
spec:
  template:
    spec:
      containers:
      - name: execmcp
        image: execmcp:latest
        env:
        - name: EXECMCP_SERVER_BIND_ADDR
          value: "0.0.0.0:8080"
        - name: EXECMCP_SERVER_AUTH_TOKEN
          valueFrom:
            secretKeyRef:
              name: execmcp-secrets
              key: auth-token
        - name: EXECMCP_SSH_HOST
          value: "production:prod.example.com:22:admin:private_key:/etc/ssh/keys/prod"
        - name: EXECMCP_SECURITY_MAX_OUTPUT_BYTES
          value: "10485760"
        - name: EXECMCP_LOGGING_LEVEL
          value: "info"
        volumeMounts:
        - name: ssh-keys
          mountPath: /etc/ssh/keys
      volumes:
      - name: ssh-keys
        secret:
          secretName: ssh-keys
```

## 配置优先级

1. **环境变量**（最高优先级）
2. **配置文件**
3. **默认值**（最低优先级）

这意味着环境变量将覆盖配置文件中的相应设置，而配置文件中的设置将覆盖默认值。

## 注意事项

1. **类型转换**: 环境变量都是字符串类型，系统会自动转换为配置中定义的类型
2. **错误处理**: 如果环境变量值无法转换为目标类型，将保持配置文件或默认值
3. **SSH 主机管理**: `EXECMCP_SSH_HOST` 会添加新主机或替换现有同名主机
4. **列表追加**: 安全规则相关的环境变量会将新值追加到现有列表中，而不是替换
5. **安全性**: 避免在环境变量中存储敏感信息，特别是在共享环境中

## 验证配置

您可以通过检查应用启动时的日志来验证环境变量是否正确应用：

```bash
# 启动应用并查看日志
./execmcp --config /path/to/config.yaml

# 日志中会显示最终的配置信息
```

或者使用健康检查端点（如果启用）来验证当前配置：

```bash
curl http://localhost:8080/health
```

## 故障排除

### 环境变量未生效

1. 检查环境变量名称是否正确
2. 确认环境变量已正确设置（使用 `env | grep EXECMCP` 检查）
3. 查看应用日志中是否有配置相关的错误信息

### SSH 主机连接失败

1. 验证 `EXECMCP_SSH_HOST` 格式是否正确
2. 检查主机地址和认证信息是否正确
3. 确认网络连接和防火墙设置

### 类型转换错误

1. 检查数值类型的环境变量是否为有效数字
2. 确认布尔值环境变量为 `true` 或 `false`
3. 查看应用日志中的配置加载错误信息