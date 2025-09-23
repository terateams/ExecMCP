# 部署指南

本文档提供了 ExecMCP 的部署指南，包括生产环境部署、容器化部署、配置管理等。

## 部署方式

### 1. 二进制部署

#### 1.1 下载二进制文件

```bash
# 从 GitHub Releases 下载
wget https://github.com/terateams/ExecMCP/releases/latest/download/execmcp-linux-amd64.tar.gz
tar -xzf execmcp-linux-amd64.tar.gz

# 或者自己构建
make build-prod
```

#### 1.2 系统服务配置

创建 systemd 服务文件：

```bash
sudo tee /etc/systemd/system/execmcp.service > /dev/null <<EOF
[Unit]
Description=ExecMCP Server
After=network.target

[Service]
Type=simple
User=execmcp
Group=execmcp
WorkingDirectory=/opt/execmcp
ExecStart=/opt/execmcp/bin/execmcp --config /etc/execmcp/config.yaml
Restart=always
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
```

#### 1.3 启动服务

```bash
# 创建用户
sudo useradd -r -s /bin/false execmcp

# 创建目录
sudo mkdir -p /opt/execmcp/bin /etc/execmcp /var/log/execmcp
sudo chown -R execmcp:execmcp /opt/execmcp /etc/execmcp /var/log/execmcp

# 复制文件
sudo cp bin/execmcp /opt/execmcp/bin/
sudo cp config.yaml /etc/execmcp/

# 启动服务
sudo systemctl daemon-reload
sudo systemctl enable execmcp
sudo systemctl start execmcp

# 检查状态
sudo systemctl status execmcp
```

### 2. Docker 部署

#### 2.1 使用 Docker 镜像

```bash
# 从 Docker Hub 拉取
docker pull terateams/execmcp:latest

# 运行容器
docker run -d \
  --name execmcp \
  -p 7458:7458 \
  -v /etc/execmcp:/etc/execmcp \
  -v /var/log/execmcp:/var/log/execmcp \
  -v ~/.ssh:/home/execmcp/.ssh:ro \
  terateams/execmcp:latest \
  --config /etc/execmcp/config.yaml
```

#### 2.2 Docker Compose

```yaml
version: '3.8'

services:
  execmcp:
    image: terateams/execmcp:latest
    container_name: execmcp
    ports:
      - "7458:7458"
    volumes:
      - ./config.yaml:/etc/execmcp/config.yaml:ro
      - ./logs:/var/log/execmcp
      - ~/.ssh:/home/execmcp/.ssh:ro
    environment:
      - EXECMCP_LOGGING_LEVEL=info
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "wget", "--quiet", "--tries=1", "--spider", "http://localhost:7458/health"]
      interval: 30s
      timeout: 10s
      retries: 3
```

#### 2.3 自定义 Dockerfile

```dockerfile
FROM golang:1.24-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN make build

FROM alpine:latest

RUN apk --no-cache add ca-certificates bash
RUN addgroup -g 1000 execmcp && \
    adduser -D -u 1000 -G execmcp execmcp

WORKDIR /app
COPY --from=builder /app/bin/execmcp .
COPY --from=builder /app/config.example.yaml ./config.example.yaml

RUN chown -R execmcp:execmcp /app
USER execmcp

EXPOSE 7458

CMD ["./execmcp", "--config", "config.yaml"]
```

### 3. Kubernetes 部署

#### 3.1 ConfigMap

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: execmcp-config
data:
  config.yaml: |
    server:
      listen: "0.0.0.0:7458"
      auth_token: "${EXECMCP_AUTH_TOKEN}"

    logging:
      level: "info"
      format: "json"
      output: "stdout"

    ssh:
      hosts:
        - id: "prod-server-1"
          name: "生产服务器 1"
          host: "192.168.1.100"
          port: 22
          user: "admin"
          auth:
            private_key:
              path: "/etc/ssh/keys/id_rsa"
```

#### 3.2 Secret

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: execmcp-secrets
type: Opaque
data:
  # echo -n "your-token" | base64
  auth-token: eW91ci10b2tlbg==
  # echo -n "private-key-content" | base64
  ssh-private-key: cHJpdmF0ZS1rZXktY29udGVudA==
```

#### 3.3 Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: execmcp
spec:
  replicas: 2
  selector:
    matchLabels:
      app: execmcp
  template:
    metadata:
      labels:
        app: execmcp
    spec:
      containers:
      - name: execmcp
        image: terateams/execmcp:latest
        ports:
        - containerPort: 7458
        env:
        - name: EXECMCP_AUTH_TOKEN
          valueFrom:
            secretKeyRef:
              name: execmcp-secrets
              key: auth-token
        volumeMounts:
        - name: config
          mountPath: /etc/execmcp
          readOnly: true
        - name: ssh-keys
          mountPath: /etc/ssh/keys
          readOnly: true
        resources:
          requests:
            memory: "64Mi"
            cpu: "250m"
          limits:
            memory: "128Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health
            port: 7458
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 7458
          initialDelaySeconds: 5
          periodSeconds: 5
      volumes:
      - name: config
        configMap:
          name: execmcp-config
      - name: ssh-keys
        secret:
          secretName: execmcp-secrets
          items:
          - key: ssh-private-key
            path: id_rsa
```

#### 3.4 Service

```yaml
apiVersion: v1
kind: Service
metadata:
  name: execmcp-service
spec:
  selector:
    app: execmcp
  ports:
  - port: 80
    targetPort: 7458
    protocol: TCP
  type: ClusterIP
```

## 配置管理

### 1. 环境变量

```bash
# 服务器配置
export EXECMCP_SERVER_LISTEN="0.0.0.0:7458"
export EXECMCP_SERVER_AUTH_TOKEN="your-token"

# 日志配置
export EXECMCP_LOGGING_LEVEL="info"
export EXECMCP_LOGGING_FORMAT="json"

# 审计配置
export EXECMCP_AUDIT_ENABLED="true"
export EXECMCP_AUDIT_LOG_FILE="/var/log/execmcp/audit.log"
```

### 2. 配置文件

```yaml
# 生产环境配置
server:
  listen: "0.0.0.0:7458"
  auth_token: "${EXECMCP_AUTH_TOKEN}"

logging:
  level: "info"
  format: "json"
  output: "file"
  file:
    path: "/var/log/execmcp/app.log"
    max_size: 100
    max_age: 30
    max_backups: 7
    compress: true

audit:
  enabled: true
  log_file: "/var/log/execmcp/audit.log"
  max_file_size: 100
  max_files: 10
  compress: true

security:
  limits:
    max_output_bytes: 1048576
    max_execution_time: "300s"
    max_concurrent_commands: 20
```

## 安全配置

### 1. 网络安全

```yaml
# 防火墙配置
sudo ufw allow 7458/tcp
sudo ufw enable
```

### 2. SSL/TLS 配置

```yaml
# 使用反向代理 (Nginx)
server {
    listen 443 ssl;
    server_name execmcp.example.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://localhost:7458;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### 3. 认证配置

```yaml
# 使用 JWT 令牌
server:
  auth_token: "${EXECMCP_AUTH_TOKEN}"
  auth_method: "jwt"
  jwt_secret: "${EXECMCP_JWT_SECRET}"
  jwt_expiry: "24h"
```

## 监控和日志

### 1. 健康检查

```bash
# 健康检查端点
curl http://localhost:7458/health
```

### 2. 指标监控

```yaml
# Prometheus 配置
scrape_configs:
  - job_name: 'execmcp'
    static_configs:
      - targets: ['localhost:7458']
    metrics_path: '/metrics'
```

### 3. 日志聚合

```yaml
# 使用 ELK Stack
logging:
  format: "json"
  output: "stdout"

# 或使用 Fluentd
logging:
  format: "json"
  output: "file"
  file:
    path: "/var/log/execmcp/app.log"
```

## 备份和恢复

### 1. 配置备份

```bash
# 备份配置
tar -czf execmcp-config-backup-$(date +%Y%m%d).tar.gz \
  /etc/execmcp/config.yaml \
  /etc/execmcp/ssh-keys \
  /var/log/execmcp
```

### 2. 恢复配置

```bash
# 恢复配置
tar -xzf execmcp-config-backup-20240101.tar.gz -C /
sudo systemctl restart execmcp
```

## 升级

### 1. 二进制升级

```bash
# 下载新版本
wget https://github.com/terateams/ExecMCP/releases/latest/download/execmcp-linux-amd64.tar.gz
tar -xzf execmcp-linux-amd64.tar.gz

# 停止服务
sudo systemctl stop execmcp

# 备份旧版本
sudo cp /opt/execmcp/bin/execmcp /opt/execmcp/bin/execmcp.backup

# 安装新版本
sudo cp execmcp /opt/execmcp/bin/

# 启动服务
sudo systemctl start execmcp
```

### 2. Docker 升级

```bash
# 拉取新镜像
docker pull terateams/execmcp:latest

# 停止并删除旧容器
docker stop execmcp
docker rm execmcp

# 启动新容器
docker run -d \
  --name execmcp \
  -p 7458:7458 \
  -v /etc/execmcp:/etc/execmcp \
  -v /var/log/execmcp:/var/log/execmcp \
  terateams/execmcp:latest
```

## 性能优化

### 1. 系统优化

```bash
# 增加文件描述符限制
echo "* soft nofile 65536" >> /etc/security/limits.conf
echo "* hard nofile 65536" >> /etc/security/limits.conf

# 内核参数优化
echo "net.core.somaxconn = 65536" >> /etc/sysctl.conf
echo "net.ipv4.tcp_max_syn_backlog = 65536" >> /etc/sysctl.conf
sysctl -p
```

### 2. 配置优化

```yaml
# 连接池优化
ssh:
  global:
    max_sessions_per_host: 10
    keep_alive_interval: "30s"

# 资源限制优化
security:
  limits:
    max_output_bytes: 1048576
    max_execution_time: "300s"
    max_concurrent_commands: 50
```

## 故障排除

### 1. 常见问题

```bash
# 查看日志
sudo journalctl -u execmcp -f

# 检查端口占用
sudo netstat -tlnp | grep 7458

# 测试 SSH 连接
ssh -v user@hostname
```

### 2. 性能问题

```bash
# 查看资源使用
ps aux | grep execmcp
top -p $(pidof execmcp)

# 查看网络连接
netstat -an | grep 7458
```

通过遵循本指南，您可以在各种环境中成功部署和管理 ExecMCP 服务。