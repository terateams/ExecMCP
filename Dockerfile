# 多阶段构建，优化镜像大小和安全性
FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS builder

# 设置工作目录
WORKDIR /app

# 安装必要的构建工具
RUN apk add --no-cache git ca-certificates

# 复制 go mod 文件
COPY go.mod go.sum ./

# 下载依赖
RUN go mod download

# 复制源代码
COPY . .

# 构建应用，支持多架构
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
    -ldflags="-w -s" \
    -o /execmcp \
    .

# 最终镜像
FROM --platform=$TARGETPLATFORM alpine:3.21

# 安装必要的运行时依赖
RUN apk add --no-cache ca-certificates openssh-client && \
    rm -rf /var/cache/apk/*

# 创建非 root 用户
RUN addgroup -g 1000 -S appuser && \
    adduser -u 1000 -S appuser -G appuser

# 设置工作目录
WORKDIR /app

# 从构建阶段复制二进制文件
COPY --from=builder /execmcp /usr/local/bin/execmcp

# 创建配置目录
RUN mkdir -p /etc/execmcp /var/log/execmcp && \
    chown -R appuser:appuser /app /etc/execmcp /var/log/execmcp

# 切换到非 root 用户
USER appuser

# 暴露端口
EXPOSE 7458

# 默认命令
CMD ["/usr/local/bin/execmcp", "--config", "/etc/execmcp/config.yaml"]