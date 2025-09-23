# 开发指南

本文档提供了 ExecMCP 的开发指南，包括环境设置、开发流程、测试方法等。

## 开发环境设置

### 1. 前置要求

- Go 1.24+
- Git
- Make
- Docker (可选，用于容器化开发)

### 2. 克隆项目

```bash
git clone https://github.com/terateams/ExecMCP.git
cd ExecMCP
```

### 3. 依赖安装

```bash
# 下载 Go 依赖
go mod download

# 验证依赖
go mod verify
```

### 4. 开发工具

```bash
# 安装开发工具
go install golang.org/x/tools/cmd/goimports@latest
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
```

## 项目结构

```
ExecMCP/
├── main.go                    # 程序入口点
├── cmd/
│   └── mcptest/              # 测试客户端
├── internal/
│   ├── audit/                # 审计日志
│   ├── common/               # 通用工具
│   ├── config/               # 配置管理
│   ├── execsvc/              # 执行服务
│   ├── logging/              # 日志系统
│   ├── mcp/                  # MCP 协议处理
│   ├── security/             # 安全过滤
│   ├── ssh/                  # SSH 管理
│   └── testutils/            # 测试工具
├── docs/                     # 文档
├── scripts/                  # 脚本
├── config.example.yaml      # 配置示例
├── config.test.yaml         # 测试配置
├── Makefile                 # 构建脚本
├── go.mod                   # Go 模块
├── go.sum                   # 依赖校验
└── README.md               # 项目说明
```

## 开发工作流

### 1. 创建分支

```bash
git checkout -b feature/your-feature-name
```

### 2. 开发

```bash
# 运行开发服务器
make dev

# 运行测试
make test

# 代码检查
make lint
```

### 3. 提交代码

```bash
# 检查代码格式
make fmt

# 运行完整测试
make test

# 提交更改
git add .
git commit -m "feat: 添加新功能"
```

### 4. 推送分支

```bash
git push origin feature/your-feature-name
```

## 构建

### 1. 本地构建

```bash
# 构建开发版本
make build

# 构建生产版本
make build-prod
```

### 2. 交叉编译

```bash
# 构建多平台版本
make build-all

# 构建特定平台
make build-linux
make build-darwin
make build-windows
```

### 3. Docker 构建

```bash
# 构建 Docker 镜像
make docker-build

# 运行 Docker 容器
make docker-run
```

## 测试

### 1. 单元测试

```bash
# 运行所有测试
make test

# 运行特定包测试
go test ./internal/security -v

# 运行特定测试
go test -run TestSecurityFilter ./internal/security -v
```

### 2. 集成测试

```bash
# 运行集成测试
make test-integration

# 运行安全边界测试
make test-security-boundary
```

### 3. 测试覆盖率

```bash
# 生成覆盖率报告
make coverage

# 查看覆盖率报告
go tool cover -html=coverage.out
```

### 4. 性能测试

```bash
# 运行基准测试
make benchmark

# 运行内存分析
make profile
```

## 代码规范

### 1. Go 代码风格

- 使用 `gofmt` 格式化代码
- 遵循 Go 官方代码规范
- 使用 `golangci-lint` 进行代码检查

### 2. 命名规范

- 包名使用小写
- 函数名使用驼峰命名
- 常量使用大写加下划线
- 错误变量以 `Err` 开头

### 3. 错误处理

```go
// 好的错误处理
if err != nil {
    return fmt.Errorf("操作失败: %w", err)
}

// 错误包装
if err != nil {
    return NewSecurityError("安全验证失败", err)
}
```

### 4. 日志记录

```go
// 结构化日志
logger.Info("命令执行开始",
    "command", req.Command,
    "host_id", req.HostID,
    "request_id", req.RequestID,
)
```

## 调试

### 1. 日志调试

```bash
# 启用调试日志
make dev LOG_LEVEL=debug

# 查看日志
tail -f /var/log/execmcp.log
```

### 2. 远程调试

```bash
# 使用 delve 调试
go install github.com/go-delve/delve/cmd/dlv@latest
dlv debug ./cmd/mcpserver
```

### 3. 性能分析

```bash
# CPU 分析
go tool pprof cpu.out

# 内存分析
go tool pprof mem.out
```

## 配置管理

### 1. 开发配置

使用 `config.test.yaml` 进行开发：

```yaml
# config.test.yaml
server:
  listen: "127.0.0.1:7458"
  auth_token: "dev-token"

logging:
  level: "debug"
  format: "text"
```

### 2. 环境变量

```bash
# 设置开发环境变量
export EXECMCP_LOGGING_LEVEL=debug
export EXECMCP_AUDIT_ENABLED=false
```

## CI/CD

### 1. GitHub Actions

项目使用 GitHub Actions 进行持续集成：

- **代码检查**: `fmt`, `vet`, `lint`
- **测试**: 单元测试、集成测试
- **覆盖率**: 生成覆盖率报告
- **构建**: 多平台构建
- **部署**: Docker 镜像构建和推送

### 2. 本地 CI

```bash
# 运行完整 CI 流程
make ci

# 运行特定 CI 步骤
make fmt
make vet
make test
make coverage
```

## 常见问题

### 1. 依赖问题

```bash
# 清理依赖缓存
go clean -modcache
go mod download
```

### 2. 测试失败

```bash
# 更新测试依赖
go test -update ./...

# 运行详细测试
go test -v -race ./...
```

### 3. 构建问题

```bash
# 清理构建缓存
go clean -cache
make build
```

## 贡献指南

### 1. 代码贡献

1. Fork 项目
2. 创建功能分支
3. 编写代码和测试
4. 运行测试和检查
5. 提交 Pull Request

### 2. 文档贡献

1. 更新相关文档
2. 确保文档准确性
3. 添加必要的示例

### 3. 问题报告

1. 使用 GitHub Issues
2. 提供复现步骤
3. 包含环境信息

## 发布流程

### 1. 版本管理

使用语义化版本控制：

- 主版本号：不兼容的 API 修改
- 次版本号：向下兼容的功能性新增
- 修订号：向下兼容的问题修正

### 2. 发布步骤

```bash
# 更新版本号
git tag v1.0.0

# 构建发布版本
make build-prod

# 推送标签
git push origin v1.0.0
```

### 3. 更新日志

维护 `CHANGELOG.md` 文件，记录每个版本的变更。

## 性能优化

### 1. 连接池优化

```go
// 配置连接池大小
ssh:
  global:
    max_sessions_per_host: 10
```

### 2. 内存优化

```go
// 限制输出大小
limits:
  max_output_bytes: 1048576
```

### 3. 并发优化

```go
// 配置并发限制
limits:
  max_concurrent_commands: 20
```

通过遵循本指南，您可以高效地开发和维护 ExecMCP 项目。