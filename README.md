# ExecMCP

[![Test](https://github.com/terateams/ExecMCP/actions/workflows/test.yml/badge.svg)](https://github.com/terateams/ExecMCP/actions/workflows/test.yml)
[![Docker Release](https://github.com/terateams/ExecMCP/actions/workflows/docker-release.yml/badge.svg)](https://github.com/terateams/ExecMCP/actions/workflows/docker-release.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/terateams/ExecMCP)](https://goreportcard.com/report/github.com/terateams/ExecMCP)
[![Coverage](https://codecov.io/gh/terateams/ExecMCP/branch/main/graph/badge.svg)](https://codecov.io/gh/terateams/ExecMCP)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Docker Pulls](https://img.shields.io/docker/pulls/terateams/execmcp)](https://hub.docker.com/r/terateams/execmcp)

安全优先的 Go 语言 MCP (Model Context Protocol) 服务器，通过 SSH 为 Linux 主机提供安全的远程命令执行服务。

## ✨ 核心特性

- **🔒 安全优先**: 多层过滤、默认拒绝策略、无 Shell 默认
- **🚀 高性能**: SSH 连接池、流式输出、并发处理
- **🛠️ 易于集成**: MCP 协议、SSE 传输、配置驱动
- **📋 完整审计**: 所有操作记录和追踪

## 🚀 快速开始

### 安装要求

- Go 1.24+
- 远程 Linux 主机访问权限
- SSH 密钥或密码认证

### 下载和构建

```bash
# 克隆项目
git clone https://github.com/terateams/ExecMCP.git
cd ExecMCP

# 构建项目
make build

# 开发模式运行
make dev

# 生产模式运行
make run
```

### 基本配置

1. 复制配置文件模板：

   ```bash
   cp config.example.yaml config.yaml
   ```

2. 编辑 `config.yaml` 配置 SSH 主机和安全规则

3. 启动服务器：

   ```bash
   ./bin/mcpserver --config config.yaml
   ```

## 📚 文档

详细文档请查看 `docs/` 目录：

- [配置指南](docs/configuration.md) - 完整配置说明
- [安全机制](docs/security.md) - 安全过滤和审计
- [开发指南](docs/development.md) - 开发和测试
- [MCP 工具](docs/mcp-tools.md) - MCP 接口说明
- [Docker 部署](docs/deployment.md) - 容器化部署

## 🛠️ 开发

```bash
# 运行测试
make test

# 生成覆盖率报告
make coverage

# 代码检查
make lint

# 完整 CI 流程
make ci
```

## 🔧 MCP 工具

服务器提供以下 MCP 工具：

- `exec_command` - 执行安全过滤的命令
- `exec_script` - 执行预定义脚本
- `list_commands` - 查看可用命令
- `test_connection` - 测试主机连接
- `list_hosts` - 列出配置的主机

## 📄 许可证

MIT License - 详见 [LICENSE](LICENSE) 文件

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

---

**注意**: 本项目设计用于安全的远程命令执行，请仔细配置安全规则并遵循最佳实践。
