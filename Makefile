# ExecMCP Makefile
.PHONY: help build clean test coverage lint fmt vet run dev ansible-mcpops

GOCACHE ?= $(CURDIR)/.gocache
export GOCACHE

# 默认目标
help:
	@echo "可用命令:"
	@echo "  build      - 构建项目"
	@echo "  clean      - 清理构建文件"
	@echo "  test       - 运行所有测试"
	@echo "  coverage   - 生成测试覆盖率报告"
	@echo "  lint       - 运行代码检查"
	@echo "  fmt        - 格式化代码"
	@echo "  vet        - 运行静态检查"
	@echo "  run        - 运行服务器"
	@echo "  dev        - 开发模式运行"
	@echo "  ansible-mcpops - 使用 Ansible 在远程主机创建 mcpops 用户"

# 构建项目
build:
	go build -o bin/mcpserver ./cmd/mcpserver

# 清理构建文件
clean:
	rm -rf bin/ coverage.out coverage.html

# 运行所有测试
test:
	go test ./... -v -race

# 生成测试覆盖率报告
coverage:
	go test ./... -coverprofile=coverage.out -covermode=atomic
	go tool cover -html=coverage.out -o coverage.html
	@echo "覆盖率报告已生成: coverage.html"

# 运行代码检查（如果有 golangci-lint）
lint:
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "golangci-lint 未安装，跳过代码检查"; \
	fi

# 格式化代码
fmt:
	go fmt ./...

# 运行静态检查
vet:
	go vet ./...

# 运行服务器
run:
	go run ./cmd/mcpserver --config ./config.yaml

# 开发模式运行
dev:
	go run ./cmd/mcpserver --config ./config.test.yaml

# 安全测试（重点关注边界情况）
test-security-boundary:
	go test ./internal/security -v -race -run=".*Deny.*|.*Blacklist.*|.*Injection.*"

# 性能测试
test-bench:
	go test ./... -bench=. -benchmem

# 运行短测试（跳过集成测试）
test-short:
	go test ./... -v -short

# 并发测试
test-race:
	go test ./... -v -race

# 清理并重新构建
rebuild: clean build

# 完整的 CI 流程
ci: fmt vet test coverage

# 开发前的快速检查
pre-commit: fmt vet test-short

tag:
	@echo "🏷️  开始标签创建流程..."
	@./scripts/tag.sh

# 生产构建（添加优化）
build-prod:
	CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags '-s -w' -o bin/mcpserver-linux ./cmd/mcpserver
	CGO_ENABLED=0 GOOS=darwin go build -a -installsuffix cgo -ldflags '-s -w' -o bin/mcpserver-darwin ./cmd/mcpserver
	CGO_ENABLED=0 GOOS=windows go build -a -installsuffix cgo -ldflags '-s -w' -o bin/mcpserver.exe ./cmd/mcpserver

# 安装开发工具
install-tools:
	@echo "安装开发工具..."
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install github.com/onsi/ginkgo/v2/ginkgo@latest

# 生成文档（如果有 godoc）
docs:
	@if command -v godoc >/dev/null 2>&1; then \
		godoc -http=:6060 & \
		echo "文档服务器启动在: http://localhost:6060"; \
	else \
		echo "godoc 未安装，运行: go install golang.org/x/tools/cmd/godoc@latest"; \
	fi

# 运行示例
example:
	@echo "运行示例配置..."
	@echo "请在另一个终端执行: make dev"
	@echo "然后可以测试 MCP 工具调用"

# 检查依赖
check-deps:
	go mod verify
	go mod tidy

# 更新依赖
update-deps:
	go get -u ./...
	go mod tidy

# 创建发布版本
release: clean build-prod test
	@echo "发布版本构建完成"
	@ls -la bin/

ansible-mcpops:
	ansible-playbook -i ansible/inventory.ini ansible/create_mcpops_user.yml --ask-become-pass $(ANSIBLE_ARGS)

