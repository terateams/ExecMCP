# SSH 包设计文档

## 概述

SSH 包提供了统一的 SSH 连接管理功能，支持真实 SSH 连接和模拟测试环境。

## 文件结构

- `manager.go` - 核心 SSH 管理器接口和真实实现
- `mock.go` - 模拟 SSH 实现，用于测试

## 接口设计

### Manager 接口
```go
type Manager interface {
    GetSession(hostID string) (Session, error)
    ReleaseSession(hostID string, session Session)
    Close()
    HealthCheck(hostID string) error
}
```

### Session 接口
```go
type Session interface {
    ExecuteCommand(command string, args []string, enablePTY bool) (string, error)
    Close()
}
```

## 使用方式

### 生产环境使用真实 SSH 管理器
```go
manager := ssh.NewManager(cfg, logger)
session, err := manager.GetSession("host-id")
// ...
```

### 测试环境使用模拟管理器
```go
manager := ssh.NewMockManager(cfg)
session, err := manager.GetSession("host-id")
// ...
```

## 设计优势

1. **接口分离**: 通过接口抽象，生产代码和测试代码使用相同的接口
2. **文件分离**: Mock 代码独立在单独文件中，不污染生产代码
3. **易于测试**: 测试时可以轻松替换为模拟实现
4. **清晰结构**: 真实实现和模拟实现各司其职
