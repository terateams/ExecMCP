# ExecMCP 敏感信息泄露审计报告

**版本**: 2.0  
**日期**: 2025-01-23  
**审计范围**: 敏感信息泄露风险评估与修复  
**审计目标**: 识别并修复可能导致敏感信息泄露的代码路径，确保密码、密钥、认证凭据等敏感数据的安全处理

## 执行摘要

本次审计专门针对 ExecMCP 项目中潜在的敏感信息泄露风险进行深入分析，发现并修复了 6 项安全问题。主要问题集中在日志记录、错误消息和配置处理中可能暴露的敏感信息。所有发现的问题已通过实施数据脱敏、日志清理和错误消息净化等措施得到有效修复。

## 发现问题与修复措施

### 1. SSH 私钥路径在日志中完整暴露（中危）

**位置**: `internal/ssh/manager.go:263`  
**问题**: 配置私钥认证成功时，完整的私钥文件路径被记录到日志中  
**风险**: 攻击者通过日志可以推断系统的目录结构和私钥存储位置  

**修复措施**:
```go
// 修复前：
m.logger.Debug("配置私钥认证成功", "host_id", hostConfig.ID, "key_path", keyPath)

// 修复后：
keyName := filepath.Base(keyPath)
m.logger.Debug("配置私钥认证成功", "host_id", hostConfig.ID, "key_file", keyName)
```

### 2. 命令执行日志暴露敏感参数（高危）

**位置**: `internal/ssh/manager.go:406, 418, 432`  
**问题**: SSH 命令执行时，完整的命令和参数（包括密码、token、密钥等）被记录到日志  
**风险**: 敏感认证信息直接暴露在日志文件中  

**修复措施**:
- 实现了 `sanitizeCommandForLogging()` 函数对命令进行脱敏
- 识别并替换常见的敏感参数：`--password`, `--token`, `--secret`, `--key`, `--auth-token` 等
- 支持 `param=value` 和 `param value` 两种格式的参数脱敏
- 敏感值统一替换为 `[REDACTED]` 标记

**脱敏示例**:
```bash
# 原命令
mysql -u admin --password secretpass123 -h localhost

# 脱敏后
mysql -u admin --password [REDACTED] -h localhost
```

### 3. 错误消息中泄露敏感路径信息（中危）

**位置**: `internal/ssh/manager.go:274, 283`  
**问题**: 密码配置错误时，环境变量名和文件路径完整暴露在错误消息中  
**风险**: 通过错误消息可以推断系统配置和文件结构  

**修复措施**:
```go
// 修复前：
return fmt.Errorf("从环境变量 %s 读取密码失败", envKey)
return fmt.Errorf("密码文件 %s 内容为空", filePath)

// 修复后：
return fmt.Errorf("从环境变量读取密码失败")
return fmt.Errorf("密码文件内容为空")
```

### 4. 命令错误日志暴露标准错误输出（中危）

**位置**: `internal/ssh/manager.go:427`  
**问题**: 命令执行失败时，完整的 stderr 内容被包含在错误消息中返回  
**风险**: stderr 可能包含敏感的系统信息或错误详情  

**修复措施**:
```go
// 修复前：
return "", fmt.Errorf("命令执行失败: %w, stderr: %s", err, stderr.String())

// 修复后：
return "", fmt.Errorf("命令执行失败: %w", err)
// stderr 长度仍记录但内容不暴露：
"stderr_length", stderr.Len()
```

### 5. MCP 接口日志暴露详细参数信息（低危）

**位置**: `internal/mcp/mcp_server.go:251, 317`  
**问题**: 命令和脚本执行请求的完整参数被记录到日志  
**风险**: 可能在参数中包含敏感信息  

**修复措施**:
```go
// 修复前：
m.logger.Info("收到命令执行请求", "host_id", hostID, "command", command, "args", argsStr, "use_shell", useShell)
m.logger.Info("收到脚本执行请求", "host_id", hostID, "script_name", scriptName, "parameters", parameters)

// 修复后：
m.logger.Info("收到命令执行请求", "host_id", hostID, "command", command, "args_count", len(argsStr), "use_shell", useShell)
m.logger.Info("收到脚本执行请求", "host_id", hostID, "script_name", scriptName, "parameter_count", len(parameters))
```

### 6. 确认 MCP API 响应安全性（已验证安全）

**位置**: `internal/mcp/mcp_server.go:488-494`  
**验证结果**: `handleListHosts` 函数仅返回非敏感的主机元数据：
- 主机 ID
- 认证类型（不包含具体凭据）
- 连接超时配置
- 会话限制配置

**不暴露的敏感信息**:
- 主机地址和端口
- 用户名
- 密码或私钥路径
- known_hosts 路径

## 安全测试验证

新增了专门的安全测试 `internal/ssh/sanitize_test.go`，包含以下测试场景：
- 普通命令不受影响
- 各种格式的敏感参数正确脱敏
- 参数值包含敏感关键词的处理
- 边界条件测试（空命令、单个命令等）
- 确保敏感信息完全移除

测试覆盖的敏感参数类型：
- 密码相关：`--password`, `-p`, `--passwd`, `--pwd`
- 认证相关：`--token`, `--auth-token`, `--bearer`, `--auth`
- 密钥相关：`--key`, `--secret`, `--private-key`, `--passphrase`
- 凭据相关：`--credentials`

## 合规性改进

### 数据最小化原则
- 日志中仅记录必要的元数据（参数数量、长度等）
- 敏感值统一使用 `[REDACTED]` 标记替代

### 防御性编程
- 错误消息不暴露内部路径和配置细节
- API 响应遵循最小权限原则

### 审计友好性
- 保留足够的上下文信息用于故障排查
- 脱敏后的日志仍具有可读性和调试价值

## 后续建议

### 运维层面
1. **日志管理**: 定期审查日志文件，确保没有遗漏的敏感信息
2. **访问控制**: 限制对日志文件的访问权限
3. **日志轮转**: 设置合理的日志保留策略

### 开发层面
1. **代码审查**: 在代码审查中特别关注新增的日志语句
2. **安全测试**: 将敏感信息泄露检查纳入 CI/CD 流程
3. **开发培训**: 提高开发团队对敏感信息处理的意识

### 监控层面
1. **异常检测**: 监控日志中是否出现明文敏感信息
2. **合规审计**: 定期进行敏感信息泄露风险评估
3. **自动化扫描**: 考虑集成静态代码分析工具检测敏感信息泄露

## 验证清单

- [x] SSH 私钥路径脱敏处理
- [x] 命令参数敏感信息脱敏
- [x] 错误消息敏感路径移除  
- [x] stderr 内容不暴露在返回值中
- [x] MCP 接口参数日志优化
- [x] MCP API 响应安全性验证
- [x] 安全测试用例完整覆盖
- [x] 所有修复措施通过测试验证

## 风险评估更新

| 风险类型 | 修复前等级 | 修复后等级 | 备注 |
|---------|-----------|-----------|------|
| 敏感参数暴露 | 高危 | 低危 | 通过命令脱敏大幅降低风险 |
| 路径信息泄露 | 中危 | 极低 | 错误消息已净化 |
| 配置信息暴露 | 中危 | 极低 | API响应已验证安全 |
| 系统信息泄露 | 中危 | 低危 | stderr内容不再暴露 |

**总体风险等级**: 从 **中危** 降低至 **低危**

## 结论

通过本次专项审计和修复，ExecMCP 项目在敏感信息保护方面得到了显著改善。所有发现的敏感信息泄露风险都已得到有效控制，系统的整体安全性得到提升。建议在未来的开发过程中继续保持对敏感信息处理的高度关注，并定期进行类似的安全审计。