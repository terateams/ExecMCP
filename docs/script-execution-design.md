# 定制脚本执行功能设计

## 功能概述

新增 `exec_script` MCP 工具，支持在配置文件中预定义脚本模板，AI Agent 可以通过配置的脚本名称执行预设的命令，同时支持动态参数替换。

## 设计原则

1. **配置驱动**: 脚本模板在配置文件中定义
2. **参数安全**: 支持安全的参数替换和验证
3. **AI友好**: Prompt 从配置中自动读取，便于 AI 理解
4. **权限控制**: 脚本执行遵循现有安全规则

## 配置结构扩展

### 新增脚本配置段

```yaml
# 在 config.yaml 中新增
scripts:
  - name: "check_disk_usage"
    description: "检查磁盘使用情况，支持指定路径和阈值"
    prompt: "检查指定路径的磁盘使用情况，如果使用率超过阈值则告警"
    template: "df -h {path} | awk 'NR>1 && $5+0 > {threshold} {print $6 \": \" $5 \" 使用率过高\"}'"
    parameters:
      - name: "path"
        type: "string"
        required: true
        default: "/"
        description: "要检查的路径"
        validation: "^[a-zA-Z0-9/_-]+$"
      - name: "threshold"
        type: "integer"
        required: false
        default: 80
        description: "使用率阈值百分比"
        validation: "^[0-9]+$"
    allowed_hosts: ["prod-*", "staging-*"]
    timeout_sec: 30
    use_shell: true

  - name: "find_large_files"
    description: "查找大文件"
    prompt: "在指定目录下查找大于指定大小的文件"
    template: "find {directory} -type f -size +{size_min} -exec ls -lh {} \\;"
    parameters:
      - name: "directory"
        type: "string"
        required: true
        default: "/var/log"
        description: "搜索目录"
      - name: "size_min"
        type: "string"
        required: false
        default: "100M"
        description: "最小文件大小"
    allowed_hosts: ["*"]
    working_dir: "/"
```

### 脚本配置字段说明

- **name**: 脚本唯一标识符
- **description**: 脚本功能描述
- **prompt**: AI Agent 使用的提示信息
- **template**: 命令模板，支持 `{参数名}` 占位符
- **parameters**: 参数定义列表
- **allowed_hosts**: 允许执行的主机模式（支持通配符）
- **timeout_sec**: 脚本执行超时时间
- **use_shell**: 是否使用 shell 执行
- **working_dir**: 工作目录

### 参数定义

```yaml
parameters:
  - name: "参数名"
    type: "string|integer|boolean"  # 参数类型
    required: true|false            # 是否必需
    default: "默认值"               # 默认值
    description: "参数描述"         # 参数说明
    validation: "正则表达式"        # 参数验证规则
```

## MCP 工具接口

### exec_script

**请求格式**:
```json
{
  "tool_name": "exec_script",
  "arguments": {
    "host_id": "prod-1",
    "script_name": "check_disk_usage",
    "parameters": {
      "path": "/var/log",
      "threshold": 85
    },
    "options": {
      "timeout_sec": 30,
      "stream": true
    }
  }
}
```

**响应格式**:
```json
{
  "success": true,
  "script_name": "check_disk_usage",
  "executed_command": "df -h /var/log | awk 'NR>1 && $5+0 > 85 {print $6 \": \" $5 \" 使用率过高\"}'",
  "exit_code": 0,
  "stdout": "/var/log: 92% 使用率过高\n",
  "stderr": "",
  "duration_ms": 456,
  "truncated": false
}
```

## 实现要点

### 1. 参数替换

实现安全的参数替换机制：
- 转义特殊字符
- 验证参数值
- 处理默认值
- 类型转换

```go
func (s *ScriptService) RenderTemplate(template string, params map[string]interface{}) (string, error) {
    // 参数验证和转义
    // 模板渲染
    // 返回最终命令
}
```

### 2. 脚本发现

提供脚本发现接口：
```go
func (s *ScriptService) ListScripts() []ScriptInfo {
    // 返回可用脚本列表，包含 name, description, prompt
}
```

### 3. 权限验证

- 验证脚本是否存在
- 验证主机是否在 allowed_hosts 中
- 应用现有安全过滤规则

## 安全考虑

### 1. 模板安全
- 参数必须经过验证和转义
- 禁止在模板中使用 shell 元字符（除非 use_shell=true）
- 限制复杂命令的执行

### 2. 参数验证
- 使用正则表达式验证参数格式
- 类型检查和范围验证
- 防止路径遍历攻击

### 3. 主机限制
- 脚本级别的主机访问控制
- 支持通配符模式匹配
- 默认拒绝策略

## 使用示例

### 场景1：磁盘空间检查
```json
{
  "tool_name": "exec_script",
  "arguments": {
    "host_id": "prod-1",
    "script_name": "check_disk_usage",
    "parameters": {
      "path": "/var/log",
      "threshold": 90
    }
  }
}
```

### 场景2：日志分析
```json
{
  "tool_name": "exec_script",
  "arguments": {
    "host_id": "staging-1",
    "script_name": "analyze_logs",
    "parameters": {
      "log_file": "/var/log/app.log",
      "error_pattern": "ERROR",
      "hours": 24
    }
  }
}
```

## 集成计划

1. **配置扩展**: 更新配置结构支持脚本定义
2. **脚本管理**: 实现 ScriptService 处理脚本逻辑
3. **MCP集成**: 注册 exec_script 工具
4. **参数验证**: 实现安全的参数替换机制
5. **测试覆盖**: 编写脚本执行相关的测试
6. **文档更新**: 更新 API 文档和使用示例