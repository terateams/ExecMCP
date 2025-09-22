下面是一份可直接给 AI 落地实现的「产品/技术需求说明（PRD + Tech Spec）」——覆盖功能、架构、安全、配置、接口协议、测试与验收要点。目标：在本地跑一个 Go MCP Server，通过 SSE 暴露给 AI Agent 使用；后端使用 golang.org/x/crypto/ssh 连接远程 Linux 主机，提供通用命令执行接口 ExecCommand，支持动态匹配命令，同时具备安全过滤（黑白名单 + 正则）、超时/资源限制与流式输出。

⸻

一、目标与非目标

1.1 目标
    •   项目名称 ExecMCP
	•	在本机启动 MCP Server（SSE），对外暴露**一个或多组工具（Tools）**给 AI Agent。
	•	通过 golang.org/x/crypto/ssh 建立到远程 Linux 主机的 SSH 连接，执行命令并流式返回输出。
	•	提供通用接口 ExecCommand：command + args[] + options（如工作目录、超时、是否分配 PTY、是否通过 shell）。
	•	安全过滤：支持黑名单（denylist）、白名单（allowlist）、正则模式、危险参数检测、默认禁用 shell 特性。
	•	支持多主机与连接复用/池化；可通过 host_id/标签选择目标主机。
	•	可观测性：结构化日志、审计日志（谁在什么时候对哪台主机执行了什么命令、结果如何）。
	•	容错：超时、网络中断、SSH 认证失败、命令不可用等错误要明确分类并友好返回。

1.2 非目标
	•	不是全功能 SSH 终端；不提供交互式 TUI。
	•	不承担文件分发/同步（可留接口扩展 SFTP）。
	•	不做多租户账号系统（先支持单用户或简单 token 验证）。

⸻

二、总体架构

AI Agent  <--MCP (SSE transport)--  本地 mcpserver (Go)
                                       ├── Tools: exec_command, list_commands, test_connection
                                       ├── Security: filter engine (deny/allow/regex/arg checks)
                                       ├── SSH Client Manager (pool, per host)
                                       └── Logger/Audit/Rate limiter

本地 mcpserver  --(x/crypto/ssh)-->  远程 Linux 主机(们)

	•	传输：使用 github.com/mark3labs/mcp-go 的 SSE。
	•	工具（Tools）：
	•	exec_command：通用命令执行。
	•	list_commands：返回允许执行的命令/模板，便于 AI 侧动态匹配。
	•	test_connection：对指定 host_id 做 SSH 健康检查。
	•	资源（Resources，可选）：/etc/os-release、uname -a 缓存为资源供模型检索（可选）。
	•	并发：每个请求开独立 goroutine；限制单机并发阈值。

⸻

三、配置设计

3.1 配置文件（建议 config.yaml）

server:
  bind_addr: "127.0.0.1:7458"         # SSE 对外监听
  log_level: "info"                    # debug|info|warn|error
  max_concurrent: 32                   # 全局并发
  request_timeout_sec: 30              # 默认超时
  auth_token: ""                       # 可选：简单鉴权（MCP 外围）

ssh_hosts:
  - id: "prod-1"
    addr: "10.0.0.11:22"
    user: "ubuntu"
    auth_method: "private_key"         # private_key|password|agent
    private_key_path: "~/.ssh/id_rsa"
    known_hosts: "~/.ssh/known_hosts"  # 或 "insecure_ignore": true（仅开发）
    connect_timeout_sec: 5
    keepalive_sec: 30
    max_sessions: 8

  - id: "staging-1"
    addr: "10.0.1.22:22"
    user: "ec2-user"
    auth_method: "password"
    password: "*****"
    known_hosts: "~/.ssh/known_hosts"
    max_sessions: 4

security:
  default_shell: false                 # 默认不经 shell；走 execve 风格
  allow_shell_for: ["bash","sh"]       # 仅当 command == "bash"/"sh" 且命中白名单模板才允许
  denylist_exact: ["rm", "reboot", "shutdown", "halt", "poweroff", "mkfs", "dd"]
  denylist_regex:
    - "^rm$"
    - "^rm\\..*"                       # 花式别名/变体
    - ".*;.*"                          # 命令串接（在 shell 模式时）
  arg_deny_regex:
    - "-{1,2}force"
    - "-{1,2}no-preserve-root"
    - "--recursive"
    - "/dev/sd[a-z].*"                 # 尝试针对 dd/mkfs 的危险目标
  allowlist_exact: ["ls","cat","tail","head","grep","uname","whoami","uptime","df","du","ps"]
  allowlist_regex:
    - "^(systemctl|journalctl)$"
  working_dir_allow: ["/home","/var/log","/tmp"]
  max_output_bytes: 1048576            # 1MiB：防止内存爆
  enable_pty: false                    # 默认不开 PTY（可在请求 options 覆盖）
  rate_limit_per_min: 120              # MCP 侧简单速率限制

说明：既有黑名单也有白名单，优先级：deny > allow；默认不经 shell，最大限度减少注入面。若必须 shell，需命中 allow_shell_for + 白名单模板。

⸻

四、MCP 工具定义（给 AI 的接口）

4.1 exec_command
	•	描述：在指定主机上执行一个 Linux 命令。默认不经 shell，逐参数传递。
	•	参数（JSON Schema）：

{
  "type": "object",
  "required": ["host_id", "command"],
  "properties": {
    "host_id": { "type": "string", "description": "目标 SSH 主机 ID" },
    "command": { "type": "string", "description": "命令名，如 ls、cat 等" },
    "args": { "type": "array", "items": {"type":"string"}, "default": [] },
    "options": {
      "type": "object",
      "properties": {
        "cwd": { "type": "string" },
        "use_shell": { "type": "boolean", "default": false },
        "allocate_pty": { "type": "boolean", "default": false },
        "timeout_sec": { "type": "integer", "default": 30 },
        "env": { "type": "object", "additionalProperties": {"type":"string"} },
        "stream": { "type": "boolean", "default": true },
        "merge_stderr": { "type": "boolean", "default": true }
      }
    }
  }
}

	•	返回：
	•	流式（推荐）：逐行/逐块通过 MCP 的流通道发送 {chunk, is_stdout, seq}，结束时发送 {exit_code, bytes, truncated}。
	•	一次性：{stdout, stderr, exit_code, truncated, duration_ms}。

4.2 list_commands
	•	描述：返回允许执行的命令集合与模板（便于 AI 动态匹配）。
	•	返回：{ allow_exact:[], allow_regex:[], examples:[] }

4.3 test_connection
	•	描述：对 host_id 做 SSH 探活。
	•	返回：{ ok: true/false, reason, remote_uname, latency_ms }

⸻

五、安全策略（硬原则）
	1.	默认无 shell（use_shell=false），仅当命中白名单模板时才可打开；禁用命令串接（;, &&, || 等）和重定向（>, >>, <, |），通过正则与 tokenizer 拦截。
	2.	黑名单（命令 + 参数）优先：如 rm、dd、mkfs、shutdown、reboot 一票否决；参数层面禁 --no-preserve-root、--recursive、可疑 block 设备。
	3.	工作目录白名单：options.cwd 仅允许在配置中的目录前缀内；否则拒绝。
	4.	输出限额：达到 max_output_bytes 立即截断并标注 truncated=true。
	5.	超时：超时达成后向远端发 session.Signal(ssh.SIGKILL)（或 SIGTERM→SIGKILL 双阶段），随后 Close。
	6.	禁止环境变量污染：仅允许白名单环境变量键（可在配置追加 env_allow_keys，默认关闭）。
	7.	审计日志：记录 timestamp, requester, host_id, command, args, options, decision(allow|deny), exit_code, bytes, duration, truncated。
	8.	连接安全：优先启用 known_hosts 校验；开发阶段可 InsecureIgnoreHostKey，但需在日志中强提示。
	9.	速率限制：全局 + 每主机；触发后返回 429 风格错误。
	10.	非 PTY 默认：避免远端命令产生复杂交互；仅在明确需要时打开。

⸻

六、实现要点（Go 代码骨架）

下述为核心结构与关键路径，便于 AI 直接编码。无需一字不差，意图清晰即可。

6.1 主要包结构

/cmd/mcpserver/main.go
/internal/config/config.go
/internal/ssh/manager.go        # 连接管理、池化、session 获取/释放
/internal/execsvc/service.go    # ExecCommand 业务逻辑 + 流式读取
/internal/security/filter.go    # 黑白名单与参数/路径/正则校验
/internal/mcp/server.go         # mcp-go 集成（SSE transport，tools 注册）
/internal/logging/logger.go

6.2 SSH 连接管理（示意）
	•	每个 host_id 对应一个 *ssh.Client 池（或单连接 + 并发 session）。
	•	manager.GetSession(hostID) → 返回活跃 *ssh.Session（含 StdoutPipe/StderrPipe）。

6.3 过滤引擎（核心逻辑）

type ExecRequest struct {
  HostID  string
  Command string
  Args    []string
  Options ExecOptions
}

func (f *Filter) Check(req ExecRequest) error {
  // 1) 空/非法字符 → 拒绝
  // 2) command 命中 denylist_exact/regex → 拒绝
  // 3) args 拼接后逐项匹配 arg_deny_regex → 拒绝
  // 4) use_shell == true：
  //    - 检查 command ∈ allow_shell_for
  //    - 检查整串没有 ; | && || > >> < 等（或只允许在受控模板内）
  // 5) cwd 路径在 working_dir_allow 前缀内
  // 6) 若设置 allowlist：command 不在 allowlist 且不命中 allowlist_regex → 拒绝
  // 7) 通过 → OK
}

6.4 执行与流式读取（非 PTY）

session.StdoutPipe() -> goroutine scan lines -> SSE stream
session.StderrPipe() -> 合并/分流（按 options.merge_stderr）
ctx 超时 -> 发送信号 -> 关闭
累计字节数，超过 max_output_bytes -> 截断并结束

6.5 MCP 集成（SSE）
	•	使用 mark3labs/mcp-go：
	•	初始化 SSE transport，注册工具 schema。
	•	exec_command handler：解析参数 → Filter.Check → 拿 session → 执行 → 流式写入 ToolResponseStream。
	•	统一错误映射：ErrDenied（403）、ErrTimeout（408）、ErrTooLarge（413/206）、ErrRateLimited（429）、ErrSSH（502/504）。

⸻

七、错误与返回规范
	•	分类：
	•	SECURITY_DENY：命中黑名单/不符合白名单/非法 shell → code=SECURITY_DENY
	•	TIMEOUT：超时被终止 → code=TIMEOUT
	•	OUTPUT_TRUNCATED：超过输出上限 → truncated=true
	•	SSH_CONNECT_ERROR / SSH_AUTH_ERROR / SSH_SESSION_ERROR
	•	RATE_LIMITED：速率超限
	•	错误载荷（建议）：

{
  "error": {
    "code": "SECURITY_DENY",
    "message": "command 'rm' is not allowed",
    "details": { "rule": "denylist_exact" }
  }
}


⸻

八、测试计划（必须覆盖）

8.1 安全/功能单测
	•	rm, dd, mkfs 等命令直接拒绝。
	•	ls、cat 等在允许目录内可执行；越界 cwd 拒绝。
	•	use_shell=true 时携带 ;、&&、管道 |、重定向符号 → 拒绝。
	•	危险参数（--no-preserve-root、--recursive 等）→ 拒绝。
	•	输出 > max_output_bytes → 截断 + 标记。
	•	超时触发后，远端进程被终止（验证 exit code/信号）。
	•	PTY=false/true 行为差异：交互命令（如 sudo 无 TTY）应报错而非卡死。

8.2 连接与恢复
	•	SSH 断线自动重连（或优雅失败 + 可重试提示）。
	•	known_hosts 校验通过/失败两种分支。

8.3 并发与限流
	•	大量并发请求不崩溃；超过阈值返回 RATE_LIMITED。

8.4 端到端集成
	•	启动 mcpserver → 用示例 Agent（或 curl SSE）调用 exec_command、list_commands、test_connection。
	•	审计日志包含完整字段；敏感信息（密码/私钥）不落盘。

⸻

九、示例调用（AI 侧提示）

exec_command（非 shell，安全）

{
  "tool_name": "exec_command",
  "arguments": {
    "host_id": "prod-1",
    "command": "ls",
    "args": ["-la", "/var/log"],
    "options": { "cwd": "/var/log", "timeout_sec": 10, "stream": true }
  }
}

exec_command（需要 shell 的安全模板，必须命中 allow_shell_for）

{
  "tool_name": "exec_command",
  "arguments": {
    "host_id": "prod-1",
    "command": "bash",
    "args": ["-lc", "journalctl -n 100 --no-pager"],
    "options": { "use_shell": true, "timeout_sec": 15, "merge_stderr": true }
  }
}

list_commands

{"tool_name":"list_commands","arguments":{}}

test_connection

{"tool_name":"test_connection","arguments":{"host_id":"prod-1"}}


⸻

十、运行与部署（本地开发）
	•	运行：
	•	go run ./cmd/mcpserver --config ./config.yaml
	•	健康检查：
	•	日志打印 SSE listening on 127.0.0.1:7458 ...
	•	开发模式：
	•	可暂时启用 InsecureIgnoreHostKey，但日志必须 WARNING。
	•	观测：
	•	日志：JSON 行，字段见审计清单。
	•	可选：Prometheus 指标（请求量、时延、拒绝/错误计数）。

⸻

十一、可扩展方向（留钩子）
	•	SFTP 上传/下载（独立工具，具备目录白名单与大小限制）。
	•	多租户鉴权（JWT / API Key，映射到不同的 host 集）。
	•	命名空间/容器执行：对接远端 nsenter 或容器 runtime（安全评估另做）。
	•	命令模板：把常用场景固化为模板 + 参数化（进一步降低 shell 暴露）。

⸻

十二、给 AI 的实现提示（编码要点）
	1.	先实现配置解析与 SSH 连接管理（含 known_hosts 校验）。
	2.	写好 filter.Check，TDD 优先：先把安全单测跑通。
	3.	接入 mcp-go，注册 exec_command/list_commands/test_connection，走最小 happy path。
	4.	做好流式输出与截断、超时终止。
	5.	打通审计日志、错误分类。
	6.	完成并发/限流，再补全 PTY 与 shell 的受限场景。

⸻

十三、灵魂拷问（帮你规避后悔药）
	1.	你的业务里真的需要 shell 吗？如果只跑标准命令，完全可以禁用 shell，风险瞬间少一半。
	2.	cwd 与文件路径必须限制吗？如果 AI 能任意指定路径，你就等于开放了半个系统。
	3.	谁来访问这个 MCP 接口？若是多方 Agent，是否需要鉴权与配额？
	4.	审计日志要保存多久？是否涉及合规（比如记录敏感命令操作）？
	5.	如果远端主机多，是否需要标签与路由规则（如 prod/* 只允许只读类命令）？

⸻

