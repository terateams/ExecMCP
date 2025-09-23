package security

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/terateams/ExecMCP/internal/audit"
	"github.com/terateams/ExecMCP/internal/config"
	"github.com/terateams/ExecMCP/internal/logging"
)

// Filter 安全过滤器
type Filter struct {
	config         *config.SecurityConfig
	logger         logging.Logger
	audit          audit.Logger
	denylistRegex  []compiledPattern
	argDenyRegex   []compiledPattern
	allowlistRegex []compiledPattern
}

type compiledPattern struct {
	pattern string
	re      *regexp.Regexp
}

// ExecRequest 执行请求
type ExecRequest struct {
	HostID  string
	Command string
	Args    []string
	Options ExecOptions
}

// ExecOptions 执行选项
type ExecOptions struct {
	CWD         string            `json:"cwd"`
	UseShell    bool              `json:"use_shell"`
	TimeoutSec  int               `json:"timeout_sec"`
	Env         map[string]string `json:"env"`
	Stream      bool              `json:"stream"`
	MergeStderr bool              `json:"merge_stderr"`
}

// NewFilter 创建新的安全过滤器
func NewFilter(cfg *config.SecurityConfig, logger logging.Logger, auditLogger audit.Logger) *Filter {
	if auditLogger == nil {
		auditLogger = audit.NewNoopLogger()
	}
	return &Filter{
		config:         cfg,
		logger:         logger,
		audit:          auditLogger,
		denylistRegex:  compilePatterns(cfg.DenylistRegex),
		argDenyRegex:   compilePatterns(cfg.ArgDenyRegex),
		allowlistRegex: compilePatterns(cfg.AllowlistRegex),
	}
}

func (f *Filter) logSecurityDeny(ctx context.Context, rule, reason string, req ExecRequest, metadata map[string]interface{}) {
	if metadata == nil {
		metadata = map[string]interface{}{}
	}

	fields := []interface{}{"rule", rule, "reason", reason, "host_id", req.HostID, "command", req.Command}
	for k, v := range metadata {
		fields = append(fields, k, v)
	}
	if f.logger != nil {
		f.logger.Warn("安全策略拒绝", fields...)
	}

	if f.audit != nil && f.audit.Enabled() {
		auditMeta := map[string]interface{}{
			"args":        append([]string(nil), req.Args...),
			"use_shell":   req.Options.UseShell,
			"cwd":         req.Options.CWD,
			"timeout_sec": req.Options.TimeoutSec,
		}
		for k, v := range metadata {
			auditMeta[k] = v
		}

		f.audit.LogEvent(ctx, audit.Event{
			Category: "security_filter",
			Type:     "command_denied",
			HostID:   req.HostID,
			Target:   req.Command,
			Outcome:  audit.OutcomeDenied,
			Severity: audit.SeverityMedium,
			Rule:     rule,
			Reason:   reason,
			Metadata: auditMeta,
		})
	}
}

// Check 按照配置逐层校验命令：先阻断黑名单、危险参数，再根据 shell 使用约束及白名单决定是否放行。
func (f *Filter) Check(ctx context.Context, req ExecRequest) error {
	// 1. 检查空命令
	if req.Command == "" {
		return &SecurityError{
			Code:    "EMPTY_COMMAND",
			Message: "命令不能为空",
		}
	}

	// 2. 检查精确黑名单
	for _, deniedCmd := range f.config.DenylistExact {
		if req.Command == deniedCmd {
			f.logSecurityDeny(ctx, "denylist_exact", "命令命中精确黑名单", req, map[string]interface{}{})
			return &SecurityError{
				Code:    "SECURITY_DENY",
				Message: fmt.Sprintf("命令 '%s' 被安全规则禁止", req.Command),
				Details: map[string]interface{}{
					"rule":    "denylist_exact",
					"command": req.Command,
				},
			}
		}
	}

	// 3. 检查正则黑名单
	for _, pattern := range f.denylistRegex {
		if pattern.re.MatchString(req.Command) {
			f.logSecurityDeny(ctx, "denylist_regex", "命令匹配禁止正则", req, map[string]interface{}{"pattern": pattern.pattern})
			return &SecurityError{
				Code:    "SECURITY_DENY",
				Message: fmt.Sprintf("命令 '%s' 匹配禁止模式 '%s'", req.Command, pattern.pattern),
				Details: map[string]interface{}{
					"rule":    "denylist_regex",
					"pattern": pattern.pattern,
					"command": req.Command,
				},
			}
		}
	}

	// 4. 检查参数黑名单
	for _, arg := range req.Args {
		for _, pattern := range f.argDenyRegex {
			if pattern.re.MatchString(arg) {
				f.logSecurityDeny(ctx, "arg_deny_regex", "参数命中禁止正则", req, map[string]interface{}{"argument": arg, "pattern": pattern.pattern})
				return &SecurityError{
					Code:    "SECURITY_DENY",
					Message: fmt.Sprintf("参数 '%s' 匹配禁止模式 '%s'", arg, pattern.pattern),
					Details: map[string]interface{}{
						"rule":     "arg_deny_regex",
						"pattern":  pattern.pattern,
						"argument": arg,
					},
				}
			}
		}
	}

	// 5. 检查 shell 使用限制
	// 检查命令是否在必须使用 shell 的列表中
	requiresShell := false
	for _, shellCmd := range f.config.AllowShellFor {
		if req.Command == shellCmd {
			requiresShell = true
			break
		}
	}

	// 如果命令必须使用 shell但没有启用 shell，则拒绝
	if requiresShell && !req.Options.UseShell {
		f.logSecurityDeny(ctx, "shell_required", "命令要求通过 shell 执行", req, nil)
		return &SecurityError{
			Code:    "SECURITY_DENY",
			Message: fmt.Sprintf("命令 '%s' 必须使用 shell 执行", req.Command),
			Details: map[string]interface{}{
				"rule":    "shell_required",
				"command": req.Command,
			},
		}
	}

	// 如果启用了 shell，进行额外检查：只有明确允许的命令可以进入 shell，
	// 同时强制拒绝常见的命令拼接与重定向符号，降低注入风险。
	if req.Options.UseShell {
		// 检查命令是否在允许使用 shell 的列表中
		allowed := false
		for _, allowedCmd := range f.config.AllowShellFor {
			if req.Command == allowedCmd {
				allowed = true
				break
			}
		}

		if !allowed {
			f.logSecurityDeny(ctx, "shell_not_allowed", "命令不允许使用 shell", req, map[string]interface{}{"allowed": f.config.AllowShellFor})
			return &SecurityError{
				Code:    "SECURITY_DENY",
				Message: fmt.Sprintf("命令 '%s' 不允许使用 shell 执行", req.Command),
				Details: map[string]interface{}{
					"rule":    "shell_not_allowed",
					"command": req.Command,
					"allowed": f.config.AllowShellFor,
				},
			}
		}

		// 检查参数中是否包含危险字符
		dangerousPatterns := []string{";", "&&", "||", "|", ">", ">>", "<"}
		for _, arg := range req.Args {
			for _, pattern := range dangerousPatterns {
				if strings.Contains(arg, pattern) {
					f.logSecurityDeny(ctx, "shell_injection", "Shell 参数包含危险拼接符号", req, map[string]interface{}{"argument": arg, "pattern": pattern})
					return &SecurityError{
						Code:    "SECURITY_DENY",
						Message: fmt.Sprintf("Shell 参数包含危险字符 '%s' 在 '%s'", pattern, arg),
						Details: map[string]interface{}{
							"rule":     "shell_injection",
							"pattern":  pattern,
							"argument": arg,
							"args":     req.Args,
						},
					}
				}
			}
		}
	}

	// 6. 检查白名单（如果配置了白名单且未使用 shell）
	// 对于使用 shell 的命令，依赖之前的黑名单检查，跳过白名单检查
	if !req.Options.UseShell && (len(f.config.AllowlistExact) > 0 || len(f.config.AllowlistRegex) > 0) {
		allowed := false

		// 检查精确白名单
		for _, allowedCmd := range f.config.AllowlistExact {
			if req.Command == allowedCmd {
				allowed = true
				break
			}
		}

		// 检查正则白名单
		if !allowed {
			for _, pattern := range f.allowlistRegex {
				if pattern.re.MatchString(req.Command) {
					allowed = true
					break
				}
			}
		}

		if !allowed {
			f.logSecurityDeny(ctx, "not_in_allowlist", "命令不在白名单中", req, nil)
			return &SecurityError{
				Code:    "SECURITY_DENY",
				Message: fmt.Sprintf("命令 '%s' 不在允许列表中", req.Command),
				Details: map[string]interface{}{
					"rule":    "not_in_allowlist",
					"command": req.Command,
				},
			}
		}
	}

	// 7. 检查工作目录
	if req.Options.CWD != "" {
		cwdAllowed := false
		for _, allowedDir := range f.config.WorkingDirAllow {
			if isPathPrefix(req.Options.CWD, allowedDir) {
				cwdAllowed = true
				break
			}
		}

		if !cwdAllowed {
			f.logSecurityDeny(ctx, "working_dir_not_allowed", "工作目录不在允许列表", req, map[string]interface{}{"cwd": req.Options.CWD})
			return &SecurityError{
				Code:    "SECURITY_DENY",
				Message: fmt.Sprintf("工作目录 '%s' 不在允许列表中", req.Options.CWD),
				Details: map[string]interface{}{
					"rule":         "working_dir_not_allowed",
					"cwd":          req.Options.CWD,
					"allowed_dirs": f.config.WorkingDirAllow,
				},
			}
		}
	}

	// 8. 通过所有检查
	return nil
}

// SecurityError 安全错误
type SecurityError struct {
	Code    string                 `json:"code"`
	Message string                 `json:"message"`
	Details map[string]interface{} `json:"details,omitempty"`
}

// Error 实现 error 接口
func (e *SecurityError) Error() string {
	return e.Message
}

// isPathPrefix 判断 path 是否位于 prefix 目录内。
// 通过绝对路径、符号链接解析与 filepath.Rel 组合，保障 ../ 或符号链接都无法逃逸。
func isPathPrefix(path, prefix string) bool {
	canonicalPrefix, err := canonicalizePath(prefix)
	if err != nil {
		return false
	}

	if pathWithinPrefix(path, canonicalPrefix) {
		return true
	}

	if !filepath.IsAbs(path) {
		joined := filepath.Join(canonicalPrefix, path)
		if pathWithinPrefix(joined, canonicalPrefix) {
			return true
		}
	}

	return false
}

// pathWithinPrefix 在拿到已规范化的白名单目录后，再次规范化目标路径，
// 通过 Rel 计算判断是否逃逸到目录外，避免简单字符串比较被绕过。
func pathWithinPrefix(candidate, canonicalPrefix string) bool {
	canonicalCandidate, err := canonicalizePath(candidate)
	if err != nil {
		return false
	}

	if pathsEqual(canonicalCandidate, canonicalPrefix) {
		return true
	}

	rel, err := filepath.Rel(canonicalPrefix, canonicalCandidate)
	if err != nil {
		return false
	}

	cleanRel := filepath.Clean(rel)
	if cleanRel == "." {
		return true
	}
	if cleanRel == ".." || strings.HasPrefix(cleanRel, ".."+string(filepath.Separator)) {
		return false
	}

	return true
}

// canonicalizePath 对输入路径做清理、绝对化及符号链接解析，返回可比较的真实路径。
func canonicalizePath(p string) (string, error) {
	if strings.TrimSpace(p) == "" {
		return "", fmt.Errorf("empty path")
	}

	cleaned := filepath.Clean(p)
	absolute := cleaned
	if !filepath.IsAbs(cleaned) {
		abs, err := filepath.Abs(cleaned)
		if err != nil {
			return "", err
		}
		absolute = abs
	}

	if resolved, err := filepath.EvalSymlinks(absolute); err == nil {
		absolute = resolved
	}

	return filepath.Clean(absolute), nil
}

func pathsEqual(a, b string) bool {
	if runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

func compilePatterns(patterns []string) []compiledPattern {
	compiled := make([]compiledPattern, 0, len(patterns))
	for _, pattern := range patterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			continue
		}
		compiled = append(compiled, compiledPattern{pattern: pattern, re: re})
	}
	return compiled
}
