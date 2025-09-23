package security

import (
	"fmt"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/terateams/ExecMCP/internal/config"
)

// Filter 安全过滤器
type Filter struct {
	config *config.SecurityConfig
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
func NewFilter(cfg *config.SecurityConfig) *Filter {
	return &Filter{
		config: cfg,
	}
}

// Check 检查执行请求是否安全
func (f *Filter) Check(req ExecRequest) error {
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
	for _, pattern := range f.config.DenylistRegex {
		re, err := regexp.Compile(pattern)
		if err != nil {
			continue // 跳过无效的正则表达式
		}
		if re.MatchString(req.Command) {
			return &SecurityError{
				Code:    "SECURITY_DENY",
				Message: fmt.Sprintf("命令 '%s' 匹配禁止模式 '%s'", req.Command, pattern),
				Details: map[string]interface{}{
					"rule":    "denylist_regex",
					"pattern": pattern,
					"command": req.Command,
				},
			}
		}
	}

	// 4. 检查参数黑名单
	for _, arg := range req.Args {
		for _, pattern := range f.config.ArgDenyRegex {
			re, err := regexp.Compile(pattern)
			if err != nil {
				continue
			}
			if re.MatchString(arg) {
				return &SecurityError{
					Code:    "SECURITY_DENY",
					Message: fmt.Sprintf("参数 '%s' 匹配禁止模式 '%s'", arg, pattern),
					Details: map[string]interface{}{
						"rule":     "arg_deny_regex",
						"pattern":  pattern,
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
		return &SecurityError{
			Code:    "SECURITY_DENY",
			Message: fmt.Sprintf("命令 '%s' 必须使用 shell 执行", req.Command),
			Details: map[string]interface{}{
				"rule":    "shell_required",
				"command": req.Command,
			},
		}
	}

	// 如果启用了 shell，进行额外检查
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
			for _, pattern := range f.config.AllowlistRegex {
				re, err := regexp.Compile(pattern)
				if err != nil {
					continue
				}
				if re.MatchString(req.Command) {
					allowed = true
					break
				}
			}
		}

		if !allowed {
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

// contains 检查字符串切片是否包含指定字符串
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// isPathPrefix 检查路径是否以指定前缀开头（处理路径遍历）
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
