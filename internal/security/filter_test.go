package security

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/terateams/ExecMCP/internal/audit"
	"github.com/terateams/ExecMCP/internal/config"
	"github.com/terateams/ExecMCP/internal/logging"
	"github.com/terateams/ExecMCP/internal/testutils"
)

func TestFilter_Check_DenylistExact(t *testing.T) {
	// 创建测试配置
	cfg := &config.SecurityConfig{
		DenylistExact: []string{"rm", "dd", "mkfs", "shutdown", "reboot"},
	}

	filter := NewFilter(cfg, logging.NewLogger(config.LoggingConfig{}), audit.NewNoopLogger())

	// 测试被禁止的命令
	deniedCommands := []string{"rm", "dd", "mkfs", "shutdown", "reboot"}
	for _, cmd := range deniedCommands {
		req := ExecRequest{
			Command: cmd,
			Args:    []string{},
		}

		err := filter.Check(context.Background(), req)
		if err == nil {
			t.Errorf("期望命令 '%s' 被拒绝，但通过了检查", cmd)
		}

		if secErr, ok := err.(*SecurityError); ok {
			if secErr.Code != "SECURITY_DENY" {
				t.Errorf("期望错误码为 'SECURITY_DENY'，但得到 '%s'", secErr.Code)
			}
		} else {
			t.Errorf("期望 SecurityError 类型，但得到 %T", err)
		}
	}

	// 测试允许的命令
	allowedCommands := []string{"ls", "cat", "echo", "pwd"}
	for _, cmd := range allowedCommands {
		req := ExecRequest{
			Command: cmd,
			Args:    []string{},
		}

		err := filter.Check(context.Background(), req)
		if err != nil {
			t.Errorf("期望命令 '%s' 通过检查，但被拒绝: %v", cmd, err)
		}
	}
}

func TestFilter_AuditLogsOnDeny(t *testing.T) {
	cfg := &config.SecurityConfig{
		DenylistExact: []string{"rm"},
	}
	recorder := testutils.NewRecordingAuditLogger()
	filter := NewFilter(cfg, logging.NewLogger(config.LoggingConfig{}), recorder)

	err := filter.Check(context.Background(), ExecRequest{Command: "rm"})
	if err == nil {
		t.Fatal("期望命令被安全策略拒绝，但通过了检查")
	}

	events := recorder.Events()
	if len(events) != 1 {
		t.Fatalf("期望记录 1 条审计事件，但得到 %d", len(events))
	}
	if events[0].Rule != "denylist_exact" {
		t.Errorf("期望记录规则为 denylist_exact，得到 %s", events[0].Rule)
	}
	if events[0].Outcome != audit.OutcomeDenied {
		t.Errorf("期望事件 Outcome=denied，得到 %s", events[0].Outcome)
	}
}

func TestFilter_Check_DenylistRegex(t *testing.T) {
	cfg := &config.SecurityConfig{
		DenylistRegex: []string{
			`^rm\..*`,  // rm 命令的各种变体
			`[invalid`, // 无效正则应被忽略
		},
		ArgDenyRegex: []string{
			`.*;.*`,  // 命令串接
			`.*&&.*`, // 逻辑与操作
		},
	}

	filter := NewFilter(cfg, logging.NewLogger(config.LoggingConfig{}), audit.NewNoopLogger())

	// 测试正则拒绝的命令
	testCases := []struct {
		command string
		args    []string
		desc    string
	}{
		{"rm.rf", []string{}, "rm 命令变体"},
		{"echo", []string{"hello;world"}, "包含分号的参数"},
		{"ls", []string{"&&", "echo", "test"}, "包含 && 的参数"},
	}

	for _, tc := range testCases {
		req := ExecRequest{
			Command: tc.command,
			Args:    tc.args,
		}

		err := filter.Check(context.Background(), req)
		if err == nil {
			t.Errorf("期望 '%s' 被正则拒绝，但通过了检查: %s", tc.desc, tc.command)
		}
	}
}

func TestFilter_Check_ArgDenyRegex(t *testing.T) {
	cfg := &config.SecurityConfig{
		ArgDenyRegex: []string{
			`-{1,2}force`,        // force 参数
			`--no-preserve-root`, // 不保留根目录
			`--recursive`,        // 递归操作
			`/dev/sd[a-z].*`,     // 块设备操作
		},
		AllowlistExact: []string{"rm"}, // 允许 rm 命令但限制参数
	}

	filter := NewFilter(cfg, logging.NewLogger(config.LoggingConfig{}), audit.NewNoopLogger())

	// 测试危险参数
	testCases := []struct {
		command string
		args    []string
		desc    string
	}{
		{"rm", []string{"-force"}, "force 参数"},
		{"rm", []string{"--no-preserve-root"}, "no-preserve-root 参数"},
		{"dd", []string{"if=/dev/sda"}, "块设备操作"},
		{"chmod", []string{"-R", "755"}, "递归参数"},
	}

	for _, tc := range testCases {
		req := ExecRequest{
			Command: tc.command,
			Args:    tc.args,
		}

		err := filter.Check(context.Background(), req)
		if err == nil {
			t.Errorf("期望 '%s' 被参数拒绝，但通过了检查", tc.desc)
		}
	}

	// 测试安全参数
	req := ExecRequest{
		Command: "rm",
		Args:    []string{"file.txt"},
	}

	err := filter.Check(context.Background(), req)
	if err != nil {
		t.Errorf("期望安全参数通过检查，但被拒绝: %v", err)
	}
}

func TestFilter_Check_Allowlist(t *testing.T) {
	cfg := &config.SecurityConfig{
		AllowlistExact: []string{"ls", "cat", "grep", "find"},
		AllowlistRegex: []string{`^systemctl.*`, `^journalctl.*`},
	}

	filter := NewFilter(cfg, logging.NewLogger(config.LoggingConfig{}), audit.NewNoopLogger())

	// 测试允许的命令
	allowedCommands := []struct {
		command string
		args    []string
		desc    string
	}{
		{"ls", []string{"-la"}, "精确允许的命令"},
		{"cat", []string{"file.txt"}, "精确允许的命令"},
		{"systemctl", []string{"status", "nginx"}, "正则允许的命令"},
		{"journalctl", []string{"-u", "nginx"}, "正则允许的命令"},
	}

	for _, tc := range allowedCommands {
		req := ExecRequest{
			Command: tc.command,
			Args:    tc.args,
		}

		err := filter.Check(context.Background(), req)
		if err != nil {
			t.Errorf("期望 '%s' 通过白名单检查，但被拒绝: %v", tc.desc, err)
		}
	}

	// 测试拒绝的命令
	deniedCommands := []string{"rm", "dd", "vi", "emacs"}
	for _, cmd := range deniedCommands {
		req := ExecRequest{
			Command: cmd,
			Args:    []string{},
		}

		err := filter.Check(context.Background(), req)
		if err == nil {
			t.Errorf("期望命令 '%s' 被白名单拒绝，但通过了检查", cmd)
		}
	}
}

func TestFilter_TemporaryApprovalBypassesAllowlist(t *testing.T) {
	cfg := &config.SecurityConfig{
		AllowlistExact: []string{"ls"},
	}
	filter := NewFilter(cfg, logging.NewLogger(config.LoggingConfig{}), audit.NewNoopLogger())
	req := ExecRequest{Command: "tar"}

	if err := filter.Check(context.Background(), req); err == nil {
		t.Fatal("期望命令不在白名单时被拒绝")
	}

	provider := &stubApprovalProvider{allowedCmd: "tar", remainingApprovals: 1}
	ctx := WithTemporaryApproval(context.Background(), provider)
	if err := filter.Check(ctx, req); err != nil {
		t.Fatalf("期望临时批准放行命令，但得到错误: %v", err)
	}
	if provider.calls != 1 {
		t.Fatalf("期望临时批准被调用一次，实际 %d", provider.calls)
	}

	// 批准已用尽，再次执行应该被拒绝
	if err := filter.Check(ctx, req); err == nil {
		t.Fatal("期望临时批准用尽后命令被拒绝")
	}
}

type stubApprovalProvider struct {
	allowedCmd         string
	remainingApprovals int
	calls              int
}

func (s *stubApprovalProvider) IsCommandApproved(_ context.Context, req ExecRequest) bool {
	s.calls++
	if req.Command != s.allowedCmd {
		return false
	}
	if s.remainingApprovals <= 0 {
		return false
	}
	s.remainingApprovals--
	return true
}

func TestFilter_Check_DockerLogsCommand(t *testing.T) {
	cfg := &config.SecurityConfig{
		AllowlistExact: []string{"docker"},
		AllowShellFor:  []string{"bash", "sh"},
	}

	filter := NewFilter(cfg, logging.NewLogger(config.LoggingConfig{}), audit.NewNoopLogger())

	dockerArgs := []string{"logs", "--tail", "50", "$(docker", "ps", "-q)"}

	t.Run("without shell passes", func(t *testing.T) {
		req := ExecRequest{
			Command: "docker",
			Args:    dockerArgs,
			Options: ExecOptions{UseShell: false},
		}

		if err := filter.Check(context.Background(), req); err != nil {
			t.Fatalf("期望命令在非 shell 模式下通过检查，但被拒绝: %v", err)
		}
	})

	t.Run("via shell command passes", func(t *testing.T) {
		req := ExecRequest{
			Command: "sh",
			Args:    []string{"-c", "docker logs --tail 50 $(docker ps -q)"},
			Options: ExecOptions{UseShell: true},
		}

		if err := filter.Check(context.Background(), req); err != nil {
			t.Fatalf("期望通过 shell 执行命令，但被拒绝: %v", err)
		}
	})

	t.Run("shell on docker command denied", func(t *testing.T) {
		req := ExecRequest{
			Command: "docker",
			Args:    dockerArgs,
			Options: ExecOptions{UseShell: true},
		}

		err := filter.Check(context.Background(), req)
		if err == nil {
			t.Fatal("期望直接在 shell 模式下执行 docker 被拒绝，但通过了检查")
		}
	})
}

func TestFilter_Check_ShellUsage(t *testing.T) {
	cfg := &config.SecurityConfig{
		DefaultShell:   false,
		AllowShellFor:  []string{"bash", "sh"},
		AllowlistExact: []string{"bash", "sh", "ls"},
	}

	filter := NewFilter(cfg, logging.NewLogger(config.LoggingConfig{}), audit.NewNoopLogger())

	// 测试不允许使用 shell 的命令
	testCases := []struct {
		command    string
		useShell   bool
		shouldPass bool
		desc       string
	}{
		{"ls", false, true, "非 shell 模式的允许命令"},
		{"ls", true, false, "不允许使用 shell 的命令"},
		{"bash", true, true, "允许使用 shell 的 bash"},
		{"sh", true, true, "允许使用 shell 的 sh"},
		{"bash", false, false, "bash 必须使用 shell"},
	}

	for _, tc := range testCases {
		req := ExecRequest{
			Command: tc.command,
			Args:    []string{},
			Options: ExecOptions{
				UseShell: tc.useShell,
			},
		}

		err := filter.Check(context.Background(), req)
		if tc.shouldPass && err != nil {
			t.Errorf("期望 '%s' 通过检查，但被拒绝: %v", tc.desc, err)
		}
		if !tc.shouldPass && err == nil {
			t.Errorf("期望 '%s' 被拒绝，但通过了检查", tc.desc)
		}
	}
}

func TestFilter_Check_PTY(t *testing.T) {
	cfg := &config.SecurityConfig{
		EnablePTY:      false,
		AllowlistExact: []string{"ls"},
	}

	filter := NewFilter(cfg, logging.NewLogger(config.LoggingConfig{}), audit.NewNoopLogger())

	req := ExecRequest{
		Command: "ls",
		Options: ExecOptions{
			EnablePTY: true,
		},
	}

	if err := filter.Check(context.Background(), req); err == nil {
		t.Fatal("期望在禁用 PTY 时被拒绝，但通过了检查")
	}

	cfg.EnablePTY = true
	filter = NewFilter(cfg, logging.NewLogger(config.LoggingConfig{}), audit.NewNoopLogger())

	if err := filter.Check(context.Background(), req); err != nil {
		t.Fatalf("期望启用 PTY 后通过检查，但被拒绝: %v", err)
	}
}

func TestIsPathPrefix(t *testing.T) {
	baseDir := t.TempDir()
	childDir := filepath.Join(baseDir, "child", "nested")
	if err := os.MkdirAll(childDir, 0o755); err != nil {
		t.Fatalf("创建测试目录失败: %v", err)
	}

	if !isPathPrefix(childDir, baseDir) {
		t.Fatalf("期望 %q 被识别为 %q 的子目录", childDir, baseDir)
	}

	// 相对路径解析到允许目录内
	if !isPathPrefix("child", baseDir) {
		t.Fatalf("期望相对路径 'child' 被允许目录 %q 接受", baseDir)
	}

	// 含有 .. 的路径应被拒绝
	if isPathPrefix("../outside", baseDir) {
		t.Fatal("包含 .. 的相对路径不应通过前缀检查")
	}

	outsideDir := filepath.Join(baseDir, "..", "outside")
	if err := os.MkdirAll(outsideDir, 0o755); err != nil {
		t.Fatalf("创建外部目录失败: %v", err)
	}
	if isPathPrefix(outsideDir, baseDir) {
		t.Fatalf("目录 %q 不应被视为 %q 的子目录", outsideDir, baseDir)
	}

	symlinkPath := filepath.Join(baseDir, "link")
	if err := os.Symlink(outsideDir, symlinkPath); err == nil {
		if isPathPrefix(symlinkPath, baseDir) {
			t.Fatal("指向外部目录的符号链接不应通过前缀检查")
		}
		_ = os.Remove(symlinkPath)
	} else if runtime.GOOS != "windows" {
		// 在非 Windows 平台上，创建符号链接失败通常意味着测试环境受限
		t.Logf("创建符号链接失败，跳过符号链接相关断言: %v", err)
	}
}

func TestFilter_Check_ShellInjection(t *testing.T) {
	cfg := &config.SecurityConfig{
		AllowShellFor:  []string{"bash"},
		AllowlistExact: []string{"bash"},
	}

	filter := NewFilter(cfg, logging.NewLogger(config.LoggingConfig{}), audit.NewNoopLogger())

	// 测试 shell 注入攻击
	injectionPatterns := []struct {
		args []string
		desc string
	}{
		{[]string{"command1;command2"}, "分号分隔的命令"},
		{[]string{"command1", "&&", "command2"}, "逻辑与操作"},
		{[]string{"command1", "||", "command2"}, "逻辑或操作"},
		{[]string{"command1", "|", "command2"}, "管道操作"},
		{[]string{"command1", ">", "file.txt"}, "输出重定向"},
		{[]string{"command1", ">>", "file.txt"}, "输出追加"},
		{[]string{"command1", "<", "input.txt"}, "输入重定向"},
	}

	for _, pattern := range injectionPatterns {
		req := ExecRequest{
			Command: "bash",
			Args:    pattern.args,
			Options: ExecOptions{
				UseShell: true,
			},
		}

		err := filter.Check(context.Background(), req)
		if err == nil {
			t.Errorf("期望 shell 注入 '%s' 被拒绝，但通过了检查", pattern.desc)
		}
	}

	// 测试安全的 shell 参数
	req := ExecRequest{
		Command: "bash",
		Args:    []string{"-c", "echo hello"},
		Options: ExecOptions{
			UseShell: true,
		},
	}

	err := filter.Check(context.Background(), req)
	if err != nil {
		t.Errorf("期望安全的 shell 参数通过检查，但被拒绝: %v", err)
	}
}

func TestFilter_Check_WorkingDirectory(t *testing.T) {
	cfg := &config.SecurityConfig{
		WorkingDirAllow: []string{"/tmp", "/var/log", "/home/user"},
		AllowlistExact:  []string{"ls"},
	}

	filter := NewFilter(cfg, logging.NewLogger(config.LoggingConfig{}), audit.NewNoopLogger())

	// 测试允许的工作目录
	allowedDirs := []string{"/tmp", "/var/log", "/home/user", "/home/user/docs"}
	for _, dir := range allowedDirs {
		req := ExecRequest{
			Command: "ls",
			Args:    []string{},
			Options: ExecOptions{
				CWD: dir,
			},
		}

		err := filter.Check(context.Background(), req)
		if err != nil {
			t.Errorf("期望工作目录 '%s' 通过检查，但被拒绝: %v", dir, err)
		}
	}

	// 测试拒绝的工作目录
	deniedDirs := []string{"/root", "/etc", "/usr", "/var", "/home/user/../../etc"}
	for _, dir := range deniedDirs {
		req := ExecRequest{
			Command: "ls",
			Args:    []string{},
			Options: ExecOptions{
				CWD: dir,
			},
		}

		err := filter.Check(context.Background(), req)
		if err == nil {
			t.Errorf("期望工作目录 '%s' 被拒绝，但通过了检查", dir)
		}
	}
}

func TestFilter_Check_EmptyCommand(t *testing.T) {
	cfg := &config.SecurityConfig{}
	filter := NewFilter(cfg, logging.NewLogger(config.LoggingConfig{}), audit.NewNoopLogger())

	req := ExecRequest{
		Command: "",
		Args:    []string{},
	}

	err := filter.Check(context.Background(), req)
	if err == nil {
		t.Error("期望空命令被拒绝，但通过了检查")
	}

	if secErr, ok := err.(*SecurityError); ok {
		if secErr.Code != "EMPTY_COMMAND" {
			t.Errorf("期望错误码为 'EMPTY_COMMAND'，但得到 '%s'", secErr.Code)
		}
	}
}

func TestFilter_Check_DefaultValues(t *testing.T) {
	cfg := &config.SecurityConfig{
		AllowlistExact: []string{"ls"},
	}

	filter := NewFilter(cfg, logging.NewLogger(config.LoggingConfig{}), audit.NewNoopLogger())

	// 测试默认值应该被应用
	req := ExecRequest{
		Command: "ls",
		Args:    []string{},
		Options: ExecOptions{
			UseShell: false, // 默认应该是 false
		},
	}

	err := filter.Check(context.Background(), req)
	if err != nil {
		t.Errorf("期望默认配置通过检查，但被拒绝: %v", err)
	}
}

func TestSecurityError_Error(t *testing.T) {
	err := &SecurityError{
		Code:    "TEST_ERROR",
		Message: "Test error message",
	}

	if err.Error() != "Test error message" {
		t.Errorf("期望错误消息为 'Test error message'，但得到 '%s'", err.Error())
	}
}

func BenchmarkFilter_Check(b *testing.B) {
	cfg := &config.SecurityConfig{
		DenylistExact:   []string{"rm", "dd", "mkfs"},
		AllowlistExact:  []string{"ls", "cat", "echo"},
		WorkingDirAllow: []string{"/tmp", "/var/log"},
	}

	filter := NewFilter(cfg, logging.NewLogger(config.LoggingConfig{}), audit.NewNoopLogger())

	req := ExecRequest{
		Command: "ls",
		Args:    []string{"-la", "/tmp"},
		Options: ExecOptions{
			CWD: "/tmp",
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := filter.Check(context.Background(), req)
		if err != nil {
			b.Fatalf("基准测试失败: %v", err)
		}
	}
}
