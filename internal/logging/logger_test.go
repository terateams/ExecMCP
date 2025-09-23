package logging

import (
	"bytes"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/terateams/ExecMCP/internal/config"
)

func TestNewLogger(t *testing.T) {
	cfg := config.LoggingConfig{
		Level:  "info",
		Format: "json",
		Output: "stdout",
	}

	logger := NewLogger(cfg)
	if logger == nil {
		t.Fatal("期望创建日志记录器，但得到 nil")
	}
}

func TestLogger_LevelFiltering(t *testing.T) {
	// 创建一个缓冲区来捕获输出
	var buf bytes.Buffer

	// 创建一个自定义的 logger，使其写入我们的缓冲区
	logger := &logger{
		level:  "info",
		format: "text",
		output: "stdout",
		logger: log.New(&buf, "", log.LstdFlags),
	}

	// 测试不同级别的日志
	logger.Debug("debug message") // 应该被过滤
	logger.Info("info message")   // 应该显示
	logger.Warn("warn message")   // 应该显示
	logger.Error("error message") // 应该显示

	output := buf.String()

	// debug 消息应该被过滤掉
	if strings.Contains(output, "debug message") {
		t.Error("期望 debug 消息被过滤，但出现在输出中")
	}

	// 其他消息应该出现
	expectedMessages := []string{"info message", "warn message", "error message"}
	for _, msg := range expectedMessages {
		if !strings.Contains(output, msg) {
			t.Errorf("期望消息 '%s' 出现在输出中", msg)
		}
	}
}

func TestLogger_JSONFormat(t *testing.T) {
	// 创建一个缓冲区来捕获输出
	var buf bytes.Buffer

	// 创建一个自定义的 logger，使其写入我们的缓冲区
	logger := &logger{
		level:  "debug",
		format: "json",
		output: "stdout",
		logger: log.New(&buf, "", log.LstdFlags),
	}

	logger.Info("test message", "key1", "value1", "key2", 42)

	output := buf.String()

	// 检查 JSON 格式
	expectedFields := []string{"level", "message", "key1", "key2"}
	for _, field := range expectedFields {
		if !strings.Contains(output, field) {
			t.Errorf("期望 JSON 包含字段 '%s'，但输出为: %s", field, output)
		}
	}

	// 检查具体值
	if !strings.Contains(output, `"level":"info"`) {
		t.Error("期望 JSON 包含正确的级别")
	}
	if !strings.Contains(output, `"message":"test message"`) {
		t.Error("期望 JSON 包含正确的消息")
	}
	if !strings.Contains(output, `"key1":"value1"`) {
		t.Error("期望 JSON 包含 key1 值")
	}
}

func TestLogger_TextFormat(t *testing.T) {
	// 创建一个缓冲区来捕获输出
	var buf bytes.Buffer

	// 创建一个自定义的 logger，使其写入我们的缓冲区
	logger := &logger{
		level:  "debug",
		format: "text",
		output: "stdout",
		logger: log.New(&buf, "", log.LstdFlags),
	}

	logger.Info("test message", "key1", "value1", "key2", 42)

	output := buf.String()

	// 检查文本格式
	expectedParts := []string{"[INFO]", "test message", "key1=value1", "key2=42"}
	for _, part := range expectedParts {
		if !strings.Contains(output, part) {
			t.Errorf("期望文本格式包含 '%s'，但输出为: %s", part, output)
		}
	}
}

func TestLogger_DebugLevel(t *testing.T) {
	// 创建一个缓冲区来捕获输出
	var buf bytes.Buffer

	// 创建一个自定义的 logger，使其写入我们的缓冲区
	logger := &logger{
		level:  "debug",
		format: "text",
		output: "stdout",
		logger: log.New(&buf, "", log.LstdFlags),
	}

	logger.Debug("debug message")
	logger.Info("info message")

	output := buf.String()

	// debug 级别应该显示所有消息
	if !strings.Contains(output, "debug message") {
		t.Error("期望 debug 消息出现在输出中")
	}
	if !strings.Contains(output, "info message") {
		t.Error("期望 info 消息出现在输出中")
	}
}

func TestLogger_ErrorLevel(t *testing.T) {
	// 创建一个缓冲区来捕获输出
	var buf bytes.Buffer

	// 创建一个自定义的 logger，使其写入我们的缓冲区
	logger := &logger{
		level:  "error",
		format: "text",
		output: "stdout",
		logger: log.New(&buf, "", log.LstdFlags),
	}

	logger.Debug("debug message") // 应该被过滤
	logger.Info("info message")   // 应该被过滤
	logger.Warn("warn message")   // 应该被过滤
	logger.Error("error message") // 应该显示

	output := buf.String()

	// 只有 error 消息应该显示
	if strings.Contains(output, "debug message") {
		t.Error("期望 debug 消息被过滤，但出现在输出中")
	}
	if strings.Contains(output, "info message") {
		t.Error("期望 info 消息被过滤，但出现在输出中")
	}
	if strings.Contains(output, "warn message") {
		t.Error("期望 warn 消息被过滤，但出现在输出中")
	}
	if !strings.Contains(output, "error message") {
		t.Error("期望 error 消息出现在输出中")
	}
}

func TestLogger_FileOutput(t *testing.T) {
	tempDir := t.TempDir()
	logFilePath := filepath.Join(tempDir, "test.log")

	cfg := config.LoggingConfig{
		Level:    "info",
		Format:   "text",
		Output:   "file",
		FilePath: logFilePath,
	}

	logger := NewLogger(cfg)
	logger.Info("test file message")

	// 关闭日志文件以确保内容写入磁盘
	if closer, ok := logger.(interface{ Close() }); ok {
		closer.Close()
	}

	// 读取日志文件内容
	content, err := os.ReadFile(logFilePath)
	if err != nil {
		t.Fatalf("读取日志文件失败: %v", err)
	}

	if !strings.Contains(string(content), "test file message") {
		t.Error("期望消息写入日志文件")
	}
}

func TestLogger_FileOutputInvalidPath(t *testing.T) {
	cfg := config.LoggingConfig{
		Level:    "info",
		Format:   "text",
		Output:   "file",
		FilePath: "/invalid/path/that/does/not/exist.log",
	}

	// 应该回退到 stdout
	logger := NewLogger(cfg)
	if logger == nil {
		t.Fatal("期望即使文件路径无效也能创建日志记录器")
	}
}

func TestLogger_FatalExit(t *testing.T) {
	if os.Getenv(config.EnvTestFatal) == "1" {
		cfg := config.LoggingConfig{
			Level:  "info",
			Format: "text",
			Output: "stdout",
		}

		logger := NewLogger(cfg)
		logger.Fatal("fatal message")
		return
	}

	// 测试 Fatal 是否会导致程序退出
	cmd := testCommand(t, "go", "test", "-run", "TestLogger_FatalExit", "-v")
	cmd.Env = append(os.Environ(), config.EnvTestFatal+"=1")

	err := cmd.Run()
	if err == nil {
		t.Error("期望 Fatal 导致程序退出，但程序正常完成")
	}
}

func TestLogger_DefaultValues(t *testing.T) {
	// 创建一个缓冲区来捕获输出
	var buf bytes.Buffer

	// 创建一个自定义的 logger，使其写入我们的缓冲区
	logger := &logger{
		level:  "info", // 默认级别
		format: "json", // 默认格式
		output: "stdout",
		logger: log.New(&buf, "", log.LstdFlags),
	}

	logger.Info("test default values")

	output := buf.String()

	// 检查是否使用了默认格式（应该是 JSON）
	if !strings.Contains(output, `"level":"info"`) {
		t.Error("期望使用默认的 JSON 格式")
	}
}

func BenchmarkLogger_Info(b *testing.B) {
	cfg := config.LoggingConfig{
		Level:  "info",
		Format: "json",
		Output: "stdout",
	}

	logger := NewLogger(cfg)

	// 重定向到 /dev/null 以避免 I/O 影响基准测试
	oldStdout := os.Stdout
	devNull, _ := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	os.Stdout = devNull

	defer func() {
		os.Stdout = oldStdout
		devNull.Close()
	}()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logger.Info("benchmark message", "iteration", i, "timestamp", time.Now().Unix())
	}
}

func BenchmarkLogger_JSONFormat(b *testing.B) {
	cfg := config.LoggingConfig{
		Level:  "debug",
		Format: "json",
		Output: "stdout",
	}

	logger := NewLogger(cfg)

	// 重定向到 /dev/null
	oldStdout := os.Stdout
	devNull, _ := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	os.Stdout = devNull

	defer func() {
		os.Stdout = oldStdout
		devNull.Close()
	}()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logger.Info("benchmark json message", "key1", "value1", "key2", i, "key3", "value3")
	}
}

func BenchmarkLogger_TextFormat(b *testing.B) {
	cfg := config.LoggingConfig{
		Level:  "debug",
		Format: "text",
		Output: "stdout",
	}

	logger := NewLogger(cfg)

	// 重定向到 /dev/null
	oldStdout := os.Stdout
	devNull, _ := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	os.Stdout = devNull

	defer func() {
		os.Stdout = oldStdout
		devNull.Close()
	}()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logger.Info("benchmark text message", "key1", "value1", "key2", i, "key3", "value3")
	}
}

// 辅助函数：创建测试命令
func testCommand(t *testing.T, name string, args ...string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = "." // 在当前目录运行
	return cmd
}
