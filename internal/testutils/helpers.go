package testutils

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/terateams/ExecMCP/internal/audit"
)

// EnvBackup 环境变量备份和恢复
type EnvBackup struct {
	original map[string]string
}

// BackupEnv 备份指定的环境变量
func BackupEnv(keys []string) *EnvBackup {
	backup := &EnvBackup{
		original: make(map[string]string),
	}
	for _, key := range keys {
		backup.original[key] = os.Getenv(key)
	}
	return backup
}

// RestoreEnv 恢复环境变量
func (e *EnvBackup) RestoreEnv() {
	for key, value := range e.original {
		if value == "" {
			os.Unsetenv(key)
		} else {
			os.Setenv(key, value)
		}
	}
}

// CreateTestConfigFile 创建测试配置文件
func CreateTestConfigFile(t *testing.T, content string) string {
	t.Helper()
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatalf("创建测试配置文件失败: %v", err)
	}
	return configPath
}

// CreateTestScriptFile 创建测试脚本文件
func CreateTestScriptFile(t *testing.T, content string) string {
	t.Helper()
	tempDir := t.TempDir()
	scriptPath := filepath.Join(tempDir, "test.sh")
	if err := os.WriteFile(scriptPath, []byte(content), 0755); err != nil {
		t.Fatalf("创建测试脚本文件失败: %v", err)
	}
	return scriptPath
}

// CreateTestKnownHostsFile 创建测试 known_hosts 文件
func CreateTestKnownHostsFile(t *testing.T, content string) string {
	t.Helper()
	tempDir := t.TempDir()
	sshDir := filepath.Join(tempDir, ".ssh")
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		t.Fatalf("创建SSH目录失败: %v", err)
	}
	knownHostsPath := filepath.Join(sshDir, "known_hosts")
	if err := os.WriteFile(knownHostsPath, []byte(content), 0644); err != nil {
		t.Fatalf("创建known_hosts文件失败: %v", err)
	}
	return knownHostsPath
}

// WithEnv 临时设置环境变量并在测试后恢复
func WithEnv(t *testing.T, key, value string, callback func()) {
	t.Helper()
	oldValue := os.Getenv(key)
	defer func() {
		if oldValue == "" {
			os.Unsetenv(key)
		} else {
			os.Setenv(key, oldValue)
		}
	}()

	os.Setenv(key, value)
	callback()
}

// RecordingAuditLogger 是测试专用的审计日志记录器，用于捕获生成的事件。
type RecordingAuditLogger struct {
	mu     sync.Mutex
	events []audit.Event
}

// NewRecordingAuditLogger 创建新的测试审计记录器。
func NewRecordingAuditLogger() *RecordingAuditLogger {
	return &RecordingAuditLogger{}
}

// LogEvent 记录事件并复制元数据，避免后续修改影响测试断言。
func (r *RecordingAuditLogger) LogEvent(_ context.Context, event audit.Event) {
	clone := event
	if len(event.Metadata) > 0 {
		copied := make(map[string]interface{}, len(event.Metadata))
		for k, v := range event.Metadata {
			copied[k] = v
		}
		clone.Metadata = copied
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, clone)
}

// Events 返回已记录的事件副本。
func (r *RecordingAuditLogger) Events() []audit.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	result := make([]audit.Event, len(r.events))
	copy(result, r.events)
	return result
}

// Close 满足 audit.Logger 接口，测试中无需处理。
func (r *RecordingAuditLogger) Close() error { return nil }

// Enabled 始终返回 true，确保测试路径不会被短路。
func (r *RecordingAuditLogger) Enabled() bool { return true }
