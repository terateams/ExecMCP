package testutils

import (
	"os"
	"path/filepath"
	"testing"
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
