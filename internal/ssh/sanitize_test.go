package ssh

import (
	"strings"
	"testing"

	"github.com/terateams/ExecMCP/internal/config"
	"github.com/terateams/ExecMCP/internal/logging"
)

func TestSanitizeCommandForLogging(t *testing.T) {
	// 创建一个虚拟的会话来测试脱敏功能
	session := &RealSession{
		connection: &RealConnection{
			HostID: "test-host",
			logger: logging.NewLogger(config.LoggingConfig{
				Level:  "debug",
				Format: "text",
				Output: "stdout",
			}),
		},
	}

	tests := []struct {
		name     string
		command  string
		expected string
	}{
		{
			name:     "普通命令不脱敏",
			command:  "ls -la /home/user",
			expected: "ls -la /home/user",
		},
		{
			name:     "包含密码参数的命令",
			command:  "mysql -u admin --password secretpass123 -h localhost",
			expected: "mysql -u admin --password [REDACTED] -h localhost",
		},
		{
			name:     "密码参数等号格式",
			command:  "mysql -u admin --password=secretpass123 -h localhost",
			expected: "mysql -u admin --password=[REDACTED] -h localhost",
		},
		{
			name:     "包含-p密码参数",
			command:  "ssh -p 22 user@host",
			expected: "ssh -p [REDACTED] user@host",
		},
		{
			name:     "包含token参数",
			command:  "curl --auth-token abc123token456 https://api.example.com",
			expected: "curl --auth-token [REDACTED] https://api.example.com",
		},
		{
			name:     "包含secret参数",
			command:  "app --secret mysecretkey --config /etc/app.conf",
			expected: "app --secret [REDACTED] --config /etc/app.conf",
		},
		{
			name:     "包含key参数",
			command:  "encrypt --key abcdef123456 --input file.txt",
			expected: "encrypt --key [REDACTED] --input file.txt",
		},
		{
			name:     "私钥参数",
			command:  "ssh --private-key /path/to/key user@host",
			expected: "ssh --private-key [REDACTED] user@host",
		},
		{
			name:     "多个敏感参数",
			command:  "deploy --token abc123 --secret xyz789 --user admin",
			expected: "deploy --token [REDACTED] --secret [REDACTED] --user admin",
		},
		{
			name:     "参数值包含敏感词",
			command:  "echo passwordfile.txt",
			expected: "echo [REDACTED]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := session.sanitizeCommandForLogging(tt.command)
			if result != tt.expected {
				t.Errorf("sanitizeCommandForLogging() = %q, expected %q", result, tt.expected)
			}

			// 确保原始敏感信息不再出现在脱敏后的命令中
			sensitiveTerms := []string{"secretpass", "abc123", "mysecretkey", "abcdef123456", "mypass123", "xyz789"}
			for _, term := range sensitiveTerms {
				if strings.Contains(result, term) {
					t.Errorf("脱敏后的命令仍包含敏感信息: %q 在 %q 中", term, result)
				}
			}
		})
	}
}

func TestSanitizeEmptyOrInvalidCommands(t *testing.T) {
	session := &RealSession{
		connection: &RealConnection{
			HostID: "test-host",
			logger: logging.NewLogger(config.LoggingConfig{
				Level:  "debug",
				Format: "text",
				Output: "stdout",
			}),
		},
	}

	tests := []struct {
		name     string
		command  string
		expected string
	}{
		{
			name:     "空命令",
			command:  "",
			expected: "",
		},
		{
			name:     "只有空格",
			command:  "   ",
			expected: "   ",
		},
		{
			name:     "单个命令",
			command:  "whoami",
			expected: "whoami",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := session.sanitizeCommandForLogging(tt.command)
			if result != tt.expected {
				t.Errorf("sanitizeCommandForLogging() = %q, expected %q", result, tt.expected)
			}
		})
	}
}

func TestNoSensitiveInfoInLogs(t *testing.T) {
	// 测试确保敏感信息不会出现在日志中
	sensitiveValues := []string{
		"password123",
		"secret_key_abc",
		"token_xyz789",
		"private_key_content",
		"auth_credentials",
	}

	session := &RealSession{
		connection: &RealConnection{
			HostID: "test-host",
			logger: logging.NewLogger(config.LoggingConfig{
				Level:  "debug",
				Format: "text",
				Output: "stdout",
			}),
		},
	}

	for _, sensitiveValue := range sensitiveValues {
		command := "app --password " + sensitiveValue + " --run"
		sanitized := session.sanitizeCommandForLogging(command)

		if strings.Contains(sanitized, sensitiveValue) {
			t.Errorf("脱敏失败: 敏感值 %q 仍出现在脱敏后的命令中: %q", sensitiveValue, sanitized)
		}

		if !strings.Contains(sanitized, "[REDACTED]") {
			t.Errorf("脱敏后的命令应包含 [REDACTED] 标记: %q", sanitized)
		}
	}
}