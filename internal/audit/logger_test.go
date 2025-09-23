package audit

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoggerWritesJSONWithContext(t *testing.T) {
	tempDir := t.TempDir()
	logPath := filepath.Join(tempDir, "audit.log")

	logger, err := NewLogger(Config{
		Enabled:  true,
		Format:   "json",
		Output:   "file",
		FilePath: logPath,
	}, nil)
	if err != nil {
		t.Fatalf("初始化审计日志失败: %v", err)
	}
	defer logger.Close()

	ctx := WithContext(context.Background(), ContextFields{
		RequestID: "req-123",
		Actor:     "tester",
		Tool:      "unit_test",
		SourceIP:  "127.0.0.1",
	})

	logger.LogEvent(ctx, Event{
		Category: "unit",
		Type:     "test_event",
		Outcome:  OutcomeSuccess,
		Severity: SeverityLow,
	})

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("读取审计日志失败: %v", err)
	}

	content := string(data)
	if !strings.Contains(content, "\"actor\":\"tester\"") {
		t.Errorf("期望日志包含 actor 字段，内容: %s", content)
	}
	if !strings.Contains(content, "\"tool\":\"unit_test\"") {
		t.Errorf("期望日志包含 tool 字段，内容: %s", content)
	}
	if !strings.Contains(content, "\"request_id\":\"req-123\"") {
		t.Errorf("期望日志包含 request_id 字段，内容: %s", content)
	}
}
