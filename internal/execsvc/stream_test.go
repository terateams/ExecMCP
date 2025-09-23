package execsvc

import (
	"context"
	"io"
	"testing"
	"time"
)

func TestStreamManager_ExecuteCommandWithStream(t *testing.T) {
	sm := newTestStreamManager(t, nil)

	stream, err := sm.ExecuteCommandWithStream(context.Background(), ExecRequest{
		HostID:  "test-host",
		Command: "pwd",
		Options: ExecOptions{Stream: true},
	})
	if err != nil {
		t.Fatalf("期望创建流成功，但得到错误: %v", err)
	}
	if stream == nil {
		t.Fatal("期望获得 CommandStream，但为 nil")
	}

	buf := make([]byte, 64)
	time.Sleep(20 * time.Millisecond)
	if _, err := stream.Read(buf); err != nil && err != io.EOF {
		t.Fatalf("读取流输出失败: %v", err)
	}

	if err := stream.Close(); err != nil {
		t.Fatalf("关闭流失败: %v", err)
	}
}

func TestStreamManager_ExecuteCommandWithStream_Timeout(t *testing.T) {
	sm := newTestStreamManager(t, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()

	stream, err := sm.ExecuteCommandWithStream(ctx, ExecRequest{
		HostID:  "test-host",
		Command: "sleep",
		Args:    []string{"1"},
		Options: ExecOptions{Stream: true},
	})
	if err != nil {
		t.Fatalf("期望创建流成功，但得到错误: %v", err)
	}

	time.Sleep(40 * time.Millisecond)
	if stream.IsClosed() {
		return
	}
	if err := stream.Close(); err != nil {
		t.Fatalf("关闭流失败: %v", err)
	}
}

func TestCommandStream_Close(t *testing.T) {
	sm := newTestStreamManager(t, nil)

	stream, err := sm.ExecuteCommandWithStream(context.Background(), ExecRequest{
		HostID:  "test-host",
		Command: "pwd",
		Options: ExecOptions{Stream: true},
	})
	if err != nil {
		t.Fatalf("期望创建流成功，但得到错误: %v", err)
	}

	if err := stream.Close(); err != nil {
		t.Fatalf("关闭流失败: %v", err)
	}

	if _, err := stream.Read(make([]byte, 8)); err == nil {
		t.Fatal("关闭后的流仍然可读，期望返回错误")
	}
}
