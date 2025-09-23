package common

import (
	"fmt"
)

// WrapError 包装错误，提供统一格式
func WrapError(message string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", message, err)
}

// NewError 创建新错误，支持格式化
func NewError(format string, args ...interface{}) error {
	return fmt.Errorf(format, args...)
}

// SSHError 创建SSH相关错误
func SSHError(operation, hostID string, err error) error {
	return fmt.Errorf("SSH %s失败 (主机: %s): %w", operation, hostID, err)
}

// ConfigError 创建配置相关错误
func ConfigError(field, message string) error {
	return fmt.Errorf("配置错误 [%s]: %s", field, message)
}

// ValidationError 创建验证相关错误
func ValidationError(field, message string) error {
	return fmt.Errorf("验证失败 [%s]: %s", field, message)
}

// TimeoutError 创建超时相关错误
func TimeoutError(operation string, timeout int) error {
	return fmt.Errorf("%s超时 (%d秒)", operation, timeout)
}