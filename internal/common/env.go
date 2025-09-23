package common

import (
	"os"
	"strconv"
)

// GetEnv 获取环境变量，带默认值
func GetEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// GetEnvBool 获取布尔环境变量，带默认值
func GetEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		return value == "true" || value == "1"
	}
	return defaultValue
}

// GetEnvInt 获取整型环境变量，带默认值
func GetEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if val, err := strconv.Atoi(value); err == nil {
			return val
		}
	}
	return defaultValue
}

// GetEnvInt64 获取int64环境变量，带默认值
func GetEnvInt64(key string, defaultValue int64) int64 {
	if value := os.Getenv(key); value != "" {
		if val, err := strconv.ParseInt(value, 10, 64); err == nil {
			return val
		}
	}
	return defaultValue
}

// SetEnv 设置环境变量（如果值不为空）
func SetEnv(key, value string) {
	if value != "" {
		os.Setenv(key, value)
	}
}

// SetEnvBool 设置布尔环境变量（如果值为true）
func SetEnvBool(key string, value bool) {
	if value {
		os.Setenv(key, "true")
	} else {
		os.Setenv(key, "false")
	}
}

// SetEnvInt 设置整型环境变量
func SetEnvInt(key string, value int) {
	os.Setenv(key, strconv.Itoa(value))
}

// UnsetEnv 取消设置环境变量
func UnsetEnv(key string) {
	os.Unsetenv(key)
}