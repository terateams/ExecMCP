package common

import (
	"strings"
)

// SplitCommaSeparated 分割逗号分隔的字符串
func SplitCommaSeparated(s string) []string {
	if s == "" {
		return []string{}
	}
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		cleaned := strings.TrimSpace(part)
		if cleaned != "" {
			result = append(result, cleaned)
		}
	}
	return result
}

// JoinCommaSeparated 用逗号连接字符串切片
func JoinCommaSeparated(parts []string) string {
	return strings.Join(parts, ",")
}

// EscapeShellArg 转义shell参数
func EscapeShellArg(arg string) string {
	return strings.ReplaceAll(arg, "'", "'\"'\"'")
}

// CleanString 清理字符串（去除空格，空字符串处理）
func CleanString(s string) string {
	return strings.TrimSpace(s)
}

// IsEmpty 检查字符串是否为空
func IsEmpty(s string) bool {
	return strings.TrimSpace(s) == ""
}

// IsNotEmpty 检查字符串是否不为空
func IsNotEmpty(s string) bool {
	return strings.TrimSpace(s) != ""
}