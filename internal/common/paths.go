package common

import (
	"os"
	"path/filepath"
	"strings"
)

// JoinPaths 安全地拼接多个路径
func JoinPaths(paths ...string) string {
	return filepath.Join(paths...)
}

// CleanPath 清理路径
func CleanPath(path string) string {
	return filepath.Clean(path)
}

// ExpandPath 展开 ~ 路径
func ExpandPath(path string) string {
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err == nil {
			return filepath.Join(home, path[2:])
		}
	}
	return path
}

// GetTestDataPath 获取测试数据路径
func GetTestDataPath(elem ...string) string {
	base := filepath.Join("..", "testdata")
	return filepath.Join(base, filepath.Join(elem...))
}

// EnsureDir 确保目录存在
func EnsureDir(path string) error {
	return os.MkdirAll(path, 0755)
}

// FileExists 检查文件是否存在
func FileExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir()
}

// DirExists 检查目录是否存在
func DirExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.IsDir()
}
