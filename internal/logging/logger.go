package logging

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/your-username/ExecMCP/internal/config"
)

// Logger 日志接口
type Logger interface {
	Info(msg string, keyvals ...interface{})
	Debug(msg string, keyvals ...interface{})
	Warn(msg string, keyvals ...interface{})
	Error(msg string, keyvals ...interface{})
	Fatal(msg string, keyvals ...interface{})
}

// logger 结构体
type logger struct {
	level  string
	format string
	output string
	logger *log.Logger
	file   *os.File
}

// NewLogger 创建新的日志记录器
func NewLogger(cfg config.LoggingConfig) Logger {
	l := &logger{
		level:  strings.ToLower(cfg.Level),
		format: strings.ToLower(cfg.Format),
		output: strings.ToLower(cfg.Output),
	}

	// 设置输出
	switch l.output {
	case "file":
		if cfg.FilePath != "" {
			file, err := os.OpenFile(cfg.FilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				log.Printf("无法打开日志文件 %s: %v", cfg.FilePath, err)
				l.logger = log.New(os.Stdout, "", log.LstdFlags)
			} else {
				l.file = file
				l.logger = log.New(file, "", log.LstdFlags)
			}
		} else {
			l.logger = log.New(os.Stdout, "", log.LstdFlags)
		}
	default:
		l.logger = log.New(os.Stdout, "", log.LstdFlags)
	}

	return l
}

// shouldLog 判断是否应该记录该级别的日志
func (l *logger) shouldLog(level string) bool {
	levels := map[string]int{
		"debug": 0,
		"info":  1,
		"warn":  2,
		"error": 3,
		"fatal": 4,
	}

	currentLevel, exists := levels[l.level]
	if !exists {
		currentLevel = 1 // 默认 info 级别
	}

	targetLevel, exists := levels[level]
	if !exists {
		return true
	}

	return targetLevel >= currentLevel
}

// formatMessage 格式化消息
func (l *logger) formatMessage(level, msg string, keyvals ...interface{}) string {
	if l.format == "json" {
		return l.formatJSON(level, msg, keyvals...)
	}
	return l.formatText(level, msg, keyvals...)
}

// formatJSON 格式化 JSON 输出
func (l *logger) formatJSON(level, msg string, keyvals ...interface{}) string {
	// 简化的 JSON 格式，实际应用中可以使用更完整的 JSON 库
	var result string
	result = `{"level":"` + level + `","message":"` + msg + `"`

	for i := 0; i < len(keyvals); i += 2 {
		if i+1 < len(keyvals) {
			key := keyvals[i]
			value := keyvals[i+1]
			result += `,"` + key.(string) + `":"` + toString(value) + `"`
		}
	}

	result += `}`
	return result
}

// formatText 格式化文本输出
func (l *logger) formatText(level, msg string, keyvals ...interface{}) string {
	result := "[" + strings.ToUpper(level) + "] " + msg

	for i := 0; i < len(keyvals); i += 2 {
		if i+1 < len(keyvals) {
			key := keyvals[i]
			value := keyvals[i+1]
			result += " " + key.(string) + "=" + toString(value)
		}
	}

	return result
}

// toString 将任意值转换为字符串
func toString(value interface{}) string {
	if value == nil {
		return ""
	}
	return fmt.Sprintf("%v", value)
}

// Info 记录信息级别日志
func (l *logger) Info(msg string, keyvals ...interface{}) {
	if l.shouldLog("info") {
		formatted := l.formatMessage("info", msg, keyvals...)
		l.logger.Println(formatted)
	}
}

// Debug 记录调试级别日志
func (l *logger) Debug(msg string, keyvals ...interface{}) {
	if l.shouldLog("debug") {
		formatted := l.formatMessage("debug", msg, keyvals...)
		l.logger.Println(formatted)
	}
}

// Warn 记录警告级别日志
func (l *logger) Warn(msg string, keyvals ...interface{}) {
	if l.shouldLog("warn") {
		formatted := l.formatMessage("warn", msg, keyvals...)
		l.logger.Println(formatted)
	}
}

// Error 记录错误级别日志
func (l *logger) Error(msg string, keyvals ...interface{}) {
	if l.shouldLog("error") {
		formatted := l.formatMessage("error", msg, keyvals...)
		l.logger.Println(formatted)
	}
}

// Fatal 记录致命错误日志并退出程序
func (l *logger) Fatal(msg string, keyvals ...interface{}) {
	if l.shouldLog("fatal") {
		formatted := l.formatMessage("fatal", msg, keyvals...)
		l.logger.Println(formatted)
		os.Exit(1)
	}
}

// Close 关闭日志文件
func (l *logger) Close() {
	if l.file != nil {
		l.file.Close()
	}
}
