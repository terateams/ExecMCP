package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/terateams/ExecMCP/internal/logging"
)

// Severity represents the criticality of a security event.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Outcome captures the result of a security relevant action.
type Outcome string

const (
	OutcomeSuccess Outcome = "success"
	OutcomeDenied  Outcome = "denied"
	OutcomeError   Outcome = "error"
	OutcomeUnknown Outcome = "unknown"
)

// Event defines the standard structure for security audit entries.
type Event struct {
	Timestamp time.Time              `json:"timestamp"`
	Category  string                 `json:"category"`
	Type      string                 `json:"type"`
	RequestID string                 `json:"request_id"`
	Actor     string                 `json:"actor,omitempty"`
	Tool      string                 `json:"tool,omitempty"`
	SourceIP  string                 `json:"source_ip,omitempty"`
	HostID    string                 `json:"host_id,omitempty"`
	Target    string                 `json:"target,omitempty"`
	Outcome   Outcome                `json:"outcome"`
	Severity  Severity               `json:"severity"`
	Reason    string                 `json:"reason,omitempty"`
	Rule      string                 `json:"rule,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// Config controls how the audit logger persists events.
type Config struct {
	Enabled  bool
	Format   string
	Output   string
	FilePath string
}

// Logger writes security audit events.
type Logger interface {
	LogEvent(ctx context.Context, event Event)
	Close() error
	Enabled() bool
}

type noopLogger struct{}

func (noopLogger) LogEvent(_ context.Context, _ Event) {}
func (noopLogger) Close() error                        { return nil }
func (noopLogger) Enabled() bool                       { return false }

// NewNoopLogger 返回一个不执行任何操作的审计日志记录器。
func NewNoopLogger() Logger {
	return noopLogger{}
}

type auditLogger struct {
	logger   *log.Logger
	format   string
	closer   io.Closer
	fallback logging.Logger
	enabled  bool
	mu       sync.Mutex
}

// NewLogger builds a security audit logger using the provided configuration.
// If configuration is disabled, a noop logger is returned.
func NewLogger(cfg Config, fallback logging.Logger) (Logger, error) {
	if !cfg.Enabled {
		return noopLogger{}, nil
	}

	format := strings.ToLower(strings.TrimSpace(cfg.Format))
	if format == "" {
		format = "json"
	}

	output := strings.ToLower(strings.TrimSpace(cfg.Output))
	if output == "" {
		output = "stdout"
	}

	var writer io.Writer
	var closer io.Closer

	switch output {
	case "stdout":
		writer = os.Stdout
	case "stderr":
		writer = os.Stderr
	case "file":
		path := strings.TrimSpace(cfg.FilePath)
		if path == "" {
			path = "security_audit.log"
		}

		dir := filepath.Dir(path)
		if dir != "." && dir != "" {
			if err := os.MkdirAll(dir, 0755); err != nil && !os.IsExist(err) {
				return nil, fmt.Errorf("create audit log directory: %w", err)
			}
		}

		file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
		if err != nil {
			return nil, fmt.Errorf("open audit log file: %w", err)
		}
		writer = file
		closer = file
	default:
		return nil, fmt.Errorf("unsupported audit logger output: %s", cfg.Output)
	}

	audit := &auditLogger{
		logger:   log.New(writer, "", 0),
		format:   format,
		closer:   closer,
		fallback: fallback,
		enabled:  true,
	}
	return audit, nil
}

func (l *auditLogger) Enabled() bool { return l.enabled }

func (l *auditLogger) Close() error {
	if l.closer != nil {
		return l.closer.Close()
	}
	return nil
}

func (l *auditLogger) LogEvent(ctx context.Context, event Event) {
	if !l.enabled || l.logger == nil {
		return
	}

	fields := FromContext(ctx)
	if event.RequestID == "" {
		if fields.RequestID != "" {
			event.RequestID = fields.RequestID
		} else {
			event.RequestID = uuid.NewString()
		}
	}
	if event.Actor == "" {
		event.Actor = fields.Actor
	}
	if event.Tool == "" {
		event.Tool = fields.Tool
	}
	if event.SourceIP == "" {
		event.SourceIP = fields.SourceIP
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	if event.Category == "" {
		event.Category = "exec"
	}
	if event.Outcome == "" {
		event.Outcome = OutcomeUnknown
	}
	if event.Severity == "" {
		event.Severity = SeverityInfo
	}

	switch l.format {
	case "json":
		l.logJSON(event)
	case "text":
		l.logText(event)
	default:
		l.logJSON(event)
	}
}

func (l *auditLogger) logJSON(event Event) {
	payload := map[string]interface{}{
		"timestamp":  event.Timestamp.Format(time.RFC3339Nano),
		"category":   event.Category,
		"type":       event.Type,
		"request_id": event.RequestID,
		"outcome":    event.Outcome,
		"severity":   event.Severity,
	}

	if event.Actor != "" {
		payload["actor"] = event.Actor
	}
	if event.Tool != "" {
		payload["tool"] = event.Tool
	}
	if event.SourceIP != "" {
		payload["source_ip"] = event.SourceIP
	}
	if event.HostID != "" {
		payload["host_id"] = event.HostID
	}
	if event.Target != "" {
		payload["target"] = event.Target
	}
	if event.Reason != "" {
		payload["reason"] = event.Reason
	}
	if event.Rule != "" {
		payload["rule"] = event.Rule
	}
	if len(event.Metadata) > 0 {
		payload["metadata"] = event.Metadata
	}

	data, err := json.Marshal(payload)
	if err != nil {
		l.handleError(fmt.Errorf("marshal audit event: %w", err))
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	l.logger.Println(string(data))
}

func (l *auditLogger) logText(event Event) {
	builder := strings.Builder{}
	builder.WriteString(event.Timestamp.Format(time.RFC3339Nano))
	builder.WriteString(" ")
	builder.WriteString(string(event.Severity))
	builder.WriteString(" [")
	builder.WriteString(event.Category)
	builder.WriteString("] type=")
	builder.WriteString(event.Type)
	builder.WriteString(" request_id=")
	builder.WriteString(event.RequestID)
	builder.WriteString(" outcome=")
	builder.WriteString(string(event.Outcome))

	if event.Actor != "" {
		builder.WriteString(" actor=")
		builder.WriteString(event.Actor)
	}
	if event.Tool != "" {
		builder.WriteString(" tool=")
		builder.WriteString(event.Tool)
	}
	if event.SourceIP != "" {
		builder.WriteString(" source_ip=")
		builder.WriteString(event.SourceIP)
	}
	if event.HostID != "" {
		builder.WriteString(" host_id=")
		builder.WriteString(event.HostID)
	}
	if event.Target != "" {
		builder.WriteString(" target=")
		builder.WriteString(event.Target)
	}
	if event.Rule != "" {
		builder.WriteString(" rule=")
		builder.WriteString(event.Rule)
	}
	if event.Reason != "" {
		builder.WriteString(" reason=")
		builder.WriteString(event.Reason)
	}
	if len(event.Metadata) > 0 {
		if metadata, err := json.Marshal(event.Metadata); err == nil {
			builder.WriteString(" metadata=")
			builder.Write(metadata)
		}
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	l.logger.Println(builder.String())
}

func (l *auditLogger) handleError(err error) {
	if l.fallback != nil {
		l.fallback.Error("记录安全审计日志失败", "error", err)
	}
}

// ContextFields holds audit relevant request metadata extracted from the caller.
type ContextFields struct {
	RequestID string
	Actor     string
	Tool      string
	SourceIP  string
}

type contextKey struct{}

var ctxKey = contextKey{}

// WithContext enriches the context with security audit metadata. New values
// override existing ones when non-empty.
func WithContext(ctx context.Context, fields ContextFields) context.Context {
	existing := FromContext(ctx)

	if fields.RequestID == "" {
		fields.RequestID = existing.RequestID
	}
	if fields.Actor == "" {
		fields.Actor = existing.Actor
	}
	if fields.Tool == "" {
		fields.Tool = existing.Tool
	}
	if fields.SourceIP == "" {
		fields.SourceIP = existing.SourceIP
	}

	return context.WithValue(ctx, ctxKey, fields)
}

// FromContext extracts audit metadata from context. Returns zero values when
// unavailable.
func FromContext(ctx context.Context) ContextFields {
	if ctx == nil {
		return ContextFields{}
	}

	if v := ctx.Value(ctxKey); v != nil {
		if fields, ok := v.(ContextFields); ok {
			return fields
		}
	}
	return ContextFields{}
}

// EnsureContext ensures the context carries a request identifier.
func EnsureContext(ctx context.Context) (context.Context, string) {
	fields := FromContext(ctx)
	if fields.RequestID == "" {
		fields.RequestID = uuid.NewString()
		ctx = WithContext(ctx, fields)
	}
	return ctx, fields.RequestID
}
