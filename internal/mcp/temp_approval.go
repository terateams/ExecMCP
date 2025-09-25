package mcp

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/terateams/ExecMCP/internal/audit"
	"github.com/terateams/ExecMCP/internal/logging"
	"github.com/terateams/ExecMCP/internal/security"
)

// temporaryApprovalCache stores short-lived command approvals keyed by client identity.
type temporaryApprovalCache struct {
	mu      sync.RWMutex
	entries map[string]map[string]*temporaryApprovalEntry
	logger  logging.Logger
	audit   audit.Logger
}

type temporaryApprovalEntry struct {
	command    string
	expiresAt  time.Time
	maxUses    int
	useCount   int
	approvedBy string
	notes      map[string]any
	createdAt  time.Time
}

type clientIdentity struct {
	IP       string
	ClientID string
}

func (c clientIdentity) Key() string {
	return buildIdentityKey(c.IP, c.ClientID)
}

func (c clientIdentity) IsValid() bool {
	return c.IP != "" || strings.TrimSpace(c.ClientID) != ""
}

func newTemporaryApprovalCache(logger logging.Logger, auditLogger audit.Logger) *temporaryApprovalCache {
	if auditLogger == nil {
		auditLogger = audit.NewNoopLogger()
	}
	return &temporaryApprovalCache{
		entries: make(map[string]map[string]*temporaryApprovalEntry),
		logger:  logger,
		audit:   auditLogger,
	}
}

func (c *temporaryApprovalCache) approve(identityKey, command string, ttl time.Duration, maxUses int, approvedBy string, notes map[string]any) *temporaryApprovalEntry {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	if maxUses < 0 {
		maxUses = 0
	}
	entry := &temporaryApprovalEntry{
		command:    command,
		expiresAt:  time.Now().Add(ttl),
		maxUses:    maxUses,
		approvedBy: strings.TrimSpace(approvedBy),
		notes:      notes,
		createdAt:  time.Now(),
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if _, ok := c.entries[identityKey]; !ok {
		c.entries[identityKey] = make(map[string]*temporaryApprovalEntry)
	}
	c.entries[identityKey][command] = entry

	if c.logger != nil {
		c.logger.Info("新增临时命令批准", "identity", identityKey, "command", command, "expires_at", entry.expiresAt, "max_uses", maxUses)
	}
	if c.audit != nil && c.audit.Enabled() {
		c.audit.LogEvent(context.Background(), audit.Event{
			Category: "temporary_approval",
			Type:     "approved",
			Outcome:  audit.OutcomeSuccess,
			Severity: audit.SeverityInfo,
			Actor:    approvedBy,
			Target:   command,
			Metadata: map[string]any{
				"identity":  identityKey,
				"expiresAt": entry.expiresAt.Format(time.RFC3339),
				"maxUses":   maxUses,
				"notes":     notes,
			},
		})
	}

	return entry
}

func (c *temporaryApprovalCache) use(identityKey, command string) (*temporaryApprovalEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	approvals, ok := c.entries[identityKey]
	if !ok {
		return nil, false
	}

	entry, ok := approvals[command]
	if !ok {
		return nil, false
	}

	if time.Now().After(entry.expiresAt) {
		delete(approvals, command)
		if len(approvals) == 0 {
			delete(c.entries, identityKey)
		}
		return nil, false
	}

	if entry.maxUses > 0 && entry.useCount >= entry.maxUses {
		delete(approvals, command)
		if len(approvals) == 0 {
			delete(c.entries, identityKey)
		}
		return nil, false
	}

	entry.useCount++

	if entry.maxUses > 0 && entry.useCount >= entry.maxUses {
		delete(approvals, command)
		if len(approvals) == 0 {
			delete(c.entries, identityKey)
		}
	}

	return entry, true
}

func (c *temporaryApprovalCache) cleanupExpiredLocked(identityKey string) {
	approvals, ok := c.entries[identityKey]
	if !ok {
		return
	}
	for cmd, entry := range approvals {
		if time.Now().After(entry.expiresAt) {
			delete(approvals, cmd)
		}
	}
	if len(approvals) == 0 {
		delete(c.entries, identityKey)
	}
}

// temporaryApprovalProvider bridges the cache and the security filter for a specific request identity.
type temporaryApprovalProvider struct {
	cache       *temporaryApprovalCache
	identityKey string
}

var _ security.TemporaryApprovalProvider = (*temporaryApprovalProvider)(nil)

func (p *temporaryApprovalProvider) IsCommandApproved(ctx context.Context, req security.ExecRequest) bool {
	if p == nil || p.cache == nil || p.identityKey == "" {
		return false
	}
	entry, ok := p.cache.use(p.identityKey, req.Command)
	if !ok {
		return false
	}

	if p.cache.logger != nil {
		p.cache.logger.Info("命令命中临时批准", "identity", p.identityKey, "command", req.Command, "uses_remaining", remainingUses(entry))
	}
	if p.cache.audit != nil && p.cache.audit.Enabled() {
		p.cache.audit.LogEvent(ctx, audit.Event{
			Category: "temporary_approval",
			Type:     "consumed",
			Outcome:  audit.OutcomeSuccess,
			Severity: audit.SeverityInfo,
			Target:   req.Command,
			Metadata: map[string]any{
				"identity":        p.identityKey,
				"uses":            entry.useCount,
				"expires_at":      entry.expiresAt.Format(time.RFC3339),
				"approved_by":     entry.approvedBy,
				"uses_remaining":  remainingUses(entry),
				"temporary_allow": true,
			},
		})
	}
	return true
}

func remainingUses(entry *temporaryApprovalEntry) int {
	if entry == nil || entry.maxUses <= 0 {
		return -1
	}
	remaining := entry.maxUses - entry.useCount
	if remaining < 0 {
		remaining = 0
	}
	return remaining
}

// buildIdentityKey combines IP and optional client identifier into a cache key.
func buildIdentityKey(ip, clientID string) string {
	ip = normalizeIP(ip)
	clientID = strings.TrimSpace(clientID)
	if ip == "" && clientID == "" {
		return ""
	}
	if clientID == "" {
		return ip
	}
	return fmt.Sprintf("%s|%s", ip, clientID)
}

func normalizeIP(ip string) string {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(ip); err == nil {
		ip = host
	}
	if parsed := net.ParseIP(ip); parsed != nil {
		return parsed.String()
	}
	// If not a direct IP (e.g. hostname), return as-is for fallback use
	return ip
}

func newTemporaryApprovalProvider(cache *temporaryApprovalCache, identityKey string) security.TemporaryApprovalProvider {
	if cache == nil || identityKey == "" {
		return nil
	}
	return &temporaryApprovalProvider{cache: cache, identityKey: identityKey}
}
