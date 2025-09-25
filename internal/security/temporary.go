package security

import "context"

// TemporaryApprovalProvider allows callers to inject runtime command approvals that can
// bypass allowlist checks in a controlled manner.
type TemporaryApprovalProvider interface {
	IsCommandApproved(ctx context.Context, req ExecRequest) bool
}

type temporaryApprovalKey struct{}

// WithTemporaryApproval attaches a temporary approval provider to the context so the
// security filter can consult it during allowlist evaluation.
func WithTemporaryApproval(ctx context.Context, provider TemporaryApprovalProvider) context.Context {
	if provider == nil {
		return ctx
	}
	return context.WithValue(ctx, temporaryApprovalKey{}, provider)
}

// temporaryApprovalFromContext retrieves the temporary approval provider from context.
func temporaryApprovalFromContext(ctx context.Context) TemporaryApprovalProvider {
	if provider, ok := ctx.Value(temporaryApprovalKey{}).(TemporaryApprovalProvider); ok {
		return provider
	}
	return nil
}
