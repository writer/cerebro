package providers

import "context"

// SyncHook runs after the wrapped provider finishes Sync.
type SyncHook func(ctx context.Context, provider Provider, result *SyncResult, syncErr error) error

// WithSyncHook wraps a provider so callers can attach post-sync behavior without
// changing existing provider implementations.
func WithSyncHook(provider Provider, after SyncHook) Provider {
	if provider == nil || after == nil {
		return provider
	}
	return syncHookProvider{Provider: provider, after: after}
}

type syncHookProvider struct {
	Provider
	after SyncHook
}

func (p syncHookProvider) Sync(ctx context.Context, opts SyncOptions) (*SyncResult, error) {
	result, err := p.Provider.Sync(ctx, opts)
	if p.after == nil {
		return result, err
	}
	if hookErr := p.after(ctx, p.Provider, result, err); hookErr != nil {
		if result == nil {
			result = &SyncResult{Provider: p.Name()}
		}
		result.Errors = append(result.Errors, hookErr.Error())
	}
	return result, err
}
