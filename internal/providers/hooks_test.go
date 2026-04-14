package providers

import (
	"context"
	"errors"
	"testing"
)

type hookTestProvider struct {
	name   string
	typ    ProviderType
	result *SyncResult
	err    error
	calls  int
}

func (p *hookTestProvider) Name() string { return p.name }

func (p *hookTestProvider) Type() ProviderType { return p.typ }

func (p *hookTestProvider) Configure(context.Context, map[string]interface{}) error { return nil }

func (p *hookTestProvider) Sync(context.Context, SyncOptions) (*SyncResult, error) {
	p.calls++
	return p.result, p.err
}

func (p *hookTestProvider) Test(context.Context) error { return nil }

func (p *hookTestProvider) Schema() []TableSchema { return nil }

func TestWithSyncHookAppendsHookErrors(t *testing.T) {
	t.Parallel()

	provider := &hookTestProvider{
		name: "sentinelone",
		typ:  ProviderTypeEndpoint,
		result: &SyncResult{
			Provider: "sentinelone",
		},
	}

	wrapped := WithSyncHook(provider, func(context.Context, Provider, *SyncResult, error) error {
		return errors.New("refresh endpoint vulnerability tables: boom")
	})

	result, err := wrapped.Sync(context.Background(), SyncOptions{FullSync: true})
	if err != nil {
		t.Fatalf("unexpected sync error: %v", err)
	}
	if provider.calls != 1 {
		t.Fatalf("expected one underlying sync call, got %d", provider.calls)
	}
	if result == nil || len(result.Errors) != 1 {
		t.Fatalf("expected hook error to be appended to result, got %#v", result)
	}
	if result.Errors[0] != "refresh endpoint vulnerability tables: boom" {
		t.Fatalf("unexpected hook error: %#v", result.Errors)
	}
}

func TestWithSyncHookPreservesUnderlyingSyncError(t *testing.T) {
	t.Parallel()

	expectedErr := errors.New("provider sync failed")
	provider := &hookTestProvider{
		name: "kandji",
		typ:  ProviderTypeEndpoint,
		err:  expectedErr,
	}

	wrapped := WithSyncHook(provider, func(context.Context, Provider, *SyncResult, error) error {
		return nil
	})

	result, err := wrapped.Sync(context.Background(), SyncOptions{FullSync: true})
	if !errors.Is(err, expectedErr) {
		t.Fatalf("expected underlying sync error, got %v", err)
	}
	if result != nil {
		t.Fatalf("expected nil result when provider returned nil result, got %#v", result)
	}
}
