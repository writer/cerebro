package cli

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/writerinternal/cerebro/internal/app"
	providerregistry "github.com/writerinternal/cerebro/internal/providers"
)

type testWorkerProvider struct {
	name   string
	err    error
	result *providerregistry.SyncResult
	calls  int
}

func (p *testWorkerProvider) Name() string { return p.name }

func (p *testWorkerProvider) Type() providerregistry.ProviderType {
	return providerregistry.ProviderTypeCustom
}

func (p *testWorkerProvider) Configure(context.Context, map[string]interface{}) error { return nil }

func (p *testWorkerProvider) Sync(context.Context, providerregistry.SyncOptions) (*providerregistry.SyncResult, error) {
	p.calls++
	if p.err != nil {
		return p.result, p.err
	}
	if p.result != nil {
		return p.result, nil
	}
	return &providerregistry.SyncResult{
		Provider:    p.name,
		StartedAt:   time.Now(),
		CompletedAt: time.Now(),
	}, nil
}

func (p *testWorkerProvider) Test(context.Context) error { return nil }

func (p *testWorkerProvider) Schema() []providerregistry.TableSchema { return nil }

func TestSyncConfiguredProviderSources_SkipsNativeProviders(t *testing.T) {
	registry := providerregistry.NewRegistry()
	native := &testWorkerProvider{name: "azure"}
	other := &testWorkerProvider{name: "okta"}
	registry.Register(native)
	registry.Register(other)

	application := &app.App{Providers: registry}

	synced, err := syncConfiguredProviderSources(context.Background(), application, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if native.calls != 0 {
		t.Fatalf("expected native provider to be skipped, got %d calls", native.calls)
	}
	if other.calls != 1 {
		t.Fatalf("expected non-native provider to be synced once, got %d calls", other.calls)
	}
	if len(synced) != 1 || synced[0] != "okta" {
		t.Fatalf("unexpected synced providers: %#v", synced)
	}
}

func TestSyncConfiguredProviderSources_AggregatesErrors(t *testing.T) {
	registry := providerregistry.NewRegistry()
	failing := &testWorkerProvider{name: "github", err: errors.New("boom")}
	success := &testWorkerProvider{name: "okta"}
	registry.Register(failing)
	registry.Register(success)

	application := &app.App{Providers: registry}

	synced, err := syncConfiguredProviderSources(context.Background(), application, nil)
	if err == nil {
		t.Fatal("expected error but got nil")
	}
	if !strings.Contains(err.Error(), "github sync failed") {
		t.Fatalf("expected github sync failure in error, got %v", err)
	}
	if failing.calls != 1 || success.calls != 1 {
		t.Fatalf("expected both providers to be attempted, got failing=%d success=%d", failing.calls, success.calls)
	}
	if len(synced) != 1 || synced[0] != "okta" {
		t.Fatalf("unexpected synced providers: %#v", synced)
	}
}
