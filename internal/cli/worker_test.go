package cli

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/evalops/cerebro/internal/app"
	providerregistry "github.com/evalops/cerebro/internal/providers"
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

	synced, failed, err := syncConfiguredProviderSources(context.Background(), application, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(failed) != 0 {
		t.Fatalf("unexpected failed providers: %#v", failed)
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

func TestSyncConfiguredProviderSources_CollectsErrorsWithoutFailing(t *testing.T) {
	registry := providerregistry.NewRegistry()
	failing := &testWorkerProvider{name: "github", err: errors.New("boom")}
	success := &testWorkerProvider{name: "okta"}
	registry.Register(failing)
	registry.Register(success)

	application := &app.App{Providers: registry}

	synced, failed, err := syncConfiguredProviderSources(context.Background(), application, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(failed) != 1 {
		t.Fatalf("expected one failed provider, got %#v", failed)
	}
	if failed[0].Provider != "github" {
		t.Fatalf("expected github failed provider, got %#v", failed)
	}
	if !strings.Contains(failed[0].Error, "github sync failed") {
		t.Fatalf("expected github sync failure message, got %q", failed[0].Error)
	}
	if failing.calls != 1 || success.calls != 1 {
		t.Fatalf("expected both providers to be attempted, got failing=%d success=%d", failing.calls, success.calls)
	}
	if len(synced) != 1 || synced[0] != "okta" {
		t.Fatalf("unexpected synced providers: %#v", synced)
	}
}

func TestSyncConfiguredProviderSources_APIModeUsesAPI(t *testing.T) {
	registry := providerregistry.NewRegistry()
	provider := &testWorkerProvider{name: "okta"}
	registry.Register(provider)

	application := &app.App{Providers: registry}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/providers/okta/sync" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"provider":"okta","errors":[]}`))
	}))
	defer server.Close()

	t.Setenv(envCLIExecutionMode, string(cliExecutionModeAPI))
	t.Setenv(envCLIAPIURL, server.URL)

	synced, failed, err := syncConfiguredProviderSources(context.Background(), application, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if provider.calls != 0 {
		t.Fatalf("expected direct provider sync to be skipped in api mode, got %d calls", provider.calls)
	}
	if len(failed) != 0 {
		t.Fatalf("unexpected failed providers: %#v", failed)
	}
	if len(synced) != 1 || synced[0] != "okta" {
		t.Fatalf("unexpected synced providers: %#v", synced)
	}
}

func TestSyncConfiguredProviderSources_AutoModeFallbacksToDirectOnTransportError(t *testing.T) {
	registry := providerregistry.NewRegistry()
	provider := &testWorkerProvider{name: "okta"}
	registry.Register(provider)

	application := &app.App{Providers: registry}

	t.Setenv(envCLIExecutionMode, string(cliExecutionModeAuto))
	t.Setenv(envCLIAPIURL, "http://127.0.0.1:1")

	synced, failed, err := syncConfiguredProviderSources(context.Background(), application, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if provider.calls != 1 {
		t.Fatalf("expected direct fallback sync call, got %d", provider.calls)
	}
	if len(failed) != 0 {
		t.Fatalf("unexpected failed providers: %#v", failed)
	}
	if len(synced) != 1 || synced[0] != "okta" {
		t.Fatalf("unexpected synced providers: %#v", synced)
	}
}

func TestSyncConfiguredProviderSources_AutoModeDoesNotFallbackOnUnauthorized(t *testing.T) {
	registry := providerregistry.NewRegistry()
	provider := &testWorkerProvider{name: "okta"}
	registry.Register(provider)

	application := &app.App{Providers: registry}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"unauthorized","code":"unauthorized"}`))
	}))
	defer server.Close()

	t.Setenv(envCLIExecutionMode, string(cliExecutionModeAuto))
	t.Setenv(envCLIAPIURL, server.URL)

	synced, failed, err := syncConfiguredProviderSources(context.Background(), application, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if provider.calls != 0 {
		t.Fatalf("did not expect direct fallback sync call, got %d", provider.calls)
	}
	if len(synced) != 0 {
		t.Fatalf("unexpected synced providers: %#v", synced)
	}
	if len(failed) != 1 {
		t.Fatalf("expected one failed provider, got %#v", failed)
	}
	if !strings.Contains(failed[0].Error, "sync via api failed") {
		t.Fatalf("expected api failure message, got %q", failed[0].Error)
	}
}

func TestNewNativeSyncJobHandler_RoutesAndSerializesResult(t *testing.T) {
	originalRunNative := runNativeSyncForJobFn
	originalSyncProviders := syncConfiguredProviderSourcesFn
	t.Cleanup(func() {
		runNativeSyncForJobFn = originalRunNative
		syncConfiguredProviderSourcesFn = originalSyncProviders
	})

	calledProvider := ""
	calledSchedule := &SyncSchedule{}
	runNativeSyncForJobFn = func(_ context.Context, provider string, schedule *SyncSchedule) error {
		calledProvider = provider
		calledSchedule = schedule
		return nil
	}
	syncConfiguredProviderSourcesFn = func(context.Context, *app.App, *slog.Logger) ([]string, []providerSyncFailure, error) {
		return []string{"okta"}, []providerSyncFailure{{Provider: "github", Error: "github sync failed: boom"}}, nil
	}

	handler := newNativeSyncJobHandler(nil)
	result, err := handler(context.Background(), `{"provider":"AWS","table":"aws_iam_roles","schedule_name":"hourly"}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if calledProvider != "aws" {
		t.Fatalf("expected normalized provider aws, got %q", calledProvider)
	}
	if calledSchedule.Provider != "aws" || calledSchedule.Table != "aws_iam_roles" || calledSchedule.Name != "hourly" {
		t.Fatalf("unexpected schedule routing payload: %#v", calledSchedule)
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(result), &payload); err != nil {
		t.Fatalf("parse result: %v", err)
	}
	if payload["provider"] != "aws" {
		t.Fatalf("expected provider aws, got %#v", payload["provider"])
	}
	if payload["schedule_name"] != "hourly" {
		t.Fatalf("expected schedule_name hourly, got %#v", payload["schedule_name"])
	}
	additional, ok := payload["additional_providers"].([]any)
	if !ok || len(additional) != 1 || additional[0] != "okta" {
		t.Fatalf("unexpected additional providers payload: %#v", payload["additional_providers"])
	}
	failed, ok := payload["failed_additional_providers"].([]any)
	if !ok || len(failed) != 1 {
		t.Fatalf("unexpected failed providers payload: %#v", payload["failed_additional_providers"])
	}
}

func TestNewNativeSyncJobHandler_FailurePaths(t *testing.T) {
	t.Run("invalid payload", func(t *testing.T) {
		handler := newNativeSyncJobHandler(nil)
		_, err := handler(context.Background(), `{not-json`)
		if err == nil || !strings.Contains(err.Error(), "decode native sync payload") {
			t.Fatalf("expected decode error, got %v", err)
		}
	})

	t.Run("unsupported provider", func(t *testing.T) {
		handler := newNativeSyncJobHandler(nil)
		_, err := handler(context.Background(), `{"provider":"okta"}`)
		if err == nil || !strings.Contains(err.Error(), "unsupported native sync provider") {
			t.Fatalf("expected unsupported provider error, got %v", err)
		}
	})

	t.Run("native sync error", func(t *testing.T) {
		originalRunNative := runNativeSyncForJobFn
		originalSyncProviders := syncConfiguredProviderSourcesFn
		t.Cleanup(func() {
			runNativeSyncForJobFn = originalRunNative
			syncConfiguredProviderSourcesFn = originalSyncProviders
		})

		runNativeSyncForJobFn = func(context.Context, string, *SyncSchedule) error {
			return errors.New("sync boom")
		}
		syncConfiguredProviderSourcesFn = func(context.Context, *app.App, *slog.Logger) ([]string, []providerSyncFailure, error) {
			t.Fatal("expected additional provider sync to be skipped after native sync error")
			return nil, nil, nil
		}

		handler := newNativeSyncJobHandler(nil)
		_, err := handler(context.Background(), `{"provider":"gcp","schedule_name":"daily"}`)
		if err == nil || !strings.Contains(err.Error(), "sync boom") {
			t.Fatalf("expected native sync error, got %v", err)
		}
	})

	t.Run("additional provider sync aggregation error", func(t *testing.T) {
		originalRunNative := runNativeSyncForJobFn
		originalSyncProviders := syncConfiguredProviderSourcesFn
		t.Cleanup(func() {
			runNativeSyncForJobFn = originalRunNative
			syncConfiguredProviderSourcesFn = originalSyncProviders
		})

		runNativeSyncForJobFn = func(context.Context, string, *SyncSchedule) error {
			return nil
		}
		syncConfiguredProviderSourcesFn = func(context.Context, *app.App, *slog.Logger) ([]string, []providerSyncFailure, error) {
			return nil, nil, errors.New("provider registry unavailable")
		}

		handler := newNativeSyncJobHandler(nil)
		_, err := handler(context.Background(), `{"provider":"azure","schedule_name":"nightly"}`)
		if err == nil || !strings.Contains(err.Error(), "provider registry unavailable") {
			t.Fatalf("expected additional provider error, got %v", err)
		}
	})
}
