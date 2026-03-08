package api

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/evalops/cerebro/internal/snowflake"
	nativesync "github.com/evalops/cerebro/internal/sync"
)

func TestBackfillRelationshipIDs_RequiresSnowflake(t *testing.T) {
	s := newTestServer(t)

	w := do(t, s, http.MethodPost, "/api/v1/sync/backfill-relationships", map[string]interface{}{
		"batch_size": 100,
	})
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d: %s", w.Code, w.Body.String())
	}
}

func TestBackfillRelationshipIDs_InvalidRequest(t *testing.T) {
	s := newTestServer(t)

	w := do(t, s, http.MethodPost, "/api/v1/sync/backfill-relationships", "not-json")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid request, got %d: %s", w.Code, w.Body.String())
	}
}

func TestSyncAzure_RequiresSnowflake(t *testing.T) {
	s := newTestServer(t)

	w := do(t, s, http.MethodPost, "/api/v1/sync/azure", map[string]interface{}{
		"subscription": "sub-123",
		"concurrency":  10,
		"tables":       []string{"azure_vm_instances"},
	})
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d: %s", w.Code, w.Body.String())
	}
}

func TestSyncAzure_InvalidRequest(t *testing.T) {
	s := newTestServer(t)

	w := do(t, s, http.MethodPost, "/api/v1/sync/azure", "not-json")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid request, got %d: %s", w.Code, w.Body.String())
	}
}

func TestSyncAzure_UsesRequestOptions(t *testing.T) {
	s := newTestServer(t)
	s.app.Snowflake = &snowflake.Client{}

	originalRun := runAzureSyncWithOptions
	t.Cleanup(func() { runAzureSyncWithOptions = originalRun })

	called := false
	runAzureSyncWithOptions = func(ctx context.Context, client *snowflake.Client, req azureSyncRequest) ([]nativesync.SyncResult, error) {
		called = true
		if client != s.app.Snowflake {
			t.Fatalf("expected server snowflake client to be passed through")
		}
		if req.Subscription != "sub-123" {
			t.Fatalf("expected trimmed subscription, got %q", req.Subscription)
		}
		if req.Concurrency != 7 {
			t.Fatalf("expected concurrency 7, got %d", req.Concurrency)
		}
		if len(req.Tables) != 2 || req.Tables[0] != "azure_vm_instances" || req.Tables[1] != "azure_storage_accounts" {
			t.Fatalf("unexpected table filter: %#v", req.Tables)
		}
		if !req.Validate {
			t.Fatal("expected validate=true")
		}
		return []nativesync.SyncResult{{Table: "azure_vm_instances", Synced: 3}}, nil
	}

	w := do(t, s, http.MethodPost, "/api/v1/sync/azure", map[string]interface{}{
		"subscription": "  sub-123  ",
		"concurrency":  7,
		"tables":       []string{"Azure_VM_Instances", "azure_vm_instances", " azure_storage_accounts "},
		"validate":     true,
	})
	if !called {
		t.Fatal("expected sync runner to be called")
	}
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"provider":"azure"`) {
		t.Fatalf("expected provider in response body, got %s", w.Body.String())
	}
}
