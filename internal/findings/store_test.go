package findings

import (
	"context"
	"testing"

	"github.com/writerinternal/cerebro/internal/policy"
)

func TestStoreUpsert(t *testing.T) {
	store := NewStore()

	pf := policy.Finding{
		ID:          "test-finding-1",
		PolicyID:    "test-policy",
		PolicyName:  "Test Policy",
		Severity:    "high",
		Resource:    map[string]interface{}{"_cq_id": "abc123", "name": "test-resource"},
		Description: "Test finding description",
	}

	f := store.Upsert(context.Background(), pf)

	if f.ID != "test-finding-1" {
		t.Errorf("expected ID 'test-finding-1', got '%s'", f.ID)
	}
	if f.Status != "open" {
		t.Errorf("expected status 'open', got '%s'", f.Status)
	}
	if f.Severity != "high" {
		t.Errorf("expected severity 'high', got '%s'", f.Severity)
	}
}

func TestStoreUpsertExisting(t *testing.T) {
	store := NewStore()

	pf := policy.Finding{
		ID:       "test-finding-1",
		PolicyID: "test-policy",
		Severity: "high",
		Resource: map[string]interface{}{"name": "original"},
	}

	store.Upsert(context.Background(), pf)

	// Update with new resource data
	pf.Resource = map[string]interface{}{"name": "updated"}
	f := store.Upsert(context.Background(), pf)

	if f.Resource["name"] != "updated" {
		t.Errorf("expected resource name 'updated', got '%v'", f.Resource["name"])
	}
}

func TestStoreResolve(t *testing.T) {
	store := NewStore()

	pf := policy.Finding{
		ID:       "test-finding-1",
		PolicyID: "test-policy",
	}
	store.Upsert(context.Background(), pf)

	if !store.Resolve("test-finding-1") {
		t.Error("expected Resolve to return true")
	}

	f, _ := store.Get("test-finding-1")
	if f.Status != "resolved" {
		t.Errorf("expected status 'resolved', got '%s'", f.Status)
	}
	if f.ResolvedAt == nil {
		t.Error("expected ResolvedAt to be set")
	}
}

func TestStoreSuppress(t *testing.T) {
	store := NewStore()

	pf := policy.Finding{
		ID:       "test-finding-1",
		PolicyID: "test-policy",
	}
	store.Upsert(context.Background(), pf)

	if !store.Suppress("test-finding-1") {
		t.Error("expected Suppress to return true")
	}

	f, _ := store.Get("test-finding-1")
	if f.Status != "suppressed" {
		t.Errorf("expected status 'suppressed', got '%s'", f.Status)
	}
}

func TestStoreList(t *testing.T) {
	store := NewStore()

	store.Upsert(context.Background(), policy.Finding{ID: "f1", PolicyID: "p1", Severity: "high"})
	store.Upsert(context.Background(), policy.Finding{ID: "f2", PolicyID: "p1", Severity: "low"})
	store.Upsert(context.Background(), policy.Finding{ID: "f3", PolicyID: "p2", Severity: "high"})

	// All findings
	all := store.List(FindingFilter{})
	if len(all) != 3 {
		t.Errorf("expected 3 findings, got %d", len(all))
	}

	// Filter by severity
	high := store.List(FindingFilter{Severity: "high"})
	if len(high) != 2 {
		t.Errorf("expected 2 high severity findings, got %d", len(high))
	}

	// Filter by policy
	p1 := store.List(FindingFilter{PolicyID: "p1"})
	if len(p1) != 2 {
		t.Errorf("expected 2 findings for policy p1, got %d", len(p1))
	}
}

func TestStoreStats(t *testing.T) {
	store := NewStore()

	store.Upsert(context.Background(), policy.Finding{ID: "f1", PolicyID: "p1", Severity: "high"})
	store.Upsert(context.Background(), policy.Finding{ID: "f2", PolicyID: "p1", Severity: "critical"})
	store.Upsert(context.Background(), policy.Finding{ID: "f3", PolicyID: "p2", Severity: "high"})
	store.Resolve("f1")

	stats := store.Stats()

	if stats.Total != 3 {
		t.Errorf("expected total 3, got %d", stats.Total)
	}
	if stats.BySeverity["high"] != 2 {
		t.Errorf("expected 2 high severity, got %d", stats.BySeverity["high"])
	}
	if stats.ByStatus["open"] != 2 {
		t.Errorf("expected 2 open, got %d", stats.ByStatus["open"])
	}
	if stats.ByStatus["resolved"] != 1 {
		t.Errorf("expected 1 resolved, got %d", stats.ByStatus["resolved"])
	}
}
