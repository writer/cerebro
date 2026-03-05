package findings

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/policy"
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
	if f.Status != "OPEN" {
		t.Errorf("expected status 'OPEN', got '%s'", f.Status)
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
	if f.Status != "RESOLVED" {
		t.Errorf("expected status 'RESOLVED', got '%s'", f.Status)
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
	if f.Status != "SUPPRESSED" {
		t.Errorf("expected status 'SUPPRESSED', got '%s'", f.Status)
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
	if stats.ByStatus["OPEN"] != 2 {
		t.Errorf("expected 2 open, got %d", stats.ByStatus["OPEN"])
	}
	if stats.ByStatus["RESOLVED"] != 1 {
		t.Errorf("expected 1 resolved, got %d", stats.ByStatus["RESOLVED"])
	}
}

func TestStoreGet_NotFound(t *testing.T) {
	store := NewStore()

	_, ok := store.Get("nonexistent")
	if ok {
		t.Error("expected Get to return false for nonexistent finding")
	}
}

func TestStoreResolve_NotFound(t *testing.T) {
	store := NewStore()

	if store.Resolve("nonexistent") {
		t.Error("expected Resolve to return false for nonexistent finding")
	}
}

func TestStoreSuppress_NotFound(t *testing.T) {
	store := NewStore()

	if store.Suppress("nonexistent") {
		t.Error("expected Suppress to return false for nonexistent finding")
	}
}

func TestStoreUpsert_ReopenResolved(t *testing.T) {
	store := NewStore()

	pf := policy.Finding{
		ID:       "test-finding",
		PolicyID: "test-policy",
		Severity: "high",
		Resource: map[string]interface{}{"name": "test"},
	}

	// Create and resolve
	store.Upsert(context.Background(), pf)
	store.Resolve("test-finding")

	f, _ := store.Get("test-finding")
	if f.Status != "RESOLVED" {
		t.Error("finding should be resolved")
	}

	// Upsert again should reopen
	store.Upsert(context.Background(), pf)

	f, _ = store.Get("test-finding")
	if f.Status != "OPEN" {
		t.Errorf("expected status 'OPEN' after reopening, got '%s'", f.Status)
	}
	if f.ResolvedAt != nil {
		t.Error("ResolvedAt should be nil after reopening")
	}
}

func TestStoreList_FilterByStatus(t *testing.T) {
	store := NewStore()

	store.Upsert(context.Background(), policy.Finding{ID: "f1", PolicyID: "p1", Severity: "high"})
	store.Upsert(context.Background(), policy.Finding{ID: "f2", PolicyID: "p1", Severity: "high"})
	store.Resolve("f1")

	open := store.List(FindingFilter{Status: "OPEN"})
	if len(open) != 1 {
		t.Errorf("expected 1 open finding, got %d", len(open))
	}

	resolved := store.List(FindingFilter{Status: "RESOLVED"})
	if len(resolved) != 1 {
		t.Errorf("expected 1 resolved finding, got %d", len(resolved))
	}
}

func TestStoreSync(t *testing.T) {
	store := NewStore()

	// Sync should be a no-op for in-memory store
	err := store.Sync(context.Background())
	if err != nil {
		t.Errorf("Sync should not return error: %v", err)
	}
}

func TestFinding_Fields(t *testing.T) {
	now := time.Now()
	resolvedAt := now.Add(time.Hour)
	resource := map[string]interface{}{"name": "test"}
	f := &Finding{
		ID:           "finding-1",
		PolicyID:     "policy-1",
		PolicyName:   "Test Policy",
		Severity:     "critical",
		Status:       "RESOLVED",
		ResourceID:   "resource-1",
		ResourceType: "aws_s3_bucket",
		Resource:     resource,
		Description:  "Test description",
		FirstSeen:    now,
		LastSeen:     now,
		ResolvedAt:   &resolvedAt,
	}

	if f.ID != "finding-1" {
		t.Error("ID field incorrect")
	}
	if f.PolicyID != "policy-1" {
		t.Error("PolicyID field incorrect")
	}
	if f.PolicyName != "Test Policy" {
		t.Error("PolicyName field incorrect")
	}
	if f.Severity != "critical" {
		t.Error("Severity field incorrect")
	}
	if f.Status != "RESOLVED" {
		t.Error("Status field incorrect")
	}
	if f.ResourceID != "resource-1" {
		t.Error("ResourceID field incorrect")
	}
	if f.ResourceType != "aws_s3_bucket" {
		t.Error("ResourceType field incorrect")
	}
	if f.Resource["name"] != "test" {
		t.Error("Resource field incorrect")
	}
	if f.Description != "Test description" {
		t.Error("Description field incorrect")
	}
	if f.FirstSeen.IsZero() {
		t.Error("FirstSeen field incorrect")
	}
	if f.LastSeen.IsZero() {
		t.Error("LastSeen field incorrect")
	}
	if f.ResolvedAt == nil {
		t.Error("ResolvedAt field incorrect")
	}
}

func TestFindingFilter_Fields(t *testing.T) {
	filter := FindingFilter{
		Severity: "high",
		Status:   "OPEN",
		PolicyID: "policy-1",
	}

	if filter.Severity != "high" {
		t.Error("Severity field incorrect")
	}
	if filter.Status != "OPEN" {
		t.Error("Status field incorrect")
	}
	if filter.PolicyID != "policy-1" {
		t.Error("PolicyID field incorrect")
	}
}

func TestStats_Fields(t *testing.T) {
	stats := Stats{
		Total:      10,
		BySeverity: map[string]int{"critical": 2, "high": 5, "medium": 3},
		ByStatus:   map[string]int{"OPEN": 8, "RESOLVED": 2},
		ByPolicy:   map[string]int{"p1": 6, "p2": 4},
	}

	if stats.Total != 10 {
		t.Error("Total field incorrect")
	}
	if stats.BySeverity["critical"] != 2 {
		t.Error("BySeverity field incorrect")
	}
	if stats.ByStatus["OPEN"] != 8 {
		t.Error("ByStatus field incorrect")
	}
	if stats.ByPolicy["p1"] != 6 {
		t.Error("ByPolicy field incorrect")
	}
}

func TestStore_ConcurrentAccess(t *testing.T) {
	store := NewStore()
	var wg sync.WaitGroup

	// Concurrent writes
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			pf := policy.Finding{
				ID:       "finding-" + string(rune('a'+id%26)),
				PolicyID: "policy-1",
				Severity: "high",
			}
			store.Upsert(context.Background(), pf)
		}(i)
	}

	// Concurrent reads
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			store.List(FindingFilter{})
			store.Stats()
		}()
	}

	wg.Wait()

	// Should complete without race condition
	stats := store.Stats()
	if stats.Total == 0 {
		t.Error("expected some findings to be stored")
	}
}
