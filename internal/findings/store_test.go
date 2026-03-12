package findings

import (
	"context"
	"fmt"
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

func TestStoreListAndCount_FilterByTenant(t *testing.T) {
	store := NewStore()

	store.Upsert(context.Background(), policy.Finding{
		ID:       "tenant-a-f1",
		PolicyID: "p1",
		Severity: "high",
		Resource: map[string]interface{}{"tenant_id": "tenant-a"},
	})
	store.Upsert(context.Background(), policy.Finding{
		ID:       "tenant-b-f1",
		PolicyID: "p1",
		Severity: "high",
		Resource: map[string]interface{}{"tenant_id": "tenant-b"},
	})

	tenantAFindings := store.List(FindingFilter{TenantID: "tenant-a"})
	if len(tenantAFindings) != 1 {
		t.Fatalf("expected 1 finding for tenant-a, got %d", len(tenantAFindings))
	}
	if tenantAFindings[0].ID != "tenant-a-f1" {
		t.Fatalf("expected tenant-a-f1, got %s", tenantAFindings[0].ID)
	}
	if got := store.Count(FindingFilter{TenantID: "tenant-a"}); got != 1 {
		t.Fatalf("expected tenant-a count=1, got %d", got)
	}
	if got := store.Count(FindingFilter{TenantID: "tenant-b"}); got != 1 {
		t.Fatalf("expected tenant-b count=1, got %d", got)
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

func TestStoreList_FilterBySignalTypeAndDomain(t *testing.T) {
	store := NewStore()

	store.Upsert(context.Background(), policy.Finding{ID: "f1", PolicyID: "p1", Severity: "high"})
	store.Upsert(context.Background(), policy.Finding{ID: "f2", PolicyID: "stripe-large-refund", Severity: "high"})

	if err := store.Update("f1", func(f *Finding) error {
		f.SignalType = SignalTypeBusiness
		f.Domain = DomainPipeline
		return nil
	}); err != nil {
		t.Fatalf("update f1: %v", err)
	}
	if err := store.Update("f2", func(f *Finding) error {
		f.SignalType = SignalTypeCompliance
		f.Domain = DomainFinancial
		return nil
	}); err != nil {
		t.Fatalf("update f2: %v", err)
	}

	filtered := store.List(FindingFilter{SignalType: SignalTypeBusiness, Domain: DomainPipeline})
	if len(filtered) != 1 {
		t.Fatalf("expected 1 filtered finding, got %d", len(filtered))
	}
	if filtered[0].ID != "f1" {
		t.Fatalf("expected f1, got %s", filtered[0].ID)
	}
}

func TestStoreStats_BySignalTypeAndDomain(t *testing.T) {
	store := NewStore()

	store.Upsert(context.Background(), policy.Finding{ID: "f1", PolicyID: "p1", Severity: "high"})
	store.Upsert(context.Background(), policy.Finding{ID: "f2", PolicyID: "stripe-large-refund", Severity: "critical"})

	if err := store.Update("f1", func(f *Finding) error {
		f.SignalType = SignalTypeBusiness
		f.Domain = DomainPipeline
		return nil
	}); err != nil {
		t.Fatalf("update f1: %v", err)
	}
	if err := store.Update("f2", func(f *Finding) error {
		f.SignalType = SignalTypeCompliance
		f.Domain = DomainFinancial
		return nil
	}); err != nil {
		t.Fatalf("update f2: %v", err)
	}

	stats := store.Stats()
	if stats.BySignalType[SignalTypeBusiness] != 1 || stats.BySignalType[SignalTypeCompliance] != 1 {
		t.Fatalf("unexpected by_signal_type stats: %#v", stats.BySignalType)
	}
	if stats.ByDomain[DomainPipeline] != 1 || stats.ByDomain[DomainFinancial] != 1 {
		t.Fatalf("unexpected by_domain stats: %#v", stats.ByDomain)
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

func TestNewStore_UsesBoundedDefaults(t *testing.T) {
	store := NewStore()
	if store.Len() != 0 {
		t.Errorf("expected empty store, got %d", store.Len())
	}

	for i := 0; i < DefaultMaxFindings+10; i++ {
		store.Upsert(context.Background(), policy.Finding{
			ID:       fmt.Sprintf("f-%d", i),
			PolicyID: "p1",
			Severity: "high",
		})
	}
	if store.Len() != DefaultMaxFindings {
		t.Errorf("expected default cap of %d findings, got %d", DefaultMaxFindings, store.Len())
	}
}

func TestNewStoreWithConfig_AllowsExplicitUnlimitedStore(t *testing.T) {
	store := NewStoreWithConfig(StoreConfig{})
	for i := 0; i < 100; i++ {
		store.Upsert(context.Background(), policy.Finding{
			ID:       fmt.Sprintf("f-%d", i),
			PolicyID: "p1",
			Severity: "high",
		})
	}
	if store.Len() != 100 {
		t.Errorf("expected explicit unlimited store to keep 100 findings, got %d", store.Len())
	}
}

func TestStoreWithMaxFindings(t *testing.T) {
	store := NewStoreWithConfig(StoreConfig{MaxFindings: 5})

	// Add 5 findings — all should fit
	for i := 0; i < 5; i++ {
		store.Upsert(context.Background(), policy.Finding{
			ID:       fmt.Sprintf("f-%d", i),
			PolicyID: "p1",
			Severity: "high",
		})
	}
	if store.Len() != 5 {
		t.Errorf("expected 5 findings, got %d", store.Len())
	}

	// Resolve f-0 and f-1 so they become eviction candidates
	store.Resolve("f-0")
	store.Resolve("f-1")

	// Add a 6th finding — should evict one resolved finding
	store.Upsert(context.Background(), policy.Finding{
		ID:       "f-5",
		PolicyID: "p1",
		Severity: "high",
	})
	if store.Len() != 5 {
		t.Errorf("expected 5 findings after eviction, got %d", store.Len())
	}

	// The oldest resolved finding should have been evicted
	if _, ok := store.Get("f-0"); ok {
		t.Error("expected f-0 to be evicted")
	}
	// f-1 should still be present (only one needed to be evicted)
	if _, ok := store.Get("f-1"); !ok {
		t.Error("expected f-1 to still be present")
	}
	// f-5 must be present
	if _, ok := store.Get("f-5"); !ok {
		t.Error("expected f-5 to be present")
	}
}

func TestStoreWithMaxFindings_HardCapWhenAllOpen(t *testing.T) {
	store := NewStoreWithConfig(StoreConfig{MaxFindings: 2})

	store.Upsert(context.Background(), policy.Finding{ID: "f-0", PolicyID: "p1", Severity: "high"})
	store.Upsert(context.Background(), policy.Finding{ID: "f-1", PolicyID: "p1", Severity: "high"})
	store.Upsert(context.Background(), policy.Finding{ID: "f-2", PolicyID: "p1", Severity: "high"})

	if store.Len() != 2 {
		t.Fatalf("expected hard cap of 2 findings, got %d", store.Len())
	}

	if _, ok := store.Get("f-0"); ok {
		t.Error("expected oldest open finding f-0 to be evicted")
	}
	if _, ok := store.Get("f-1"); !ok {
		t.Error("expected f-1 to remain in store")
	}
	if _, ok := store.Get("f-2"); !ok {
		t.Error("expected newest finding f-2 to remain in store")
	}
}

func TestStoreWithResolvedRetention(t *testing.T) {
	store := NewStoreWithConfig(StoreConfig{ResolvedRetention: time.Hour})

	store.Upsert(context.Background(), policy.Finding{ID: "f-old", PolicyID: "p1", Severity: "high"})
	store.Resolve("f-old")

	func() {
		store.mu.Lock()
		defer store.mu.Unlock()
		store.findings["f-old"].LastSeen = time.Now().Add(-2 * time.Hour)
	}()

	store.Upsert(context.Background(), policy.Finding{ID: "f-new", PolicyID: "p1", Severity: "high"})

	if _, ok := store.Get("f-old"); ok {
		t.Error("expected old resolved finding to be removed by retention cleanup")
	}
	if _, ok := store.Get("f-new"); !ok {
		t.Error("expected new finding to be present")
	}
}

func TestStoreResolvedRetentionCleanupIsAmortized(t *testing.T) {
	store := NewStoreWithConfig(StoreConfig{ResolvedRetention: time.Hour})

	store.Upsert(context.Background(), policy.Finding{ID: "f-old", PolicyID: "p1", Severity: "high"})
	store.Resolve("f-old")

	func() {
		store.mu.Lock()
		defer store.mu.Unlock()
		store.findings["f-old"].LastSeen = time.Now().Add(-2 * time.Hour)
		store.lastResolvedSweep = time.Now()
	}()

	store.Upsert(context.Background(), policy.Finding{ID: "f-new", PolicyID: "p1", Severity: "high"})
	if _, ok := store.Get("f-old"); !ok {
		t.Fatal("expected cleanup to skip resolved scan before the amortized interval")
	}

	func() {
		store.mu.Lock()
		defer store.mu.Unlock()
		store.lastResolvedSweep = time.Now().Add(-store.resolvedCleanupInterval())
	}()

	store.Upsert(context.Background(), policy.Finding{ID: "f-newer", PolicyID: "p1", Severity: "high"})
	if _, ok := store.Get("f-old"); ok {
		t.Fatal("expected expired resolved finding to be removed once cleanup interval elapses")
	}
}

func TestStoreCleanup(t *testing.T) {
	store := NewStore()

	store.Upsert(context.Background(), policy.Finding{ID: "f1", PolicyID: "p1", Severity: "high"})
	store.Upsert(context.Background(), policy.Finding{ID: "f2", PolicyID: "p1", Severity: "high"})
	store.Upsert(context.Background(), policy.Finding{ID: "f3", PolicyID: "p1", Severity: "high"})

	// Resolve f1 and f2
	store.Resolve("f1")
	store.Resolve("f2")

	// Manually backdate LastSeen on f1 so it's older than maxAge
	func() {
		store.mu.Lock()
		defer store.mu.Unlock()
		old := time.Now().Add(-2 * time.Hour)
		store.findings["f1"].LastSeen = old
	}()

	// Cleanup with 1h maxAge should remove f1 but not f2
	removed := store.Cleanup(1 * time.Hour)
	if removed != 1 {
		t.Errorf("expected 1 removed, got %d", removed)
	}
	if _, ok := store.Get("f1"); ok {
		t.Error("expected f1 to be cleaned up")
	}
	if _, ok := store.Get("f2"); !ok {
		t.Error("expected f2 to still be present")
	}
	if _, ok := store.Get("f3"); !ok {
		t.Error("expected f3 to still be present")
	}
}

func TestStoreEvictToCapacityRecountsResolvedCountOnUndercount(t *testing.T) {
	store := NewStoreWithConfig(StoreConfig{MaxFindings: 1})

	store.mu.Lock()
	store.findings["resolved-1"] = &Finding{ID: "resolved-1", PolicyID: "p1", Status: "RESOLVED", LastSeen: time.Now().Add(-2 * time.Hour)}
	store.findings["resolved-2"] = &Finding{ID: "resolved-2", PolicyID: "p1", Status: "RESOLVED", LastSeen: time.Now().Add(-time.Hour)}
	store.resolvedCount = 0
	store.evictToCapacity()
	store.mu.Unlock()

	if got := store.Len(); got != 1 {
		t.Fatalf("expected one finding after eviction, got %d", got)
	}
	if got := store.resolvedCount; got != 1 {
		t.Fatalf("expected resolvedCount to be recomputed to 1, got %d", got)
	}
}

func TestStoreCleanupRecountsResolvedCountOnUndercount(t *testing.T) {
	store := NewStoreWithConfig(StoreConfig{ResolvedRetention: time.Hour})

	store.mu.Lock()
	store.findings["resolved-old"] = &Finding{ID: "resolved-old", PolicyID: "p1", Status: "RESOLVED", LastSeen: time.Now().Add(-3 * time.Hour)}
	store.findings["resolved-current"] = &Finding{ID: "resolved-current", PolicyID: "p1", Status: "RESOLVED", LastSeen: time.Now().Add(-10 * time.Minute)}
	store.resolvedCount = 0
	removed := store.cleanupResolvedBeforeLocked(time.Now().Add(-time.Hour))
	store.mu.Unlock()

	if removed != 1 {
		t.Fatalf("expected one resolved finding removed, got %d", removed)
	}
	if got := store.resolvedCount; got != 1 {
		t.Fatalf("expected resolvedCount to be recomputed to 1, got %d", got)
	}
}

func TestStoreLen(t *testing.T) {
	store := NewStore()
	if store.Len() != 0 {
		t.Errorf("expected 0, got %d", store.Len())
	}

	store.Upsert(context.Background(), policy.Finding{ID: "f1", PolicyID: "p1"})
	if store.Len() != 1 {
		t.Errorf("expected 1, got %d", store.Len())
	}

	store.Upsert(context.Background(), policy.Finding{ID: "f2", PolicyID: "p1"})
	if store.Len() != 2 {
		t.Errorf("expected 2, got %d", store.Len())
	}

	// Upserting an existing finding should not increase count
	store.Upsert(context.Background(), policy.Finding{ID: "f1", PolicyID: "p1"})
	if store.Len() != 2 {
		t.Errorf("expected 2 after re-upsert, got %d", store.Len())
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
