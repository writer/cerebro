package findings

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/policy"
)

func TestSQLiteStore(t *testing.T) {
	// Create temp DB file
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_findings.db")

	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer func() {
		_ = store.Close()
	}()

	ctx := context.Background()

	// Test Upsert (Insert)
	finding1 := policy.Finding{
		ID:          "finding-1",
		PolicyID:    "policy-1",
		PolicyName:  "Test Policy",
		Severity:    "high",
		Description: "Test finding",
		Resource: map[string]interface{}{
			"id":   "res-1",
			"name": "resource-1",
		},
	}

	f1 := store.Upsert(ctx, finding1)
	if f1 == nil {
		t.Fatal("Upsert returned nil")
		return
	}
	if f1.ID != finding1.ID {
		t.Errorf("expected ID %s, got %s", finding1.ID, f1.ID)
	}
	if f1.Status != "OPEN" {
		t.Errorf("expected status OPEN, got %s", f1.Status)
	}

	// Test Get
	got, ok := store.Get(finding1.ID)
	if !ok {
		t.Fatal("Get returned false")
	}
	if got.ID != finding1.ID {
		t.Errorf("expected ID %s, got %s", finding1.ID, got.ID)
	}
	if got.Resource["name"] != "resource-1" {
		t.Errorf("expected resource name resource-1, got %v", got.Resource["name"])
	}

	// Test Upsert (Update)
	finding1Updated := finding1
	finding1Updated.Description = "Updated description"
	// Simulate time passing
	time.Sleep(10 * time.Millisecond)

	f1Updated := store.Upsert(ctx, finding1Updated)
	if f1Updated.Description != "Updated description" {
		t.Errorf("expected updated description, got %s", f1Updated.Description)
	}
	if !f1Updated.LastSeen.After(f1.LastSeen) {
		t.Error("expected LastSeen to be updated")
	}

	// Test List
	findings := store.List(FindingFilter{})
	if len(findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(findings))
	}

	// Test Resolve
	if !store.Resolve(finding1.ID) {
		t.Error("Resolve failed")
	}

	got, _ = store.Get(finding1.ID)
	if got.Status != "RESOLVED" {
		t.Errorf("expected status RESOLVED, got %s", got.Status)
	}
	if got.ResolvedAt == nil {
		t.Error("expected ResolvedAt to be set")
	}

	// Test Upsert re-opening resolved finding
	f1Reopened := store.Upsert(ctx, finding1)
	if f1Reopened.Status != "OPEN" {
		t.Errorf("expected status OPEN after re-occurrence, got %s", f1Reopened.Status)
	}
	if f1Reopened.ResolvedAt != nil {
		t.Error("expected ResolvedAt to be nil after re-opening")
	}

	// Test Stats
	stats := store.Stats()
	if stats.Total != 1 {
		t.Errorf("expected 1 total finding, got %d", stats.Total)
	}
	if stats.ByStatus["OPEN"] != 1 {
		t.Errorf("expected 1 open finding, got %d", stats.ByStatus["OPEN"])
	}

	// Test Persistence (close and reopen)
	if err := store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	store2, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to re-open store: %v", err)
	}
	defer func() {
		_ = store2.Close()
	}()

	stats2 := store2.Stats()
	if stats2.Total != 1 {
		t.Errorf("expected 1 total finding after reload, got %d", stats2.Total)
	}
}

func TestSQLiteStore_Concurrency(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "concurrent_test.db")

	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer func() {
		_ = store.Close()
	}()

	ctx := context.Background()
	count := 100
	done := make(chan bool)

	for i := 0; i < count; i++ {
		go func(id int) {
			f := policy.Finding{
				ID:         fmt.Sprintf("f-%d", id),
				PolicyID:   "p-1",
				PolicyName: "Policy 1",
				Severity:   "medium",
				Resource:   map[string]interface{}{"id": id},
			}
			store.Upsert(ctx, f)
			done <- true
		}(i)
	}

	for i := 0; i < count; i++ {
		<-done
	}

	stats := store.Stats()
	if stats.Total != count {
		t.Errorf("expected %d total findings, got %d", count, stats.Total)
	}
}

func TestSQLiteStore_ListOffsetWithoutLimit(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "pagination_test.db")

	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer func() {
		_ = store.Close()
	}()

	ctx := context.Background()
	for i := 0; i < 5; i++ {
		store.Upsert(ctx, policy.Finding{
			ID:         fmt.Sprintf("finding-%d", i),
			PolicyID:   "policy-1",
			PolicyName: "Test Policy",
			Severity:   "high",
			Resource:   map[string]interface{}{"id": fmt.Sprintf("resource-%d", i)},
		})
		time.Sleep(time.Millisecond)
	}

	findings := store.List(FindingFilter{Offset: 2})
	if len(findings) != 3 {
		t.Fatalf("expected 3 findings after offset-only pagination, got %d", len(findings))
	}
}

func TestSQLiteStore_SignalTypeDomainFiltersAndStats(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "signals_test.db")

	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer func() {
		_ = store.Close()
	}()

	ctx := context.Background()
	store.Upsert(ctx, policy.Finding{ID: "f-1", PolicyID: "p-1", Severity: "high"})
	store.Upsert(ctx, policy.Finding{ID: "f-2", PolicyID: "stripe-large-refund", Severity: "critical"})

	if err := store.Update("f-1", func(f *Finding) error {
		f.SignalType = SignalTypeBusiness
		f.Domain = DomainPipeline
		return nil
	}); err != nil {
		t.Fatalf("update f-1: %v", err)
	}
	if err := store.Update("f-2", func(f *Finding) error {
		f.SignalType = SignalTypeCompliance
		f.Domain = DomainFinancial
		return nil
	}); err != nil {
		t.Fatalf("update f-2: %v", err)
	}

	filtered := store.List(FindingFilter{SignalType: SignalTypeBusiness, Domain: DomainPipeline})
	if len(filtered) != 1 || filtered[0].ID != "f-1" {
		t.Fatalf("unexpected filtered results: %#v", filtered)
	}

	if got := store.Count(FindingFilter{SignalType: SignalTypeCompliance, Domain: DomainFinancial}); got != 1 {
		t.Fatalf("count = %d, want 1", got)
	}

	stats := store.Stats()
	if stats.BySignalType[SignalTypeBusiness] != 1 || stats.BySignalType[SignalTypeCompliance] != 1 {
		t.Fatalf("unexpected by_signal_type stats: %#v", stats.BySignalType)
	}
	if stats.ByDomain[DomainPipeline] != 1 || stats.ByDomain[DomainFinancial] != 1 {
		t.Fatalf("unexpected by_domain stats: %#v", stats.ByDomain)
	}
}
