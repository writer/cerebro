package findings

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/writer/cerebro/internal/policy"
)

func semanticDuplicatePolicyFindings() (policy.Finding, policy.Finding) {
	base := policy.Finding{
		Severity:     "high",
		ControlID:    "s3-public-access",
		Title:        "Bucket is public",
		Description:  "Bucket allows public access",
		ResourceID:   "arn:aws:s3:::data-lake",
		ResourceType: "aws_s3_bucket",
		ResourceName: "data-lake",
		Resource: map[string]interface{}{
			"arn":  "arn:aws:s3:::data-lake",
			"name": "data-lake",
		},
	}

	first := base
	first.ID = "finding-v1"
	first.PolicyID = "s3-public-access-v1"
	first.PolicyName = "S3 Public Access v1"

	second := base
	second.ID = "finding-v2"
	second.PolicyID = "s3-public-access-v2"
	second.PolicyName = "S3 Public Access v2"
	second.Description = "Bucket still allows public access"

	return first, second
}

func TestStoreSemanticDedupMergesPolicyVersions(t *testing.T) {
	store := NewStore()
	first, second := semanticDuplicatePolicyFindings()

	initial := store.Upsert(context.Background(), first)
	merged := store.Upsert(context.Background(), second)

	if store.Len() != 1 {
		t.Fatalf("expected 1 canonical finding, got %d", store.Len())
	}
	if initial.ID != "finding-v1" || merged.ID != "finding-v1" {
		t.Fatalf("expected canonical finding id finding-v1, got initial=%s merged=%s", initial.ID, merged.ID)
	}
	if got, ok := store.Get("finding-v2"); ok || got != nil {
		t.Fatal("did not expect exact lookup for duplicate finding-v2 to exist")
	}
	if merged.PolicyID != "s3-public-access-v2" {
		t.Fatalf("expected latest policy id to win, got %q", merged.PolicyID)
	}
	if merged.SemanticKey == "" {
		t.Fatal("expected semantic key to be recorded")
	}
	if len(merged.ObservedFindingIDs) != 2 {
		t.Fatalf("observed finding ids = %#v, want 2 entries", merged.ObservedFindingIDs)
	}
	if len(merged.ObservedPolicyIDs) != 2 {
		t.Fatalf("observed policy ids = %#v, want 2 entries", merged.ObservedPolicyIDs)
	}
}

func TestStoreSemanticDedupCanBeDisabled(t *testing.T) {
	store := NewStoreWithConfig(StoreConfig{SemanticDedup: false})
	first, second := semanticDuplicatePolicyFindings()

	store.Upsert(context.Background(), first)
	store.Upsert(context.Background(), second)

	if store.Len() != 2 {
		t.Fatalf("expected strict ID mode to keep duplicates, got %d", store.Len())
	}
}

func TestSQLiteStoreSemanticDedupPersistsAcrossReopen(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "findings.db")
	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("create sqlite store: %v", err)
	}
	first, second := semanticDuplicatePolicyFindings()

	store.Upsert(context.Background(), first)
	store.Upsert(context.Background(), second)
	if err := store.Close(); err != nil {
		t.Fatalf("close sqlite store: %v", err)
	}

	reloaded, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("re-open sqlite store: %v", err)
	}
	defer func() { _ = reloaded.Close() }()

	if got := reloaded.Count(FindingFilter{}); got != 1 {
		t.Fatalf("expected 1 canonical finding after reopen, got %d", got)
	}
	f, ok := reloaded.Get("finding-v1")
	if !ok {
		t.Fatal("expected canonical finding after reopen")
	}
	if len(f.ObservedPolicyIDs) != 2 {
		t.Fatalf("observed policy ids after reopen = %#v, want 2 entries", f.ObservedPolicyIDs)
	}
}

func TestSQLiteStoreSemanticDedupFallsBackToResourceTypeIdentity(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "findings.db")
	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("create sqlite store: %v", err)
	}
	defer func() { _ = store.Close() }()

	first, second := semanticDuplicatePolicyFindings()
	first.ResourceID = ""
	second.ResourceID = ""
	first.Resource = map[string]interface{}{"name": "data-lake"}
	second.Resource = map[string]interface{}{"name": "data-lake"}

	store.Upsert(context.Background(), first)
	store.Upsert(context.Background(), second)

	if got := store.Count(FindingFilter{}); got != 1 {
		t.Fatalf("expected resource-type fallback dedup to keep 1 finding, got %d", got)
	}
}

func TestSnowflakeStoreSemanticDedupUsesCanonicalDirtyID(t *testing.T) {
	store := NewSnowflakeStore(nil, "DB", "SCHEMA")
	first, second := semanticDuplicatePolicyFindings()

	store.Upsert(context.Background(), first)
	merged := store.Upsert(context.Background(), second)

	if merged == nil {
		t.Fatal("expected merged finding")
		return
	}
	if merged.ID != "finding-v1" {
		t.Fatalf("expected canonical id finding-v1, got %q", merged.ID)
	}
	if store.DirtyCount() != 1 {
		t.Fatalf("expected only one dirty canonical finding, got %d", store.DirtyCount())
	}
	if _, ok := store.Get("finding-v2"); ok {
		t.Fatal("did not expect duplicate cache entry for finding-v2")
	}
	if len(merged.ObservedFindingIDs) != 2 {
		t.Fatalf("observed finding ids = %#v, want 2 entries", merged.ObservedFindingIDs)
	}
}

func TestStoreSemanticDedupUpdateRemovesStaleIndexEntry(t *testing.T) {
	store := NewStore()
	first, second := semanticDuplicatePolicyFindings()

	canonical := store.Upsert(context.Background(), first)
	oldKey := canonical.SemanticKey
	if oldKey == "" {
		t.Fatal("expected old semantic key")
	}

	if err := store.Update(canonical.ID, func(f *Finding) error {
		f.Severity = "critical"
		return nil
	}); err != nil {
		t.Fatalf("update canonical finding: %v", err)
	}
	updated, ok := store.Get(canonical.ID)
	if !ok {
		t.Fatal("expected canonical finding after update")
	}
	if updated.SemanticKey == oldKey {
		t.Fatal("expected semantic key to change after severity update")
	}

	duplicate := second
	duplicate.Severity = "high"
	other := store.Upsert(context.Background(), duplicate)
	if other.ID == canonical.ID {
		t.Fatalf("expected stale index entry to be removed; duplicate incorrectly matched canonical id %q", canonical.ID)
	}
	if store.Len() != 2 {
		t.Fatalf("expected 2 findings after stale-key reinsert, got %d", store.Len())
	}
}

func TestSnowflakeStoreSemanticDedupUpdateRemovesStaleIndexEntry(t *testing.T) {
	store := NewSnowflakeStore(nil, "DB", "SCHEMA")
	first, second := semanticDuplicatePolicyFindings()

	canonical := store.Upsert(context.Background(), first)
	oldKey := canonical.SemanticKey
	if oldKey == "" {
		t.Fatal("expected old semantic key")
	}

	if err := store.Update(canonical.ID, func(f *Finding) error {
		f.Severity = "critical"
		return nil
	}); err != nil {
		t.Fatalf("update canonical finding: %v", err)
	}
	updated, ok := store.Get(canonical.ID)
	if !ok {
		t.Fatal("expected canonical finding after update")
	}
	if updated.SemanticKey == oldKey {
		t.Fatal("expected semantic key to change after severity update")
	}

	duplicate := second
	duplicate.Severity = "high"
	other := store.Upsert(context.Background(), duplicate)
	if other.ID == canonical.ID {
		t.Fatalf("expected stale index entry to be removed; duplicate incorrectly matched canonical id %q", canonical.ID)
	}
	if len(store.cache) != 2 {
		t.Fatalf("expected 2 cached findings after stale-key reinsert, got %d", len(store.cache))
	}
}
