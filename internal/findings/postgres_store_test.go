package findings

import (
	"context"
	"database/sql"
	"encoding/json"
	"regexp"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/writer/cerebro/internal/policy"
	"github.com/writer/cerebro/internal/snowflake"
)

var postgresDollarPlaceholderRe = regexp.MustCompile(`\$\d+`)

func postgresSQLiteRewrite(query string) string {
	return postgresDollarPlaceholderRe.ReplaceAllString(query, "?")
}

func newTestPostgresFindingsStore(t *testing.T) (*PostgresStore, *sql.DB) {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	store := &PostgresStore{
		db:            db,
		cache:         make(map[string]*Finding),
		semanticIndex: make(map[string]string),
		dirty:         make(map[string]bool),
		semanticDedup: DefaultSemanticDedupEnabled,
		rewriteSQL:    postgresSQLiteRewrite,
	}
	if err := store.EnsureSchema(context.Background()); err != nil {
		_ = db.Close()
		t.Fatalf("ensure schema: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return store, db
}

func TestPostgresStoreImportRecordsPersistsAndLoads(t *testing.T) {
	store, db := newTestPostgresFindingsStore(t)

	resolvedAt := time.Now().UTC().Add(-time.Hour)
	if err := store.ImportRecords(context.Background(), []*snowflake.FindingRecord{
		{
			ID:           "finding-1",
			PolicyID:     "policy-1",
			PolicyName:   "Public bucket",
			Severity:     "high",
			Status:       "OPEN",
			ResourceID:   "bucket-1",
			ResourceType: "s3_bucket",
			ResourceData: map[string]interface{}{"name": "bucket-1"},
			Description:  "bucket is public",
			Metadata:     json.RawMessage(`{"tenant_id":"tenant-a","signal_type":"security","domain":"infra"}`),
			FirstSeen:    time.Now().UTC().Add(-2 * time.Hour),
			LastSeen:     time.Now().UTC(),
			ResolvedAt:   &resolvedAt,
		},
	}); err != nil {
		t.Fatalf("ImportRecords() error = %v", err)
	}

	reloaded := &PostgresStore{
		db:            db,
		cache:         make(map[string]*Finding),
		semanticIndex: make(map[string]string),
		dirty:         make(map[string]bool),
		semanticDedup: DefaultSemanticDedupEnabled,
		rewriteSQL:    postgresSQLiteRewrite,
	}
	if err := reloaded.Load(context.Background()); err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	finding, ok := reloaded.Get("finding-1")
	if !ok {
		t.Fatal("expected migrated finding to be available after reload")
	}
	if finding.TenantID != "tenant-a" {
		t.Fatalf("TenantID = %q, want tenant-a", finding.TenantID)
	}
	if finding.SignalType != SignalTypeSecurity {
		t.Fatalf("SignalType = %q, want %q", finding.SignalType, SignalTypeSecurity)
	}
	if finding.Domain != DomainInfra {
		t.Fatalf("Domain = %q, want %q", finding.Domain, DomainInfra)
	}
}

func TestPostgresStoreResolveSyncPersistsStatus(t *testing.T) {
	store, db := newTestPostgresFindingsStore(t)
	pf := policy.Finding{
		ID:           "finding-2",
		PolicyID:     "policy-2",
		PolicyName:   "Encrypt storage",
		Severity:     "medium",
		ResourceID:   "bucket-2",
		ResourceType: "s3_bucket",
		Description:  "bucket is not encrypted",
	}

	if store.Upsert(context.Background(), pf) == nil {
		t.Fatal("expected Upsert() to create a finding")
	}
	if err := store.Sync(context.Background()); err != nil {
		t.Fatalf("initial Sync() error = %v", err)
	}
	if !store.Resolve("finding-2") {
		t.Fatal("expected Resolve() to update existing finding")
	}
	if err := store.Sync(context.Background()); err != nil {
		t.Fatalf("resolve Sync() error = %v", err)
	}

	reloaded := &PostgresStore{
		db:            db,
		cache:         make(map[string]*Finding),
		semanticIndex: make(map[string]string),
		dirty:         make(map[string]bool),
		semanticDedup: DefaultSemanticDedupEnabled,
		rewriteSQL:    postgresSQLiteRewrite,
	}
	if err := reloaded.Load(context.Background()); err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	finding, ok := reloaded.Get("finding-2")
	if !ok {
		t.Fatal("expected resolved finding to remain loadable")
	}
	if got := normalizeStatus(finding.Status); got != "RESOLVED" {
		t.Fatalf("Status = %q, want RESOLVED", got)
	}
}
