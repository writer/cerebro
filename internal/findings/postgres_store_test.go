package findings

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
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

func TestPostgresStoreResolvePersistsWithoutExplicitSync(t *testing.T) {
	store, db := newTestPostgresFindingsStore(t)
	pf := policy.Finding{
		ID:           "finding-resolve-immediate",
		PolicyID:     "policy-resolve",
		PolicyName:   "Resolve now",
		Severity:     "medium",
		ResourceID:   "bucket-resolve",
		ResourceType: "s3_bucket",
		Description:  "bucket is not encrypted",
	}

	if store.Upsert(context.Background(), pf) == nil {
		t.Fatal("expected Upsert() to create a finding")
	}
	if err := store.Sync(context.Background()); err != nil {
		t.Fatalf("initial Sync() error = %v", err)
	}
	if !store.Resolve(pf.ID) {
		t.Fatalf("Resolve(%q) = false, want true", pf.ID)
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
	finding, ok := reloaded.Get(pf.ID)
	if !ok {
		t.Fatalf("expected finding %q to reload", pf.ID)
	}
	if got := normalizeStatus(finding.Status); got != "RESOLVED" {
		t.Fatalf("Status = %q, want RESOLVED", got)
	}
}

func TestPostgresStoreLoadDoesNotTruncateOpenFindings(t *testing.T) {
	store, db := newTestPostgresFindingsStore(t)
	now := time.Now().UTC().Add(-90 * 24 * time.Hour)
	total := 10050

	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	stmt, err := tx.Prepare(`
INSERT INTO cerebro_findings (
	id, policy_id, policy_name, severity, status,
	resource_id, resource_type, resource_data, description,
	remediation, metadata, first_seen, last_seen, resolved_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`)
	if err != nil {
		_ = tx.Rollback()
		t.Fatalf("prepare insert: %v", err)
	}
	defer func() { _ = stmt.Close() }()

	for i := 0; i < total; i++ {
		if _, err := stmt.Exec(
			fmt.Sprintf("finding-open-%05d", i),
			"policy-open",
			"Open finding",
			"medium",
			"OPEN",
			fmt.Sprintf("resource-%05d", i),
			"s3_bucket",
			`{"name":"bucket"}`,
			"bucket is open",
			"",
			"{}",
			now,
			now,
			nil,
		); err != nil {
			_ = tx.Rollback()
			t.Fatalf("insert finding %d: %v", i, err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit insert tx: %v", err)
	}

	if err := store.Load(context.Background()); err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got := store.Count(FindingFilter{}); got != total {
		t.Fatalf("Count() = %d, want %d", got, total)
	}
}

func TestPostgresStoreUpdatePersistsWithoutExplicitSync(t *testing.T) {
	store, db := newTestPostgresFindingsStore(t)
	pf := policy.Finding{
		ID:           "finding-update-immediate",
		PolicyID:     "policy-update",
		PolicyName:   "Update now",
		Severity:     "low",
		ResourceID:   "bucket-update",
		ResourceType: "s3_bucket",
		Description:  "bucket needs triage",
	}

	if store.Upsert(context.Background(), pf) == nil {
		t.Fatal("expected Upsert() to create a finding")
	}
	if err := store.Sync(context.Background()); err != nil {
		t.Fatalf("initial Sync() error = %v", err)
	}
	if err := store.Update(pf.ID, func(f *Finding) error {
		f.Status = "IN_PROGRESS"
		f.Resolution = "triaged"
		return nil
	}); err != nil {
		t.Fatalf("Update() error = %v", err)
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
	finding, ok := reloaded.Get(pf.ID)
	if !ok {
		t.Fatalf("expected finding %q to reload", pf.ID)
	}
	if got := normalizeStatus(finding.Status); got != "IN_PROGRESS" {
		t.Fatalf("Status = %q, want IN_PROGRESS", got)
	}
	if finding.Resolution != "triaged" {
		t.Fatalf("Resolution = %q, want triaged", finding.Resolution)
	}
}

func TestPostgresStoreImportRecordsDoesNotOverwriteResolvedFindings(t *testing.T) {
	store, db := newTestPostgresFindingsStore(t)
	record := &snowflake.FindingRecord{
		ID:           "finding-3",
		PolicyID:     "policy-3",
		PolicyName:   "Public bucket",
		Severity:     "high",
		Status:       "OPEN",
		ResourceID:   "bucket-3",
		ResourceType: "s3_bucket",
		Description:  "bucket is public",
		FirstSeen:    time.Now().UTC().Add(-2 * time.Hour),
		LastSeen:     time.Now().UTC().Add(-time.Hour),
	}

	if err := store.ImportRecords(context.Background(), []*snowflake.FindingRecord{record}); err != nil {
		t.Fatalf("initial ImportRecords() error = %v", err)
	}
	if !store.Resolve(record.ID) {
		t.Fatalf("Resolve(%q) = false, want true", record.ID)
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
	if err := reloaded.ImportRecords(context.Background(), []*snowflake.FindingRecord{record}); err != nil {
		t.Fatalf("repeat ImportRecords() error = %v", err)
	}

	final := &PostgresStore{
		db:            db,
		cache:         make(map[string]*Finding),
		semanticIndex: make(map[string]string),
		dirty:         make(map[string]bool),
		semanticDedup: DefaultSemanticDedupEnabled,
		rewriteSQL:    postgresSQLiteRewrite,
	}
	if err := final.Load(context.Background()); err != nil {
		t.Fatalf("final Load() error = %v", err)
	}

	finding, ok := final.Get(record.ID)
	if !ok {
		t.Fatalf("expected finding %q to remain loadable", record.ID)
	}
	if got := normalizeStatus(finding.Status); got != "RESOLVED" {
		t.Fatalf("Status = %q, want RESOLVED after repeat import", got)
	}
	if finding.ResolvedAt == nil {
		t.Fatal("expected ResolvedAt to be preserved after repeat import")
	}
}

func TestPostgresStoreResolveWithErrorRollsBackOnSyncFailure(t *testing.T) {
	store, _ := newTestPostgresFindingsStore(t)
	pf := policy.Finding{
		ID:           "finding-resolve-rollback",
		PolicyID:     "policy-resolve-rollback",
		PolicyName:   "Resolve rollback",
		Severity:     "medium",
		ResourceID:   "bucket-resolve-rollback",
		ResourceType: "s3_bucket",
		Description:  "bucket is not encrypted",
	}

	if store.Upsert(context.Background(), pf) == nil {
		t.Fatal("expected Upsert() to create a finding")
	}
	if err := store.Sync(context.Background()); err != nil {
		t.Fatalf("initial Sync() error = %v", err)
	}

	store.db = nil
	if err := store.ResolveWithError(pf.ID); err == nil {
		t.Fatal("expected ResolveWithError() to fail when persistence is unavailable")
	}

	finding, ok := store.Get(pf.ID)
	if !ok {
		t.Fatalf("expected finding %q to remain in cache", pf.ID)
	}
	if got := normalizeStatus(finding.Status); got != "OPEN" {
		t.Fatalf("Status = %q, want OPEN after rollback", got)
	}
	if finding.ResolvedAt != nil {
		t.Fatal("expected ResolvedAt to be rolled back on sync failure")
	}
	if dirty := store.DirtyCount(); dirty != 0 {
		t.Fatalf("DirtyCount() = %d, want 0 after rollback", dirty)
	}
}

func TestPostgresStoreUpdateRollsBackOnSyncFailure(t *testing.T) {
	store, _ := newTestPostgresFindingsStore(t)
	pf := policy.Finding{
		ID:           "finding-update-rollback",
		PolicyID:     "policy-update-rollback",
		PolicyName:   "Update rollback",
		Severity:     "low",
		ResourceID:   "bucket-update-rollback",
		ResourceType: "s3_bucket",
		Description:  "bucket needs triage",
	}

	if store.Upsert(context.Background(), pf) == nil {
		t.Fatal("expected Upsert() to create a finding")
	}
	if err := store.Sync(context.Background()); err != nil {
		t.Fatalf("initial Sync() error = %v", err)
	}

	store.db = nil
	if err := store.Update(pf.ID, func(f *Finding) error {
		f.Status = "IN_PROGRESS"
		f.Resolution = "triaged"
		return nil
	}); err == nil {
		t.Fatal("expected Update() to fail when persistence is unavailable")
	}

	finding, ok := store.Get(pf.ID)
	if !ok {
		t.Fatalf("expected finding %q to remain in cache", pf.ID)
	}
	if got := normalizeStatus(finding.Status); got != "OPEN" {
		t.Fatalf("Status = %q, want OPEN after rollback", got)
	}
	if finding.Resolution != "" {
		t.Fatalf("Resolution = %q, want empty after rollback", finding.Resolution)
	}
	if dirty := store.DirtyCount(); dirty != 0 {
		t.Fatalf("DirtyCount() = %d, want 0 after rollback", dirty)
	}
}
