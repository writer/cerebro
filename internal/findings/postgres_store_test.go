package findings

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/writer/cerebro/internal/policy"
	"github.com/writer/cerebro/internal/snowflake"
)

var postgresDollarPlaceholderRe = regexp.MustCompile(`\$\d+`)

const postgresSchemaCaptureDriverName = "postgres-findings-schema-capture"

var (
	registerPostgresSchemaCaptureDriverOnce sync.Once
	postgresSchemaCaptureRecorders          sync.Map
)

func postgresSQLiteRewrite(query string) string {
	return postgresDollarPlaceholderRe.ReplaceAllString(query, "?")
}

type postgresSchemaCaptureRecorder struct {
	mu      sync.Mutex
	queries []string
}

func (r *postgresSchemaCaptureRecorder) record(query string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.queries = append(r.queries, query)
}

func (r *postgresSchemaCaptureRecorder) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.queries...)
}

type postgresSchemaCaptureDriver struct{}

type postgresSchemaCaptureConn struct {
	recorder *postgresSchemaCaptureRecorder
}

func (postgresSchemaCaptureDriver) Open(name string) (driver.Conn, error) {
	recorderAny, _ := postgresSchemaCaptureRecorders.Load(name)
	recorder, _ := recorderAny.(*postgresSchemaCaptureRecorder)
	return &postgresSchemaCaptureConn{recorder: recorder}, nil
}

func (c *postgresSchemaCaptureConn) Prepare(string) (driver.Stmt, error) { return nil, driver.ErrSkip }

func (c *postgresSchemaCaptureConn) Close() error { return nil }

func (c *postgresSchemaCaptureConn) Begin() (driver.Tx, error) { return nil, driver.ErrSkip }

func (c *postgresSchemaCaptureConn) ExecContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Result, error) {
	if c.recorder != nil {
		c.recorder.record(query)
	}
	return driver.RowsAffected(0), nil
}

func (c *postgresSchemaCaptureConn) CheckNamedValue(*driver.NamedValue) error { return nil }

func newTestPostgresFindingsStore(t *testing.T) (*PostgresStore, *sql.DB) {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
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

func TestNewPostgresStoreWithDBEnsuresQualifiedSchema(t *testing.T) {
	registerPostgresSchemaCaptureDriverOnce.Do(func() {
		sql.Register(postgresSchemaCaptureDriverName, postgresSchemaCaptureDriver{})
	})

	recorder := &postgresSchemaCaptureRecorder{}
	dsn := t.Name()
	postgresSchemaCaptureRecorders.Store(dsn, recorder)
	t.Cleanup(func() { postgresSchemaCaptureRecorders.Delete(dsn) })

	db, err := sql.Open(postgresSchemaCaptureDriverName, dsn)
	if err != nil {
		t.Fatalf("open capture driver: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	store, err := NewPostgresStoreWithDB(db, "cerebro")
	if err != nil {
		t.Fatalf("NewPostgresStoreWithDB() error = %v", err)
	}
	if store == nil {
		t.Fatal("expected initialized postgres store")
		return
	}

	queries := strings.Join(recorder.snapshot(), "\n")
	if !strings.Contains(queries, "CREATE SCHEMA IF NOT EXISTS cerebro") {
		t.Fatalf("expected schema creation query, got %q", queries)
	}
	if !strings.Contains(queries, "CREATE TABLE IF NOT EXISTS cerebro.findings") {
		t.Fatalf("expected qualified table creation query, got %q", queries)
	}
}

func TestPostgresStoreEnsureSchemaBackfillsRemediationColumn(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	if _, err := db.Exec(`
CREATE TABLE cerebro_findings (
	id TEXT PRIMARY KEY,
	policy_id TEXT NOT NULL,
	policy_name TEXT NOT NULL,
	severity TEXT NOT NULL,
	status TEXT NOT NULL,
	resource_id TEXT,
	resource_type TEXT,
	resource_data TEXT,
	description TEXT,
	metadata TEXT NOT NULL DEFAULT '{}',
	first_seen TIMESTAMP NOT NULL,
	last_seen TIMESTAMP NOT NULL,
	resolved_at TIMESTAMP
)`); err != nil {
		t.Fatalf("create legacy findings table: %v", err)
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
		t.Fatalf("EnsureSchema() error = %v", err)
	}

	rows, err := db.Query(`PRAGMA table_info(cerebro_findings)`)
	if err != nil {
		t.Fatalf("pragma table_info: %v", err)
	}
	defer func() { _ = rows.Close() }()

	foundRemediation := false
	for rows.Next() {
		var (
			cid        int
			name       string
			columnType string
			notNull    int
			defaultVal sql.NullString
			pk         int
		)
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultVal, &pk); err != nil {
			t.Fatalf("scan table_info: %v", err)
		}
		if name == "remediation" {
			foundRemediation = true
			break
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate table_info: %v", err)
	}
	if !foundRemediation {
		t.Fatal("expected EnsureSchema to backfill remediation column")
	}
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
		return
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
		return
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

func TestPostgresStoreUpsertPersistsWithoutExplicitSync(t *testing.T) {
	store, db := newTestPostgresFindingsStore(t)
	pf := policy.Finding{
		ID:           "finding-upsert-immediate",
		PolicyID:     "policy-upsert",
		PolicyName:   "Upsert now",
		Severity:     "high",
		ResourceID:   "bucket-upsert",
		ResourceType: "s3_bucket",
		Description:  "bucket is public",
	}

	finding := store.Upsert(context.Background(), pf)
	if finding == nil {
		t.Fatal("expected Upsert() to persist a finding")
		return
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
	persisted, ok := reloaded.Get(pf.ID)
	if !ok {
		t.Fatalf("expected finding %q to reload without explicit Sync()", pf.ID)
	}
	if persisted.PolicyID != pf.PolicyID {
		t.Fatalf("PolicyID = %q, want %q", persisted.PolicyID, pf.PolicyID)
	}
}

func TestPostgresStoreUpsertMatchesPersistedSemanticFindingWithoutResourceType(t *testing.T) {
	store, db := newTestPostgresFindingsStore(t)

	original := policy.Finding{
		ID:          "finding-original",
		PolicyID:    "policy-semantic",
		PolicyName:  "Semantic policy",
		Severity:    "high",
		ResourceID:  "bucket-1",
		Description: "bucket is public",
	}
	if store.Upsert(context.Background(), original) == nil {
		t.Fatal("expected original finding to be persisted")
		return
	}

	reloaded := &PostgresStore{
		db:            db,
		cache:         make(map[string]*Finding),
		semanticIndex: make(map[string]string),
		dirty:         make(map[string]bool),
		semanticDedup: DefaultSemanticDedupEnabled,
		rewriteSQL:    postgresSQLiteRewrite,
	}

	updated := policy.Finding{
		ID:           "finding-updated",
		PolicyID:     "policy-semantic",
		PolicyName:   "Semantic policy",
		Severity:     "high",
		ResourceID:   "bucket-1",
		ResourceType: "s3_bucket",
		Description:  "bucket is public",
	}
	matched := reloaded.Upsert(context.Background(), updated)
	if matched == nil {
		t.Fatal("expected semantic match to reuse persisted finding")
		return
	}
	if matched.ID != original.ID {
		t.Fatalf("matched finding id = %q, want %q", matched.ID, original.ID)
	}

	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM cerebro_findings`).Scan(&count); err != nil {
		t.Fatalf("count findings: %v", err)
	}
	if count != 1 {
		t.Fatalf("finding row count = %d, want 1", count)
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
		return
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
		return
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
		return
	}
	if err := store.Sync(context.Background()); err != nil {
		t.Fatalf("initial Sync() error = %v", err)
	}

	store.db = nil
	if err := store.ResolveWithError(pf.ID); err == nil {
		t.Fatal("expected ResolveWithError() to fail when persistence is unavailable")
		return
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
		return
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
		return
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

func TestPostgresStoreUpsertRollsBackOnSyncFailure(t *testing.T) {
	store, _ := newTestPostgresFindingsStore(t)
	pf := policy.Finding{
		ID:           "finding-upsert-rollback",
		PolicyID:     "policy-upsert-rollback",
		PolicyName:   "Upsert rollback",
		Severity:     "high",
		ResourceID:   "bucket-upsert-rollback",
		ResourceType: "s3_bucket",
		Description:  "bucket is public",
	}

	store.db = nil
	if finding := store.Upsert(context.Background(), pf); finding != nil {
		t.Fatal("expected Upsert() to return nil when persistence is unavailable")
	}

	if _, ok := store.Get(pf.ID); ok {
		t.Fatalf("expected finding %q to be removed from cache after rollback", pf.ID)
	}
	store.mu.RLock()
	match := store.findSemanticMatchLocked(semanticKeyForPolicyFinding(pf))
	store.mu.RUnlock()
	if match != nil {
		t.Fatalf("expected semantic index rollback for %q", pf.ID)
	}
	if dirty := store.DirtyCount(); dirty != 0 {
		t.Fatalf("DirtyCount() = %d, want 0 after rollback", dirty)
	}
}

func TestPostgresStoreReadsPersistedStateAcrossStoreInstances(t *testing.T) {
	storeA, db := newTestPostgresFindingsStore(t)
	storeB := &PostgresStore{
		db:            db,
		cache:         make(map[string]*Finding),
		semanticIndex: make(map[string]string),
		dirty:         make(map[string]bool),
		semanticDedup: DefaultSemanticDedupEnabled,
		rewriteSQL:    postgresSQLiteRewrite,
	}

	pf := policy.Finding{
		ID:           "finding-shared-state",
		PolicyID:     "policy-shared-state",
		PolicyName:   "Shared state",
		Severity:     "high",
		ResourceID:   "bucket-shared-state",
		ResourceType: "s3_bucket",
		Description:  "bucket is public",
	}

	if finding := storeA.Upsert(context.Background(), pf); finding == nil {
		t.Fatal("expected initial upsert to persist finding")
		return
	}

	remote, ok := storeB.Get(pf.ID)
	if !ok || remote == nil {
		t.Fatal("expected second store to read persisted finding without preloading cache")
	}
	if got := normalizeStatus(remote.Status); got != "OPEN" {
		t.Fatalf("Status = %q, want OPEN", got)
	}

	if err := storeB.ResolveWithError(pf.ID); err != nil {
		t.Fatalf("ResolveWithError() error = %v", err)
	}

	resolved, ok := storeA.Get(pf.ID)
	if !ok || resolved == nil {
		t.Fatal("expected first store to refresh finding state from persistence")
	}
	if got := normalizeStatus(resolved.Status); got != "RESOLVED" {
		t.Fatalf("Status = %q, want RESOLVED", got)
	}
	if resolved.ResolvedAt == nil {
		t.Fatal("expected resolved finding to include ResolvedAt")
		return
	}
}

func TestPostgresStoreListUsesStablePaginationOrder(t *testing.T) {
	store, _ := newTestPostgresFindingsStore(t)
	base := time.Date(2026, time.April, 1, 12, 0, 0, 0, time.UTC)
	ids := []string{"finding-a", "finding-b", "finding-c"}
	for idx, id := range ids {
		pf := policy.Finding{
			ID:           id,
			PolicyID:     fmt.Sprintf("policy-%d", idx),
			PolicyName:   fmt.Sprintf("Policy %d", idx),
			Severity:     "high",
			ResourceID:   fmt.Sprintf("bucket-%d", idx),
			ResourceType: "s3_bucket",
			Description:  "bucket is public",
		}
		if finding := store.Upsert(context.Background(), pf); finding == nil {
			t.Fatalf("Upsert(%q) returned nil", id)
			return
		}
		lastSeen := base.Add(time.Duration(idx) * time.Minute)
		if err := store.Update(id, func(finding *Finding) error {
			finding.FirstSeen = lastSeen
			finding.LastSeen = lastSeen
			return nil
		}); err != nil {
			t.Fatalf("Update(%q) error = %v", id, err)
		}
	}

	page := store.List(FindingFilter{Limit: 2, Offset: 1})
	if len(page) != 2 {
		t.Fatalf("List() returned %d findings, want 2", len(page))
	}
	if page[0].ID != "finding-b" || page[1].ID != "finding-a" {
		t.Fatalf("List() ids = [%s %s], want [finding-b finding-a]", page[0].ID, page[1].ID)
	}
}

func TestPostgresFindingsQualifiedTable(t *testing.T) {
	tableName, err := postgresFindingsQualifiedTable("cerebro")
	if err != nil {
		t.Fatalf("postgresFindingsQualifiedTable() error = %v", err)
	}
	if tableName != "cerebro.findings" {
		t.Fatalf("postgresFindingsQualifiedTable() = %q, want %q", tableName, "cerebro.findings")
	}

	if _, err := postgresFindingsQualifiedTable("bad schema"); err == nil {
		t.Fatal("expected invalid findings schema to be rejected")
		return
	}
}
