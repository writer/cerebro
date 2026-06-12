package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/ports"
)

func tombstoneStoreFromEnv(t *testing.T) *Store {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("CEREBRO_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("set CEREBRO_POSTGRES_DSN to run tombstone schema integration tests")
	}
	store, err := Open(config.StateStoreConfig{Driver: config.StateStoreDriverPostgres, PostgresDSN: dsn})
	if err != nil {
		t.Fatalf("open postgres store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func dropTombstoneSchema(t *testing.T, ctx context.Context, store *Store) {
	t.Helper()
	for _, stmt := range []string{
		`DROP TABLE IF EXISTS finding_tombstone_events`,
		`DROP TABLE IF EXISTS closeout_run`,
		`DROP TABLE IF EXISTS findings`,
	} {
		if _, err := store.db.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("reset schema with %q: %v", stmt, err)
		}
	}
	store.schemaMu.Lock()
	store.findingTablesReady = false
	store.schemaMu.Unlock()
}

// resetTombstoneSchema drops the tombstone-aware tables and immediately
// re-runs the migration so the database is left in the post-migration state
// regardless of which `*Store` (or which test/package) touches it next.
// Without the re-run, a later `*Store` that has already cached
// findingTablesReady=true would skip ensureFindingTables and hit a missing
// `findings` table on its next UpsertFinding.
func resetTombstoneSchema(t *testing.T, ctx context.Context, store *Store) {
	t.Helper()
	dropTombstoneSchema(t, ctx, store)
	if err := store.ensureFindingTables(ctx); err != nil {
		t.Fatalf("ensureFindingTables after reset: %v", err)
	}
}

func ensureTombstoneSchema(t *testing.T, ctx context.Context, store *Store) {
	t.Helper()
	if err := store.ensureFindingTables(ctx); err != nil {
		t.Fatalf("ensureFindingTables: %v", err)
	}
}

// TestResetTombstoneSchema_LeavesSchemaUsableForCachedStore guards the
// cross-package test-pollution fix: a second *Store that has already cached
// findingTablesReady=true must be able to UpsertFinding immediately after
// resetTombstoneSchema runs against the shared DSN, because the helper now
// re-creates the schema after dropping it.
func TestResetTombstoneSchema_LeavesSchemaUsableForCachedStore(t *testing.T) {
	ctx := context.Background()
	primed := tombstoneStoreFromEnv(t)
	dropTombstoneSchema(t, ctx, primed)
	if err := primed.ensureFindingTables(ctx); err != nil {
		t.Fatalf("prime ensureFindingTables: %v", err)
	}
	if !primed.findingTablesReady {
		t.Fatalf("primed store findingTablesReady = false, want true (precondition for the regression)")
	}

	other := tombstoneStoreFromEnv(t)
	resetTombstoneSchema(t, ctx, other)

	now := time.Now().UTC().Truncate(time.Microsecond)
	fp := fmt.Sprintf("fp-cross-store-%d", now.UnixNano())
	id := fmt.Sprintf("finding-cross-store-%d", now.UnixNano())
	if _, err := primed.UpsertFinding(ctx, newUpsertFinding(id, fp, "open", now)); err != nil {
		t.Fatalf("UpsertFinding on cached store after reset: %v", err)
	}
}

func TestEnsureFindingStatements_AddsTombstoneColumns(t *testing.T) {
	ctx := context.Background()
	store := tombstoneStoreFromEnv(t)
	resetTombstoneSchema(t, ctx, store)
	ensureTombstoneSchema(t, ctx, store)

	want := map[string]struct {
		dataType   string
		isNullable string
		colDefault string
	}{
		"tombstoned":           {dataType: "boolean", isNullable: "NO", colDefault: "false"},
		"tombstoned_at":        {dataType: "timestamp with time zone", isNullable: "YES", colDefault: ""},
		"tombstoned_by":        {dataType: "text", isNullable: "NO", colDefault: "''::text"},
		"tombstoned_reason":    {dataType: "text", isNullable: "NO", colDefault: "''::text"},
		"tombstoned_run_id":    {dataType: "text", isNullable: "NO", colDefault: "''::text"},
		"prior_status":         {dataType: "text", isNullable: "NO", colDefault: "''::text"},
		"tombstone_generation": {dataType: "integer", isNullable: "NO", colDefault: "0"},
	}
	rows, err := store.db.QueryContext(ctx, `
        SELECT column_name, data_type, is_nullable, COALESCE(column_default, '')
          FROM information_schema.columns
         WHERE table_name = 'findings' AND column_name = ANY($1)`,
		[]string{"tombstoned", "tombstoned_at", "tombstoned_by", "tombstoned_reason", "tombstoned_run_id", "prior_status", "tombstone_generation"})
	if err != nil {
		t.Fatalf("query columns: %v", err)
	}
	defer func() { _ = rows.Close() }()
	got := map[string]struct {
		dataType   string
		isNullable string
		colDefault string
	}{}
	for rows.Next() {
		var name, dt, nullable, def string
		if err := rows.Scan(&name, &dt, &nullable, &def); err != nil {
			t.Fatalf("scan: %v", err)
		}
		got[name] = struct {
			dataType   string
			isNullable string
			colDefault string
		}{dt, nullable, def}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows.Err: %v", err)
	}
	for name, w := range want {
		g, ok := got[name]
		if !ok {
			t.Errorf("findings missing column %q", name)
			continue
		}
		if g.dataType != w.dataType {
			t.Errorf("findings.%s data_type = %q, want %q", name, g.dataType, w.dataType)
		}
		if g.isNullable != w.isNullable {
			t.Errorf("findings.%s is_nullable = %q, want %q", name, g.isNullable, w.isNullable)
		}
		if w.colDefault != "" && g.colDefault != w.colDefault {
			t.Errorf("findings.%s column_default = %q, want %q", name, g.colDefault, w.colDefault)
		}
		if w.colDefault == "" && g.colDefault != "" {
			t.Errorf("findings.%s column_default = %q, want empty", name, g.colDefault)
		}
	}

	var legacy int
	if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM pg_constraint WHERE conname = 'findings_fingerprint_key'`).Scan(&legacy); err != nil {
		t.Fatalf("query legacy constraint: %v", err)
	}
	if legacy != 0 {
		t.Fatalf("findings_fingerprint_key still exists; it must be dropped after tombstone migration")
	}

	indexes := map[string]bool{
		"findings_active_fingerprint_uidx":      false,
		"findings_tombstoned_run_idx":           false,
		"findings_tombstoned_rule_observed_idx": false,
	}
	idxRows, err := store.db.QueryContext(ctx, `SELECT indexname, indexdef FROM pg_indexes WHERE tablename = 'findings'`)
	if err != nil {
		t.Fatalf("query indexes: %v", err)
	}
	defer func() { _ = idxRows.Close() }()
	defs := map[string]string{}
	for idxRows.Next() {
		var name, def string
		if err := idxRows.Scan(&name, &def); err != nil {
			t.Fatalf("scan idx: %v", err)
		}
		if _, ok := indexes[name]; ok {
			indexes[name] = true
			defs[name] = def
		}
	}
	if err := idxRows.Err(); err != nil {
		t.Fatalf("iterate indexes: %v", err)
	}
	for name, found := range indexes {
		if !found {
			t.Errorf("missing index %q on findings", name)
		}
	}
	if def := defs["findings_active_fingerprint_uidx"]; def != "" {
		if !strings.Contains(def, "UNIQUE") || !strings.Contains(def, "WHERE (tombstoned = false)") {
			t.Errorf("findings_active_fingerprint_uidx def = %q, want partial unique on tombstoned=false", def)
		}
	}
	if def := defs["findings_tombstoned_run_idx"]; def != "" {
		if !strings.Contains(def, "WHERE (tombstoned = true)") {
			t.Errorf("findings_tombstoned_run_idx def = %q, want partial WHERE tombstoned=true", def)
		}
	}
}

func TestEnsureFindingStatements_CreatesTombstoneEventsTable(t *testing.T) {
	ctx := context.Background()
	store := tombstoneStoreFromEnv(t)
	resetTombstoneSchema(t, ctx, store)
	ensureTombstoneSchema(t, ctx, store)

	want := map[string]struct {
		dataType   string
		isNullable string
	}{
		"id":            {dataType: "bigint", isNullable: "NO"},
		"finding_id":    {dataType: "text", isNullable: "NO"},
		"tenant_id":     {dataType: "text", isNullable: "NO"},
		"rule_id":       {dataType: "text", isNullable: "NO"},
		"anchor_uri":    {dataType: "text", isNullable: "NO"},
		"prior_status":  {dataType: "text", isNullable: "NO"},
		"reason":        {dataType: "text", isNullable: "NO"},
		"actor":         {dataType: "text", isNullable: "NO"},
		"run_id":        {dataType: "text", isNullable: "NO"},
		"tombstoned_at": {dataType: "timestamp with time zone", isNullable: "NO"},
	}
	rows, err := store.db.QueryContext(ctx, `
        SELECT column_name, data_type, is_nullable
          FROM information_schema.columns
         WHERE table_name = 'finding_tombstone_events'`)
	if err != nil {
		t.Fatalf("query columns: %v", err)
	}
	defer func() { _ = rows.Close() }()
	got := map[string]struct {
		dataType   string
		isNullable string
	}{}
	for rows.Next() {
		var name, dt, nullable string
		if err := rows.Scan(&name, &dt, &nullable); err != nil {
			t.Fatalf("scan: %v", err)
		}
		got[name] = struct {
			dataType   string
			isNullable string
		}{dt, nullable}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate columns: %v", err)
	}
	for name, w := range want {
		g, ok := got[name]
		if !ok {
			t.Errorf("finding_tombstone_events missing column %q", name)
			continue
		}
		if g.dataType != w.dataType {
			t.Errorf("finding_tombstone_events.%s data_type = %q, want %q", name, g.dataType, w.dataType)
		}
		if g.isNullable != w.isNullable {
			t.Errorf("finding_tombstone_events.%s is_nullable = %q, want %q", name, g.isNullable, w.isNullable)
		}
	}

	indexes := map[string]bool{
		"finding_tombstone_events_run_idx":     false,
		"finding_tombstone_events_finding_idx": false,
	}
	idxRows, err := store.db.QueryContext(ctx, `SELECT indexname FROM pg_indexes WHERE tablename = 'finding_tombstone_events'`)
	if err != nil {
		t.Fatalf("query indexes: %v", err)
	}
	defer func() { _ = idxRows.Close() }()
	for idxRows.Next() {
		var name string
		if err := idxRows.Scan(&name); err != nil {
			t.Fatalf("scan idx: %v", err)
		}
		if _, ok := indexes[name]; ok {
			indexes[name] = true
		}
	}
	if err := idxRows.Err(); err != nil {
		t.Fatalf("iterate tombstone event indexes: %v", err)
	}
	for name, found := range indexes {
		if !found {
			t.Errorf("missing index %q on finding_tombstone_events", name)
		}
	}

	// closeout_run table assertions
	closeoutWant := map[string]string{
		"run_id":         "text",
		"actor":          "text",
		"change_ticket":  "text",
		"selector_json":  "jsonb",
		"status":         "text",
		"started_at":     "timestamp with time zone",
		"heartbeat_at":   "timestamp with time zone",
		"finished_at":    "timestamp with time zone",
		"dry_run":        "boolean",
		"proposed_count": "integer",
		"applied_count":  "integer",
		"error_message":  "text",
		"s3_summary_key": "text",
	}
	coRows, err := store.db.QueryContext(ctx, `SELECT column_name, data_type FROM information_schema.columns WHERE table_name = 'closeout_run'`)
	if err != nil {
		t.Fatalf("query closeout_run: %v", err)
	}
	defer func() { _ = coRows.Close() }()
	coGot := map[string]string{}
	for coRows.Next() {
		var name, dt string
		if err := coRows.Scan(&name, &dt); err != nil {
			t.Fatalf("scan: %v", err)
		}
		coGot[name] = dt
	}
	if err := coRows.Err(); err != nil {
		t.Fatalf("iterate closeout_run columns: %v", err)
	}
	for name, dt := range closeoutWant {
		g, ok := coGot[name]
		if !ok {
			t.Errorf("closeout_run missing column %q", name)
			continue
		}
		if g != dt {
			t.Errorf("closeout_run.%s data_type = %q, want %q", name, g, dt)
		}
	}

	var coIdxDef string
	err = store.db.QueryRowContext(ctx, `SELECT indexdef FROM pg_indexes WHERE indexname = 'closeout_run_singleton_running_idx'`).Scan(&coIdxDef)
	if err != nil {
		t.Fatalf("query closeout_run singleton index: %v", err)
	}
	if !strings.Contains(coIdxDef, "UNIQUE") {
		t.Errorf("closeout_run_singleton_running_idx is not unique: %s", coIdxDef)
	}
	if !strings.Contains(coIdxDef, "(1)") {
		t.Errorf("closeout_run_singleton_running_idx not on ((1)): %s", coIdxDef)
	}
	if !strings.Contains(coIdxDef, "WHERE (status = 'running'::text)") && !strings.Contains(coIdxDef, "WHERE (status = 'running')") {
		t.Errorf("closeout_run_singleton_running_idx missing running predicate: %s", coIdxDef)
	}
}

func TestEnsureFindingStatements_Idempotent(t *testing.T) {
	ctx := context.Background()
	store := tombstoneStoreFromEnv(t)
	resetTombstoneSchema(t, ctx, store)

	ensureTombstoneSchema(t, ctx, store)
	first := schemaSnapshot(t, ctx, store)

	store.schemaMu.Lock()
	store.findingTablesReady = false
	store.schemaMu.Unlock()

	ensureTombstoneSchema(t, ctx, store)
	second := schemaSnapshot(t, ctx, store)

	if first.columns != second.columns {
		t.Errorf("information_schema.columns changed after second ensure run\nfirst:\n%s\nsecond:\n%s", first.columns, second.columns)
	}
	if first.indexes != second.indexes {
		t.Errorf("pg_indexes changed after second ensure run\nfirst:\n%s\nsecond:\n%s", first.indexes, second.indexes)
	}
	if first.constraints != second.constraints {
		t.Errorf("pg_constraint changed after second ensure run\nfirst:\n%s\nsecond:\n%s", first.constraints, second.constraints)
	}
}

type schemaSnap struct {
	columns     string
	indexes     string
	constraints string
}

func schemaSnapshot(t *testing.T, ctx context.Context, store *Store) schemaSnap {
	t.Helper()
	cols := captureRows(t, ctx, store, `
        SELECT table_name, column_name, data_type, is_nullable, COALESCE(column_default, '')
          FROM information_schema.columns
         WHERE table_name IN ('findings', 'finding_tombstone_events', 'closeout_run')
         ORDER BY table_name, ordinal_position`)
	idx := captureRows(t, ctx, store, `
        SELECT tablename, indexname, indexdef
          FROM pg_indexes
         WHERE tablename IN ('findings', 'finding_tombstone_events', 'closeout_run')
         ORDER BY tablename, indexname`)
	con := captureRows(t, ctx, store, `
        SELECT conname, contype, conrelid::regclass::text
          FROM pg_constraint
         WHERE conrelid::regclass::text IN ('findings', 'finding_tombstone_events', 'closeout_run')
         ORDER BY conname`)
	return schemaSnap{columns: cols, indexes: idx, constraints: con}
}

func captureRows(t *testing.T, ctx context.Context, store *Store, query string) string {
	t.Helper()
	rows, err := store.db.QueryContext(ctx, query)
	if err != nil {
		t.Fatalf("snapshot query %q: %v", query, err)
	}
	defer func() { _ = rows.Close() }()
	cols, err := rows.Columns()
	if err != nil {
		t.Fatalf("snapshot columns: %v", err)
	}
	var b strings.Builder
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			t.Fatalf("snapshot scan: %v", err)
		}
		for i, v := range vals {
			if i > 0 {
				b.WriteString("|")
			}
			fmt.Fprintf(&b, "%v", v)
		}
		b.WriteString("\n")
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("snapshot rows.Err: %v", err)
	}
	return b.String()
}

func TestFindingsActiveFingerprint_RejectsDuplicate(t *testing.T) {
	ctx := context.Background()
	store := tombstoneStoreFromEnv(t)
	resetTombstoneSchema(t, ctx, store)
	ensureTombstoneSchema(t, ctx, store)

	tenant := fmt.Sprintf("tenant-active-%d", time.Now().UnixNano())
	fp := fmt.Sprintf("fp-active-%d", time.Now().UnixNano())
	now := time.Now().UTC()
	insert := func(id string) error {
		_, err := store.db.ExecContext(ctx, `
            INSERT INTO findings (id, fingerprint, tenant_id, runtime_id, rule_id, title, severity, status, summary, first_observed_at, last_observed_at)
            VALUES ($1, $2, $3, 'runtime-test', 'rule-test', 'title', 'HIGH', 'open', 'summary', $4, $4)`,
			id, fp, tenant, now)
		return err
	}
	if err := insert("active-1"); err != nil {
		t.Fatalf("first insert: %v", err)
	}
	err := insert("active-2")
	if err == nil {
		t.Fatal("duplicate active fingerprint insert succeeded, want unique violation")
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23505" {
		t.Fatalf("duplicate insert error = %v, want SQLSTATE 23505 unique violation", err)
	}

	if _, err := store.db.ExecContext(ctx,
		`UPDATE findings SET tombstoned = TRUE, tombstoned_at = $1 WHERE id = 'active-1'`, now); err != nil {
		t.Fatalf("tombstone first row: %v", err)
	}
	if err := insert("active-2"); err != nil {
		t.Fatalf("second insert after tombstoning first should succeed, got: %v", err)
	}
}

func TestFindingsActiveFingerprint_AllowsDuplicateAcrossTenants(t *testing.T) {
	ctx := context.Background()
	store := tombstoneStoreFromEnv(t)
	resetTombstoneSchema(t, ctx, store)
	ensureTombstoneSchema(t, ctx, store)

	fp := fmt.Sprintf("fp-cross-tenant-%d", time.Now().UnixNano())
	now := time.Now().UTC()
	for _, tenant := range []string{"example-tenant-a", "example-tenant-b"} {
		if _, err := store.db.ExecContext(ctx, `
            INSERT INTO findings (id, fingerprint, tenant_id, runtime_id, rule_id, title, severity, status, summary, first_observed_at, last_observed_at)
            VALUES ($1, $2, $3, $4, 'rule-test', 'title', 'HIGH', 'open', 'summary', $5, $5)`,
			fmt.Sprintf("active-%s", tenant), fp, tenant, "runtime-"+tenant, now); err != nil {
			t.Fatalf("insert active row for %s: %v", tenant, err)
		}
	}

	var count int
	if err := store.db.QueryRowContext(ctx, `SELECT count(*) FROM findings WHERE fingerprint = $1 AND tombstoned = FALSE`, fp).Scan(&count); err != nil {
		t.Fatalf("count active rows: %v", err)
	}
	if count != 2 {
		t.Fatalf("active rows for shared fingerprint = %d, want 2 across different tenants", count)
	}
}

func TestEnsureFindingStatements_BackfillsTenantScopedFingerprints(t *testing.T) {
	ctx := context.Background()
	store := tombstoneStoreFromEnv(t)
	resetTombstoneSchema(t, ctx, store)

	tenantID := fmt.Sprintf("example-backfill-%d", time.Now().UnixNano())
	const dependabotRuleID = "github-dependabot-open-alert"
	oldFingerprint := testFindingFingerprint(dependabotRuleID, "writer/cerebro", "7")
	wantFingerprint := testFindingFingerprint(dependabotRuleID, tenantID, "writer/cerebro", "7")
	now := time.Now().UTC()
	if _, err := store.db.ExecContext(ctx, `
        INSERT INTO findings (
            id, fingerprint, tenant_id, runtime_id, rule_id, title, severity, status, summary,
            attributes_json, first_observed_at, last_observed_at
        )
        VALUES (
            'legacy-dependabot-row', $1, $2, 'legacy-runtime', $3, 'Dependabot', 'HIGH', 'open', 'summary',
            '{"repository":"writer/cerebro","alert_number":"7"}'::jsonb, $4, $4
        )`,
		oldFingerprint, tenantID, dependabotRuleID, now); err != nil {
		t.Fatalf("insert legacy row: %v", err)
	}

	store.schemaMu.Lock()
	store.findingTablesReady = false
	store.schemaMu.Unlock()
	ensureTombstoneSchema(t, ctx, store)

	var gotID, gotFingerprint string
	if err := store.db.QueryRowContext(ctx, `SELECT id, fingerprint FROM findings WHERE id = 'legacy-dependabot-row'`).Scan(&gotID, &gotFingerprint); err != nil {
		t.Fatalf("reload backfilled row: %v", err)
	}
	if gotID != "legacy-dependabot-row" {
		t.Fatalf("backfill changed id = %q, want legacy-dependabot-row", gotID)
	}
	if gotFingerprint != wantFingerprint {
		t.Fatalf("backfilled fingerprint = %q, want %q", gotFingerprint, wantFingerprint)
	}
}

func TestBackfillTenantScopedFindingFingerprints_UsesIdentityProjectionURN(t *testing.T) {
	ctx := context.Background()
	store := tombstoneStoreFromEnv(t)
	resetTombstoneSchema(t, ctx, store)

	nonce := time.Now().UnixNano()
	tenantID := fmt.Sprintf("example-identity-backfill-%d", nonce)
	runtimeID := fmt.Sprintf("legacy-runtime-%d", nonce)
	const ruleID = "identity-privileged-account-without-mfa"
	sourceID := "okta"
	userID := fmt.Sprintf("00u-backfill-%d", nonce)
	legacyID := fmt.Sprintf("legacy-identity-row-%d", nonce)
	runtimeIDAfterBackfill := fmt.Sprintf("runtime-after-backfill-%d", nonce)
	runtimeEmitID := fmt.Sprintf("runtime-identity-row-%d", nonce)
	wantUserURN := testIdentityProjectionURN(tenantID, sourceID+"_user", userID)
	oldFingerprint := testFindingFingerprint(ruleID, userID)
	wantFingerprint := testFindingFingerprint(ruleID, tenantID, wantUserURN)
	now := time.Now().UTC().Truncate(time.Microsecond)

	attributesJSON := fmt.Sprintf(`{"source_id":%q,"user_id":%q,"email":"alice@example.com"}`, sourceID, userID)
	if _, err := store.db.ExecContext(ctx, `
        INSERT INTO findings (
            id, fingerprint, tenant_id, runtime_id, rule_id, title, severity, status, summary,
            attributes_json, first_observed_at, last_observed_at
        )
        VALUES (
            $1, $2, $3, $4, $5, 'Legacy identity', 'HIGH', 'open', 'summary',
            $6::jsonb, $7, $7
        )`,
		legacyID, oldFingerprint, tenantID, runtimeID, ruleID, attributesJSON, now.Add(-time.Hour)); err != nil {
		t.Fatalf("insert legacy identity row: %v", err)
	}

	store.schemaMu.Lock()
	store.findingTablesReady = false
	store.schemaMu.Unlock()
	ensureTombstoneSchema(t, ctx, store)

	var gotFingerprint string
	if err := store.db.QueryRowContext(ctx, `SELECT fingerprint FROM findings WHERE id = $1`, legacyID).Scan(&gotFingerprint); err != nil {
		t.Fatalf("reload backfilled identity row: %v", err)
	}
	if gotFingerprint != wantFingerprint {
		t.Fatalf("backfilled identity fingerprint = %q, want fingerprint built from user_urn %q (%q)", gotFingerprint, wantUserURN, wantFingerprint)
	}

	stored, err := store.UpsertFinding(ctx, &ports.FindingRecord{
		ID:              runtimeEmitID,
		Fingerprint:     wantFingerprint,
		TenantID:        tenantID,
		RuntimeID:       runtimeIDAfterBackfill,
		RuleID:          ruleID,
		Title:           "Runtime identity",
		Severity:        "HIGH",
		Status:          "open",
		Summary:         "runtime finding should reuse the backfilled row",
		ResourceURNs:    []string{wantUserURN},
		Attributes:      map[string]string{"source_id": sourceID, "user_id": userID, "user_urn": wantUserURN},
		FirstObservedAt: now,
		LastObservedAt:  now,
	})
	if err != nil {
		t.Fatalf("upsert runtime identity finding after backfill: %v", err)
	}
	if stored.ID != legacyID {
		t.Fatalf("upsert reused id %q, want legacy row id %q", stored.ID, legacyID)
	}

	var activeRows int
	if err := store.db.QueryRowContext(ctx, `
        SELECT count(*)
        FROM findings
        WHERE tenant_id = $1 AND rule_id = $2 AND tombstoned = FALSE`,
		tenantID, ruleID).Scan(&activeRows); err != nil {
		t.Fatalf("count active identity rows: %v", err)
	}
	if activeRows != 1 {
		t.Fatalf("active identity rows after runtime upsert = %d, want 1 (no duplicate insert)", activeRows)
	}
}

func TestTenantScopedBackfillIdentityUserURN_MatchesIdentityProjectionURNFormat(t *testing.T) {
	tenantID := "example-identity-backfill-format"
	sourceID := "okta"
	userID := "00u-format-regression"
	got := tenantScopedBackfillIdentityUserURN(tenantID, map[string]string{
		"source_id": sourceID,
		"user_id":   userID,
	})
	want := testIdentityProjectionURN(tenantID, sourceID+"_user", userID)
	if got != want {
		t.Fatalf("tenantScopedBackfillIdentityUserURN() = %q, want %q", got, want)
	}
}

func testFindingFingerprint(parts ...string) string {
	hash := sha256.New()
	for _, part := range parts {
		_, _ = hash.Write([]byte(strings.TrimSpace(part)))
		_, _ = hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func testIdentityProjectionURN(tenantID string, kind string, parts ...string) string {
	values := []string{"urn", "cerebro", strings.TrimSpace(tenantID), strings.TrimSpace(kind)}
	for _, part := range parts {
		value := strings.TrimSpace(part)
		if value == "" {
			continue
		}
		values = append(values, value)
	}
	return strings.Join(values, ":")
}

func TestCloseoutRunSingleton_RejectsConcurrent(t *testing.T) {
	ctx := context.Background()
	store := tombstoneStoreFromEnv(t)
	resetTombstoneSchema(t, ctx, store)
	ensureTombstoneSchema(t, ctx, store)
	if _, err := store.db.ExecContext(ctx, `DELETE FROM closeout_run`); err != nil {
		t.Fatalf("clear closeout_run: %v", err)
	}

	insertRunning := func(runID string) error {
		_, err := store.db.ExecContext(ctx, `
            INSERT INTO closeout_run (run_id, actor, selector_json, status, dry_run)
            VALUES ($1, 'tester', '{}'::jsonb, 'running', false)`, runID)
		return err
	}

	var wg sync.WaitGroup
	results := make([]error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx] = insertRunning(fmt.Sprintf("run-%d", idx))
		}(i)
	}
	wg.Wait()

	var successes, conflicts int
	for _, err := range results {
		if err == nil {
			successes++
			continue
		}
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			conflicts++
			continue
		}
		t.Fatalf("unexpected concurrent insert error: %v", err)
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("singleton index allowed concurrent running rows: successes=%d conflicts=%d", successes, conflicts)
	}

	if _, err := store.db.ExecContext(ctx, `UPDATE closeout_run SET status = 'succeeded', finished_at = now() WHERE status = 'running'`); err != nil {
		t.Fatalf("finish first run: %v", err)
	}
	if err := insertRunning("run-after"); err != nil {
		t.Fatalf("new running insert after first finished should succeed, got: %v", err)
	}
}

func TestTombstoneFinding_CommitsBeforeWorkflowEmit(t *testing.T) {
	ctx := context.Background()
	store := tombstoneStoreFromEnv(t)
	ensureTombstoneSchema(t, ctx, store)

	nonce := time.Now().UTC().UnixNano()
	tenantID := fmt.Sprintf("example-commit-before-emit-%d", nonce)
	runtimeID := fmt.Sprintf("runtime-commit-before-emit-%d", nonce)
	ruleID := "rule-critical-resource-deleted"
	findingID := fmt.Sprintf("finding-commit-before-emit-%d", nonce)
	fingerprint := fmt.Sprintf("fp-commit-before-emit-%d", nonce)
	runID := fmt.Sprintf("run-commit-before-emit-%d", nonce)
	anchorURI := fmt.Sprintf("urn:cerebro:%s:github_code_repository:writer/cerebro-%d", tenantID, nonce)
	cleanup := func() {
		bg := context.Background()
		_, _ = store.db.ExecContext(bg, `DELETE FROM finding_tombstone_events WHERE run_id = $1`, runID)
		_, _ = store.db.ExecContext(bg, `DELETE FROM findings WHERE tenant_id = $1`, tenantID)
	}
	cleanup()
	t.Cleanup(cleanup)

	observedAt := time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Microsecond)
	if _, err := store.UpsertFinding(ctx, &ports.FindingRecord{
		ID:              findingID,
		Fingerprint:     fingerprint,
		TenantID:        tenantID,
		RuntimeID:       runtimeID,
		RuleID:          ruleID,
		Title:           "Commit-before-emit regression",
		Severity:        "MEDIUM",
		Status:          "open",
		Summary:         "finding used for tombstone commit-before-emit regression",
		ResourceURNs:    []string{anchorURI},
		EventIDs:        []string{fmt.Sprintf("event-%d", nonce)},
		FirstObservedAt: observedAt.Add(-24 * time.Hour),
		LastObservedAt:  observedAt,
	}); err != nil {
		t.Fatalf("seed finding %q: %v", findingID, err)
	}

	installDeferredTombstoneCommitFailure(t, ctx, store, runID)

	emitted := 0
	result, err := store.TombstoneFindingAtomic(ctx, ports.FindingTombstoneAtomicRequest{
		FindingID:      findingID,
		ExpectedStatus: "open",
		Status:         "resolved",
		Reason:         "bulk closeout: commit-before-emit regression",
		Actor:          "operator@writer.com",
		RunID:          runID,
		AnchorURI:      anchorURI,
		EventIDs:       []string{fmt.Sprintf("event-%d", nonce)},
		UpdatedAt:      time.Now().UTC(),
		EmitWorkflowEvent: func(context.Context, *ports.FindingRecord, string, time.Time) error {
			emitted++
			return nil
		},
	})
	if err == nil {
		t.Fatalf("TombstoneFindingAtomic returned nil error and result=%+v, want injected commit failure", result)
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "P0001" {
		t.Fatalf("TombstoneFindingAtomic error = %v, want injected commit pg error P0001", err)
	}
	if emitted != 0 {
		t.Fatalf("workflow tombstone events emitted before failed commit = %d, want 0", emitted)
	}

	var (
		status          string
		tombstoned      bool
		tombstonedRunID string
	)
	if err := store.db.QueryRowContext(ctx, `
SELECT status, tombstoned, tombstoned_run_id
FROM findings
WHERE id = $1`, findingID).Scan(&status, &tombstoned, &tombstonedRunID); err != nil {
		t.Fatalf("read finding after failed commit: %v", err)
	}
	if status != "open" {
		t.Fatalf("status after failed commit = %q, want open", status)
	}
	if tombstoned {
		t.Fatalf("tombstoned after failed commit = true, want false")
	}
	if tombstonedRunID != "" {
		t.Fatalf("tombstoned_run_id after failed commit = %q, want empty", tombstonedRunID)
	}
	var auditRows int
	if err := store.db.QueryRowContext(ctx, `SELECT count(*) FROM finding_tombstone_events WHERE run_id = $1`, runID).Scan(&auditRows); err != nil {
		t.Fatalf("count audit rows after failed commit: %v", err)
	}
	if auditRows != 0 {
		t.Fatalf("audit rows after failed commit = %d, want 0", auditRows)
	}
}

func installDeferredTombstoneCommitFailure(t *testing.T, ctx context.Context, store *Store, runID string) {
	t.Helper()
	nonce := time.Now().UTC().UnixNano()
	functionName := fmt.Sprintf("test_tombstone_commit_fail_fn_%d", nonce)
	triggerName := fmt.Sprintf("test_tombstone_commit_fail_trg_%d", nonce)
	runLiteral := strings.ReplaceAll(runID, "'", "''")

	if _, err := store.db.ExecContext(ctx, fmt.Sprintf(`
CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'injected tombstone commit failure for run_id %s' USING ERRCODE = 'P0001';
END;
$$`, functionName, runLiteral)); err != nil {
		t.Fatalf("create deferred commit failure function: %v", err)
	}
	t.Cleanup(func() {
		_, _ = store.db.ExecContext(ctx, fmt.Sprintf(`DROP FUNCTION IF EXISTS %s()`, functionName))
	})

	if _, err := store.db.ExecContext(ctx, fmt.Sprintf(`
CREATE CONSTRAINT TRIGGER %s
AFTER INSERT ON finding_tombstone_events
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
WHEN (NEW.run_id = '%s')
EXECUTE FUNCTION %s()`, triggerName, runLiteral, functionName)); err != nil {
		t.Fatalf("create deferred commit failure trigger: %v", err)
	}
	t.Cleanup(func() {
		_, _ = store.db.ExecContext(ctx, fmt.Sprintf(`DROP TRIGGER IF EXISTS %s ON finding_tombstone_events`, triggerName))
	})
}

func TestUpdateCloseoutRunSummary_PersistsS3KeyOnFailure(t *testing.T) {
	ctx := context.Background()
	store := tombstoneStoreFromEnv(t)
	resetTombstoneSchema(t, ctx, store)
	ensureTombstoneSchema(t, ctx, store)

	runID := fmt.Sprintf("run-summary-fail-%d", time.Now().UnixNano())
	if err := store.InsertCloseoutRun(ctx, ports.CloseoutRunInsert{
		RunID:        runID,
		Actor:        "operator@example.com",
		SelectorJSON: []byte(`{"rule_ids":["rule-alpha"]}`),
		DryRun:       false,
		StartedAt:    time.Now().UTC(),
	}); err != nil {
		t.Fatalf("InsertCloseoutRun: %v", err)
	}
	if err := store.FinishCloseoutRun(ctx, ports.CloseoutRunFinish{
		RunID:         runID,
		Status:        "succeeded",
		ProposedCount: 1,
		AppliedCount:  1,
		FinishedAt:    time.Now().UTC(),
	}); err != nil {
		t.Fatalf("FinishCloseoutRun: %v", err)
	}

	summaryKey := "closeout/" + runID + ".json"
	const summaryErrMessage = "injected summary upload failure"
	summaryErr := errors.New(summaryErrMessage)
	if err := store.UpdateCloseoutRunSummary(ctx, runID, summaryKey, summaryErr); err != nil {
		t.Fatalf("UpdateCloseoutRunSummary: %v", err)
	}
	run, err := store.GetCloseoutRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetCloseoutRun: %v", err)
	}
	if run.Status != "failed" {
		t.Fatalf("status = %q, want failed", run.Status)
	}
	if !strings.Contains(run.ErrorMessage, summaryErrMessage) {
		t.Fatalf("error_message = %q, want it to contain %q", run.ErrorMessage, summaryErrMessage)
	}
	if run.S3SummaryKey != summaryKey {
		t.Fatalf("s3_summary_key = %q, want %q", run.S3SummaryKey, summaryKey)
	}
}

func TestSupportsTombstones(t *testing.T) {
	ctx := context.Background()
	store := tombstoneStoreFromEnv(t)
	dropTombstoneSchema(t, ctx, store)

	if _, err := store.db.ExecContext(ctx, `
        CREATE TABLE findings (
            id TEXT PRIMARY KEY,
            fingerprint TEXT NOT NULL UNIQUE,
            tenant_id TEXT NOT NULL,
            runtime_id TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            status TEXT NOT NULL,
            summary TEXT NOT NULL,
            risk_score INTEGER NOT NULL DEFAULT 0,
            likelihood_score INTEGER NOT NULL DEFAULT 0,
            impact_score INTEGER NOT NULL DEFAULT 0,
            confidence_score INTEGER NOT NULL DEFAULT 0,
            likelihood_level TEXT NOT NULL DEFAULT '',
            impact_level TEXT NOT NULL DEFAULT '',
            risk_reasons_json JSONB NOT NULL DEFAULT '[]'::jsonb,
            risk_model_version TEXT NOT NULL DEFAULT '',
            resource_urns_json JSONB NOT NULL DEFAULT '[]'::jsonb,
            event_ids_json JSONB NOT NULL DEFAULT '[]'::jsonb,
            observed_policy_ids_json JSONB NOT NULL DEFAULT '[]'::jsonb,
            control_refs_json JSONB NOT NULL DEFAULT '[]'::jsonb,
            notes_json JSONB NOT NULL DEFAULT '[]'::jsonb,
            tickets_json JSONB NOT NULL DEFAULT '[]'::jsonb,
            attributes_json JSONB NOT NULL DEFAULT '{}'::jsonb,
            policy_id TEXT NOT NULL DEFAULT '',
            policy_name TEXT NOT NULL DEFAULT '',
            check_id TEXT NOT NULL DEFAULT '',
            check_name TEXT NOT NULL DEFAULT '',
            assignee TEXT NOT NULL DEFAULT '',
            due_at TIMESTAMPTZ,
            status_reason TEXT NOT NULL DEFAULT '',
            status_updated_at TIMESTAMPTZ,
            first_observed_at TIMESTAMPTZ NOT NULL,
            last_observed_at TIMESTAMPTZ NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )`); err != nil {
		t.Fatalf("install pre-migration findings table: %v", err)
	}
	ok, err := store.SupportsTombstones(ctx)
	if err != nil {
		t.Fatalf("SupportsTombstones() pre-migration error = %v", err)
	}
	if ok {
		t.Fatal("SupportsTombstones() pre-migration = true, want false")
	}

	ensureTombstoneSchema(t, ctx, store)
	ok, err = store.SupportsTombstones(ctx)
	if err != nil {
		t.Fatalf("SupportsTombstones() post-migration error = %v", err)
	}
	if !ok {
		t.Fatal("SupportsTombstones() post-migration = false, want true")
	}
}
