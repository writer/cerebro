package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"
)

const (
	tenantScopedBackfillTestRuleID = "identity-api-token-or-oauth-app-created"
	wantBackfillCollisionReason    = "backfill_collision"
	wantBackfillCollisionActor     = "tenant_scoped_fingerprint_backfill"
	wantBackfillCollisionRunID     = "tenant_scoped_fingerprint_backfill"
)

func TestBackfillTenantScopedFindingFingerprints_CollisionKeepsMostRecent(t *testing.T) {
	ctx := context.Background()
	store := tombstoneStoreFromEnv(t)
	resetTombstoneSchema(t, ctx, store)

	nonce := time.Now().UnixNano()
	tenantID := fmt.Sprintf("example-backfill-collision-two-%d", nonce)
	userURN := testIdentityProjectionURN(tenantID, "okta_user", "00u-collision-two")
	wantFingerprint := testFindingFingerprint(tenantScopedBackfillTestRuleID, tenantID, userURN, "cred-collision-two")
	base := time.Date(2026, 5, 24, 10, 0, 0, 0, time.UTC)

	insertTenantScopedBackfillFinding(t, ctx, store, tenantScopedBackfillFinding{
		id:           "older-two-row",
		tenantID:     tenantID,
		userID:       "00u-collision-two",
		credentialID: "cred-collision-two",
		resourceURN:  "urn:cerebro:" + tenantID + ":okta_user:00u-collision-two",
		createdAt:    base,
		updatedAt:    base.Add(1 * time.Minute),
	})
	insertTenantScopedBackfillFinding(t, ctx, store, tenantScopedBackfillFinding{
		id:           "winner-two-row",
		tenantID:     tenantID,
		userID:       "00u-collision-two",
		credentialID: "cred-collision-two",
		resourceURN:  "urn:cerebro:" + tenantID + ":okta_user:00u-collision-two",
		createdAt:    base.Add(2 * time.Minute),
		updatedAt:    base.Add(3 * time.Minute),
	})

	runTenantScopedBackfillForTest(t, ctx, store)

	assertTenantScopedBackfillWinner(t, ctx, store, "winner-two-row", wantFingerprint)
	assertTenantScopedBackfillLoser(t, ctx, store, "older-two-row")
	events := loadBackfillCollisionEvents(t, ctx, store, wantBackfillCollisionRunID)
	if got, want := len(events), 1; got != want {
		t.Fatalf("backfill tombstone events = %d, want %d: %#v", got, want, events)
	}
	if got := events[0].findingID; got != "older-two-row" {
		t.Fatalf("event finding_id = %q, want older-two-row", got)
	}
}

func TestBackfillTenantScopedFindingFingerprints_CollisionUsesUpdatedThenCreatedTieBreak(t *testing.T) {
	ctx := context.Background()
	store := tombstoneStoreFromEnv(t)
	resetTombstoneSchema(t, ctx, store)

	nonce := time.Now().UnixNano()
	tenantID := fmt.Sprintf("example-backfill-collision-three-%d", nonce)
	userURN := testIdentityProjectionURN(tenantID, "okta_user", "00u-collision-three")
	wantFingerprint := testFindingFingerprint(tenantScopedBackfillTestRuleID, tenantID, userURN, "cred-collision-three")
	base := time.Date(2026, 5, 24, 11, 0, 0, 0, time.UTC)

	rows := []tenantScopedBackfillFinding{
		{
			id:           "old-updated-new-created-loser",
			tenantID:     tenantID,
			userID:       "00u-collision-three",
			credentialID: "cred-collision-three",
			resourceURN:  "urn:cerebro:" + tenantID + ":okta_user:old-updated",
			createdAt:    base.Add(30 * time.Minute),
			updatedAt:    base.Add(1 * time.Minute),
		},
		{
			id:           "new-updated-old-created-loser",
			tenantID:     tenantID,
			userID:       "00u-collision-three",
			credentialID: "cred-collision-three",
			resourceURN:  "urn:cerebro:" + tenantID + ":okta_user:new-updated-old-created",
			createdAt:    base.Add(2 * time.Minute),
			updatedAt:    base.Add(40 * time.Minute),
		},
		{
			id:           "new-updated-new-created-winner",
			tenantID:     tenantID,
			userID:       "00u-collision-three",
			credentialID: "cred-collision-three",
			resourceURN:  "urn:cerebro:" + tenantID + ":okta_user:new-updated-new-created",
			createdAt:    base.Add(3 * time.Minute),
			updatedAt:    base.Add(40 * time.Minute),
		},
	}
	for _, row := range rows {
		insertTenantScopedBackfillFinding(t, ctx, store, row)
	}

	runTenantScopedBackfillForTest(t, ctx, store)

	assertTenantScopedBackfillWinner(t, ctx, store, "new-updated-new-created-winner", wantFingerprint)
	assertTenantScopedBackfillLoser(t, ctx, store, "old-updated-new-created-loser")
	assertTenantScopedBackfillLoser(t, ctx, store, "new-updated-old-created-loser")
	events := loadBackfillCollisionEvents(t, ctx, store, wantBackfillCollisionRunID)
	if got, want := len(events), 2; got != want {
		t.Fatalf("backfill tombstone events = %d, want %d: %#v", got, want, events)
	}
	gotLosers := []string{events[0].findingID, events[1].findingID}
	sort.Strings(gotLosers)
	wantLosers := []string{"new-updated-old-created-loser", "old-updated-new-created-loser"}
	for i := range wantLosers {
		if gotLosers[i] != wantLosers[i] {
			t.Fatalf("event loser IDs = %#v, want %#v", gotLosers, wantLosers)
		}
	}
}

func TestBackfillTenantScopedFindingFingerprints_CollisionTieBreaksByID(t *testing.T) {
	ctx := context.Background()
	store := tombstoneStoreFromEnv(t)
	resetTombstoneSchema(t, ctx, store)

	nonce := time.Now().UnixNano()
	tenantID := fmt.Sprintf("example-backfill-collision-tie-%d", nonce)
	userURN := testIdentityProjectionURN(tenantID, "okta_user", "00u-collision-tie")
	wantFingerprint := testFindingFingerprint(tenantScopedBackfillTestRuleID, tenantID, userURN, "cred-collision-tie")
	ts := time.Date(2026, 5, 24, 12, 0, 0, 0, time.UTC)

	for _, id := range []string{"b-loser", "a-winner", "c-loser"} {
		insertTenantScopedBackfillFinding(t, ctx, store, tenantScopedBackfillFinding{
			id:           id,
			tenantID:     tenantID,
			userID:       "00u-collision-tie",
			credentialID: "cred-collision-tie",
			resourceURN:  "urn:cerebro:" + tenantID + ":okta_user:" + id,
			createdAt:    ts,
			updatedAt:    ts,
		})
	}

	runTenantScopedBackfillForTest(t, ctx, store)

	assertTenantScopedBackfillWinner(t, ctx, store, "a-winner", wantFingerprint)
	assertTenantScopedBackfillLoser(t, ctx, store, "b-loser")
	assertTenantScopedBackfillLoser(t, ctx, store, "c-loser")
}

func TestBackfillTenantScopedFindingFingerprints_NoCollisionUpdatesOnlyLegacyRows(t *testing.T) {
	ctx := context.Background()
	store := tombstoneStoreFromEnv(t)
	resetTombstoneSchema(t, ctx, store)

	nonce := time.Now().UnixNano()
	tenantID := fmt.Sprintf("example-backfill-no-collision-%d", nonce)
	base := time.Date(2026, 5, 24, 13, 0, 0, 0, time.UTC).Truncate(time.Microsecond)
	alreadyCurrentUserURN := testIdentityProjectionURN(tenantID, "okta_user", "00u-current")
	alreadyCurrentFingerprint := testFindingFingerprint(tenantScopedBackfillTestRuleID, tenantID, alreadyCurrentUserURN, "cred-current")
	legacyUserURN := testIdentityProjectionURN(tenantID, "okta_user", "00u-legacy")
	legacyWantFingerprint := testFindingFingerprint(tenantScopedBackfillTestRuleID, tenantID, legacyUserURN, "cred-legacy")

	insertTenantScopedBackfillFinding(t, ctx, store, tenantScopedBackfillFinding{
		id:           "already-current",
		tenantID:     tenantID,
		fingerprint:  alreadyCurrentFingerprint,
		userID:       "00u-current",
		credentialID: "cred-current",
		resourceURN:  "urn:cerebro:" + tenantID + ":okta_user:current",
		createdAt:    base,
		updatedAt:    base.Add(1 * time.Minute),
	})
	insertTenantScopedBackfillFinding(t, ctx, store, tenantScopedBackfillFinding{
		id:           "legacy-no-collision",
		tenantID:     tenantID,
		userID:       "00u-legacy",
		credentialID: "cred-legacy",
		resourceURN:  "urn:cerebro:" + tenantID + ":okta_user:legacy",
		createdAt:    base.Add(2 * time.Minute),
		updatedAt:    base.Add(3 * time.Minute),
	})

	beforeCurrent := loadTenantScopedBackfillRow(t, ctx, store, "already-current")
	runTenantScopedBackfillForTest(t, ctx, store)

	afterCurrent := loadTenantScopedBackfillRow(t, ctx, store, "already-current")
	if afterCurrent.fingerprint != alreadyCurrentFingerprint {
		t.Fatalf("already-current fingerprint = %q, want %q", afterCurrent.fingerprint, alreadyCurrentFingerprint)
	}
	if !afterCurrent.updatedAt.Equal(beforeCurrent.updatedAt) {
		t.Fatalf("already-current updated_at = %s, want unchanged %s", afterCurrent.updatedAt, beforeCurrent.updatedAt)
	}
	assertTenantScopedBackfillWinner(t, ctx, store, "legacy-no-collision", legacyWantFingerprint)
	var tombstoned int
	if err := store.db.QueryRowContext(ctx, `SELECT count(*) FROM findings WHERE tenant_id = $1 AND tombstoned = TRUE`, tenantID).Scan(&tombstoned); err != nil {
		t.Fatalf("count tombstoned rows: %v", err)
	}
	if tombstoned != 0 {
		t.Fatalf("tombstoned rows in no-collision case = %d, want 0", tombstoned)
	}
	if events := loadBackfillCollisionEvents(t, ctx, store, wantBackfillCollisionRunID); len(events) != 0 {
		t.Fatalf("backfill collision events in no-collision case = %#v, want none", events)
	}
}

func TestBackfillTenantScopedFindingFingerprints_IdempotentSkipsTombstonedLosers(t *testing.T) {
	ctx := context.Background()
	store := tombstoneStoreFromEnv(t)
	resetTombstoneSchema(t, ctx, store)

	nonce := time.Now().UnixNano()
	tenantID := fmt.Sprintf("example-backfill-idempotent-%d", nonce)
	userURN := testIdentityProjectionURN(tenantID, "okta_user", "00u-idempotent")
	wantFingerprint := testFindingFingerprint(tenantScopedBackfillTestRuleID, tenantID, userURN, "cred-idempotent")
	base := time.Date(2026, 5, 24, 14, 0, 0, 0, time.UTC)

	insertTenantScopedBackfillFinding(t, ctx, store, tenantScopedBackfillFinding{
		id:           "idempotent-loser",
		tenantID:     tenantID,
		userID:       "00u-idempotent",
		credentialID: "cred-idempotent", // #nosec G101 -- test credential identifier fixture, not credential material.
		resourceURN:  "urn:cerebro:" + tenantID + ":okta_user:idempotent-loser",
		createdAt:    base,
		updatedAt:    base.Add(1 * time.Minute),
	})
	insertTenantScopedBackfillFinding(t, ctx, store, tenantScopedBackfillFinding{
		id:           "idempotent-winner",
		tenantID:     tenantID,
		userID:       "00u-idempotent",
		credentialID: "cred-idempotent", // #nosec G101 -- test credential identifier fixture, not credential material.
		resourceURN:  "urn:cerebro:" + tenantID + ":okta_user:idempotent-winner",
		createdAt:    base.Add(2 * time.Minute),
		updatedAt:    base.Add(3 * time.Minute),
	})

	runTenantScopedBackfillForTest(t, ctx, store)
	assertTenantScopedBackfillWinner(t, ctx, store, "idempotent-winner", wantFingerprint)
	assertTenantScopedBackfillLoser(t, ctx, store, "idempotent-loser")
	eventsAfterFirst := loadBackfillCollisionEvents(t, ctx, store, wantBackfillCollisionRunID)
	if len(eventsAfterFirst) != 1 {
		t.Fatalf("events after first backfill = %d, want 1", len(eventsAfterFirst))
	}

	runTenantScopedBackfillForTest(t, ctx, store)
	assertTenantScopedBackfillWinner(t, ctx, store, "idempotent-winner", wantFingerprint)
	assertTenantScopedBackfillLoser(t, ctx, store, "idempotent-loser")
	eventsAfterSecond := loadBackfillCollisionEvents(t, ctx, store, wantBackfillCollisionRunID)
	if len(eventsAfterSecond) != len(eventsAfterFirst) {
		t.Fatalf("events after second backfill = %d, want unchanged %d", len(eventsAfterSecond), len(eventsAfterFirst))
	}
}

type tenantScopedBackfillFinding struct {
	id           string
	tenantID     string
	fingerprint  string
	userID       string
	credentialID string
	resourceURN  string
	createdAt    time.Time
	updatedAt    time.Time
}

func insertTenantScopedBackfillFinding(t *testing.T, ctx context.Context, store *Store, row tenantScopedBackfillFinding) {
	t.Helper()
	if strings.TrimSpace(row.fingerprint) == "" {
		row.fingerprint = testFindingFingerprint(tenantScopedBackfillTestRuleID, row.id, row.userID, row.credentialID)
	}
	attributes := map[string]string{
		"source_id":     "okta",
		"user_id":       row.userID,
		"credential_id": row.credentialID,
	}
	attributesJSON, err := json.Marshal(attributes)
	if err != nil {
		t.Fatalf("marshal attributes: %v", err)
	}
	resourceURNs := []string{}
	if strings.TrimSpace(row.resourceURN) != "" {
		resourceURNs = append(resourceURNs, row.resourceURN)
	}
	resourceURNsJSON, err := json.Marshal(resourceURNs)
	if err != nil {
		t.Fatalf("marshal resource urns: %v", err)
	}
	createdAt := row.createdAt.UTC().Truncate(time.Microsecond)
	updatedAt := row.updatedAt.UTC().Truncate(time.Microsecond)
	if createdAt.IsZero() {
		createdAt = time.Now().UTC().Truncate(time.Microsecond)
	}
	if updatedAt.IsZero() {
		updatedAt = createdAt
	}
	if _, err := store.db.ExecContext(ctx, `
        INSERT INTO findings (
            id, fingerprint, tenant_id, runtime_id, rule_id, title, severity, status, summary,
            resource_urns_json, attributes_json, first_observed_at, last_observed_at, created_at, updated_at
        )
        VALUES (
            $1, $2, $3, $4, $5, 'Tenant-scoped backfill test', 'HIGH', 'open', 'summary',
            $6::jsonb, $7::jsonb, $8, $9, $10, $11
        )`,
		row.id,
		row.fingerprint,
		row.tenantID,
		"runtime-"+row.id,
		tenantScopedBackfillTestRuleID,
		string(resourceURNsJSON),
		string(attributesJSON),
		createdAt,
		updatedAt,
		createdAt,
		updatedAt,
	); err != nil {
		t.Fatalf("insert tenant-scoped backfill row %q: %v", row.id, err)
	}
}

func runTenantScopedBackfillForTest(t *testing.T, ctx context.Context, store *Store) {
	t.Helper()
	store.schemaMu.Lock()
	store.findingTablesReady = false
	store.schemaMu.Unlock()
	ensureTombstoneSchema(t, ctx, store)
}

type tenantScopedBackfillRow struct {
	id               string
	fingerprint      string
	status           string
	statusReason     string
	tombstoned       bool
	tombstonedAt     sql.NullTime
	tombstonedReason string
	tombstonedBy     string
	tombstonedRunID  string
	priorStatus      string
	createdAt        time.Time
	updatedAt        time.Time
}

func loadTenantScopedBackfillRow(t *testing.T, ctx context.Context, store *Store, id string) tenantScopedBackfillRow {
	t.Helper()
	var row tenantScopedBackfillRow
	if err := store.db.QueryRowContext(ctx, `
        SELECT id, fingerprint, status, status_reason, tombstoned, tombstoned_at,
               tombstoned_reason, tombstoned_by, tombstoned_run_id, prior_status,
               created_at, updated_at
        FROM findings
        WHERE id = $1`, id,
	).Scan(
		&row.id,
		&row.fingerprint,
		&row.status,
		&row.statusReason,
		&row.tombstoned,
		&row.tombstonedAt,
		&row.tombstonedReason,
		&row.tombstonedBy,
		&row.tombstonedRunID,
		&row.priorStatus,
		&row.createdAt,
		&row.updatedAt,
	); err != nil {
		t.Fatalf("load backfill row %q: %v", id, err)
	}
	row.createdAt = row.createdAt.UTC()
	row.updatedAt = row.updatedAt.UTC()
	return row
}

func assertTenantScopedBackfillWinner(t *testing.T, ctx context.Context, store *Store, id string, wantFingerprint string) {
	t.Helper()
	row := loadTenantScopedBackfillRow(t, ctx, store, id)
	if row.fingerprint != wantFingerprint {
		t.Fatalf("%s fingerprint = %q, want %q", id, row.fingerprint, wantFingerprint)
	}
	if row.tombstoned {
		t.Fatalf("%s tombstoned = true, want active winner", id)
	}
	if row.status != "open" {
		t.Fatalf("%s status = %q, want open", id, row.status)
	}
}

func assertTenantScopedBackfillLoser(t *testing.T, ctx context.Context, store *Store, id string) {
	t.Helper()
	row := loadTenantScopedBackfillRow(t, ctx, store, id)
	if !row.tombstoned {
		t.Fatalf("%s tombstoned = false, want true", id)
	}
	if !row.tombstonedAt.Valid || row.tombstonedAt.Time.IsZero() {
		t.Fatalf("%s tombstoned_at = %#v, want non-zero timestamp", id, row.tombstonedAt)
	}
	if row.status != "resolved" {
		t.Fatalf("%s status = %q, want resolved", id, row.status)
	}
	if row.statusReason != wantBackfillCollisionReason {
		t.Fatalf("%s status_reason = %q, want %q", id, row.statusReason, wantBackfillCollisionReason)
	}
	if row.tombstonedReason != wantBackfillCollisionReason {
		t.Fatalf("%s tombstoned_reason = %q, want %q", id, row.tombstonedReason, wantBackfillCollisionReason)
	}
	if row.tombstonedBy != wantBackfillCollisionActor {
		t.Fatalf("%s tombstoned_by = %q, want %q", id, row.tombstonedBy, wantBackfillCollisionActor)
	}
	if row.tombstonedRunID != wantBackfillCollisionRunID {
		t.Fatalf("%s tombstoned_run_id = %q, want %q", id, row.tombstonedRunID, wantBackfillCollisionRunID)
	}
	if row.priorStatus != "open" {
		t.Fatalf("%s prior_status = %q, want open", id, row.priorStatus)
	}
}

type backfillCollisionEvent struct {
	findingID    string
	tenantID     string
	ruleID       string
	anchorURI    string
	priorStatus  string
	reason       string
	actor        string
	runID        string
	tombstonedAt time.Time
}

//nolint:unparam // Helper keeps run ID explicit to document the queried backfill fixture.
func loadBackfillCollisionEvents(t *testing.T, ctx context.Context, store *Store, runID string) []backfillCollisionEvent {
	t.Helper()
	rows, err := store.db.QueryContext(ctx, `
        SELECT finding_id, tenant_id, rule_id, anchor_uri, prior_status, reason, actor, run_id, tombstoned_at
        FROM finding_tombstone_events
        WHERE run_id = $1
        ORDER BY finding_id`, runID)
	if err != nil {
		t.Fatalf("query backfill collision events: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var events []backfillCollisionEvent
	for rows.Next() {
		var event backfillCollisionEvent
		if err := rows.Scan(
			&event.findingID,
			&event.tenantID,
			&event.ruleID,
			&event.anchorURI,
			&event.priorStatus,
			&event.reason,
			&event.actor,
			&event.runID,
			&event.tombstonedAt,
		); err != nil {
			t.Fatalf("scan backfill collision event: %v", err)
		}
		if event.reason != wantBackfillCollisionReason {
			t.Fatalf("event %q reason = %q, want %q", event.findingID, event.reason, wantBackfillCollisionReason)
		}
		if event.actor != wantBackfillCollisionActor {
			t.Fatalf("event %q actor = %q, want %q", event.findingID, event.actor, wantBackfillCollisionActor)
		}
		if event.runID != wantBackfillCollisionRunID {
			t.Fatalf("event %q run_id = %q, want %q", event.findingID, event.runID, wantBackfillCollisionRunID)
		}
		if event.priorStatus != "open" {
			t.Fatalf("event %q prior_status = %q, want open", event.findingID, event.priorStatus)
		}
		if event.tombstonedAt.IsZero() {
			t.Fatalf("event %q tombstoned_at is zero", event.findingID)
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate backfill collision events: %v", err)
	}
	return events
}
