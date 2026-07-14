package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/ports"
)

func TestAppendLogDeadLetterSchemaShape(t *testing.T) {
	joined := strings.Join(ensureAppendLogDeadLetterStatements, "\n")
	for _, fragment := range []string{
		"CREATE TABLE IF NOT EXISTS append_log_dead_letters",
		"id TEXT PRIMARY KEY",
		"status TEXT NOT NULL",
		"subject TEXT NOT NULL",
		"runtime_id TEXT NOT NULL DEFAULT ''",
		"job_id TEXT NOT NULL DEFAULT ''",
		"event_json JSONB NOT NULL",
		"replay_owner TEXT NOT NULL DEFAULT ''",
		"replay_token TEXT NOT NULL DEFAULT ''",
		"replay_lease_expires_at TIMESTAMPTZ",
		"replay_attempt_count INTEGER NOT NULL DEFAULT 0",
		"last_replay_started_at TIMESTAMPTZ",
		"last_replay_finished_at TIMESTAMPTZ",
		"last_replay_error_category TEXT NOT NULL DEFAULT ''",
		"append_log_dead_letters_status_updated_idx",
		"append_log_dead_letters_subject_status_idx",
		"append_log_dead_letters_runtime_status_idx",
		"append_log_dead_letters_source_status_idx",
		"CREATE TABLE IF NOT EXISTS append_log_dead_letter_audit",
		"dead_letter_id TEXT NOT NULL",
		"actor TEXT NOT NULL",
		"reason TEXT NOT NULL",
		"append_log_dead_letter_audit_record_created_idx",
	} {
		if !strings.Contains(joined, fragment) {
			t.Fatalf("append log dead letter schema missing %q:\n%s", fragment, joined)
		}
	}
}

func TestAppendLogDeadLetterCleanupSelectsOnlyTerminalRowsInBoundedLockingBatch(t *testing.T) {
	query := appendLogDeadLetterCleanupSelectSQL()
	for _, fragment := range []string{
		"status IN ('replayed', 'discarded')",
		"updated_at < $1",
		"id > $2",
		"ORDER BY id ASC",
		"LIMIT $3",
		"FOR UPDATE SKIP LOCKED",
	} {
		if !strings.Contains(query, fragment) {
			t.Fatalf("appendLogDeadLetterCleanupSelectSQL() missing %q:\n%s", fragment, query)
		}
	}
	if strings.Contains(query, "'pending'") {
		t.Fatalf("appendLogDeadLetterCleanupSelectSQL() may not select pending rows:\n%s", query)
	}
}

func TestAppendLogDeadLetterCapacityProjectionAndHardLimitBoundary(t *testing.T) {
	base := ports.AppendLogDeadLetterBacklog{PendingRecords: 9, PendingPayloadBytes: 900}
	policy := config.StateStoreConfig{DeadLetterHardRecords: 10, DeadLetterHardBytes: 1000}
	created := projectAppendLogDeadLetterBacklog(base, "", 0, 100)
	if created.PendingRecords != 10 || created.PendingPayloadBytes != 1000 || appendLogDeadLetterHardLimitExceeded(created, policy) {
		t.Fatalf("created projection = %#v, want hard boundary accepted", created)
	}
	over := projectAppendLogDeadLetterBacklog(created, "", 0, 1)
	if !appendLogDeadLetterHardLimitExceeded(over, policy) {
		t.Fatalf("over projection = %#v, want hard limit rejection", over)
	}
	replaced := projectAppendLogDeadLetterBacklog(created, ports.AppendLogDeadLetterStatusPending, 100, 75)
	if replaced.PendingRecords != 10 || replaced.PendingPayloadBytes != 975 {
		t.Fatalf("replaced projection = %#v, want same row and adjusted bytes", replaced)
	}
	terminal := projectAppendLogDeadLetterBacklog(created, ports.AppendLogDeadLetterStatusReplayed, 100, 500)
	if terminal != created {
		t.Fatalf("terminal conflict projection = %#v, want unchanged %#v", terminal, created)
	}
}

func TestAppendLogDeadLetterWritesSerializeCapacityAndAuditActions(t *testing.T) {
	if !strings.Contains(appendLogDeadLetterCapacityLockSQL, "pg_advisory_xact_lock") {
		t.Fatalf("capacity lock SQL = %q, want transaction advisory lock", appendLogDeadLetterCapacityLockSQL)
	}
	for _, fragment := range []string{"dead_letter_id", "action", "actor", "reason"} {
		if !strings.Contains(appendLogDeadLetterAuditInsertSQL, fragment) {
			t.Fatalf("audit insert SQL missing %q: %s", fragment, appendLogDeadLetterAuditInsertSQL)
		}
	}
}

func TestAppendLogDeadLetterMetricKeysHaveBoundedCardinality(t *testing.T) {
	seen := map[string]struct{}{}
	keys := append([]string(nil), appendLogDeadLetterMetricKeys[:]...)
	for _, key := range appendLogDeadLetterForcePurgeMetricKeys {
		keys = append(keys, key)
	}
	for _, key := range keys {
		if _, ok := seen[key]; ok {
			t.Fatalf("duplicate dead-letter metric key %q", key)
		}
		seen[key] = struct{}{}
		for _, forbidden := range []string{"tenant", "source", "runtime", "record_id"} {
			if strings.Contains(key, forbidden) {
				t.Fatalf("dead-letter metric key %q contains unbounded dimension %q", key, forbidden)
			}
		}
	}
}

func TestAppendLogDeadLetterForcePurgeSQLProtectsTenantStateLeaseAndPayload(t *testing.T) {
	for _, fragment := range []string{
		"WHERE id = $1 AND tenant_id = $2",
		"FOR UPDATE",
		"replay_lease_expires_at > NOW()",
	} {
		if !strings.Contains(appendLogDeadLetterForcePurgeSelectSQL, fragment) {
			t.Fatalf("force purge select missing %q:\n%s", fragment, appendLogDeadLetterForcePurgeSelectSQL)
		}
	}
	for _, fragment := range []string{
		"WHERE id = $1",
		"tenant_id = $2",
		"status = 'pending'",
		"replay_token = '' OR replay_lease_expires_at IS NULL OR replay_lease_expires_at <= NOW()",
	} {
		if !strings.Contains(appendLogDeadLetterForcePurgeDeleteSQL, fragment) {
			t.Fatalf("force purge delete missing %q:\n%s", fragment, appendLogDeadLetterForcePurgeDeleteSQL)
		}
	}
	joined := appendLogDeadLetterForcePurgeSelectSQL + appendLogDeadLetterForcePurgeDeleteSQL
	if strings.Contains(joined, "event_json") {
		t.Fatalf("force purge SQL must not select or return the event envelope:\n%s", joined)
	}
}

func TestAppendLogDeadLetterForcePurgeOutcomeIsBounded(t *testing.T) {
	for _, test := range []struct {
		err  error
		want string
	}{
		{err: nil, want: "deleted"},
		{err: ports.ErrAppendLogDeadLetterNotFound, want: "not_found"},
		{err: ports.ErrAppendLogDeadLetterNotPending, want: "not_pending"},
		{err: ports.ErrAppendLogDeadLetterReplayClaimed, want: "active_claim"},
		{err: errors.New("database unavailable"), want: "failed"},
	} {
		if got := appendLogDeadLetterForcePurgeOutcome(test.err); got != test.want {
			t.Fatalf("outcome(%v) = %q, want %q", test.err, got, test.want)
		}
		if appendLogDeadLetterForcePurgeMetricKeys[test.want] == "" {
			t.Fatalf("outcome %q has no fixed metric key", test.want)
		}
	}
}

func TestAppendLogDeadLetterForcePurgeCommitsAuditAndDeleteAtomically(t *testing.T) {
	ctx := context.Background()
	store := tombstoneStoreFromEnv(t)
	if err := store.ensureAppendLogDeadLetterTables(ctx); err != nil {
		t.Fatalf("ensure dead letter tables: %v", err)
	}
	id := fmt.Sprintf("apdl-force-purge-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		_, _ = store.db.ExecContext(ctx, `DELETE FROM append_log_dead_letter_audit WHERE dead_letter_id = $1`, id)
		_, _ = store.db.ExecContext(ctx, `DELETE FROM append_log_dead_letters WHERE id = $1`, id)
	})
	insertDeadLetterForcePurgeFixture(t, ctx, store, id, ports.AppendLogDeadLetterStatusPending, "", time.Time{})
	request := ports.AppendLogDeadLetterForcePurgeRequest{
		ID:       id,
		TenantID: "tenant-force-purge",
		Actor:    "admin@example.test",
		Reason:   "INC-1234 publication recovery",
	}
	if err := store.forcePurgeAppendLogDeadLetter(ctx, request); err != nil {
		t.Fatalf("force purge: %v", err)
	}
	var recordCount int
	if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM append_log_dead_letters WHERE id = $1`, id).Scan(&recordCount); err != nil {
		t.Fatalf("count deleted record: %v", err)
	}
	var action, actor, reason string
	if err := store.db.QueryRowContext(ctx, `SELECT action, actor, reason FROM append_log_dead_letter_audit WHERE dead_letter_id = $1`, id).Scan(&action, &actor, &reason); err != nil {
		t.Fatalf("read durable purge audit: %v", err)
	}
	if recordCount != 0 || action != "forced_pending_purge" || actor != request.Actor || reason != request.Reason {
		t.Fatalf("record_count=%d audit=(%q,%q,%q)", recordCount, action, actor, reason)
	}
}

func TestAppendLogDeadLetterForcePurgeProtectsTerminalAndActiveClaimRecords(t *testing.T) {
	ctx := context.Background()
	store := tombstoneStoreFromEnv(t)
	if err := store.ensureAppendLogDeadLetterTables(ctx); err != nil {
		t.Fatalf("ensure dead letter tables: %v", err)
	}
	for _, test := range []struct {
		name    string
		status  string
		token   string
		lease   time.Time
		wantErr error
	}{
		{name: "terminal", status: ports.AppendLogDeadLetterStatusReplayed, wantErr: ports.ErrAppendLogDeadLetterNotPending},
		{name: "active claim", status: ports.AppendLogDeadLetterStatusPending, token: "opaque-claim", lease: time.Now().Add(time.Hour), wantErr: ports.ErrAppendLogDeadLetterReplayClaimed}, // #nosec G101 -- synthetic claim fixture, not a credential.
	} {
		t.Run(test.name, func(t *testing.T) {
			id := fmt.Sprintf("apdl-force-purge-protected-%s-%d", strings.ReplaceAll(test.name, " ", "-"), time.Now().UnixNano())
			t.Cleanup(func() {
				_, _ = store.db.ExecContext(ctx, `DELETE FROM append_log_dead_letter_audit WHERE dead_letter_id = $1`, id)
				_, _ = store.db.ExecContext(ctx, `DELETE FROM append_log_dead_letters WHERE id = $1`, id)
			})
			insertDeadLetterForcePurgeFixture(t, ctx, store, id, test.status, test.token, test.lease)
			err := store.forcePurgeAppendLogDeadLetter(ctx, ports.AppendLogDeadLetterForcePurgeRequest{
				ID: id, TenantID: "tenant-force-purge", Actor: "admin@example.test", Reason: "INC-1234",
			})
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("force purge error = %v, want %v", err, test.wantErr)
			}
			var recordCount, auditCount int
			if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM append_log_dead_letters WHERE id = $1`, id).Scan(&recordCount); err != nil {
				t.Fatalf("count protected record: %v", err)
			}
			if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM append_log_dead_letter_audit WHERE dead_letter_id = $1`, id).Scan(&auditCount); err != nil {
				t.Fatalf("count protected audit: %v", err)
			}
			if recordCount != 1 || auditCount != 0 {
				t.Fatalf("record_count=%d audit_count=%d, want protected record and no audit", recordCount, auditCount)
			}
		})
	}
}

func insertDeadLetterForcePurgeFixture(t *testing.T, ctx context.Context, store *Store, id string, status string, token string, lease time.Time) {
	t.Helper()
	var leaseValue any
	if !lease.IsZero() {
		leaseValue = lease
	}
	_, err := store.db.ExecContext(ctx, `INSERT INTO append_log_dead_letters (
  id, status, subject, operation, event_id, event_kind, tenant_id,
  payload_hash, payload_bytes, event_json, replay_token, replay_lease_expires_at
) VALUES ($1, $2, 'sec.findings.v1.recorded', 'append', $3, 'finding.recorded', $4,
          'fixture-hash', 42, '{}'::jsonb, $5, $6)`, id, status, "event-"+id, "tenant-force-purge", token, leaseValue)
	if err != nil {
		t.Fatalf("insert dead letter fixture: %v", err)
	}
}

func TestClaimAppendLogDeadLetterReplayUsesAtomicLease(t *testing.T) {
	query := claimAppendLogDeadLetterReplaySQL()
	for _, fragment := range []string{
		"replay_attempt_count = replay_attempt_count + 1",
		"status = 'pending'",
		"replay_token = '' OR replay_lease_expires_at IS NULL OR replay_lease_expires_at <= NOW()",
		"RETURNING id, status",
	} {
		if !strings.Contains(query, fragment) {
			t.Fatalf("claimAppendLogDeadLetterReplaySQL() missing %q:\n%s", fragment, query)
		}
	}
}

func TestAppendLogDeadLetterListQueryDefaultsToPending(t *testing.T) {
	query, args := appendLogDeadLetterListQuery(ports.AppendLogDeadLetterFilter{})
	for _, fragment := range []string{
		"WHERE status = $1",
		"ORDER BY updated_at ASC, id ASC LIMIT $2",
	} {
		if !strings.Contains(query, fragment) {
			t.Fatalf("appendLogDeadLetterListQuery() = %q, missing %q", query, fragment)
		}
	}
	if len(args) != 2 || args[0] != ports.AppendLogDeadLetterStatusPending || args[1] != int64(appendLogDeadLetterDefaultLimit) {
		t.Fatalf("query args = %#v, want pending and default limit", args)
	}
}

func TestRecordAppendLogDeadLetterUpsertOnlyUpdatesPendingRows(t *testing.T) {
	for _, fragment := range []string{
		"ON CONFLICT (id)",
		"discarded_at = NULL",
		"discard_reason = ''",
		"WHERE append_log_dead_letters.status = 'pending'",
	} {
		if !strings.Contains(recordAppendLogDeadLetterSQL, fragment) {
			t.Fatalf("recordAppendLogDeadLetterSQL missing %q:\n%s", fragment, recordAppendLogDeadLetterSQL)
		}
	}
}

func TestAppendLogDeadLetterTransitionConflictAlreadyReplayed(t *testing.T) {
	err := appendLogDeadLetterTransitionConflictError("apdl_1", ports.AppendLogDeadLetterStatusReplayed, ports.AppendLogDeadLetterStatusReplayed)
	if !errors.Is(err, ports.ErrAppendLogDeadLetterAlreadyReplayed) {
		t.Fatalf("transition conflict error = %v, want already replayed sentinel", err)
	}

	err = appendLogDeadLetterTransitionConflictError("apdl_1", ports.AppendLogDeadLetterStatusReplayed, ports.AppendLogDeadLetterStatusDiscarded)
	if err == nil || errors.Is(err, ports.ErrAppendLogDeadLetterAlreadyReplayed) {
		t.Fatalf("transition conflict error = %v, want status conflict", err)
	}
}

func TestAppendLogDeadLetterListQueryBoundsFilters(t *testing.T) {
	query, args := appendLogDeadLetterListQuery(ports.AppendLogDeadLetterFilter{
		Status:    "all",
		Subject:   " sec.findings.v1.recorded ",
		RuntimeID: " runtime-1 ",
		SourceID:  " github ",
		Limit:     1000,
	})
	if strings.Contains(query, "status =") {
		t.Fatalf("query with status=all should not include status predicate: %q", query)
	}
	for _, fragment := range []string{
		"subject = $1",
		"runtime_id = $2",
		"source_id = $3",
		"LIMIT $4",
	} {
		if !strings.Contains(query, fragment) {
			t.Fatalf("appendLogDeadLetterListQuery() = %q, missing %q", query, fragment)
		}
	}
	if len(args) != 4 || args[0] != "sec.findings.v1.recorded" || args[1] != "runtime-1" || args[2] != "github" || args[3] != int64(appendLogDeadLetterMaxLimit) {
		t.Fatalf("query args = %#v, want trimmed filters and capped limit", args)
	}
}

func TestValidateAppendLogDeadLetterRequiresReplayableEvent(t *testing.T) {
	record := normalizeAppendLogDeadLetter(ports.AppendLogDeadLetter{
		ID:          " apdl_1 ",
		Subject:     " sec.findings.v1.recorded ",
		EventID:     " event-1 ",
		EventKind:   " sec.findings.v1.recorded ",
		PayloadHash: " hash ",
		Event:       &cerebrov1.EventEnvelope{Id: "event-1"},
	})
	if err := validateAppendLogDeadLetter(record); err != nil {
		t.Fatalf("validateAppendLogDeadLetter() error = %v", err)
	}
	record.Event = nil
	if err := validateAppendLogDeadLetter(record); err == nil {
		t.Fatal("validateAppendLogDeadLetter() error = nil, want missing event error")
	}
}
