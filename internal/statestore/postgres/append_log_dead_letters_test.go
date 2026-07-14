package postgres

import (
	"errors"
	"strings"
	"testing"

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
	for _, key := range appendLogDeadLetterMetricKeys {
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
