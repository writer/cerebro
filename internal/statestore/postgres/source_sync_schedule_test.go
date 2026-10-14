package postgres

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/ports"
)

func TestSourceRuntimeSyncScheduleSchemaShape(t *testing.T) {
	joined := strings.Join(ensureSourceRuntimeSyncScheduleStatements, "\n")
	for _, fragment := range []string{
		"CREATE TABLE IF NOT EXISTS source_runtime_sync_schedules",
		"runtime_id TEXT PRIMARY KEY",
		"tenant_id TEXT NOT NULL DEFAULT ''",
		"consecutive_failures INTEGER NOT NULL DEFAULT 0",
		"last_failure_class TEXT NOT NULL DEFAULT ''",
		"next_attempt_at TIMESTAMPTZ NOT NULL",
		"circuit_open BOOLEAN NOT NULL DEFAULT FALSE",
		"config_digest TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE source_runtime_sync_schedules ADD COLUMN IF NOT EXISTS config_digest TEXT NOT NULL DEFAULT ''",
		"updated_at TIMESTAMPTZ NOT NULL",
	} {
		if !strings.Contains(joined, fragment) {
			t.Fatalf("source runtime sync schedule schema missing %q:\n%s", fragment, joined)
		}
	}
}

func TestSourceRuntimeSyncScheduleFailureIncrementsAtomically(t *testing.T) {
	for _, fragment := range []string{
		"ON CONFLICT (runtime_id) DO UPDATE SET",
		"consecutive_failures = LEAST(source_runtime_sync_schedules.consecutive_failures, 2147483646) + 1",
		"circuit_open = $5::INTEGER > 0 AND LEAST(source_runtime_sync_schedules.consecutive_failures, 2147483646) + 1 >= $5::INTEGER",
		"config_digest = EXCLUDED.config_digest",
		"RETURNING runtime_id, tenant_id, consecutive_failures",
	} {
		if !strings.Contains(recordSourceRuntimeSyncFailureSQL, fragment) {
			t.Fatalf("recordSourceRuntimeSyncFailureSQL missing %q:\n%s", fragment, recordSourceRuntimeSyncFailureSQL)
		}
	}
	if !strings.HasPrefix(recordSourceRuntimeSyncSuccessSQL, "DELETE FROM source_runtime_sync_schedules") {
		t.Fatalf("recordSourceRuntimeSyncSuccessSQL = %q, want delete", recordSourceRuntimeSyncSuccessSQL)
	}
}

func TestSourceRuntimeSyncScheduleRejectsMissingInputsWithoutDatabase(t *testing.T) {
	store := &Store{}
	ctx := context.Background()
	if _, _, err := store.GetSourceRuntimeSyncSchedule(ctx, " "); err == nil {
		t.Fatal("GetSourceRuntimeSyncSchedule(blank) error = nil")
	}
	if _, err := store.RecordSourceRuntimeSyncFailure(ctx, ports.SourceRuntimeSyncFailure{RuntimeID: "runtime-1"}); err == nil {
		t.Fatal("RecordSourceRuntimeSyncFailure(zero times) error = nil")
	}
	if err := store.RecordSourceRuntimeSyncSuccess(ctx, "runtime-1"); err == nil {
		t.Fatal("RecordSourceRuntimeSyncSuccess(unconfigured) error = nil")
	}
}

func TestSourceRuntimeSyncSchedulePostgresIntegration(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("CEREBRO_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("set CEREBRO_POSTGRES_DSN to run source runtime sync schedule integration test")
	}
	store, err := Open(config.StateStoreConfig{Driver: config.StateStoreDriverPostgres, PostgresDSN: dsn})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	ctx := context.Background()
	runtimeID := strings.ToLower(t.Name()) + "-" + time.Now().UTC().Format("20060102150405.000000000")
	t.Cleanup(func() { _ = store.RecordSourceRuntimeSyncSuccess(ctx, runtimeID) })

	if _, found, err := store.GetSourceRuntimeSyncSchedule(ctx, runtimeID); err != nil || found {
		t.Fatalf("GetSourceRuntimeSyncSchedule(missing) = found %v err %v, want not found", found, err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	var last ports.SourceRuntimeSyncSchedule
	for attempt := uint32(1); attempt <= 3; attempt++ {
		last, err = store.RecordSourceRuntimeSyncFailure(ctx, ports.SourceRuntimeSyncFailure{
			RuntimeID:        runtimeID,
			TenantID:         "tenant-a",
			FailureClass:     "provider_unavailable",
			NextAttemptAt:    now.Add(time.Duration(attempt) * time.Minute),
			CircuitOpenAfter: 3,
			ConfigDigest:     "digest-a",
			ObservedAt:       now,
		})
		if err != nil {
			t.Fatalf("RecordSourceRuntimeSyncFailure(%d) error = %v", attempt, err)
		}
		if last.ConsecutiveFailures != attempt || last.CircuitOpen != (attempt >= 3) {
			t.Fatalf("attempt %d schedule = %#v, want count %d", attempt, last, attempt)
		}
	}
	got, found, err := store.GetSourceRuntimeSyncSchedule(ctx, runtimeID)
	if err != nil || !found {
		t.Fatalf("GetSourceRuntimeSyncSchedule() found %v err %v", found, err)
	}
	if got.TenantID != "tenant-a" || got.LastFailureClass != "provider_unavailable" || !got.NextAttemptAt.Equal(now.Add(3*time.Minute)) || !got.CircuitOpen || got.ConfigDigest != "digest-a" {
		t.Fatalf("stored schedule = %#v", got)
	}
	reclassified, err := store.RecordSourceRuntimeSyncFailure(ctx, ports.SourceRuntimeSyncFailure{
		RuntimeID:     runtimeID,
		TenantID:      "tenant-a",
		FailureClass:  "unauthorized",
		NextAttemptAt: now.Add(6 * time.Hour),
		ConfigDigest:  "digest-b",
		ObservedAt:    now,
	})
	if err != nil {
		t.Fatalf("RecordSourceRuntimeSyncFailure(unauthorized) error = %v", err)
	}
	if reclassified.ConsecutiveFailures != 4 || reclassified.CircuitOpen || reclassified.LastFailureClass != "unauthorized" || reclassified.ConfigDigest != "digest-b" {
		t.Fatalf("reclassified schedule = %#v, want count 4, circuit closed", reclassified)
	}
	if err := store.RecordSourceRuntimeSyncSuccess(ctx, runtimeID); err != nil {
		t.Fatalf("RecordSourceRuntimeSyncSuccess() error = %v", err)
	}
	if _, found, err := store.GetSourceRuntimeSyncSchedule(ctx, runtimeID); err != nil || found {
		t.Fatalf("GetSourceRuntimeSyncSchedule(after success) = found %v err %v, want cleared", found, err)
	}
}
