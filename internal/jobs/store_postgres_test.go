package jobs

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// dollarPlaceholderRe matches Postgres-style $N placeholders.
var dollarPlaceholderRe = regexp.MustCompile(`\$\d+`)

// sqliteRewrite converts $1,$2,... placeholders to ? for SQLite compatibility.
// All queries in PostgresStore number $N in SQL-text order so that this simple
// positional replacement is correct.
func sqliteRewrite(q string) string {
	return dollarPlaceholderRe.ReplaceAllString(q, "?")
}

// newTestPostgresStore creates a PostgresStore backed by an in-memory SQLite
// database. The $N→? rewriter is installed so the Postgres-style queries work
// unchanged.
func newTestPostgresStore(t *testing.T) *PostgresStore {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	store := &PostgresStore{
		db:         db,
		rewriteSQL: sqliteRewrite,
	}
	if err := store.EnsureSchema(context.Background()); err != nil {
		t.Fatal(err)
	}
	return store
}

// seedJob inserts a job directly for test setup and returns it.
func seedJob(t *testing.T, store *PostgresStore, job *Job) *Job {
	t.Helper()
	if err := store.CreateJob(context.Background(), job); err != nil {
		t.Fatalf("seedJob: %v", err)
	}
	return job
}

// ---------------------------------------------------------------------------
// Interface compliance
// ---------------------------------------------------------------------------

func TestPostgresStoreInterface(t *testing.T) {
	var _ Store = (*PostgresStore)(nil)
}

// ---------------------------------------------------------------------------
// EnsureSchema
// ---------------------------------------------------------------------------

func TestPostgresStore_EnsureSchema_Idempotent(t *testing.T) {
	store := newTestPostgresStore(t)
	// Second call must succeed without error (IF NOT EXISTS).
	if err := store.EnsureSchema(context.Background()); err != nil {
		t.Fatalf("second EnsureSchema failed: %v", err)
	}
}

// ---------------------------------------------------------------------------
// CreateJob
// ---------------------------------------------------------------------------

func TestPostgresStore_CreateJob(t *testing.T) {
	store := newTestPostgresStore(t)
	ctx := context.Background()
	now := time.Now().Unix()

	job := &Job{
		ID:            "job-1",
		Type:          JobTypeInspectResource,
		Status:        StatusQueued,
		Payload:       `{"key":"value"}`,
		MaxAttempts:   3,
		GroupID:       "grp-1",
		CreatedAt:     now,
		UpdatedAt:     now,
		CorrelationID: "corr-1",
		ParentID:      "parent-1",
	}
	if err := store.CreateJob(ctx, job); err != nil {
		t.Fatalf("CreateJob: %v", err)
	}

	got, err := store.GetJob(ctx, "job-1")
	if err != nil {
		t.Fatalf("GetJob: %v", err)
	}
	if got.ID != "job-1" {
		t.Errorf("ID = %q, want job-1", got.ID)
	}
	if got.Type != JobTypeInspectResource {
		t.Errorf("Type = %q, want %q", got.Type, JobTypeInspectResource)
	}
	if got.Status != StatusQueued {
		t.Errorf("Status = %q, want %q", got.Status, StatusQueued)
	}
	if got.Payload != `{"key":"value"}` {
		t.Errorf("Payload = %q", got.Payload)
	}
	if got.MaxAttempts != 3 {
		t.Errorf("MaxAttempts = %d, want 3", got.MaxAttempts)
	}
	if got.GroupID != "grp-1" {
		t.Errorf("GroupID = %q, want grp-1", got.GroupID)
	}
	if got.CorrelationID != "corr-1" {
		t.Errorf("CorrelationID = %q, want corr-1", got.CorrelationID)
	}
	if got.ParentID != "parent-1" {
		t.Errorf("ParentID = %q, want parent-1", got.ParentID)
	}
}

func TestPostgresStore_CreateJob_NilJob(t *testing.T) {
	store := newTestPostgresStore(t)
	if err := store.CreateJob(context.Background(), nil); err == nil {
		t.Fatal("expected error for nil job")
	}
}

func TestPostgresStore_CreateJob_Duplicate(t *testing.T) {
	store := newTestPostgresStore(t)
	ctx := context.Background()
	now := time.Now().Unix()

	job := &Job{ID: "dup-1", Type: JobTypeInspectResource, Status: StatusQueued, CreatedAt: now, UpdatedAt: now}
	if err := store.CreateJob(ctx, job); err != nil {
		t.Fatalf("first CreateJob: %v", err)
	}
	err := store.CreateJob(ctx, job)
	if err == nil {
		t.Fatal("expected error for duplicate job")
	}
}

// ---------------------------------------------------------------------------
// GetJob
// ---------------------------------------------------------------------------

func TestPostgresStore_GetJob_NotFound(t *testing.T) {
	store := newTestPostgresStore(t)
	_, err := store.GetJob(context.Background(), "nonexistent")
	if !errors.Is(err, ErrJobNotFound) {
		t.Fatalf("expected ErrJobNotFound, got %v", err)
	}
}

func TestPostgresStore_GetJob_EmptyID(t *testing.T) {
	store := newTestPostgresStore(t)
	_, err := store.GetJob(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty ID")
	}
}

// ---------------------------------------------------------------------------
// ClaimJob
// ---------------------------------------------------------------------------

func TestPostgresStore_ClaimJob_Queued(t *testing.T) {
	store := newTestPostgresStore(t)
	ctx := context.Background()
	now := time.Now().Unix()

	seedJob(t, store, &Job{
		ID: "claim-1", Type: JobTypeInspectResource, Status: StatusQueued,
		MaxAttempts: 3, CreatedAt: now, UpdatedAt: now,
	})
	if err := store.MarkDispatched(ctx, "claim-1"); err != nil {
		t.Fatalf("MarkDispatched: %v", err)
	}

	got, ok, err := store.ClaimJob(ctx, "claim-1", "worker-A", 30*time.Second)
	if err != nil {
		t.Fatalf("ClaimJob: %v", err)
	}
	if !ok {
		t.Fatal("expected claim to succeed")
	}
	if got.Status != StatusRunning {
		t.Errorf("Status = %q, want running", got.Status)
	}
	if got.WorkerID != "worker-A" {
		t.Errorf("WorkerID = %q, want worker-A", got.WorkerID)
	}
	if got.Attempt != 1 {
		t.Errorf("Attempt = %d, want 1", got.Attempt)
	}
	if got.LeaseExpiresAt <= now {
		t.Errorf("LeaseExpiresAt = %d, expected > %d", got.LeaseExpiresAt, now)
	}
}

func TestPostgresStore_ClaimJob_NonExistent(t *testing.T) {
	store := newTestPostgresStore(t)
	_, ok, err := store.ClaimJob(context.Background(), "no-such-job", "w", 30*time.Second)
	if err != nil {
		t.Fatalf("ClaimJob: %v", err)
	}
	if ok {
		t.Fatal("expected claim to fail for non-existent job")
	}
}

func TestPostgresStore_ClaimJob_AlreadyRunning(t *testing.T) {
	store := newTestPostgresStore(t)
	ctx := context.Background()
	now := time.Now().Unix()

	// Seed a running job with a lease far in the future.
	seedJob(t, store, &Job{
		ID: "running-1", Type: JobTypeInspectResource, Status: StatusRunning,
		WorkerID: "worker-A", Attempt: 1, LeaseExpiresAt: now + 3600,
		CreatedAt: now, UpdatedAt: now,
	})

	_, ok, err := store.ClaimJob(ctx, "running-1", "worker-B", 30*time.Second)
	if err != nil {
		t.Fatalf("ClaimJob: %v", err)
	}
	if ok {
		t.Fatal("expected claim to fail for actively running job")
	}
}

func TestPostgresStore_ClaimJob_ExpiredLease(t *testing.T) {
	store := newTestPostgresStore(t)
	ctx := context.Background()
	now := time.Now().Unix()

	// Seed a running job whose lease expired in the past.
	seedJob(t, store, &Job{
		ID: "expired-1", Type: JobTypeInspectResource, Status: StatusRunning,
		WorkerID: "worker-A", Attempt: 1, LeaseExpiresAt: now - 60,
		CreatedAt: now, UpdatedAt: now,
	})

	got, ok, err := store.ClaimJob(ctx, "expired-1", "worker-B", 30*time.Second)
	if err != nil {
		t.Fatalf("ClaimJob: %v", err)
	}
	if !ok {
		t.Fatal("expected lease steal to succeed")
	}
	if got.WorkerID != "worker-B" {
		t.Errorf("WorkerID = %q, want worker-B", got.WorkerID)
	}
	if got.Attempt != 2 {
		t.Errorf("Attempt = %d, want 2 (incremented)", got.Attempt)
	}
}

func TestPostgresStore_ClaimJob_TerminalStatus(t *testing.T) {
	store := newTestPostgresStore(t)
	ctx := context.Background()
	now := time.Now().Unix()

	seedJob(t, store, &Job{
		ID: "done-1", Type: JobTypeInspectResource, Status: StatusSucceeded,
		CreatedAt: now, UpdatedAt: now,
	})

	_, ok, err := store.ClaimJob(ctx, "done-1", "worker-A", 30*time.Second)
	if err != nil {
		t.Fatalf("ClaimJob: %v", err)
	}
	if ok {
		t.Fatal("expected claim to fail for terminal job")
	}
}

// ---------------------------------------------------------------------------
// ExtendLease
// ---------------------------------------------------------------------------

func TestPostgresStore_ExtendLease(t *testing.T) {
	store := newTestPostgresStore(t)
	ctx := context.Background()
	now := time.Now().Unix()

	seedJob(t, store, &Job{
		ID: "ext-1", Type: JobTypeInspectResource, Status: StatusRunning,
		WorkerID: "worker-A", Attempt: 1, LeaseExpiresAt: now + 30,
		CreatedAt: now, UpdatedAt: now,
	})

	if err := store.ExtendLease(ctx, "ext-1", "worker-A", 60*time.Second); err != nil {
		t.Fatalf("ExtendLease: %v", err)
	}

	got, _ := store.GetJob(ctx, "ext-1")
	if got.LeaseExpiresAt <= now+30 {
		t.Errorf("LeaseExpiresAt not extended: %d", got.LeaseExpiresAt)
	}
}

func TestPostgresStore_ExtendLease_WrongWorker(t *testing.T) {
	store := newTestPostgresStore(t)
	ctx := context.Background()
	now := time.Now().Unix()

	seedJob(t, store, &Job{
		ID: "ext-2", Type: JobTypeInspectResource, Status: StatusRunning,
		WorkerID: "worker-A", Attempt: 1, LeaseExpiresAt: now + 30,
		CreatedAt: now, UpdatedAt: now,
	})

	err := store.ExtendLease(ctx, "ext-2", "worker-B", 60*time.Second)
	if !errors.Is(err, ErrJobLeaseLost) {
		t.Fatalf("expected ErrJobLeaseLost, got %v", err)
	}
}

func TestPostgresStore_ExtendLease_NotRunning(t *testing.T) {
	store := newTestPostgresStore(t)
	ctx := context.Background()
	now := time.Now().Unix()

	seedJob(t, store, &Job{
		ID: "ext-3", Type: JobTypeInspectResource, Status: StatusQueued,
		CreatedAt: now, UpdatedAt: now,
	})

	err := store.ExtendLease(ctx, "ext-3", "worker-A", 60*time.Second)
	if !errors.Is(err, ErrJobLeaseLost) {
		t.Fatalf("expected ErrJobLeaseLost, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// CompleteJob / FailJob / RetryJob (unconditional)
// ---------------------------------------------------------------------------

func TestPostgresStore_CompleteJob(t *testing.T) {
	store := newTestPostgresStore(t)
	ctx := context.Background()
	now := time.Now().Unix()

	seedJob(t, store, &Job{
		ID: "comp-1", Type: JobTypeInspectResource, Status: StatusRunning,
		WorkerID: "w", Attempt: 1, LeaseExpiresAt: now + 60,
		CreatedAt: now, UpdatedAt: now,
	})

	if err := store.CompleteJob(ctx, "comp-1", "result-ok"); err != nil {
		t.Fatalf("CompleteJob: %v", err)
	}

	got, _ := store.GetJob(ctx, "comp-1")
	if got.Status != StatusSucceeded {
		t.Errorf("Status = %q, want succeeded", got.Status)
	}
	if got.Result != "result-ok" {
		t.Errorf("Result = %q, want result-ok", got.Result)
	}
	if got.Error != "" {
		t.Errorf("Error = %q, want empty", got.Error)
	}
	if got.LeaseExpiresAt != 0 {
		t.Errorf("LeaseExpiresAt = %d, want 0", got.LeaseExpiresAt)
	}
}

func TestPostgresStore_FailJob(t *testing.T) {
	store := newTestPostgresStore(t)
	ctx := context.Background()
	now := time.Now().Unix()

	seedJob(t, store, &Job{
		ID: "fail-1", Type: JobTypeInspectResource, Status: StatusRunning,
		WorkerID: "w", Attempt: 1, LeaseExpiresAt: now + 60,
		CreatedAt: now, UpdatedAt: now,
	})

	if err := store.FailJob(ctx, "fail-1", "something broke"); err != nil {
		t.Fatalf("FailJob: %v", err)
	}

	got, _ := store.GetJob(ctx, "fail-1")
	if got.Status != StatusFailed {
		t.Errorf("Status = %q, want failed", got.Status)
	}
	if got.Error != "something broke" {
		t.Errorf("Error = %q", got.Error)
	}
	if got.LeaseExpiresAt != 0 {
		t.Errorf("LeaseExpiresAt = %d, want 0", got.LeaseExpiresAt)
	}
}

func TestPostgresStore_RetryJob(t *testing.T) {
	store := newTestPostgresStore(t)
	ctx := context.Background()
	now := time.Now().Unix()

	seedJob(t, store, &Job{
		ID: "retry-1", Type: JobTypeInspectResource, Status: StatusRunning,
		WorkerID: "w", Attempt: 1, LeaseExpiresAt: now + 60,
		CreatedAt: now, UpdatedAt: now,
	})

	if err := store.RetryJob(ctx, "retry-1", "transient error"); err != nil {
		t.Fatalf("RetryJob: %v", err)
	}

	got, _ := store.GetJob(ctx, "retry-1")
	if got.Status != StatusQueued {
		t.Errorf("Status = %q, want queued", got.Status)
	}
	if got.Error != "transient error" {
		t.Errorf("Error = %q", got.Error)
	}
	if got.WorkerID != "" {
		t.Errorf("WorkerID = %q, want empty", got.WorkerID)
	}
	if got.LeaseExpiresAt != 0 {
		t.Errorf("LeaseExpiresAt = %d, want 0", got.LeaseExpiresAt)
	}
}

// ---------------------------------------------------------------------------
// CompleteJobOwned / FailJobOwned / RetryJobOwned (conditional)
// ---------------------------------------------------------------------------

func TestPostgresStore_CompleteJobOwned(t *testing.T) {
	store := newTestPostgresStore(t)
	ctx := context.Background()
	now := time.Now().Unix()

	seedJob(t, store, &Job{
		ID: "owned-c1", Type: JobTypeInspectResource, Status: StatusRunning,
		WorkerID: "w1", Attempt: 2, LeaseExpiresAt: now + 60,
		CreatedAt: now, UpdatedAt: now,
	})

	if err := store.CompleteJobOwned(ctx, "owned-c1", "w1", 2, "done"); err != nil {
		t.Fatalf("CompleteJobOwned: %v", err)
	}

	got, _ := store.GetJob(ctx, "owned-c1")
	if got.Status != StatusSucceeded {
		t.Errorf("Status = %q, want succeeded", got.Status)
	}
	if got.Result != "done" {
		t.Errorf("Result = %q", got.Result)
	}
}

func TestPostgresStore_CompleteJobOwned_WrongWorker(t *testing.T) {
	store := newTestPostgresStore(t)
	ctx := context.Background()
	now := time.Now().Unix()

	seedJob(t, store, &Job{
		ID: "owned-c2", Type: JobTypeInspectResource, Status: StatusRunning,
		WorkerID: "w1", Attempt: 1, LeaseExpiresAt: now + 60,
		CreatedAt: now, UpdatedAt: now,
	})

	err := store.CompleteJobOwned(ctx, "owned-c2", "wrong-worker", 1, "done")
	if !errors.Is(err, ErrJobLeaseLost) {
		t.Fatalf("expected ErrJobLeaseLost, got %v", err)
	}
}

func TestPostgresStore_CompleteJobOwned_WrongAttempt(t *testing.T) {
	store := newTestPostgresStore(t)
	ctx := context.Background()
	now := time.Now().Unix()

	seedJob(t, store, &Job{
		ID: "owned-c3", Type: JobTypeInspectResource, Status: StatusRunning,
		WorkerID: "w1", Attempt: 1, LeaseExpiresAt: now + 60,
		CreatedAt: now, UpdatedAt: now,
	})

	err := store.CompleteJobOwned(ctx, "owned-c3", "w1", 99, "done")
	if !errors.Is(err, ErrJobLeaseLost) {
		t.Fatalf("expected ErrJobLeaseLost, got %v", err)
	}
}

func TestPostgresStore_CompleteJobOwned_NotRunning(t *testing.T) {
	store := newTestPostgresStore(t)
	ctx := context.Background()
	now := time.Now().Unix()

	seedJob(t, store, &Job{
		ID: "owned-c4", Type: JobTypeInspectResource, Status: StatusQueued,
		CreatedAt: now, UpdatedAt: now,
	})

	err := store.CompleteJobOwned(ctx, "owned-c4", "w1", 0, "done")
	if !errors.Is(err, ErrJobLeaseLost) {
		t.Fatalf("expected ErrJobLeaseLost, got %v", err)
	}
}

func TestPostgresStore_FailJobOwned(t *testing.T) {
	store := newTestPostgresStore(t)
	ctx := context.Background()
	now := time.Now().Unix()

	seedJob(t, store, &Job{
		ID: "owned-f1", Type: JobTypeInspectResource, Status: StatusRunning,
		WorkerID: "w1", Attempt: 1, LeaseExpiresAt: now + 60,
		CreatedAt: now, UpdatedAt: now,
	})

	if err := store.FailJobOwned(ctx, "owned-f1", "w1", 1, "crash"); err != nil {
		t.Fatalf("FailJobOwned: %v", err)
	}

	got, _ := store.GetJob(ctx, "owned-f1")
	if got.Status != StatusFailed {
		t.Errorf("Status = %q, want failed", got.Status)
	}
	if got.Error != "crash" {
		t.Errorf("Error = %q", got.Error)
	}
}

func TestPostgresStore_FailJobOwned_WrongWorker(t *testing.T) {
	store := newTestPostgresStore(t)
	ctx := context.Background()
	now := time.Now().Unix()

	seedJob(t, store, &Job{
		ID: "owned-f2", Type: JobTypeInspectResource, Status: StatusRunning,
		WorkerID: "w1", Attempt: 1, LeaseExpiresAt: now + 60,
		CreatedAt: now, UpdatedAt: now,
	})

	err := store.FailJobOwned(ctx, "owned-f2", "wrong-worker", 1, "crash")
	if !errors.Is(err, ErrJobLeaseLost) {
		t.Fatalf("expected ErrJobLeaseLost, got %v", err)
	}
}

func TestPostgresStore_RetryJobOwned(t *testing.T) {
	store := newTestPostgresStore(t)
	ctx := context.Background()
	now := time.Now().Unix()

	seedJob(t, store, &Job{
		ID: "owned-r1", Type: JobTypeInspectResource, Status: StatusRunning,
		WorkerID: "w1", Attempt: 1, LeaseExpiresAt: now + 60,
		CreatedAt: now, UpdatedAt: now,
	})

	if err := store.RetryJobOwned(ctx, "owned-r1", "w1", 1, "retry plz"); err != nil {
		t.Fatalf("RetryJobOwned: %v", err)
	}

	got, _ := store.GetJob(ctx, "owned-r1")
	if got.Status != StatusQueued {
		t.Errorf("Status = %q, want queued", got.Status)
	}
	if got.WorkerID != "" {
		t.Errorf("WorkerID = %q, want empty", got.WorkerID)
	}
	if got.Error != "retry plz" {
		t.Errorf("Error = %q", got.Error)
	}
}

func TestPostgresStore_RetryJobOwned_WrongWorker(t *testing.T) {
	store := newTestPostgresStore(t)
	ctx := context.Background()
	now := time.Now().Unix()

	seedJob(t, store, &Job{
		ID: "owned-r2", Type: JobTypeInspectResource, Status: StatusRunning,
		WorkerID: "w1", Attempt: 1, LeaseExpiresAt: now + 60,
		CreatedAt: now, UpdatedAt: now,
	})

	err := store.RetryJobOwned(ctx, "owned-r2", "wrong-worker", 1, "retry plz")
	if !errors.Is(err, ErrJobLeaseLost) {
		t.Fatalf("expected ErrJobLeaseLost, got %v", err)
	}
}

func TestPostgresStore_RetryJobOwned_WrongAttempt(t *testing.T) {
	store := newTestPostgresStore(t)
	ctx := context.Background()
	now := time.Now().Unix()

	seedJob(t, store, &Job{
		ID: "owned-r3", Type: JobTypeInspectResource, Status: StatusRunning,
		WorkerID: "w1", Attempt: 1, LeaseExpiresAt: now + 60,
		CreatedAt: now, UpdatedAt: now,
	})

	err := store.RetryJobOwned(ctx, "owned-r3", "w1", 99, "retry plz")
	if !errors.Is(err, ErrJobLeaseLost) {
		t.Fatalf("expected ErrJobLeaseLost, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// FindOrphanedJobs
// ---------------------------------------------------------------------------

func TestPostgresStore_FindOrphanedJobs(t *testing.T) {
	store := newTestPostgresStore(t)
	ctx := context.Background()
	now := time.Now().Unix()

	// Orphaned: running with expired lease.
	seedJob(t, store, &Job{
		ID: "orphan-1", Type: JobTypeInspectResource, Status: StatusRunning,
		WorkerID: "w1", Attempt: 1, LeaseExpiresAt: now - 120,
		CreatedAt: now, UpdatedAt: now,
	})
	seedJob(t, store, &Job{
		ID: "orphan-2", Type: JobTypeInspectResource, Status: StatusRunning,
		WorkerID: "w2", Attempt: 1, LeaseExpiresAt: now - 60,
		CreatedAt: now, UpdatedAt: now,
	})
	// Not orphaned: running with active lease.
	seedJob(t, store, &Job{
		ID: "active-1", Type: JobTypeInspectResource, Status: StatusRunning,
		WorkerID: "w3", Attempt: 1, LeaseExpiresAt: now + 3600,
		CreatedAt: now, UpdatedAt: now,
	})
	// Not orphaned: queued.
	seedJob(t, store, &Job{
		ID: "queued-1", Type: JobTypeInspectResource, Status: StatusQueued,
		CreatedAt: now, UpdatedAt: now,
	})
	// Not orphaned: succeeded.
	seedJob(t, store, &Job{
		ID: "done-1", Type: JobTypeInspectResource, Status: StatusSucceeded,
		CreatedAt: now, UpdatedAt: now,
	})

	jobs, err := store.FindOrphanedJobs(ctx, 10)
	if err != nil {
		t.Fatalf("FindOrphanedJobs: %v", err)
	}
	if len(jobs) != 2 {
		t.Fatalf("found %d orphaned jobs, want 2", len(jobs))
	}
	// Should be ordered by lease_expires_at ascending.
	if jobs[0].ID != "orphan-1" {
		t.Errorf("first orphan = %q, want orphan-1", jobs[0].ID)
	}
	if jobs[1].ID != "orphan-2" {
		t.Errorf("second orphan = %q, want orphan-2", jobs[1].ID)
	}
}

func TestPostgresStore_FindOrphanedJobs_RespectsLimit(t *testing.T) {
	store := newTestPostgresStore(t)
	ctx := context.Background()
	now := time.Now().Unix()

	for i := 0; i < 5; i++ {
		seedJob(t, store, &Job{
			ID: "lim-" + string(rune('a'+i)), Type: JobTypeInspectResource,
			Status: StatusRunning, WorkerID: "w", Attempt: 1,
			LeaseExpiresAt: now - int64(100-i),
			CreatedAt:      now, UpdatedAt: now,
		})
	}

	jobs, err := store.FindOrphanedJobs(ctx, 2)
	if err != nil {
		t.Fatalf("FindOrphanedJobs: %v", err)
	}
	if len(jobs) != 2 {
		t.Fatalf("found %d jobs, want 2 (limit)", len(jobs))
	}
}

func TestPostgresStore_FindOrphanedJobs_Empty(t *testing.T) {
	store := newTestPostgresStore(t)
	jobs, err := store.FindOrphanedJobs(context.Background(), 10)
	if err != nil {
		t.Fatalf("FindOrphanedJobs: %v", err)
	}
	if len(jobs) != 0 {
		t.Fatalf("expected 0 orphans, got %d", len(jobs))
	}
}

// ---------------------------------------------------------------------------
// Full lifecycle
// ---------------------------------------------------------------------------

func TestPostgresStore_FullLifecycle(t *testing.T) {
	store := newTestPostgresStore(t)
	ctx := context.Background()
	now := time.Now().Unix()

	// 1. Create a job.
	job := &Job{
		ID: "lifecycle-1", Type: JobTypeInspectResource, Status: StatusQueued,
		Payload: `{}`, MaxAttempts: 3, CreatedAt: now, UpdatedAt: now,
	}
	if err := store.CreateJob(ctx, job); err != nil {
		t.Fatalf("CreateJob: %v", err)
	}
	if err := store.MarkDispatched(ctx, "lifecycle-1"); err != nil {
		t.Fatalf("MarkDispatched: %v", err)
	}

	// 2. Claim it.
	claimed, ok, err := store.ClaimJob(ctx, "lifecycle-1", "w1", 30*time.Second)
	if err != nil || !ok {
		t.Fatalf("ClaimJob: ok=%v err=%v", ok, err)
	}
	if claimed.Status != StatusRunning || claimed.Attempt != 1 {
		t.Fatalf("unexpected claimed state: %+v", claimed)
	}

	// 3. Extend lease.
	if err := store.ExtendLease(ctx, "lifecycle-1", "w1", 60*time.Second); err != nil {
		t.Fatalf("ExtendLease: %v", err)
	}

	// 4. Complete (owned).
	if err := store.CompleteJobOwned(ctx, "lifecycle-1", "w1", 1, "all good"); err != nil {
		t.Fatalf("CompleteJobOwned: %v", err)
	}

	// 5. Verify final state.
	final, err := store.GetJob(ctx, "lifecycle-1")
	if err != nil {
		t.Fatalf("GetJob: %v", err)
	}
	if final.Status != StatusSucceeded {
		t.Errorf("final Status = %q, want succeeded", final.Status)
	}
	if final.Result != "all good" {
		t.Errorf("final Result = %q", final.Result)
	}
	if final.LeaseExpiresAt != 0 {
		t.Errorf("final LeaseExpiresAt = %d, want 0", final.LeaseExpiresAt)
	}
}
