package jobs

import (
	"context"
	"testing"
	"time"
)

func TestPostgresStore_ClaimJobRequiresDispatchMarker(t *testing.T) {
	store := newTestPostgresStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Unix()

	job := &Job{
		ID:          "dispatch-claim-1",
		Type:        JobTypeNativeSync,
		Status:      StatusQueued,
		Payload:     "{}",
		MaxAttempts: 1,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := store.CreateJob(ctx, job); err != nil {
		t.Fatalf("CreateJob: %v", err)
	}

	if claimed, ok, err := store.ClaimJob(ctx, job.ID, "worker-1", 30*time.Second); err != nil {
		t.Fatalf("ClaimJob before dispatch: %v", err)
	} else if ok || claimed != nil {
		t.Fatalf("expected undispatched queued job to be unclaimable, got %+v ok=%t", claimed, ok)
	}

	if err := store.MarkDispatched(ctx, job.ID); err != nil {
		t.Fatalf("MarkDispatched: %v", err)
	}

	claimed, ok, err := store.ClaimJob(ctx, job.ID, "worker-1", 30*time.Second)
	if err != nil {
		t.Fatalf("ClaimJob after dispatch: %v", err)
	}
	if !ok || claimed == nil {
		t.Fatal("expected dispatched queued job to be claimable")
	}
	if claimed.Status != StatusRunning {
		t.Fatalf("expected running status, got %s", claimed.Status)
	}
}

func TestPostgresStore_FindPendingDispatchJobs(t *testing.T) {
	store := newTestPostgresStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	oldJob := &Job{
		ID:          "pending-old",
		Type:        JobTypeNativeSync,
		Status:      StatusQueued,
		Payload:     "{}",
		MaxAttempts: 1,
		CreatedAt:   now.Add(-time.Minute).Unix(),
		UpdatedAt:   now.Add(-time.Minute).Unix(),
	}
	freshJob := &Job{
		ID:          "pending-fresh",
		Type:        JobTypeNativeSync,
		Status:      StatusQueued,
		Payload:     "{}",
		MaxAttempts: 1,
		CreatedAt:   now.Unix(),
		UpdatedAt:   now.Unix(),
	}
	dispatchedJob := &Job{
		ID:          "pending-done",
		Type:        JobTypeNativeSync,
		Status:      StatusQueued,
		Payload:     "{}",
		MaxAttempts: 1,
		CreatedAt:   now.Add(-time.Minute).Unix(),
		UpdatedAt:   now.Add(-time.Minute).Unix(),
	}

	for _, job := range []*Job{oldJob, freshJob, dispatchedJob} {
		if err := store.CreateJob(ctx, job); err != nil {
			t.Fatalf("CreateJob(%s): %v", job.ID, err)
		}
	}
	if err := store.MarkDispatched(ctx, dispatchedJob.ID); err != nil {
		t.Fatalf("MarkDispatched: %v", err)
	}

	jobs, err := store.FindPendingDispatchJobs(ctx, 10, 5*time.Second)
	if err != nil {
		t.Fatalf("FindPendingDispatchJobs: %v", err)
	}
	if len(jobs) != 1 || jobs[0].ID != oldJob.ID {
		t.Fatalf("unexpected pending dispatch jobs: %+v", jobs)
	}
}
