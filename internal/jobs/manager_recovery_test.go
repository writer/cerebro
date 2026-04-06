package jobs

import (
	"context"
	"errors"
	"testing"
	"time"
)

type pendingDispatchStore struct {
	*MockStore
	dispatched map[string]bool
}

func newPendingDispatchStore() *pendingDispatchStore {
	return &pendingDispatchStore{
		MockStore:  NewMockStore(),
		dispatched: make(map[string]bool),
	}
}

func (s *pendingDispatchStore) MarkDispatched(_ context.Context, jobID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dispatched[jobID] = true
	if job, ok := s.jobs[jobID]; ok {
		job.UpdatedAt = time.Now().UTC().Unix()
	}
	return nil
}

func (s *pendingDispatchStore) FindPendingDispatchJobs(_ context.Context, limit int, olderThan time.Duration) ([]*Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cutoff := time.Now().UTC().Add(-olderThan).Unix()
	jobs := make([]*Job, 0, limit)
	for _, job := range s.jobs {
		if job.Status != StatusQueued || s.dispatched[job.ID] || job.UpdatedAt > cutoff {
			continue
		}
		jobs = append(jobs, job)
		if limit > 0 && len(jobs) >= limit {
			break
		}
	}
	return jobs, nil
}

type failingQueue struct {
	*MockQueue
	enqueueErr error
}

func (q *failingQueue) Enqueue(ctx context.Context, msg JobMessage) error {
	if q.enqueueErr != nil {
		return q.enqueueErr
	}
	return q.MockQueue.Enqueue(ctx, msg)
}

func (q *failingQueue) EnqueueWithDelay(ctx context.Context, msg JobMessage, delay time.Duration) error {
	if q.enqueueErr != nil {
		return q.enqueueErr
	}
	return q.MockQueue.EnqueueWithDelay(ctx, msg, delay)
}

func TestManager_EnqueueNativeSyncMarksQueuedJobDispatched(t *testing.T) {
	store := newPendingDispatchStore()
	queue := &MockQueue{}
	manager := NewManager(queue, store, nil)

	job, err := manager.EnqueueNativeSync(context.Background(), NativeSyncPayload{Provider: "aws"}, EnqueueOptions{MaxAttempts: 1})
	if err != nil {
		t.Fatalf("EnqueueNativeSync: %v", err)
	}
	if job == nil {
		t.Fatal("expected job")
	}
	if !store.dispatched[job.ID] {
		t.Fatalf("expected job %s to be marked dispatched", job.ID)
	}
	if len(queue.enqueuedMsgs) != 1 || queue.enqueuedMsgs[0].JobID != job.ID {
		t.Fatalf("unexpected enqueued messages: %+v", queue.enqueuedMsgs)
	}
}

func TestManager_EnqueueNativeSyncLeavesQueuedJobForRecoveryOnPublishFailure(t *testing.T) {
	store := newPendingDispatchStore()
	queue := &failingQueue{
		MockQueue:  &MockQueue{},
		enqueueErr: errors.New("jetstream unavailable"),
	}
	manager := NewManager(queue, store, nil)

	if _, err := manager.EnqueueNativeSync(context.Background(), NativeSyncPayload{Provider: "aws"}, EnqueueOptions{MaxAttempts: 1}); err == nil {
		t.Fatal("expected enqueue error")
	}

	if len(store.jobs) != 1 {
		t.Fatalf("expected one persisted job, got %d", len(store.jobs))
	}
	for jobID, job := range store.jobs {
		if job.Status != StatusQueued {
			t.Fatalf("expected job %s to remain queued, got %s", jobID, job.Status)
		}
		if store.dispatched[jobID] {
			t.Fatalf("expected job %s to remain undispatched", jobID)
		}
	}
}

func TestPendingDispatchScanner_RePublishesQueuedJobs(t *testing.T) {
	store := newPendingDispatchStore()
	queue := &MockQueue{}
	old := time.Now().UTC().Add(-time.Minute).Unix()
	store.AddJob(&Job{
		ID:        "queued-1",
		Type:      JobTypeNativeSync,
		Status:    StatusQueued,
		GroupID:   "grp-1",
		CreatedAt: old,
		UpdatedAt: old,
	})

	scanner := NewPendingDispatchScanner(store, queue, nil, time.Minute, 5*time.Second)
	scanner.scan(context.Background())

	if len(queue.enqueuedMsgs) != 1 {
		t.Fatalf("expected one republished job, got %+v", queue.enqueuedMsgs)
	}
	if queue.enqueuedMsgs[0].JobID != "queued-1" || queue.enqueuedMsgs[0].GroupID != "grp-1" {
		t.Fatalf("unexpected republished message: %+v", queue.enqueuedMsgs[0])
	}
	if !store.dispatched["queued-1"] {
		t.Fatal("expected republished job to be marked dispatched")
	}
}
