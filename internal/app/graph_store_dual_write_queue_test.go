package app

import (
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/health"
)

type failingDualWriteReplayStore struct {
	graph.GraphStore
	failIDs map[string]error
}

func (s failingDualWriteReplayStore) UpsertNode(ctx context.Context, node *graph.Node) error {
	if node != nil {
		if err := s.failIDs[node.ID]; err != nil {
			return err
		}
	}
	return s.GraphStore.UpsertNode(ctx, node)
}

func TestGraphStoreDualWriteSQLiteQueueMutationMethodsIgnoreStatsObservationErrors(t *testing.T) {
	t.Parallel()

	queue, err := newGraphStoreDualWriteSQLiteQueue(filepath.Join(t.TempDir(), "dual-write-queue.sqlite"))
	if err != nil {
		t.Fatalf("newGraphStoreDualWriteSQLiteQueue() error = %v", err)
	}
	defer func() {
		if err := queue.Close(); err != nil {
			t.Fatalf("queue.Close() error = %v", err)
		}
	}()

	items := []graph.DualWriteReconciliationItem{
		{
			Operation:      graph.DualWriteMutationUpsertNode,
			Identifiers:    []string{"service:payments"},
			Node:           &graph.Node{ID: "service:payments", Kind: graph.NodeKindService, Name: "payments"},
			TargetBackend:  graph.StoreBackendSpanner,
			FirstFailureAt: time.Date(2026, 3, 23, 22, 30, 0, 0, time.UTC),
			Retryable:      true,
		},
		{
			Operation:      graph.DualWriteMutationUpsertNode,
			Identifiers:    []string{"service:billing"},
			Node:           &graph.Node{ID: "service:billing", Kind: graph.NodeKindService, Name: "billing"},
			TargetBackend:  graph.StoreBackendSpanner,
			FirstFailureAt: time.Date(2026, 3, 23, 22, 35, 0, 0, time.UTC),
			Retryable:      true,
		},
	}
	for _, item := range items {
		if err := queue.Enqueue(context.Background(), item); err != nil {
			t.Fatalf("Enqueue(%v) error = %v", item.Identifiers, err)
		}
	}

	queue.postMutationObserveStats = func(context.Context) error {
		return errors.New("stats unavailable")
	}

	leases, err := queue.Lease(context.Background(), "worker-a", 1, time.Second)
	if err != nil {
		t.Fatalf("Lease() error = %v", err)
	}
	if len(leases) != 1 {
		t.Fatalf("Lease() returned %d items, want 1", len(leases))
	}
	if err := queue.Ack(context.Background(), leases[0]); err != nil {
		t.Fatalf("Ack() error = %v", err)
	}

	leases, err = queue.Lease(context.Background(), "worker-b", 1, time.Second)
	if err != nil {
		t.Fatalf("Lease(second) error = %v", err)
	}
	if len(leases) != 1 {
		t.Fatalf("Lease(second) returned %d items, want 1", len(leases))
	}
	deadLettered, err := queue.Retry(context.Background(), leases[0], errors.New("still failing"), true, 3)
	if err != nil {
		t.Fatalf("Retry() error = %v", err)
	}
	if deadLettered {
		t.Fatal("Retry() dead-lettered item before max attempts")
	}

	stats, err := queue.Stats(context.Background())
	if err != nil {
		t.Fatalf("Stats() error = %v", err)
	}
	if stats.Pending != 1 || stats.Leased != 0 || stats.DeadLettered != 0 {
		t.Fatalf("Stats() = %#v, want pending=1 leased=0 dead_lettered=0", stats)
	}
}

func TestGraphStoreDualWriteReconciliationQueueCrashSafeRecoveryViaLeaseExpiry(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "dual-write-queue.sqlite")
	leaseTTL := 200 * time.Millisecond
	queue, err := newGraphStoreDualWriteReconciliationQueue(path)
	if err != nil {
		t.Fatalf("newGraphStoreDualWriteReconciliationQueue() error = %v", err)
	}

	item := graph.DualWriteReconciliationItem{
		Operation:      graph.DualWriteMutationUpsertNode,
		Identifiers:    []string{"service:payments"},
		Node:           &graph.Node{ID: "service:payments", Kind: graph.NodeKindService, Name: "payments"},
		TargetBackend:  graph.StoreBackendSpanner,
		FirstFailureAt: time.Date(2026, 3, 23, 22, 30, 0, 0, time.UTC),
		RetryCount:     1,
		LastError:      "temporary failure",
		Retryable:      true,
	}
	if err := queue.Enqueue(context.Background(), item); err != nil {
		t.Fatalf("Enqueue() error = %v", err)
	}
	if err := queue.Close(); err != nil {
		t.Fatalf("queue.Close() error = %v", err)
	}

	crashed, err := newGraphStoreDualWriteReconciliationQueue(path)
	if err != nil {
		t.Fatalf("newGraphStoreDualWriteReconciliationQueue(reopen) error = %v", err)
	}
	defer func() {
		if err := crashed.Close(); err != nil {
			t.Fatalf("crashed.Close() error = %v", err)
		}
	}()

	leases, err := crashed.Lease(context.Background(), "worker-a", 1, leaseTTL)
	if err != nil {
		t.Fatalf("Lease(worker-a) error = %v", err)
	}
	if len(leases) != 1 {
		t.Fatalf("Lease(worker-a) returned %d items, want 1", len(leases))
	}

	secondAttempt, err := crashed.Lease(context.Background(), "worker-b", 1, time.Second)
	if err != nil {
		t.Fatalf("Lease(worker-b) error = %v", err)
	}
	if len(secondAttempt) != 0 {
		t.Fatalf("Lease(worker-b) = %#v, want no items before lease expiry", secondAttempt)
	}

	time.Sleep(leaseTTL + 100*time.Millisecond)

	recovered, err := newGraphStoreDualWriteReconciliationQueue(path)
	if err != nil {
		t.Fatalf("newGraphStoreDualWriteReconciliationQueue(second reopen) error = %v", err)
	}
	defer func() {
		if err := recovered.Close(); err != nil {
			t.Fatalf("recovered.Close() error = %v", err)
		}
	}()

	store := graph.New()
	result, err := replayGraphStoreDualWriteQueueOnce(context.Background(), slog.Default(), recovered, store, graphStoreDualWriteReplayOptions{
		WorkerID:      "worker-b",
		BatchSize:     1,
		LeaseDuration: time.Second,
		MaxAttempts:   3,
	})
	if err != nil {
		t.Fatalf("replayGraphStoreDualWriteQueueOnce() error = %v", err)
	}
	if result.Replayed != 1 || result.Pending != 0 || result.DeadLettered != 0 {
		t.Fatalf("replayGraphStoreDualWriteQueueOnce() result = %#v, want replayed=1 pending=0 dead_lettered=0", result)
	}
	if _, ok := store.GetNode("service:payments"); !ok {
		t.Fatal("expected replay after crash recovery to persist node")
	}
}

func TestGraphStoreDualWriteReconciliationQueueStatsTreatExpiredLeaseAsPending(t *testing.T) {
	t.Parallel()

	leaseTTL := 200 * time.Millisecond
	queue, err := newGraphStoreDualWriteReconciliationQueue(filepath.Join(t.TempDir(), "dual-write-queue.sqlite"))
	if err != nil {
		t.Fatalf("newGraphStoreDualWriteReconciliationQueue() error = %v", err)
	}
	defer func() {
		if err := queue.Close(); err != nil {
			t.Fatalf("queue.Close() error = %v", err)
		}
	}()

	item := graph.DualWriteReconciliationItem{
		Operation:      graph.DualWriteMutationUpsertNode,
		Identifiers:    []string{"service:payments"},
		Node:           &graph.Node{ID: "service:payments", Kind: graph.NodeKindService, Name: "payments"},
		TargetBackend:  graph.StoreBackendSpanner,
		FirstFailureAt: time.Date(2026, 3, 23, 22, 30, 0, 0, time.UTC),
		RetryCount:     1,
		LastError:      "temporary failure",
		Retryable:      true,
	}
	if err := queue.Enqueue(context.Background(), item); err != nil {
		t.Fatalf("Enqueue() error = %v", err)
	}

	leases, err := queue.Lease(context.Background(), "worker-a", 1, leaseTTL)
	if err != nil {
		t.Fatalf("Lease() error = %v", err)
	}
	if len(leases) != 1 {
		t.Fatalf("Lease() returned %d items, want 1", len(leases))
	}

	time.Sleep(leaseTTL + 100*time.Millisecond)

	stats, err := queue.Stats(context.Background())
	if err != nil {
		t.Fatalf("Stats() error = %v", err)
	}
	if stats.Pending != 1 || stats.Leased != 0 || stats.DeadLettered != 0 {
		t.Fatalf("Stats() = %#v, want pending=1 leased=0 dead_lettered=0", stats)
	}
	if stats.OldestPendingAt.IsZero() {
		t.Fatal("Stats() oldest pending timestamp is zero, want enqueued item timestamp")
	}
}

func TestGraphStoreDualWriteReconciliationQueueReplayToleratesDuplicateDelivery(t *testing.T) {
	t.Parallel()

	queue, err := newGraphStoreDualWriteReconciliationQueue(filepath.Join(t.TempDir(), "dual-write-queue.sqlite"))
	if err != nil {
		t.Fatalf("newGraphStoreDualWriteReconciliationQueue() error = %v", err)
	}
	defer func() {
		if err := queue.Close(); err != nil {
			t.Fatalf("queue.Close() error = %v", err)
		}
	}()

	item := graph.DualWriteReconciliationItem{
		Operation:      graph.DualWriteMutationUpsertNode,
		Identifiers:    []string{"service:payments"},
		Node:           &graph.Node{ID: "service:payments", Kind: graph.NodeKindService, Name: "payments"},
		TargetBackend:  graph.StoreBackendSpanner,
		FirstFailureAt: time.Date(2026, 3, 23, 22, 30, 0, 0, time.UTC),
		RetryCount:     1,
		LastError:      "temporary failure",
		Retryable:      true,
	}
	for i := 0; i < 2; i++ {
		if err := queue.Enqueue(context.Background(), item); err != nil {
			t.Fatalf("Enqueue(%d) error = %v", i, err)
		}
	}

	store := graph.New()
	result, err := replayGraphStoreDualWriteQueueOnce(context.Background(), slog.Default(), queue, store, graphStoreDualWriteReplayOptions{
		WorkerID:      "worker-a",
		BatchSize:     10,
		LeaseDuration: time.Second,
		MaxAttempts:   3,
	})
	if err != nil {
		t.Fatalf("replayGraphStoreDualWriteQueueOnce() error = %v", err)
	}
	if result.Replayed != 2 || result.Pending != 0 || result.DeadLettered != 0 {
		t.Fatalf("replayGraphStoreDualWriteQueueOnce() result = %#v, want replayed=2 pending=0 dead_lettered=0", result)
	}
	if count, err := store.CountNodes(context.Background()); err != nil || count != 1 {
		t.Fatalf("store.CountNodes() = %d err=%v, want 1 idempotent node", count, err)
	}
}

func TestGraphStoreDualWriteReconciliationQueueReplayIsolatesPoisonMessages(t *testing.T) {
	t.Parallel()

	queue, err := newGraphStoreDualWriteReconciliationQueue(filepath.Join(t.TempDir(), "dual-write-queue.sqlite"))
	if err != nil {
		t.Fatalf("newGraphStoreDualWriteReconciliationQueue() error = %v", err)
	}
	defer func() {
		if err := queue.Close(); err != nil {
			t.Fatalf("queue.Close() error = %v", err)
		}
	}()

	goodItem := graph.DualWriteReconciliationItem{
		Operation:      graph.DualWriteMutationUpsertNode,
		Identifiers:    []string{"service:payments"},
		Node:           &graph.Node{ID: "service:payments", Kind: graph.NodeKindService, Name: "payments"},
		TargetBackend:  graph.StoreBackendSpanner,
		FirstFailureAt: time.Date(2026, 3, 23, 22, 30, 0, 0, time.UTC),
		RetryCount:     1,
		LastError:      "temporary failure",
		Retryable:      true,
	}
	poisonItem := graph.DualWriteReconciliationItem{
		Operation:      graph.DualWriteMutationUpsertNode,
		Identifiers:    []string{"service:poison"},
		Node:           &graph.Node{ID: "service:poison", Kind: graph.NodeKindService, Name: "poison"},
		TargetBackend:  graph.StoreBackendSpanner,
		FirstFailureAt: time.Date(2026, 3, 23, 22, 30, 0, 0, time.UTC),
		RetryCount:     2,
		LastError:      "temporary failure",
		Retryable:      false,
	}
	for _, item := range []graph.DualWriteReconciliationItem{goodItem, poisonItem} {
		if err := queue.Enqueue(context.Background(), item); err != nil {
			t.Fatalf("Enqueue(%s) error = %v", item.Identifiers[0], err)
		}
	}

	store := failingDualWriteReplayStore{
		GraphStore: graph.New(),
		failIDs: map[string]error{
			"service:poison": errors.New("poison payload"),
		},
	}
	result, err := replayGraphStoreDualWriteQueueOnce(context.Background(), slog.Default(), queue, store, graphStoreDualWriteReplayOptions{
		WorkerID:      "worker-a",
		BatchSize:     10,
		LeaseDuration: time.Second,
		MaxAttempts:   2,
		ClassifyRetryable: func(error) bool {
			return false
		},
	})
	if err != nil {
		t.Fatalf("replayGraphStoreDualWriteQueueOnce() error = %v", err)
	}
	if result.Replayed != 1 || result.DeadLettered != 1 || result.Pending != 0 {
		t.Fatalf("replayGraphStoreDualWriteQueueOnce() result = %#v, want replayed=1 dead_lettered=1 pending=0", result)
	}
	if _, ok, err := store.LookupNode(context.Background(), "service:payments"); err != nil || !ok {
		t.Fatalf("expected healthy item to replay despite poison message: ok=%v err=%v", ok, err)
	}
	deadLetters, err := queue.DeadLetters(context.Background(), 10)
	if err != nil {
		t.Fatalf("DeadLetters() error = %v", err)
	}
	if len(deadLetters) != 1 {
		t.Fatalf("DeadLetters() = %#v, want 1 item", deadLetters)
	}
	if deadLetters[0].Identifiers[0] != "service:poison" {
		t.Fatalf("dead-letter identifiers = %#v, want poison item", deadLetters[0].Identifiers)
	}
}

func TestGraphStoreDualWriteReconciliationQueueRetryPersistsFailureMetadata(t *testing.T) {
	t.Parallel()

	queue, err := newGraphStoreDualWriteReconciliationQueue(filepath.Join(t.TempDir(), "dual-write-queue.sqlite"))
	if err != nil {
		t.Fatalf("newGraphStoreDualWriteReconciliationQueue() error = %v", err)
	}
	defer func() {
		if err := queue.Close(); err != nil {
			t.Fatalf("queue.Close() error = %v", err)
		}
	}()

	item := graph.DualWriteReconciliationItem{
		Operation:      graph.DualWriteMutationUpsertNode,
		Identifiers:    []string{"service:payments"},
		Node:           &graph.Node{ID: "service:payments", Kind: graph.NodeKindService, Name: "payments"},
		TargetBackend:  graph.StoreBackendSpanner,
		FirstFailureAt: time.Date(2026, 3, 23, 22, 30, 0, 0, time.UTC),
		RetryCount:     1,
		LastError:      "temporary failure",
		Retryable:      true,
	}
	if err := queue.Enqueue(context.Background(), item); err != nil {
		t.Fatalf("Enqueue() error = %v", err)
	}

	leases, err := queue.Lease(context.Background(), "worker-a", 1, time.Second)
	if err != nil {
		t.Fatalf("Lease() error = %v", err)
	}
	if len(leases) != 1 {
		t.Fatalf("Lease() returned %d items, want 1", len(leases))
	}
	deadLettered, err := queue.Retry(context.Background(), leases[0], errors.New("still failing"), true, 3)
	if err != nil {
		t.Fatalf("Retry() error = %v", err)
	}
	if deadLettered {
		t.Fatal("Retry() dead-lettered item before max attempts")
	}

	leasedAgain, err := queue.Lease(context.Background(), "worker-b", 1, time.Second)
	if err != nil {
		t.Fatalf("Lease(second) error = %v", err)
	}
	if len(leasedAgain) != 1 {
		t.Fatalf("Lease(second) returned %d items, want 1", len(leasedAgain))
	}
	if leasedAgain[0].Item.RetryCount != 2 {
		t.Fatalf("leasedAgain retry_count = %d, want 2", leasedAgain[0].Item.RetryCount)
	}
	if leasedAgain[0].Item.LastError != "still failing" {
		t.Fatalf("leasedAgain last_error = %q, want %q", leasedAgain[0].Item.LastError, "still failing")
	}
}

func TestGraphStoreDualWriteReconciliationHealthCheckReportsDeadLetters(t *testing.T) {
	t.Parallel()

	queue, err := newGraphStoreDualWriteReconciliationQueue(filepath.Join(t.TempDir(), "dual-write-queue.sqlite"))
	if err != nil {
		t.Fatalf("newGraphStoreDualWriteReconciliationQueue() error = %v", err)
	}
	defer func() {
		if err := queue.Close(); err != nil {
			t.Fatalf("queue.Close() error = %v", err)
		}
	}()

	item := graph.DualWriteReconciliationItem{
		Operation:      graph.DualWriteMutationUpsertNode,
		Identifiers:    []string{"service:poison"},
		Node:           &graph.Node{ID: "service:poison", Kind: graph.NodeKindService, Name: "poison"},
		TargetBackend:  graph.StoreBackendSpanner,
		FirstFailureAt: time.Date(2026, 3, 23, 22, 30, 0, 0, time.UTC),
		RetryCount:     2,
		LastError:      "temporary failure",
		Retryable:      false,
	}
	if err := queue.Enqueue(context.Background(), item); err != nil {
		t.Fatalf("Enqueue() error = %v", err)
	}
	leases, err := queue.Lease(context.Background(), "worker-a", 1, time.Second)
	if err != nil {
		t.Fatalf("Lease() error = %v", err)
	}
	if _, err := queue.Retry(context.Background(), leases[0], errors.New("poison"), false, 2); err != nil {
		t.Fatalf("Retry() error = %v", err)
	}

	application := &App{
		graphStoreDualWriteReplayQueue: queue,
	}
	result := application.graphDualWriteReconciliationHealthCheck()(context.Background())
	if result.Status != health.StatusDegraded {
		t.Fatalf("graphDualWriteReconciliationHealthCheck() status = %s, want degraded", result.Status)
	}
}
