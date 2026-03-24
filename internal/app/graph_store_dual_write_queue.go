package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/metrics"
)

const (
	graphStoreDualWriteSQLitePrefix       = "sqlite://"
	defaultGraphStoreDualWriteLeaseTTL    = 30 * time.Second
	defaultGraphStoreDualWriteMaxAttempts = 3
)

type graphStoreDualWriteQueueBackend string

const (
	graphStoreDualWriteQueueBackendFile   graphStoreDualWriteQueueBackend = "file"
	graphStoreDualWriteQueueBackendSQLite graphStoreDualWriteQueueBackend = "sqlite"
)

type graphStoreDualWriteReplayResult struct {
	Replayed     int
	Pending      int
	DeadLettered int
	Failed       int
}

type graphStoreDualWriteReplayOptions struct {
	WorkerID          string
	BatchSize         int
	LeaseDuration     time.Duration
	MaxAttempts       int
	ClassifyRetryable func(error) bool
}

type graphStoreDualWriteQueueStats struct {
	Pending         int
	Leased          int
	DeadLettered    int
	OldestPendingAt time.Time
}

type graphStoreDualWriteLeasedItem struct {
	QueueID    int64
	LeaseOwner string
	LeaseToken string
	Item       graph.DualWriteReconciliationItem
}

type graphStoreDualWriteReplayQueue interface {
	graph.DualWriteReconciliationQueue
	Lease(ctx context.Context, owner string, limit int, leaseDuration time.Duration) ([]graphStoreDualWriteLeasedItem, error)
	Ack(ctx context.Context, lease graphStoreDualWriteLeasedItem) error
	Retry(ctx context.Context, lease graphStoreDualWriteLeasedItem, replayErr error, retryable bool, maxAttempts int) (bool, error)
	Stats(ctx context.Context) (graphStoreDualWriteQueueStats, error)
	DeadLetters(ctx context.Context, limit int) ([]graph.DualWriteReconciliationItem, error)
	Close() error
}

type graphStoreDualWriteQueueRecord struct {
	ID               int64                             `json:"id"`
	Item             graph.DualWriteReconciliationItem `json:"item"`
	EnqueuedAt       time.Time                         `json:"enqueued_at"`
	AvailableAt      time.Time                         `json:"available_at"`
	LeaseOwner       string                            `json:"lease_owner,omitempty"`
	LeaseToken       string                            `json:"lease_token,omitempty"`
	LeasedUntil      time.Time                         `json:"leased_until,omitempty"`
	DeadLetteredAt   time.Time                         `json:"dead_lettered_at,omitempty"`
	DeadLetterReason string                            `json:"dead_letter_reason,omitempty"`
}

type graphStoreDualWriteFileQueueState struct {
	NextID  int64                            `json:"next_id"`
	Records []graphStoreDualWriteQueueRecord `json:"records,omitempty"`
}

type graphStoreDualWriteFileQueue struct {
	path string
	mu   sync.Mutex
}

func newGraphStoreDualWriteReconciliationQueue(path string) (graphStoreDualWriteReplayQueue, error) {
	backend, resolved, err := resolveGraphStoreDualWriteQueueBackend(path)
	if err != nil {
		return nil, err
	}
	switch backend {
	case graphStoreDualWriteQueueBackendSQLite:
		return newGraphStoreDualWriteSQLiteQueue(resolved)
	default:
		return &graphStoreDualWriteFileQueue{path: filepath.Clean(resolved)}, nil
	}
}

func resolveGraphStoreDualWriteQueueBackend(path string) (graphStoreDualWriteQueueBackend, string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", "", fmt.Errorf("graph dual-write reconciliation queue path is required")
	}
	if strings.HasPrefix(strings.ToLower(path), graphStoreDualWriteSQLitePrefix) {
		resolved := strings.TrimSpace(path[len(graphStoreDualWriteSQLitePrefix):])
		if resolved == "" {
			return "", "", fmt.Errorf("graph dual-write reconciliation sqlite path is required")
		}
		return graphStoreDualWriteQueueBackendSQLite, resolved, nil
	}
	switch strings.ToLower(filepath.Ext(path)) {
	case ".db", ".sqlite", ".sqlite3":
		return graphStoreDualWriteQueueBackendSQLite, path, nil
	default:
		return graphStoreDualWriteQueueBackendFile, path, nil
	}
}

func replayGraphStoreDualWriteQueueOnce(ctx context.Context, logger *slog.Logger, queue graphStoreDualWriteReplayQueue, store graph.GraphStore, opts graphStoreDualWriteReplayOptions) (graphStoreDualWriteReplayResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := context.Cause(ctx); err != nil {
		return graphStoreDualWriteReplayResult{}, err
	}
	if queue == nil {
		return graphStoreDualWriteReplayResult{}, nil
	}
	if store == nil {
		return graphStoreDualWriteReplayResult{}, graph.ErrStoreUnavailable
	}
	opts = normalizeGraphStoreDualWriteReplayOptions(opts)

	leases, err := queue.Lease(ctx, opts.WorkerID, opts.BatchSize, opts.LeaseDuration)
	if err != nil {
		return graphStoreDualWriteReplayResult{}, err
	}
	result := graphStoreDualWriteReplayResult{}
	for _, lease := range leases {
		if err := graph.ApplyDualWriteReconciliationItem(ctx, store, lease.Item); err != nil {
			deadLettered, retryErr := queue.Retry(ctx, lease, err, opts.ClassifyRetryable(err), opts.MaxAttempts)
			if retryErr != nil {
				return result, retryErr
			}
			if deadLettered {
				result.DeadLettered++
				if logger != nil {
					logger.Warn("graph dual-write reconciliation dead-lettered mutation", "queue_id", lease.QueueID, "identifiers", lease.Item.Identifiers, "error", err)
				}
			} else {
				result.Failed++
			}
			continue
		}
		if err := queue.Ack(ctx, lease); err != nil {
			return result, err
		}
		result.Replayed++
	}
	stats, err := queue.Stats(ctx)
	if err != nil {
		return result, err
	}
	result.Pending = stats.Pending
	return result, nil
}

func normalizeGraphStoreDualWriteReplayOptions(opts graphStoreDualWriteReplayOptions) graphStoreDualWriteReplayOptions {
	if strings.TrimSpace(opts.WorkerID) == "" {
		opts.WorkerID = fmt.Sprintf("graph-dual-write-%d", os.Getpid())
	}
	if opts.BatchSize <= 0 {
		opts.BatchSize = 1
	}
	if opts.LeaseDuration <= 0 {
		opts.LeaseDuration = defaultGraphStoreDualWriteLeaseTTL
	}
	if opts.MaxAttempts <= 0 {
		opts.MaxAttempts = defaultGraphStoreDualWriteMaxAttempts
	}
	if opts.ClassifyRetryable == nil {
		opts.ClassifyRetryable = graph.DefaultDualWriteRetryable
	}
	return opts
}

func startGraphStoreDualWriteReplayLoop(ctx context.Context, logger *slog.Logger, queue graphStoreDualWriteReplayQueue, store graph.GraphStore, interval time.Duration, batchSize int) func() error {
	if queue == nil || store == nil || interval <= 0 || batchSize <= 0 {
		return func() error { return nil }
	}
	workerID := fmt.Sprintf("graph-dual-write-replay-%d", os.Getpid())
	loopCtx, cancel := context.WithCancel(backgroundWorkContext(ctx)) // #nosec G118 -- cancel is returned to the caller and invoked by the returned shutdown function.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		runReplay := func() {
			result, err := replayGraphStoreDualWriteQueueOnce(loopCtx, logger, queue, store, graphStoreDualWriteReplayOptions{
				WorkerID:      workerID,
				BatchSize:     batchSize,
				LeaseDuration: defaultGraphStoreDualWriteLeaseTTL,
				MaxAttempts:   defaultGraphStoreDualWriteMaxAttempts,
			})
			if err != nil && logger != nil && !errors.Is(err, context.Canceled) {
				logger.Warn("graph dual-write reconciliation replay failed", "error", err)
				return
			}
			if logger != nil && (result.Replayed > 0 || result.DeadLettered > 0) {
				logger.Info("graph dual-write reconciliation replayed mutations", "replayed", result.Replayed, "dead_lettered", result.DeadLettered, "pending", result.Pending)
			}
		}
		runReplay()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-loopCtx.Done():
				return
			case <-ticker.C:
				runReplay()
			}
		}
	}()
	return func() error {
		cancel()
		wg.Wait()
		return nil
	}
}

func (q *graphStoreDualWriteFileQueue) Enqueue(ctx context.Context, item graph.DualWriteReconciliationItem) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := context.Cause(ctx); err != nil {
		return err
	}
	q.mu.Lock()
	defer q.mu.Unlock()

	state, err := q.readStateLocked()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	state.NextID++
	state.Records = append(state.Records, graphStoreDualWriteQueueRecord{
		ID:          state.NextID,
		Item:        cloneDualWriteReconciliationItem(item),
		EnqueuedAt:  now,
		AvailableAt: now,
	})
	if err := q.writeStateLocked(state); err != nil {
		return err
	}
	metrics.RecordGraphDualWriteReconciliationEvent("enqueued")
	observeGraphStoreDualWriteQueueStats(statsFromRecords(state.Records))
	return nil
}

func (q *graphStoreDualWriteFileQueue) Lease(ctx context.Context, owner string, limit int, leaseDuration time.Duration) ([]graphStoreDualWriteLeasedItem, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := context.Cause(ctx); err != nil {
		return nil, err
	}
	owner = strings.TrimSpace(owner)
	if owner == "" {
		return nil, fmt.Errorf("graph dual-write lease owner is required")
	}
	if limit <= 0 {
		return nil, nil
	}
	if leaseDuration <= 0 {
		leaseDuration = defaultGraphStoreDualWriteLeaseTTL
	}
	q.mu.Lock()
	defer q.mu.Unlock()

	state, err := q.readStateLocked()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	releaseExpiredLeases(state.Records, now)
	claimable := make([]int, 0, len(state.Records))
	for idx, record := range state.Records {
		switch {
		case !record.DeadLetteredAt.IsZero():
			continue
		case !record.AvailableAt.IsZero() && record.AvailableAt.After(now):
			continue
		case strings.TrimSpace(record.LeaseOwner) != "":
			continue
		default:
			claimable = append(claimable, idx)
		}
	}
	sort.Slice(claimable, func(i, j int) bool {
		left := state.Records[claimable[i]]
		right := state.Records[claimable[j]]
		if !left.AvailableAt.Equal(right.AvailableAt) {
			return left.AvailableAt.Before(right.AvailableAt)
		}
		return left.ID < right.ID
	})
	if limit > len(claimable) {
		limit = len(claimable)
	}

	leases := make([]graphStoreDualWriteLeasedItem, 0, limit)
	for _, idx := range claimable[:limit] {
		record := &state.Records[idx]
		record.LeaseOwner = owner
		record.LeaseToken = fmt.Sprintf("%s-%d-%d", owner, record.ID, now.UnixNano())
		record.LeasedUntil = now.Add(leaseDuration)
		leases = append(leases, graphStoreDualWriteLeasedItem{
			QueueID:    record.ID,
			LeaseOwner: record.LeaseOwner,
			LeaseToken: record.LeaseToken,
			Item:       cloneDualWriteReconciliationItem(record.Item),
		})
	}
	if err := q.writeStateLocked(state); err != nil {
		return nil, err
	}
	observeGraphStoreDualWriteQueueStats(statsFromRecords(state.Records))
	return leases, nil
}

func (q *graphStoreDualWriteFileQueue) Ack(ctx context.Context, lease graphStoreDualWriteLeasedItem) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := context.Cause(ctx); err != nil {
		return err
	}
	q.mu.Lock()
	defer q.mu.Unlock()

	state, err := q.readStateLocked()
	if err != nil {
		return err
	}
	index := findGraphStoreDualWriteRecord(state.Records, lease)
	if index < 0 {
		return fmt.Errorf("graph dual-write reconciliation lease not found for ack")
	}
	state.Records = append(state.Records[:index], state.Records[index+1:]...)
	if err := q.writeStateLocked(state); err != nil {
		return err
	}
	metrics.RecordGraphDualWriteReconciliationEvent("acked")
	observeGraphStoreDualWriteQueueStats(statsFromRecords(state.Records))
	return nil
}

func (q *graphStoreDualWriteFileQueue) Retry(ctx context.Context, lease graphStoreDualWriteLeasedItem, replayErr error, retryable bool, maxAttempts int) (bool, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := context.Cause(ctx); err != nil {
		return false, err
	}
	if maxAttempts <= 0 {
		maxAttempts = defaultGraphStoreDualWriteMaxAttempts
	}
	q.mu.Lock()
	defer q.mu.Unlock()

	state, err := q.readStateLocked()
	if err != nil {
		return false, err
	}
	index := findGraphStoreDualWriteRecord(state.Records, lease)
	if index < 0 {
		return false, fmt.Errorf("graph dual-write reconciliation lease not found for retry")
	}
	now := time.Now().UTC()
	record := &state.Records[index]
	record.Item.RetryCount++
	record.Item.LastError = strings.TrimSpace(replayErr.Error())
	record.Item.Retryable = retryable
	record.LeaseOwner = ""
	record.LeaseToken = ""
	record.LeasedUntil = time.Time{}
	record.AvailableAt = now
	deadLettered := !retryable || record.Item.RetryCount >= maxAttempts
	if deadLettered {
		record.DeadLetteredAt = now
		record.DeadLetterReason = strings.TrimSpace(replayErr.Error())
		record.AvailableAt = time.Time{}
		metrics.RecordGraphDualWriteReconciliationEvent("dead_lettered")
	} else {
		metrics.RecordGraphDualWriteReconciliationEvent("retried")
	}
	if err := q.writeStateLocked(state); err != nil {
		return false, err
	}
	observeGraphStoreDualWriteQueueStats(statsFromRecords(state.Records))
	return deadLettered, nil
}

func (q *graphStoreDualWriteFileQueue) Stats(ctx context.Context) (graphStoreDualWriteQueueStats, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := context.Cause(ctx); err != nil {
		return graphStoreDualWriteQueueStats{}, err
	}
	q.mu.Lock()
	defer q.mu.Unlock()

	state, err := q.readStateLocked()
	if err != nil {
		return graphStoreDualWriteQueueStats{}, err
	}
	stats := statsFromRecords(state.Records)
	observeGraphStoreDualWriteQueueStats(stats)
	return stats, nil
}

func (q *graphStoreDualWriteFileQueue) DeadLetters(ctx context.Context, limit int) ([]graph.DualWriteReconciliationItem, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := context.Cause(ctx); err != nil {
		return nil, err
	}
	q.mu.Lock()
	defer q.mu.Unlock()

	state, err := q.readStateLocked()
	if err != nil {
		return nil, err
	}
	items := deadLettersFromRecords(state.Records, limit)
	return items, nil
}

func (q *graphStoreDualWriteFileQueue) Close() error {
	return nil
}

func (q *graphStoreDualWriteFileQueue) readStateLocked() (graphStoreDualWriteFileQueueState, error) {
	if q == nil || q.path == "" {
		return graphStoreDualWriteFileQueueState{}, fmt.Errorf("graph dual-write reconciliation queue path is required")
	}
	data, err := os.ReadFile(q.path) // #nosec G304 -- local operator-controlled path.
	if errors.Is(err, os.ErrNotExist) {
		return graphStoreDualWriteFileQueueState{}, nil
	}
	if err != nil {
		return graphStoreDualWriteFileQueueState{}, err
	}
	if len(data) == 0 {
		return graphStoreDualWriteFileQueueState{}, nil
	}
	var state graphStoreDualWriteFileQueueState
	if err := json.Unmarshal(data, &state); err == nil {
		if state.NextID == 0 {
			for _, record := range state.Records {
				if record.ID > state.NextID {
					state.NextID = record.ID
				}
			}
		}
		return state, nil
	}
	var legacy []graph.DualWriteReconciliationItem
	if err := json.Unmarshal(data, &legacy); err != nil {
		return graphStoreDualWriteFileQueueState{}, err
	}
	state.Records = make([]graphStoreDualWriteQueueRecord, 0, len(legacy))
	now := time.Now().UTC()
	for idx, item := range legacy {
		state.Records = append(state.Records, graphStoreDualWriteQueueRecord{
			ID:          int64(idx + 1),
			Item:        cloneDualWriteReconciliationItem(item),
			EnqueuedAt:  now,
			AvailableAt: now,
		})
	}
	state.NextID = int64(len(state.Records))
	return state, nil
}

func (q *graphStoreDualWriteFileQueue) writeStateLocked(state graphStoreDualWriteFileQueueState) error {
	if q == nil || q.path == "" {
		return fmt.Errorf("graph dual-write reconciliation queue path is required")
	}
	payload, err := json.Marshal(state)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(q.path), 0o750); err != nil {
		return err
	}
	tmpPath := q.path + ".tmp"
	if err := os.WriteFile(tmpPath, payload, 0o600); err != nil { // #nosec G304 -- local operator-controlled path.
		_ = os.Remove(tmpPath)
		return err
	}
	return os.Rename(tmpPath, q.path)
}

func releaseExpiredLeases(records []graphStoreDualWriteQueueRecord, now time.Time) {
	for i := range records {
		if records[i].LeasedUntil.IsZero() || records[i].LeasedUntil.After(now) {
			continue
		}
		records[i].LeaseOwner = ""
		records[i].LeaseToken = ""
		records[i].LeasedUntil = time.Time{}
	}
}

func findGraphStoreDualWriteRecord(records []graphStoreDualWriteQueueRecord, lease graphStoreDualWriteLeasedItem) int {
	for idx, record := range records {
		if record.ID != lease.QueueID {
			continue
		}
		if record.LeaseOwner != lease.LeaseOwner || record.LeaseToken != lease.LeaseToken {
			return -1
		}
		return idx
	}
	return -1
}

func statsFromRecords(records []graphStoreDualWriteQueueRecord) graphStoreDualWriteQueueStats {
	now := time.Now().UTC()
	stats := graphStoreDualWriteQueueStats{}
	for _, record := range records {
		switch {
		case !record.DeadLetteredAt.IsZero():
			stats.DeadLettered++
		case strings.TrimSpace(record.LeaseOwner) != "" && (record.LeasedUntil.IsZero() || record.LeasedUntil.After(now)):
			stats.Leased++
		default:
			stats.Pending++
			if stats.OldestPendingAt.IsZero() || (!record.AvailableAt.IsZero() && record.AvailableAt.Before(stats.OldestPendingAt)) {
				stats.OldestPendingAt = record.AvailableAt
			}
		}
	}
	return stats
}

func deadLettersFromRecords(records []graphStoreDualWriteQueueRecord, limit int) []graph.DualWriteReconciliationItem {
	out := make([]graph.DualWriteReconciliationItem, 0)
	for _, record := range records {
		if record.DeadLetteredAt.IsZero() {
			continue
		}
		out = append(out, cloneDualWriteReconciliationItem(record.Item))
		if limit > 0 && len(out) == limit {
			break
		}
	}
	return out
}

func observeGraphStoreDualWriteQueueStats(stats graphStoreDualWriteQueueStats) {
	metrics.SetGraphDualWriteReconciliationQueueDepths(stats.Pending, stats.Leased, stats.DeadLettered)
}

func cloneDualWriteReconciliationItem(item graph.DualWriteReconciliationItem) graph.DualWriteReconciliationItem {
	payload, err := json.Marshal(item)
	if err != nil {
		return item
	}
	var cloned graph.DualWriteReconciliationItem
	if err := json.Unmarshal(payload, &cloned); err != nil {
		return item
	}
	return cloned
}
