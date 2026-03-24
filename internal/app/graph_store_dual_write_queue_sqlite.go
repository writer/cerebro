package app

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/metrics"
)

type graphStoreDualWriteSQLiteQueue struct {
	path string
	db   *sql.DB

	postMutationObserveStats func(context.Context) error
}

func newGraphStoreDualWriteSQLiteQueue(path string) (*graphStoreDualWriteSQLiteQueue, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("graph dual-write reconciliation sqlite path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("create graph dual-write reconciliation sqlite directory: %w", err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open graph dual-write reconciliation sqlite: %w", err)
	}
	if err := initGraphStoreDualWriteSQLiteQueueSchema(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	queue := &graphStoreDualWriteSQLiteQueue{path: path, db: db}
	queue.postMutationObserveStats = queue.observeStats
	_ = queue.observeStats(context.Background())
	return queue, nil
}

func initGraphStoreDualWriteSQLiteQueueSchema(db *sql.DB) error {
	if db == nil {
		return fmt.Errorf("graph dual-write reconciliation sqlite db is nil")
	}
	_, err := db.ExecContext(context.Background(), `
		CREATE TABLE IF NOT EXISTS graph_dual_write_reconciliation_queue (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			payload_json TEXT NOT NULL,
			enqueued_at TEXT NOT NULL,
			available_at TEXT NOT NULL,
			lease_owner TEXT,
			lease_token TEXT,
			leased_until TEXT,
			dead_lettered_at TEXT,
			dead_letter_reason TEXT
		);
		CREATE INDEX IF NOT EXISTS idx_graph_dual_write_queue_available
			ON graph_dual_write_reconciliation_queue(dead_lettered_at, available_at, id);
		CREATE INDEX IF NOT EXISTS idx_graph_dual_write_queue_leased_until
			ON graph_dual_write_reconciliation_queue(dead_lettered_at, leased_until);
	`)
	if err != nil {
		return fmt.Errorf("initialize graph dual-write reconciliation sqlite schema: %w", err)
	}
	return nil
}

func (q *graphStoreDualWriteSQLiteQueue) Enqueue(ctx context.Context, item graph.DualWriteReconciliationItem) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := context.Cause(ctx); err != nil {
		return err
	}
	if q == nil || q.db == nil {
		return fmt.Errorf("graph dual-write reconciliation sqlite queue is nil")
	}
	now := time.Now().UTC()
	payload, err := json.Marshal(cloneDualWriteReconciliationItem(item))
	if err != nil {
		return fmt.Errorf("marshal graph dual-write reconciliation item: %w", err)
	}
	_, err = q.db.ExecContext(ctx, `
		INSERT INTO graph_dual_write_reconciliation_queue (payload_json, enqueued_at, available_at)
		VALUES (?, ?, ?)
	`, string(payload), now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
	if err != nil {
		return fmt.Errorf("insert graph dual-write reconciliation item: %w", err)
	}
	metrics.RecordGraphDualWriteReconciliationEvent("enqueued")
	return q.observeStats(ctx)
}

func (q *graphStoreDualWriteSQLiteQueue) Lease(ctx context.Context, owner string, limit int, leaseDuration time.Duration) ([]graphStoreDualWriteLeasedItem, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := context.Cause(ctx); err != nil {
		return nil, err
	}
	if q == nil || q.db == nil {
		return nil, fmt.Errorf("graph dual-write reconciliation sqlite queue is nil")
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

	now := time.Now().UTC()
	tx, err := q.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin graph dual-write lease tx: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	if _, err := tx.ExecContext(ctx, `
		UPDATE graph_dual_write_reconciliation_queue
		SET lease_owner = NULL, lease_token = NULL, leased_until = NULL
		WHERE dead_lettered_at IS NULL
		  AND leased_until IS NOT NULL
		  AND leased_until <= ?
	`, now.Format(time.RFC3339Nano)); err != nil {
		return nil, fmt.Errorf("release expired graph dual-write leases: %w", err)
	}

	rows, err := tx.QueryContext(ctx, `
		SELECT id, payload_json
		FROM graph_dual_write_reconciliation_queue
		WHERE dead_lettered_at IS NULL
		  AND available_at <= ?
		  AND lease_owner IS NULL
		ORDER BY available_at ASC, id ASC
		LIMIT ?
	`, now.Format(time.RFC3339Nano), limit)
	if err != nil {
		return nil, fmt.Errorf("query graph dual-write lease candidates: %w", err)
	}
	defer func() { _ = rows.Close() }()

	leases := make([]graphStoreDualWriteLeasedItem, 0, limit)
	for rows.Next() {
		var (
			id      int64
			payload string
		)
		if err := rows.Scan(&id, &payload); err != nil {
			return nil, fmt.Errorf("scan graph dual-write lease candidate: %w", err)
		}
		var item graph.DualWriteReconciliationItem
		if err := json.Unmarshal([]byte(payload), &item); err != nil {
			return nil, fmt.Errorf("decode graph dual-write lease payload: %w", err)
		}
		token := fmt.Sprintf("%s-%d-%d", owner, id, now.UnixNano())
		result, err := tx.ExecContext(ctx, `
			UPDATE graph_dual_write_reconciliation_queue
			SET lease_owner = ?, lease_token = ?, leased_until = ?
			WHERE id = ? AND dead_lettered_at IS NULL AND lease_owner IS NULL
		`, owner, token, now.Add(leaseDuration).Format(time.RFC3339Nano), id)
		if err != nil {
			return nil, fmt.Errorf("claim graph dual-write lease: %w", err)
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return nil, fmt.Errorf("rows affected for graph dual-write lease: %w", err)
		}
		if affected == 0 {
			continue
		}
		leases = append(leases, graphStoreDualWriteLeasedItem{
			QueueID:    id,
			LeaseOwner: owner,
			LeaseToken: token,
			Item:       cloneDualWriteReconciliationItem(item),
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate graph dual-write lease candidates: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit graph dual-write lease tx: %w", err)
	}
	q.observePostMutationStats(ctx)
	return leases, nil
}

func (q *graphStoreDualWriteSQLiteQueue) Ack(ctx context.Context, lease graphStoreDualWriteLeasedItem) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := context.Cause(ctx); err != nil {
		return err
	}
	if q == nil || q.db == nil {
		return fmt.Errorf("graph dual-write reconciliation sqlite queue is nil")
	}
	result, err := q.db.ExecContext(ctx, `
		DELETE FROM graph_dual_write_reconciliation_queue
		WHERE id = ? AND lease_owner = ? AND lease_token = ?
	`, lease.QueueID, lease.LeaseOwner, lease.LeaseToken)
	if err != nil {
		return fmt.Errorf("ack graph dual-write reconciliation item: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected for graph dual-write ack: %w", err)
	}
	if affected == 0 {
		return fmt.Errorf("graph dual-write reconciliation lease not found for ack")
	}
	metrics.RecordGraphDualWriteReconciliationEvent("acked")
	q.observePostMutationStats(ctx)
	return nil
}

func (q *graphStoreDualWriteSQLiteQueue) Retry(ctx context.Context, lease graphStoreDualWriteLeasedItem, replayErr error, retryable bool, maxAttempts int) (bool, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := context.Cause(ctx); err != nil {
		return false, err
	}
	if q == nil || q.db == nil {
		return false, fmt.Errorf("graph dual-write reconciliation sqlite queue is nil")
	}
	if maxAttempts <= 0 {
		maxAttempts = defaultGraphStoreDualWriteMaxAttempts
	}
	now := time.Now().UTC()
	item := cloneDualWriteReconciliationItem(lease.Item)
	item.RetryCount++
	item.LastError = strings.TrimSpace(replayErr.Error())
	item.Retryable = retryable
	payload, err := json.Marshal(item)
	if err != nil {
		return false, fmt.Errorf("marshal graph dual-write retry item: %w", err)
	}

	deadLettered := !retryable || item.RetryCount >= maxAttempts
	var result sql.Result
	if deadLettered {
		result, err = q.db.ExecContext(ctx, `
			UPDATE graph_dual_write_reconciliation_queue
			SET payload_json = ?,
				lease_owner = NULL,
				lease_token = NULL,
				leased_until = NULL,
				available_at = ?,
				dead_lettered_at = ?,
				dead_letter_reason = ?
			WHERE id = ? AND lease_owner = ? AND lease_token = ?
		`, string(payload), now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano), strings.TrimSpace(replayErr.Error()), lease.QueueID, lease.LeaseOwner, lease.LeaseToken)
	} else {
		result, err = q.db.ExecContext(ctx, `
			UPDATE graph_dual_write_reconciliation_queue
			SET payload_json = ?,
				lease_owner = NULL,
				lease_token = NULL,
				leased_until = NULL,
				available_at = ?,
				dead_lettered_at = NULL,
				dead_letter_reason = NULL
			WHERE id = ? AND lease_owner = ? AND lease_token = ?
		`, string(payload), now.Format(time.RFC3339Nano), lease.QueueID, lease.LeaseOwner, lease.LeaseToken)
	}
	if err != nil {
		return false, fmt.Errorf("update graph dual-write retry state: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("rows affected for graph dual-write retry: %w", err)
	}
	if affected == 0 {
		return false, fmt.Errorf("graph dual-write reconciliation lease not found for retry")
	}
	if deadLettered {
		metrics.RecordGraphDualWriteReconciliationEvent("dead_lettered")
	} else {
		metrics.RecordGraphDualWriteReconciliationEvent("retried")
	}
	q.observePostMutationStats(ctx)
	return deadLettered, nil
}

func (q *graphStoreDualWriteSQLiteQueue) Stats(ctx context.Context) (graphStoreDualWriteQueueStats, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := context.Cause(ctx); err != nil {
		return graphStoreDualWriteQueueStats{}, err
	}
	if q == nil || q.db == nil {
		return graphStoreDualWriteQueueStats{}, fmt.Errorf("graph dual-write reconciliation sqlite queue is nil")
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	stats := graphStoreDualWriteQueueStats{}
	rows, err := q.db.QueryContext(ctx, `
		SELECT
			SUM(CASE
				WHEN dead_lettered_at IS NULL
				 AND (lease_owner IS NULL OR (leased_until IS NOT NULL AND leased_until <= ?))
				THEN 1 ELSE 0
			END) AS pending,
			SUM(CASE
				WHEN dead_lettered_at IS NULL
				 AND lease_owner IS NOT NULL
				 AND (leased_until IS NULL OR leased_until > ?)
				THEN 1 ELSE 0
			END) AS leased,
			SUM(CASE WHEN dead_lettered_at IS NOT NULL THEN 1 ELSE 0 END) AS dead_lettered,
			MIN(CASE
				WHEN dead_lettered_at IS NULL
				 AND (lease_owner IS NULL OR (leased_until IS NOT NULL AND leased_until <= ?))
				THEN available_at ELSE NULL
			END) AS oldest_pending_at
		FROM graph_dual_write_reconciliation_queue
	`, now, now, now)
	if err != nil {
		return graphStoreDualWriteQueueStats{}, fmt.Errorf("query graph dual-write reconciliation stats: %w", err)
	}
	defer func() { _ = rows.Close() }()
	if rows.Next() {
		var (
			pending      sql.NullInt64
			leased       sql.NullInt64
			deadLettered sql.NullInt64
			oldest       sql.NullString
		)
		if err := rows.Scan(&pending, &leased, &deadLettered, &oldest); err != nil {
			return graphStoreDualWriteQueueStats{}, fmt.Errorf("scan graph dual-write reconciliation stats: %w", err)
		}
		stats.Pending = int(pending.Int64)
		stats.Leased = int(leased.Int64)
		stats.DeadLettered = int(deadLettered.Int64)
		if oldest.Valid && strings.TrimSpace(oldest.String) != "" {
			if parsed, err := time.Parse(time.RFC3339Nano, oldest.String); err == nil {
				stats.OldestPendingAt = parsed.UTC()
			}
		}
	}
	if err := rows.Err(); err != nil {
		return graphStoreDualWriteQueueStats{}, fmt.Errorf("iterate graph dual-write reconciliation stats: %w", err)
	}
	observeGraphStoreDualWriteQueueStats(stats)
	return stats, nil
}

func (q *graphStoreDualWriteSQLiteQueue) DeadLetters(ctx context.Context, limit int) ([]graph.DualWriteReconciliationItem, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := context.Cause(ctx); err != nil {
		return nil, err
	}
	if q == nil || q.db == nil {
		return nil, fmt.Errorf("graph dual-write reconciliation sqlite queue is nil")
	}
	if limit <= 0 {
		limit = 100
	}
	rows, err := q.db.QueryContext(ctx, `
		SELECT payload_json
		FROM graph_dual_write_reconciliation_queue
		WHERE dead_lettered_at IS NOT NULL
		ORDER BY dead_lettered_at ASC, id ASC
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, fmt.Errorf("query graph dual-write dead letters: %w", err)
	}
	defer func() { _ = rows.Close() }()
	items := make([]graph.DualWriteReconciliationItem, 0, limit)
	for rows.Next() {
		var payload string
		if err := rows.Scan(&payload); err != nil {
			return nil, fmt.Errorf("scan graph dual-write dead letter: %w", err)
		}
		var item graph.DualWriteReconciliationItem
		if err := json.Unmarshal([]byte(payload), &item); err != nil {
			return nil, fmt.Errorf("decode graph dual-write dead letter: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate graph dual-write dead letters: %w", err)
	}
	return items, nil
}

func (q *graphStoreDualWriteSQLiteQueue) Close() error {
	if q == nil || q.db == nil {
		return nil
	}
	return q.db.Close()
}

func (q *graphStoreDualWriteSQLiteQueue) observeStats(ctx context.Context) error {
	_, err := q.Stats(ctx)
	return err
}

func (q *graphStoreDualWriteSQLiteQueue) observePostMutationStats(ctx context.Context) {
	if q == nil {
		return
	}
	observer := q.postMutationObserveStats
	if observer == nil {
		observer = q.observeStats
	}
	_ = observer(ctx)
}
