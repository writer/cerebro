package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/writer/cerebro/internal/ports"
)

// appendLogRuntimeIndexer names the single watermark row tracking how far the
// per-runtime append-log replay index has been populated.
const appendLogRuntimeIndexer = "append_log_runtime_index"

var ensureAppendLogRuntimeIndexStatements = []string{
	`CREATE TABLE IF NOT EXISTS append_log_runtime_index (
  runtime_id TEXT NOT NULL,
  seq BIGINT NOT NULL,
  tenant_id TEXT NOT NULL DEFAULT '',
  kind TEXT NOT NULL DEFAULT '',
  occurred_at TIMESTAMPTZ,
  PRIMARY KEY (runtime_id, seq)
)`,
	`CREATE INDEX IF NOT EXISTS append_log_runtime_index_runtime_observed_idx ON append_log_runtime_index (runtime_id, occurred_at DESC NULLS LAST, seq DESC)`,
	`CREATE INDEX IF NOT EXISTS append_log_runtime_index_runtime_kind_observed_idx ON append_log_runtime_index (runtime_id, kind, occurred_at DESC NULLS LAST, seq DESC)`,
	`CREATE TABLE IF NOT EXISTS append_log_index_state (
  indexer TEXT PRIMARY KEY,
  last_seq BIGINT NOT NULL DEFAULT 0,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`,
}

// PutRuntimeIndexEntries upserts per-runtime replay index entries and advances
// the population watermark to at least the supplied value, atomically.
func (s *Store) PutRuntimeIndexEntries(ctx context.Context, entries []ports.RuntimeIndexEntry, watermark uint64) error {
	if s == nil || s.db == nil {
		return errors.New("postgres is not configured")
	}
	if err := s.ensureAppendLogRuntimeIndexTable(ctx); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin append log runtime index batch: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()
	for _, entry := range entries {
		runtimeID := strings.TrimSpace(entry.RuntimeID)
		if runtimeID == "" {
			continue
		}
		var occurredAt any
		if !entry.OccurredAt.IsZero() {
			occurredAt = entry.OccurredAt.UTC()
		}
		if _, err := tx.ExecContext(ctx, `
INSERT INTO append_log_runtime_index (runtime_id, seq, tenant_id, kind, occurred_at)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (runtime_id, seq)
DO UPDATE SET tenant_id = EXCLUDED.tenant_id, kind = EXCLUDED.kind, occurred_at = EXCLUDED.occurred_at`,
			runtimeID, boundedInt64(entry.Seq), strings.TrimSpace(entry.TenantID), strings.TrimSpace(entry.Kind), occurredAt); err != nil {
			return fmt.Errorf("upsert append log runtime index entry %q:%d: %w", runtimeID, entry.Seq, err)
		}
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO append_log_index_state (indexer, last_seq, updated_at)
VALUES ($1, $2, NOW())
ON CONFLICT (indexer)
DO UPDATE SET last_seq = GREATEST(append_log_index_state.last_seq, EXCLUDED.last_seq), updated_at = NOW()`,
		appendLogRuntimeIndexer, boundedInt64(watermark)); err != nil {
		return fmt.Errorf("advance append log runtime index watermark: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit append log runtime index batch: %w", err)
	}
	return nil
}

// RuntimeIndexWatermark reports the highest stream sequence indexed so far.
func (s *Store) RuntimeIndexWatermark(ctx context.Context) (uint64, error) {
	if s == nil || s.db == nil {
		return 0, errors.New("postgres is not configured")
	}
	if err := s.ensureAppendLogRuntimeIndexTable(ctx); err != nil {
		return 0, err
	}
	var lastSeq int64
	err := s.db.QueryRowContext(ctx, `SELECT last_seq FROM append_log_index_state WHERE indexer = $1`, appendLogRuntimeIndexer).Scan(&lastSeq)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("query append log runtime index watermark: %w", err)
	}
	if lastSeq < 0 {
		return 0, nil
	}
	return uint64(lastSeq), nil
}

// LookupRuntimeReplay returns the newest-observed indexed stream sequences for one
// runtime, optionally narrowed to exact event kinds, along with the watermark.
func (s *Store) LookupRuntimeReplay(ctx context.Context, query ports.RuntimeIndexQuery) (ports.RuntimeIndexResult, error) {
	runtimeID := strings.TrimSpace(query.RuntimeID)
	if runtimeID == "" {
		return ports.RuntimeIndexResult{}, errors.New("runtime id is required")
	}
	if s == nil || s.db == nil {
		return ports.RuntimeIndexResult{}, errors.New("postgres is not configured")
	}
	if err := s.ensureAppendLogRuntimeIndexTable(ctx); err != nil {
		return ports.RuntimeIndexResult{}, err
	}
	watermark, err := s.RuntimeIndexWatermark(ctx)
	if err != nil {
		return ports.RuntimeIndexResult{}, err
	}
	result := ports.RuntimeIndexResult{Watermark: watermark, Available: watermark > 0}
	if !result.Available || query.Limit == 0 {
		return result, nil
	}
	statement, args := runtimeReplayIndexQuery(runtimeID, query.Kinds, watermark, query.Limit)
	rows, err := s.db.QueryContext(ctx, statement, args...)
	if err != nil {
		return ports.RuntimeIndexResult{}, fmt.Errorf("query append log runtime index %q: %w", runtimeID, err)
	}
	defer func() {
		_ = rows.Close()
	}()
	for rows.Next() {
		var seq int64
		if err := rows.Scan(&seq); err != nil {
			return ports.RuntimeIndexResult{}, fmt.Errorf("scan append log runtime index sequence: %w", err)
		}
		if seq > 0 {
			result.Sequences = append(result.Sequences, uint64(seq))
		}
	}
	if err := rows.Err(); err != nil {
		return ports.RuntimeIndexResult{}, fmt.Errorf("iterate append log runtime index %q: %w", runtimeID, err)
	}
	return result, nil
}

// runtimeReplayIndexQuery builds the newest-observed-first sequence lookup, bounding by
// the watermark and (optionally) exact event kinds. Values stay parameterized.
func runtimeReplayIndexQuery(runtimeID string, kinds []string, watermark uint64, limit uint32) (string, []any) {
	args := []any{runtimeID, boundedInt64(watermark)}
	var builder strings.Builder
	builder.WriteString("SELECT seq FROM append_log_runtime_index WHERE runtime_id = $1 AND seq <= $2")
	normalizedKinds := normalizedNonEmptyStrings(kinds)
	if len(normalizedKinds) > 0 {
		placeholders := make([]string, 0, len(normalizedKinds))
		for _, kind := range normalizedKinds {
			args = append(args, kind)
			placeholders = append(placeholders, "$"+strconv.Itoa(len(args)))
		}
		builder.WriteString(" AND kind IN (")
		builder.WriteString(strings.Join(placeholders, ", "))
		builder.WriteString(")")
	}
	args = append(args, boundedInt64(uint64(limit)))
	builder.WriteString(" ORDER BY occurred_at DESC NULLS LAST, seq DESC LIMIT $")
	builder.WriteString(strconv.Itoa(len(args)))
	return builder.String(), args
}

func boundedInt64(value uint64) int64 {
	if value > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(value) // #nosec G115 -- bounded above by the MaxInt64 check.
}

func (s *Store) ensureAppendLogRuntimeIndexTable(ctx context.Context) error {
	return s.ensureStatements(ctx, &s.appendLogRuntimeIndexReady, "append log runtime index", ensureAppendLogRuntimeIndexStatements)
}
