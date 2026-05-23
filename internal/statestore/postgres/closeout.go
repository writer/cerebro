package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/writer/cerebro/internal/ports"
)

// InsertCloseoutRun starts one closeout_run row with status='running'.
// A concurrent running row is rejected by the singleton partial unique index
// (closeout_run_singleton_running_idx) and surfaces as ports.ErrCloseoutRunInFlight.
// A duplicate run_id (primary key) surfaces as ports.ErrCloseoutRunAlreadyExists.
func (s *Store) InsertCloseoutRun(ctx context.Context, run ports.CloseoutRunInsert) error {
	if s == nil || s.db == nil {
		return errors.New("postgres is not configured")
	}
	if err := s.ensureFindingTables(ctx); err != nil {
		return err
	}
	runID := strings.TrimSpace(run.RunID)
	if runID == "" {
		return errors.New("closeout run id is required")
	}
	actor := strings.TrimSpace(run.Actor)
	if actor == "" {
		return errors.New("closeout actor is required")
	}
	selectorJSON := run.SelectorJSON
	if len(selectorJSON) == 0 {
		selectorJSON = []byte(`{}`)
	}
	startedAt := run.StartedAt.UTC()
	if startedAt.IsZero() {
		startedAt = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx, `
        INSERT INTO closeout_run (run_id, actor, change_ticket, selector_json, status, started_at, dry_run, proposed_count, applied_count, error_message, s3_summary_key)
        VALUES ($1, $2, $3, $4::jsonb, 'running', $5, $6, 0, 0, '', '')`,
		runID,
		actor,
		strings.TrimSpace(run.ChangeTicket),
		string(selectorJSON),
		startedAt,
		run.DryRun,
	)
	if err == nil {
		return nil
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		if strings.Contains(pgErr.ConstraintName, "closeout_run_singleton_running_idx") ||
			strings.Contains(pgErr.Message, "closeout_run_singleton_running_idx") {
			return ports.ErrCloseoutRunInFlight
		}
		if strings.Contains(pgErr.ConstraintName, "closeout_run_pkey") ||
			strings.Contains(pgErr.Message, "closeout_run_pkey") {
			return ports.ErrCloseoutRunAlreadyExists
		}
	}
	return fmt.Errorf("insert closeout_run %q: %w", runID, err)
}

// FinishCloseoutRun marks one closeout_run row as completed (succeeded|failed).
func (s *Store) FinishCloseoutRun(ctx context.Context, finish ports.CloseoutRunFinish) error {
	if s == nil || s.db == nil {
		return errors.New("postgres is not configured")
	}
	if err := s.ensureFindingTables(ctx); err != nil {
		return err
	}
	runID := strings.TrimSpace(finish.RunID)
	if runID == "" {
		return errors.New("closeout run id is required")
	}
	status := strings.TrimSpace(finish.Status)
	if status != "succeeded" && status != "failed" {
		return fmt.Errorf("invalid closeout finish status %q", status)
	}
	finishedAt := finish.FinishedAt.UTC()
	if finishedAt.IsZero() {
		finishedAt = time.Now().UTC()
	}
	result, err := s.db.ExecContext(ctx, `
        UPDATE closeout_run
        SET status = $2,
            finished_at = $3,
            proposed_count = $4,
            applied_count = $5,
            error_message = $6,
            s3_summary_key = CASE WHEN $7 = '' THEN s3_summary_key ELSE $7 END
        WHERE run_id = $1`,
		runID,
		status,
		finishedAt,
		finish.ProposedCount,
		finish.AppliedCount,
		strings.TrimSpace(finish.ErrorMessage),
		strings.TrimSpace(finish.S3SummaryKey),
	)
	if err != nil {
		return fmt.Errorf("update closeout_run %q: %w", runID, err)
	}
	affected, err := result.RowsAffected()
	if err == nil && affected == 0 {
		return fmt.Errorf("closeout_run %q not found", runID)
	}
	return nil
}

// GetCloseoutRun loads one closeout_run row by run_id.
func (s *Store) GetCloseoutRun(ctx context.Context, runID string) (*ports.CloseoutRunRecord, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureFindingTables(ctx); err != nil {
		return nil, err
	}
	id := strings.TrimSpace(runID)
	if id == "" {
		return nil, errors.New("closeout run id is required")
	}
	var rec ports.CloseoutRunRecord
	var selectorJSON string
	var finishedAt sql.NullTime
	err := s.db.QueryRowContext(ctx, `
        SELECT run_id, actor, change_ticket, selector_json::text, status,
               started_at, finished_at, dry_run, proposed_count, applied_count,
               error_message, s3_summary_key
        FROM closeout_run
        WHERE run_id = $1`, id,
	).Scan(
		&rec.RunID,
		&rec.Actor,
		&rec.ChangeTicket,
		&selectorJSON,
		&rec.Status,
		&rec.StartedAt,
		&finishedAt,
		&rec.DryRun,
		&rec.ProposedCount,
		&rec.AppliedCount,
		&rec.ErrorMessage,
		&rec.S3SummaryKey,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("closeout_run %q not found", id)
		}
		return nil, fmt.Errorf("query closeout_run %q: %w", id, err)
	}
	rec.SelectorJSON = []byte(selectorJSON)
	if finishedAt.Valid {
		rec.FinishedAt = finishedAt.Time.UTC()
	}
	rec.StartedAt = rec.StartedAt.UTC()
	return &rec, nil
}

// InsertFindingTombstoneEvent appends one audit row to finding_tombstone_events.
func (s *Store) InsertFindingTombstoneEvent(ctx context.Context, event ports.FindingTombstoneEvent) error {
	if s == nil || s.db == nil {
		return errors.New("postgres is not configured")
	}
	if err := s.ensureFindingTables(ctx); err != nil {
		return err
	}
	findingID := strings.TrimSpace(event.FindingID)
	if findingID == "" {
		return errors.New("finding id is required")
	}
	tombstonedAt := event.TombstonedAt.UTC()
	if tombstonedAt.IsZero() {
		tombstonedAt = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx, `
        INSERT INTO finding_tombstone_events (finding_id, tenant_id, rule_id, anchor_uri, prior_status, reason, actor, run_id, tombstoned_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		findingID,
		strings.TrimSpace(event.TenantID),
		strings.TrimSpace(event.RuleID),
		strings.TrimSpace(event.AnchorURI),
		strings.TrimSpace(event.PriorStatus),
		strings.TrimSpace(event.Reason),
		strings.TrimSpace(event.Actor),
		strings.TrimSpace(event.RunID),
		tombstonedAt,
	)
	if err != nil {
		return fmt.Errorf("insert finding_tombstone_event for %q: %w", findingID, err)
	}
	return nil
}

// BreakStaleRunningCloseoutRuns flips any closeout_run rows still marked
// status='running' with started_at < cutoff to status='failed', records the
// supplied error_message, and sets finished_at=now(). Returns the number of
// rows updated. Used by the bulk tombstone primitive to recover from operator
// crashes without manual intervention (CROSS-008 stale-lock break).
func (s *Store) BreakStaleRunningCloseoutRuns(ctx context.Context, cutoff time.Time, errMessage string) (int, error) {
	if s == nil || s.db == nil {
		return 0, errors.New("postgres is not configured")
	}
	if err := s.ensureFindingTables(ctx); err != nil {
		return 0, err
	}
	if cutoff.IsZero() {
		return 0, nil
	}
	result, err := s.db.ExecContext(ctx, `
        UPDATE closeout_run
        SET status = 'failed',
            finished_at = now(),
            error_message = CASE WHEN $2 = '' THEN error_message ELSE $2 END
        WHERE status = 'running' AND started_at < $1`,
		cutoff.UTC(),
		strings.TrimSpace(errMessage),
	)
	if err != nil {
		return 0, fmt.Errorf("break stale closeout_run rows: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("break stale closeout_run rows rowsAffected: %w", err)
	}
	return int(affected), nil
}

// UpdateCloseoutRunSummary records the S3 audit summary key on a closeout_run
// row that has already been finished, or flips the row to status='failed' when
// summaryErr is non-nil so the missing S3 object stays correlatable with the
// run record. The committed tombstones are unaffected.
func (s *Store) UpdateCloseoutRunSummary(ctx context.Context, runID, summaryKey string, summaryErr error) error {
	if s == nil || s.db == nil {
		return errors.New("postgres is not configured")
	}
	if err := s.ensureFindingTables(ctx); err != nil {
		return err
	}
	id := strings.TrimSpace(runID)
	if id == "" {
		return errors.New("closeout run id is required")
	}
	if summaryErr != nil {
		result, err := s.db.ExecContext(ctx, `
            UPDATE closeout_run
            SET status = 'failed',
                finished_at = now(),
                error_message = $2
            WHERE run_id = $1`,
			id,
			summaryErr.Error(),
		)
		if err != nil {
			return fmt.Errorf("mark closeout_run %q failed on summary error: %w", id, err)
		}
		affected, _ := result.RowsAffected()
		if affected == 0 {
			return fmt.Errorf("closeout_run %q not found", id)
		}
		return nil
	}
	result, err := s.db.ExecContext(ctx, `
        UPDATE closeout_run
        SET s3_summary_key = CASE WHEN $2 = '' THEN s3_summary_key ELSE $2 END
        WHERE run_id = $1`,
		id,
		strings.TrimSpace(summaryKey),
	)
	if err != nil {
		return fmt.Errorf("update closeout_run %q summary key: %w", id, err)
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		return fmt.Errorf("closeout_run %q not found", id)
	}
	return nil
}

// CountFindingTombstoneEventsByRun counts audit rows for a given run_id.
func (s *Store) CountFindingTombstoneEventsByRun(ctx context.Context, runID string) (int, error) {
	if s == nil || s.db == nil {
		return 0, errors.New("postgres is not configured")
	}
	if err := s.ensureFindingTables(ctx); err != nil {
		return 0, err
	}
	id := strings.TrimSpace(runID)
	if id == "" {
		return 0, errors.New("closeout run id is required")
	}
	var count int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM finding_tombstone_events WHERE run_id = $1`, id,
	).Scan(&count); err != nil {
		return 0, fmt.Errorf("count finding_tombstone_events for run %q: %w", id, err)
	}
	return count, nil
}
