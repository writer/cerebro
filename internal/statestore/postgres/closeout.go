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
	heartbeatAt := run.HeartbeatAt.UTC()
	if heartbeatAt.IsZero() {
		heartbeatAt = startedAt
	}
	_, err := s.db.ExecContext(ctx, `
        INSERT INTO closeout_run (run_id, actor, change_ticket, selector_json, status, started_at, heartbeat_at, dry_run, proposed_count, applied_count, error_message, s3_summary_key)
        VALUES ($1, $2, $3, $4::jsonb, 'running', $5, $6, $7, 0, 0, '', '')`,
		runID,
		actor,
		strings.TrimSpace(run.ChangeTicket),
		string(selectorJSON),
		startedAt,
		heartbeatAt,
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

// RetryFailedCloseoutRun re-acquires the singleton-running closeout lock for a
// previously failed run_id before retrying its remaining work.
func (s *Store) RetryFailedCloseoutRun(ctx context.Context, runID string, heartbeatAt time.Time) error {
	if s == nil || s.db == nil {
		return errors.New("postgres is not configured")
	}
	if err := s.ensureFindingTables(ctx); err != nil {
		return err
	}
	runID = strings.TrimSpace(runID)
	if runID == "" {
		return errors.New("closeout run id is required")
	}
	heartbeatAt = heartbeatAt.UTC()
	if heartbeatAt.IsZero() {
		heartbeatAt = time.Now().UTC()
	}
	result, err := s.db.ExecContext(ctx, `
        UPDATE closeout_run
        SET status = 'running',
            heartbeat_at = $2,
            finished_at = NULL,
            error_message = ''
        WHERE run_id = $1 AND status = 'failed'`,
		runID,
		heartbeatAt,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" &&
			(strings.Contains(pgErr.ConstraintName, "closeout_run_singleton_running_idx") ||
				strings.Contains(pgErr.Message, "closeout_run_singleton_running_idx")) {
			return ports.ErrCloseoutRunInFlight
		}
		return fmt.Errorf("retry closeout_run %q: %w", runID, err)
	}
	affected, err := result.RowsAffected()
	if err == nil && affected == 0 {
		return ports.ErrCloseoutRunAlreadyExists
	}
	return nil
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
               started_at, heartbeat_at, finished_at, dry_run, proposed_count, applied_count,
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
		&rec.HeartbeatAt,
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
	rec.HeartbeatAt = rec.HeartbeatAt.UTC()
	return &rec, nil
}

// RefreshCloseoutRunHeartbeat records recent activity for a running closeout
// run. It is intentionally a no-op for already-finished rows so a late ticker
// cannot mutate completed audit records.
func (s *Store) RefreshCloseoutRunHeartbeat(ctx context.Context, runID string, heartbeatAt time.Time) error {
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
	refreshedAt := heartbeatAt.UTC()
	if refreshedAt.IsZero() {
		refreshedAt = time.Now().UTC()
	}
	if _, err := s.db.ExecContext(ctx, `
        UPDATE closeout_run
        SET heartbeat_at = $2
        WHERE run_id = $1 AND status = 'running'`,
		id,
		refreshedAt,
	); err != nil {
		return fmt.Errorf("refresh closeout_run %q heartbeat: %w", id, err)
	}
	return nil
}

// InsertFindingTombstoneEvent appends one audit row to finding_tombstone_events.
func (s *Store) InsertFindingTombstoneEvent(ctx context.Context, event ports.FindingTombstoneEvent) error {
	if s == nil || s.db == nil {
		return errors.New("postgres is not configured")
	}
	if err := s.ensureFindingTables(ctx); err != nil {
		return err
	}
	return insertFindingTombstoneEvent(ctx, s.db, event)
}

// TombstoneFindingAtomic tombstones one finding row, appends its audit record,
// commits that Postgres transaction, and only then emits the external workflow
// tombstone event. The live finding row is re-read under SELECT FOR UPDATE so a
// status change that lands after candidate listing is honored instead of
// recording a stale prior_status snapshot.
func (s *Store) TombstoneFindingAtomic(ctx context.Context, request ports.FindingTombstoneAtomicRequest) (_ *ports.FindingTombstoneAtomicResult, err error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureFindingTables(ctx); err != nil {
		return nil, err
	}
	findingID := strings.TrimSpace(request.FindingID)
	if findingID == "" {
		return nil, errors.New("finding id is required")
	}
	status := strings.TrimSpace(request.Status)
	if status == "" {
		return nil, errors.New("finding status is required")
	}
	reason := strings.TrimSpace(request.Reason)
	actor := strings.TrimSpace(request.Actor)
	runID := strings.TrimSpace(request.RunID)
	if reason == "" {
		return nil, errors.New("tombstone reason is required")
	}
	if actor == "" {
		return nil, errors.New("tombstone actor is required")
	}
	if runID == "" {
		return nil, errors.New("tombstone run id is required")
	}
	updatedAt := request.UpdatedAt.UTC()
	if updatedAt.IsZero() {
		updatedAt = time.Now().UTC()
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin finding tombstone transaction for %q: %w", findingID, err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	var currentRow findingRow
	if err := scanFindingRow(tx.QueryRowContext(ctx, `
SELECT `+findingSelectColumns+`
FROM findings
WHERE id = $1
FOR UPDATE`,
		findingID,
	), &currentRow); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ports.ErrFindingNotFound
		}
		return nil, fmt.Errorf("lock finding %q before tombstone: %w", findingID, err)
	}
	current, err := currentRow.record()
	if err != nil {
		return nil, fmt.Errorf("decode locked finding %q: %w", findingID, err)
	}
	priorStatus := strings.TrimSpace(current.Status)
	if priorStatus == "" {
		priorStatus = "open"
	}
	expectedStatus := strings.TrimSpace(request.ExpectedStatus)
	if current.Tombstoned || (expectedStatus != "" && priorStatus != expectedStatus) {
		return &ports.FindingTombstoneAtomicResult{
			Finding:       current,
			Applied:       false,
			StatusChanged: expectedStatus != "" && priorStatus != expectedStatus,
			PriorStatus:   priorStatus,
		}, nil
	}

	tombstonedAt := updatedAt
	updated, err := tombstoneFindingStatusInTx(ctx, tx, ports.FindingStatusUpdate{
		FindingID: findingID,
		Status:    status,
		Reason:    reason,
		UpdatedAt: updatedAt,
		EventIDs:  append([]string(nil), request.EventIDs...),
		Tombstone: &ports.FindingTombstoneApply{
			By:           actor,
			Reason:       reason,
			RunID:        runID,
			PriorStatus:  priorStatus,
			TombstonedAt: tombstonedAt,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("update finding %q tombstone status: %w", findingID, err)
	}
	sourceSeverity := strings.TrimSpace(updated.Attributes["source_severity"])
	if sourceSeverity == "" {
		sourceSeverity = strings.TrimSpace(updated.Attributes["rule_severity"])
	}
	if sourceSeverity == "" {
		sourceSeverity = strings.TrimSpace(updated.Severity)
	}
	risk := findingBackfillRisk(updated, updatedAt)
	updated, err = updateFindingRiskInTx(ctx, tx, strings.TrimSpace(updated.ID), risk, findingRiskAttributesForUpdate(risk, sourceSeverity))
	if err != nil {
		return nil, fmt.Errorf("update finding %q tombstone risk: %w", findingID, err)
	}
	if err := insertFindingTombstoneEvent(ctx, tx, ports.FindingTombstoneEvent{
		FindingID:    findingID,
		TenantID:     strings.TrimSpace(updated.TenantID),
		RuleID:       strings.TrimSpace(updated.RuleID),
		AnchorURI:    strings.TrimSpace(request.AnchorURI),
		PriorStatus:  priorStatus,
		Reason:       reason,
		Actor:        actor,
		RunID:        runID,
		TombstonedAt: tombstonedAt,
	}); err != nil {
		return nil, fmt.Errorf("audit finding %q tombstone: %w", findingID, err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit finding %q tombstone transaction: %w", findingID, err)
	}
	committed = true
	result := &ports.FindingTombstoneAtomicResult{
		Finding:      updated,
		Applied:      true,
		PriorStatus:  priorStatus,
		TombstonedAt: tombstonedAt,
	}
	if request.EmitWorkflowEvent != nil {
		if err := request.EmitWorkflowEvent(ctx, updated, priorStatus, tombstonedAt); err != nil {
			return result, fmt.Errorf("emit finding %q tombstone workflow after commit: %w", findingID, err)
		}
	}
	return result, nil
}

type closeoutExecer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func insertFindingTombstoneEvent(ctx context.Context, execer closeoutExecer, event ports.FindingTombstoneEvent) error {
	findingID := strings.TrimSpace(event.FindingID)
	if findingID == "" {
		return errors.New("finding id is required")
	}
	tombstonedAt := event.TombstonedAt.UTC()
	if tombstonedAt.IsZero() {
		tombstonedAt = time.Now().UTC()
	}
	_, err := execer.ExecContext(ctx, `
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

func tombstoneFindingStatusInTx(ctx context.Context, tx *sql.Tx, request ports.FindingStatusUpdate) (*ports.FindingRecord, error) {
	findingID := strings.TrimSpace(request.FindingID)
	if findingID == "" {
		return nil, errors.New("finding id is required")
	}
	status := strings.TrimSpace(request.Status)
	if status == "" {
		return nil, errors.New("finding status is required")
	}
	statusReason := strings.TrimSpace(request.Reason)
	updatedAt := request.UpdatedAt.UTC()
	if updatedAt.IsZero() {
		updatedAt = time.Now().UTC()
	}
	eventIDsJSON, err := findingStringsJSON(request.EventIDs)
	if err != nil {
		return nil, fmt.Errorf("marshal finding status event ids: %w", err)
	}
	if request.Tombstone == nil {
		return nil, errors.New("finding tombstone payload is required")
	}
	t := request.Tombstone
	tombstonedAt := t.TombstonedAt.UTC()
	if tombstonedAt.IsZero() {
		tombstonedAt = updatedAt
	}
	var row findingRow
	if err := scanFindingRow(tx.QueryRowContext(ctx, `
UPDATE findings
SET status = $2,
    status_reason = $3,
    status_updated_at = $4,
    tombstoned = TRUE,
    tombstoned_at = $5,
    tombstoned_by = $6,
    tombstoned_reason = $7,
    tombstoned_run_id = $8,
    prior_status = $9,
    event_ids_json = CASE
      WHEN jsonb_array_length($10::jsonb) = 0 THEN event_ids_json
      ELSE (
        SELECT COALESCE(jsonb_agg(event_id ORDER BY event_id), '[]'::jsonb)
        FROM (
          SELECT DISTINCT btrim(value) AS event_id
          FROM jsonb_array_elements_text(COALESCE(findings.event_ids_json, '[]'::jsonb) || $10::jsonb) AS merged(value)
          WHERE btrim(value) <> ''
        ) AS unique_event_ids
      )
    END,
    updated_at = NOW()
WHERE id = $1
RETURNING `+findingSelectColumns,
		findingID,
		status,
		statusReason,
		updatedAt,
		tombstonedAt,
		strings.TrimSpace(t.By),
		strings.TrimSpace(t.Reason),
		strings.TrimSpace(t.RunID),
		strings.TrimSpace(t.PriorStatus),
		eventIDsJSON,
	), &row); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ports.ErrFindingNotFound
		}
		return nil, err
	}
	return row.record()
}

func updateFindingRiskInTx(ctx context.Context, tx *sql.Tx, findingID string, risk ports.FindingRisk, attributes map[string]string) (*ports.FindingRecord, error) {
	reasonsJSON, err := findingStringsJSON(risk.RiskReasons)
	if err != nil {
		return nil, fmt.Errorf("marshal finding risk reasons: %w", err)
	}
	attributesJSON, err := findingAttributesJSON(attributes)
	if err != nil {
		return nil, fmt.Errorf("marshal finding risk attributes: %w", err)
	}
	var row findingRow
	if err := scanFindingRow(tx.QueryRowContext(ctx, `
UPDATE findings
SET risk_score = $2,
    likelihood_score = $3,
    impact_score = $4,
    confidence_score = $5,
    likelihood_level = $6,
    impact_level = $7,
    risk_reasons_json = $8::jsonb,
    risk_model_version = $9,
    attributes_json = attributes_json || $10::jsonb,
    updated_at = NOW()
WHERE id = $1
RETURNING `+findingSelectColumns,
		strings.TrimSpace(findingID),
		risk.RiskScore,
		risk.LikelihoodScore,
		risk.ImpactScore,
		risk.ConfidenceScore,
		strings.TrimSpace(risk.LikelihoodLevel),
		strings.TrimSpace(risk.ImpactLevel),
		reasonsJSON,
		strings.TrimSpace(risk.RiskModelVersion),
		attributesJSON,
	), &row); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ports.ErrFindingNotFound
		}
		return nil, err
	}
	return row.record()
}

// BreakStaleRunningCloseoutRuns flips any closeout_run rows still marked
// status='running' with heartbeat_at < cutoff (falling back to started_at for
// legacy rows) to status='failed', records the supplied error_message, and sets
// finished_at=now(). Returns the number of rows updated. Used by the bulk
// tombstone primitive to recover from operator crashes without manual
// intervention (CROSS-008 stale-lock break).
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
        WHERE status = 'running' AND COALESCE(heartbeat_at, started_at) < $1`,
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
                error_message = $2,
                s3_summary_key = CASE WHEN $3 = '' THEN s3_summary_key ELSE $3 END
            WHERE run_id = $1`,
			id,
			summaryErr.Error(),
			strings.TrimSpace(summaryKey),
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
