package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/writer/cerebro/internal/ports"
)

var ensureAskTrajectoryStatements = []string{
	`CREATE TABLE IF NOT EXISTS ask_trajectory_runs (
  trace_id TEXT PRIMARY KEY,
  parent_trace_id TEXT NOT NULL DEFAULT '',
  tenant_id TEXT NOT NULL,
  scope_urn TEXT NOT NULL DEFAULT '',
  model TEXT NOT NULL DEFAULT '',
  question_len INTEGER NOT NULL DEFAULT 0,
  depth INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'running',
  total_ms BIGINT NOT NULL DEFAULT 0,
  event_count INTEGER NOT NULL DEFAULT 0,
  started_at TIMESTAMPTZ NOT NULL,
  finished_at TIMESTAMPTZ,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`,
	`CREATE TABLE IF NOT EXISTS ask_trajectory_events (
  trace_id TEXT NOT NULL REFERENCES ask_trajectory_runs(trace_id) ON DELETE CASCADE,
  sequence INTEGER NOT NULL,
  name TEXT NOT NULL,
  event_json JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (trace_id, sequence)
)`,
	`CREATE INDEX IF NOT EXISTS ask_trajectory_runs_tenant_started_idx ON ask_trajectory_runs (tenant_id, started_at DESC)`,
}

// PutAskTrajectoryRun creates or refreshes the run header for an Ask trajectory.
func (s *Store) PutAskTrajectoryRun(ctx context.Context, run ports.AskTrajectoryRun) error {
	if run.TraceID == "" {
		return errors.New("ask trajectory trace_id is required")
	}
	if s == nil || s.db == nil {
		return errors.New("postgres is not configured")
	}
	if err := s.ensureAskTrajectoryTables(ctx); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `
INSERT INTO ask_trajectory_runs (
  trace_id, parent_trace_id, tenant_id, scope_urn, model, question_len, depth, started_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (trace_id)
DO UPDATE SET
  parent_trace_id = EXCLUDED.parent_trace_id,
  tenant_id = EXCLUDED.tenant_id,
  scope_urn = EXCLUDED.scope_urn,
  model = EXCLUDED.model,
  question_len = EXCLUDED.question_len,
  depth = EXCLUDED.depth,
  updated_at = NOW()`,
		run.TraceID,
		run.ParentTraceID,
		run.TenantID,
		run.ScopeURN,
		run.Model,
		run.QuestionLen,
		run.Depth,
		run.StartedAt,
	); err != nil {
		return fmt.Errorf("upsert ask trajectory run %q: %w", run.TraceID, err)
	}
	return nil
}

// AppendAskTrajectoryEvent persists one redacted Ask event.
func (s *Store) AppendAskTrajectoryEvent(ctx context.Context, event ports.AskTrajectoryEvent) error {
	if event.TraceID == "" {
		return errors.New("ask trajectory trace_id is required")
	}
	if s == nil || s.db == nil {
		return errors.New("postgres is not configured")
	}
	if err := s.ensureAskTrajectoryTables(ctx); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `
INSERT INTO ask_trajectory_events (trace_id, sequence, name, event_json, created_at)
VALUES ($1, $2, $3, $4::jsonb, $5)
ON CONFLICT (trace_id, sequence)
DO UPDATE SET name = EXCLUDED.name, event_json = EXCLUDED.event_json, created_at = EXCLUDED.created_at`,
		event.TraceID,
		event.Sequence,
		event.Name,
		string(event.Data),
		event.At,
	); err != nil {
		return fmt.Errorf("append ask trajectory event %q/%d: %w", event.TraceID, event.Sequence, err)
	}
	return nil
}

// FinishAskTrajectoryRun marks an Ask trajectory terminal.
func (s *Store) FinishAskTrajectoryRun(ctx context.Context, finish ports.AskTrajectoryFinish) error {
	if finish.TraceID == "" {
		return errors.New("ask trajectory trace_id is required")
	}
	if s == nil || s.db == nil {
		return errors.New("postgres is not configured")
	}
	if err := s.ensureAskTrajectoryTables(ctx); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `
UPDATE ask_trajectory_runs
SET status = $2, total_ms = $3, event_count = $4, finished_at = $5, updated_at = NOW()
WHERE trace_id = $1`,
		finish.TraceID,
		finish.Status,
		finish.TotalMS,
		finish.EventCount,
		finish.FinishedAt,
	); err != nil {
		return fmt.Errorf("finish ask trajectory run %q: %w", finish.TraceID, err)
	}
	return nil
}

func (s *Store) ensureAskTrajectoryTables(ctx context.Context) error {
	return s.ensureStatements(ctx, &s.ask.trajectory, "ask trajectory", ensureAskTrajectoryStatements)
}
