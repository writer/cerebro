package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

var ensureFindingEvaluationRunStatements = []string{
	`CREATE TABLE IF NOT EXISTS finding_evaluation_runs (
  id TEXT PRIMARY KEY,
  runtime_id TEXT NOT NULL,
  rule_id TEXT NOT NULL,
  status TEXT NOT NULL,
  started_at TIMESTAMPTZ NOT NULL,
  finished_at TIMESTAMPTZ,
  finding_evaluation_run_json JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`,
	`CREATE INDEX IF NOT EXISTS finding_evaluation_runs_runtime_idx ON finding_evaluation_runs (runtime_id, started_at DESC)`,
	`CREATE INDEX IF NOT EXISTS finding_evaluation_runs_rule_idx ON finding_evaluation_runs (rule_id, started_at DESC)`,
	`CREATE INDEX IF NOT EXISTS finding_evaluation_runs_status_idx ON finding_evaluation_runs (status, started_at DESC)`,
}

// PutFindingEvaluationRun upserts one durable finding evaluation run.
func (s *Store) PutFindingEvaluationRun(ctx context.Context, run *cerebrov1.FindingEvaluationRun) error {
	if run == nil {
		return errors.New("finding evaluation run is required")
	}
	id := strings.TrimSpace(run.GetId())
	if id == "" {
		return errors.New("finding evaluation run id is required")
	}
	runtimeID := strings.TrimSpace(run.GetRuntimeId())
	if runtimeID == "" {
		return errors.New("finding evaluation runtime id is required")
	}
	ruleID := strings.TrimSpace(run.GetRuleId())
	if ruleID == "" {
		return errors.New("finding evaluation rule id is required")
	}
	status := strings.TrimSpace(run.GetStatus())
	if status == "" {
		return errors.New("finding evaluation status is required")
	}
	startedAt := run.GetStartedAt()
	if startedAt == nil || startedAt.AsTime().IsZero() {
		return errors.New("finding evaluation started_at is required")
	}
	if s == nil || s.db == nil {
		return errors.New("postgres is not configured")
	}
	if err := s.ensureFindingEvaluationRunTables(ctx); err != nil {
		return err
	}
	payload, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(run)
	if err != nil {
		return fmt.Errorf("marshal finding evaluation run: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `
INSERT INTO finding_evaluation_runs (
  id, runtime_id, rule_id, status, started_at, finished_at, finding_evaluation_run_json
)
VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)
ON CONFLICT (id)
DO UPDATE SET
  runtime_id = EXCLUDED.runtime_id,
  rule_id = EXCLUDED.rule_id,
  status = EXCLUDED.status,
  started_at = EXCLUDED.started_at,
  finished_at = EXCLUDED.finished_at,
  finding_evaluation_run_json = EXCLUDED.finding_evaluation_run_json,
  updated_at = NOW()`,
		id,
		runtimeID,
		ruleID,
		status,
		run.GetStartedAt().AsTime().UTC(),
		nullableTime(findingEvaluationRunTime(run.GetFinishedAt())),
		string(payload),
	); err != nil {
		return fmt.Errorf("upsert finding evaluation run %q: %w", id, err)
	}
	return nil
}

// GetFindingEvaluationRun loads one persisted finding evaluation run.
func (s *Store) GetFindingEvaluationRun(ctx context.Context, runID string) (*cerebrov1.FindingEvaluationRun, error) {
	id := strings.TrimSpace(runID)
	if id == "" {
		return nil, errors.New("finding evaluation run id is required")
	}
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureFindingEvaluationRunTables(ctx); err != nil {
		return nil, err
	}
	var payload string
	if err := s.db.QueryRowContext(ctx, `SELECT finding_evaluation_run_json::text FROM finding_evaluation_runs WHERE id = $1`, id).Scan(&payload); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: %s", ports.ErrFindingEvaluationRunNotFound, id)
		}
		return nil, fmt.Errorf("query finding evaluation run %q: %w", id, err)
	}
	run := &cerebrov1.FindingEvaluationRun{}
	if err := protojson.Unmarshal([]byte(payload), run); err != nil {
		return nil, fmt.Errorf("decode finding evaluation run %q: %w", id, err)
	}
	return run, nil
}

// ListFindingEvaluationRuns loads persisted finding evaluation runs for one runtime.
func (s *Store) ListFindingEvaluationRuns(ctx context.Context, request ports.ListFindingEvaluationRunsRequest) (_ []*cerebrov1.FindingEvaluationRun, err error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureFindingEvaluationRunTables(ctx); err != nil {
		return nil, err
	}
	query, args, err := findingEvaluationRunListQuery(request)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query finding evaluation runs for runtime %q: %w", strings.TrimSpace(request.RuntimeID), err)
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("close finding evaluation run rows: %w", closeErr)
		}
	}()

	runs := []*cerebrov1.FindingEvaluationRun{}
	for rows.Next() {
		var payload string
		if err := rows.Scan(&payload); err != nil {
			return nil, fmt.Errorf("scan finding evaluation run row: %w", err)
		}
		run := &cerebrov1.FindingEvaluationRun{}
		if err := protojson.Unmarshal([]byte(payload), run); err != nil {
			return nil, fmt.Errorf("decode finding evaluation run: %w", err)
		}
		runs = append(runs, run)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate finding evaluation run rows: %w", err)
	}
	return runs, nil
}

func ensureFindingEvaluationRunTable(ctx context.Context, db *sql.DB) error {
	for _, statement := range ensureFindingEvaluationRunStatements {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("ensure finding evaluation run tables: %w", err)
		}
	}
	return nil
}

func (s *Store) ensureFindingEvaluationRunTables(ctx context.Context) error {
	return ensureFindingEvaluationRunTable(ctx, s.db)
}

func findingEvaluationRunListQuery(request ports.ListFindingEvaluationRunsRequest) (string, []any, error) {
	runtimeID := strings.TrimSpace(request.RuntimeID)
	if runtimeID == "" {
		return "", nil, errors.New("finding evaluation runtime id is required")
	}
	clauses := []string{"runtime_id = $1"}
	args := []any{runtimeID}
	addFindingEvaluationRunFilter(&clauses, &args, "rule_id", request.RuleID)
	addFindingEvaluationRunFilter(&clauses, &args, "status", request.Status)
	query := `
SELECT finding_evaluation_run_json::text
FROM finding_evaluation_runs
WHERE ` + strings.Join(clauses, " AND ") + `
ORDER BY started_at DESC, id`
	if request.Limit != 0 {
		args = append(args, int64(request.Limit))
		query += fmt.Sprintf(" LIMIT $%d", len(args))
	}
	return query, args, nil
}

func addFindingEvaluationRunFilter(clauses *[]string, args *[]any, column string, value string) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return
	}
	*args = append(*args, trimmed)
	*clauses = append(*clauses, fmt.Sprintf("%s = $%d", column, len(*args)))
}

func findingEvaluationRunTime(value interface{ AsTime() time.Time }) time.Time {
	if value == nil {
		return time.Time{}
	}
	return value.AsTime().UTC()
}
