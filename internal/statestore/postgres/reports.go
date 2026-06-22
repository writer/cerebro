package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"google.golang.org/protobuf/encoding/protojson"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

var ensureReportRunStatements = []string{`
CREATE TABLE IF NOT EXISTS report_runs (
  id TEXT PRIMARY KEY,
  report_run_json JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`}

// PutReportRun upserts one durable report run.
func (s *Store) PutReportRun(ctx context.Context, run *cerebrov1.ReportRun) error {
	if run == nil {
		return errors.New("report run is required")
	}
	id := strings.TrimSpace(run.GetId())
	if id == "" {
		return errors.New("report run id is required")
	}
	reportID := strings.TrimSpace(run.GetReportId())
	if reportID == "" {
		return errors.New("report id is required")
	}
	status := strings.TrimSpace(run.GetStatus())
	if status == "" {
		return errors.New("report run status is required")
	}
	if s == nil || s.db == nil {
		return errors.New("postgres is not configured")
	}
	if err := s.ensureReportRunTable(ctx); err != nil {
		return err
	}
	payload, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(run)
	if err != nil {
		return fmt.Errorf("marshal report run: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `
INSERT INTO report_runs (id, report_run_json)
VALUES ($1, $2::jsonb)
ON CONFLICT (id)
DO UPDATE SET report_run_json = EXCLUDED.report_run_json, updated_at = NOW()`, id, string(payload)); err != nil {
		return fmt.Errorf("upsert report run %q: %w", id, err)
	}
	return nil
}

// GetReportRun loads one persisted report run.
func (s *Store) GetReportRun(ctx context.Context, reportRunID string) (*cerebrov1.ReportRun, error) {
	id := strings.TrimSpace(reportRunID)
	if id == "" {
		return nil, errors.New("report run id is required")
	}
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureReportRunTable(ctx); err != nil {
		return nil, err
	}
	var payload string
	if err := s.db.QueryRowContext(ctx, `SELECT report_run_json::text FROM report_runs WHERE id = $1`, id).Scan(&payload); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: %s", ports.ErrReportRunNotFound, id)
		}
		return nil, fmt.Errorf("query report run %q: %w", id, err)
	}
	run := &cerebrov1.ReportRun{}
	if err := protojson.Unmarshal([]byte(payload), run); err != nil {
		return nil, fmt.Errorf("decode report run %q: %w", id, err)
	}
	return run, nil
}

// ListReportRuns returns recent persisted report runs newest-first, scoped by
// tenant (read from the run parameters) and optionally by report id.
func (s *Store) ListReportRuns(ctx context.Context, filter ports.ReportRunFilter) ([]*cerebrov1.ReportRun, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureReportRunTable(ctx); err != nil {
		return nil, err
	}
	clauses := []string{}
	args := []any{}
	if tenantID := strings.TrimSpace(filter.TenantID); tenantID != "" {
		args = append(args, tenantID)
		clauses = append(clauses, fmt.Sprintf("report_run_json->'parameters'->>'tenant_id' = $%d", len(args)))
	}
	if reportID := strings.TrimSpace(filter.ReportID); reportID != "" {
		args = append(args, reportID)
		clauses = append(clauses, fmt.Sprintf("report_run_json->>'report_id' = $%d", len(args)))
	}
	where := ""
	if len(clauses) > 0 {
		where = "WHERE " + strings.Join(clauses, " AND ")
	}
	limit := reportRunListLimit(filter.Limit)
	args = append(args, limit)
	// #nosec G201 -- clauses use fixed JSONB column predicates and all values remain parameterized.
	query := fmt.Sprintf(`
SELECT report_run_json::text
FROM report_runs
%s
ORDER BY created_at DESC
LIMIT $%d`, where, len(args))
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list report runs: %w", err)
	}
	defer func() { _ = rows.Close() }()
	runs := []*cerebrov1.ReportRun{}
	for rows.Next() {
		var payload string
		if err := rows.Scan(&payload); err != nil {
			return nil, fmt.Errorf("scan report run: %w", err)
		}
		run := &cerebrov1.ReportRun{}
		if err := protojson.Unmarshal([]byte(payload), run); err != nil {
			return nil, fmt.Errorf("decode report run: %w", err)
		}
		runs = append(runs, run)
	}
	return runs, rows.Err()
}

func reportRunListLimit(limit uint32) uint32 {
	const (
		defaultLimit uint32 = 50
		maxLimit     uint32 = 200
	)
	switch {
	case limit == 0:
		return defaultLimit
	case limit > maxLimit:
		return maxLimit
	default:
		return limit
	}
}

func (s *Store) ensureReportRunTable(ctx context.Context) error {
	return s.ensureStatements(ctx, &s.reportRunTableReady, "report run", ensureReportRunStatements)
}
