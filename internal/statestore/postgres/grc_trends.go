package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/ports"
)

var grcTrendIntervals = map[string]struct{}{
	"day":   {},
	"week":  {},
	"month": {},
}

// SummarizeGRCFindingTrends derives a time-bucketed finding flow series from the
// findings table. Findings are bucketed as opened by first_observed_at and as
// closed by status_updated_at for non-open rows; the baseline counts findings
// that were open at the window start so callers can reconstruct a running open
// total. Counts share the dashboard's current-state fidelity: only the latest
// status transition is retained, so historical reopen cycles are approximate.
func (s *Store) SummarizeGRCFindingTrends(ctx context.Context, request ports.GRCFindingTrendsRequest) (ports.GRCFindingTrends, error) {
	if s == nil || s.db == nil {
		return ports.GRCFindingTrends{}, errors.New("postgres is not configured")
	}
	interval := strings.ToLower(strings.TrimSpace(request.Interval))
	if interval == "" {
		interval = "day"
	}
	if _, ok := grcTrendIntervals[interval]; !ok {
		return ports.GRCFindingTrends{}, fmt.Errorf("unsupported grc trends interval %q", request.Interval)
	}
	if request.Start.IsZero() || request.End.IsZero() || !request.End.After(request.Start) {
		return ports.GRCFindingTrends{}, errors.New("grc trends window requires start before end")
	}
	if err := s.ensureFindingTables(ctx); err != nil {
		return ports.GRCFindingTrends{}, err
	}
	clauses, findingArgs, err := findingFilterClauses(request.FindingRequest)
	if err != nil {
		return ports.GRCFindingTrends{}, err
	}
	whereFindings := strings.Join(clauses, " AND ")

	seriesQuery, seriesArgs := grcFindingTrendsSeriesQuery(whereFindings, findingArgs, interval, request.Start, request.End)
	rows, err := s.db.QueryContext(ctx, seriesQuery, seriesArgs...)
	if err != nil {
		return ports.GRCFindingTrends{}, fmt.Errorf("summarize grc finding trends: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var points []ports.GRCFindingTrendPoint
	for rows.Next() {
		var point ports.GRCFindingTrendPoint
		if err := rows.Scan(&point.BucketStart, &point.Opened, &point.OpenedCritical, &point.OpenedHigh, &point.Closed); err != nil {
			return ports.GRCFindingTrends{}, fmt.Errorf("scan grc finding trend point: %w", err)
		}
		point.BucketStart = point.BucketStart.UTC()
		points = append(points, point)
	}
	if err := rows.Err(); err != nil {
		return ports.GRCFindingTrends{}, fmt.Errorf("iterate grc finding trends: %w", err)
	}

	baselineQuery, baselineArgs := grcFindingTrendsBaselineQuery(whereFindings, findingArgs, interval, request.Start)
	var openAtStart int
	if err := s.db.QueryRowContext(ctx, baselineQuery, baselineArgs...).Scan(&openAtStart); err != nil {
		return ports.GRCFindingTrends{}, fmt.Errorf("summarize grc finding trends baseline: %w", err)
	}

	return ports.GRCFindingTrends{Points: points, OpenAtStart: openAtStart}, nil
}

func grcFindingTrendsSeriesQuery(whereFindings string, findingArgs []any, interval string, start, end time.Time) (string, []any) {
	args := append([]any{}, findingArgs...)
	intervalArg := fmt.Sprintf("$%d", len(args)+1)
	args = append(args, interval)
	startArg := fmt.Sprintf("$%d", len(args)+1)
	args = append(args, start.UTC())
	endArg := fmt.Sprintf("$%d", len(args)+1)
	args = append(args, end.UTC())
	effectiveSeverity := findingEffectiveSeveritySQL()
	query := `
WITH scope AS (
  SELECT status, ` + effectiveSeverity + ` AS effective_severity, first_observed_at, status_updated_at
  FROM findings
  WHERE ` + whereFindings + `
),
bounds AS (
  SELECT
    date_trunc(` + intervalArg + `, ` + startArg + `::timestamptz) AS start_bucket,
    date_trunc(` + intervalArg + `, ` + endArg + `::timestamptz) AS end_bucket,
    ('1 ' || ` + intervalArg + `)::interval AS step
),
buckets AS (
  SELECT generate_series(b.start_bucket, b.end_bucket, b.step) AS bucket_start FROM bounds b
),
opened AS (
  SELECT
    date_trunc(` + intervalArg + `, scope.first_observed_at) AS bucket_start,
    COUNT(*) AS opened,
    COUNT(*) FILTER (WHERE scope.effective_severity = 'CRITICAL') AS opened_critical,
    COUNT(*) FILTER (WHERE scope.effective_severity = 'HIGH') AS opened_high
  FROM scope, bounds b
  WHERE scope.first_observed_at >= b.start_bucket AND scope.first_observed_at < b.end_bucket + b.step
  GROUP BY 1
),
closed AS (
  SELECT
    date_trunc(` + intervalArg + `, scope.status_updated_at) AS bucket_start,
    COUNT(*) AS closed
  FROM scope, bounds b
  WHERE LOWER(scope.status) <> 'open'
    AND scope.status_updated_at IS NOT NULL
    AND scope.status_updated_at >= b.start_bucket AND scope.status_updated_at < b.end_bucket + b.step
  GROUP BY 1
)
SELECT
  buckets.bucket_start,
  COALESCE(opened.opened, 0),
  COALESCE(opened.opened_critical, 0),
  COALESCE(opened.opened_high, 0),
  COALESCE(closed.closed, 0)
FROM buckets
LEFT JOIN opened ON opened.bucket_start = buckets.bucket_start
LEFT JOIN closed ON closed.bucket_start = buckets.bucket_start
ORDER BY buckets.bucket_start`
	return query, args
}

func grcFindingTrendsBaselineQuery(whereFindings string, findingArgs []any, interval string, start time.Time) (string, []any) {
	args := append([]any{}, findingArgs...)
	intervalArg := fmt.Sprintf("$%d", len(args)+1)
	args = append(args, interval)
	startArg := fmt.Sprintf("$%d", len(args)+1)
	args = append(args, start.UTC())
	query := `
SELECT COUNT(*)
FROM findings
WHERE ` + whereFindings + `
  AND first_observed_at < date_trunc(` + intervalArg + `, ` + startArg + `::timestamptz)
  AND (
    LOWER(status) = 'open'
    OR (status_updated_at IS NOT NULL AND status_updated_at >= date_trunc(` + intervalArg + `, ` + startArg + `::timestamptz))
  )`
	return query, args
}
