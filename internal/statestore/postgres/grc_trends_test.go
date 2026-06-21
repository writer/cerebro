package postgres

import (
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/ports"
)

func TestGRCFindingTrendsSeriesQueryStructure(t *testing.T) {
	clauses, args, err := findingFilterClauses(ports.ListFindingsRequest{TenantID: "writer", RuntimeIDs: []string{"writer-okta"}})
	if err != nil {
		t.Fatalf("findingFilterClauses error = %v", err)
	}
	where := strings.Join(clauses, " AND ")
	start := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	query, queryArgs := grcFindingTrendsSeriesQuery(where, args, "day", start, end)

	for _, fragment := range []string{
		"WHERE tenant_id = $1",
		"generate_series",
		"date_trunc(",
		"FILTER (WHERE scope.effective_severity = 'CRITICAL')",
		"FILTER (WHERE scope.effective_severity = 'HIGH')",
		"LOWER(scope.status) <> 'open'",
		"scope.status_updated_at IS NOT NULL",
		"LEFT JOIN opened",
		"LEFT JOIN closed",
		"ORDER BY buckets.bucket_start",
	} {
		if !strings.Contains(query, fragment) {
			t.Fatalf("series query missing %q:\n%s", fragment, query)
		}
	}

	if len(queryArgs) != len(args)+3 {
		t.Fatalf("series args = %d, want %d", len(queryArgs), len(args)+3)
	}
	if queryArgs[len(args)] != "day" {
		t.Fatalf("interval arg = %v, want day", queryArgs[len(args)])
	}
	if got, ok := queryArgs[len(args)+1].(time.Time); !ok || !got.Equal(start.UTC()) {
		t.Fatalf("start arg = %v, want %v", queryArgs[len(args)+1], start.UTC())
	}
	if got, ok := queryArgs[len(args)+2].(time.Time); !ok || !got.Equal(end.UTC()) {
		t.Fatalf("end arg = %v, want %v", queryArgs[len(args)+2], end.UTC())
	}
}

func TestGRCFindingTrendsBaselineQueryStructure(t *testing.T) {
	clauses, args, err := findingFilterClauses(ports.ListFindingsRequest{TenantID: "writer", RuntimeIDs: []string{"writer-okta"}})
	if err != nil {
		t.Fatalf("findingFilterClauses error = %v", err)
	}
	where := strings.Join(clauses, " AND ")
	start := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)

	query, queryArgs := grcFindingTrendsBaselineQuery(where, args, "week", start)

	for _, fragment := range []string{
		"SELECT COUNT(*)",
		"WHERE tenant_id = $1",
		"first_observed_at < date_trunc(",
		"LOWER(status) = 'open'",
		"status_updated_at >= date_trunc(",
	} {
		if !strings.Contains(query, fragment) {
			t.Fatalf("baseline query missing %q:\n%s", fragment, query)
		}
	}

	if len(queryArgs) != len(args)+2 {
		t.Fatalf("baseline args = %d, want %d", len(queryArgs), len(args)+2)
	}
	if queryArgs[len(args)] != "week" {
		t.Fatalf("interval arg = %v, want week", queryArgs[len(args)])
	}
	if got, ok := queryArgs[len(args)+1].(time.Time); !ok || !got.Equal(start.UTC()) {
		t.Fatalf("start arg = %v, want %v", queryArgs[len(args)+1], start.UTC())
	}
}
