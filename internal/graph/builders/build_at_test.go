package builders

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

type captureQuerySource struct {
	mu      sync.Mutex
	queries []string
}

var _ DataSource = (*captureQuerySource)(nil)

func (s *captureQuerySource) Query(ctx context.Context, query string, args ...any) (*DataQueryResult, error) {
	_ = ctx
	_ = args
	s.mu.Lock()
	s.queries = append(s.queries, query)
	s.mu.Unlock()
	return &DataQueryResult{Rows: []map[string]any{}}, nil
}

func (s *captureQuerySource) allQueries() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.queries))
	copy(out, s.queries)
	return out
}

func TestApplyTimeTravelClauses(t *testing.T) {
	ts := time.Date(2026, 3, 7, 12, 30, 0, 0, time.UTC)
	query := `SELECT u.arn FROM aws_iam_users u JOIN aws_iam_roles r ON u.arn = r.arn`
	got := applyTimeTravelClauses(query, ts)

	if !strings.Contains(got, "FROM aws_iam_users AT(TIMESTAMP => '2026-03-07 12:30:00')") {
		t.Fatalf("expected FROM clause to include time travel, got %q", got)
	}
	if !strings.Contains(got, "JOIN aws_iam_roles AT(TIMESTAMP => '2026-03-07 12:30:00')") {
		t.Fatalf("expected JOIN clause to include time travel, got %q", got)
	}

	infoQuery := `SELECT table_name FROM information_schema.tables WHERE table_schema = 'RAW'`
	infoGot := applyTimeTravelClauses(infoQuery, ts)
	if strings.Contains(strings.ToUpper(infoGot), "AT(TIMESTAMP") {
		t.Fatalf("did not expect information_schema query to include time travel clause, got %q", infoGot)
	}
}

func TestBuilderBuildAt_RewritesQueriesWithTimeTravel(t *testing.T) {
	source := &captureQuerySource{}
	builder := NewBuilder(source, nil)
	ts := time.Date(2026, 3, 7, 0, 0, 0, 0, time.UTC)

	historicalGraph, err := builder.BuildAt(context.Background(), ts)
	if err != nil {
		t.Fatalf("BuildAt failed: %v", err)
	}
	if historicalGraph == nil {
		t.Fatal("expected non-nil graph from BuildAt")
	}

	queries := source.allQueries()
	if len(queries) == 0 {
		t.Fatal("expected captured queries from BuildAt")
	}

	foundTimeTravel := false
	foundInfoSchema := false
	for _, query := range queries {
		lower := strings.ToLower(query)
		if strings.Contains(lower, "from aws_iam_users at(timestamp => '2026-03-07 00:00:00')") {
			foundTimeTravel = true
		}
		if strings.Contains(lower, "from information_schema.tables") && !strings.Contains(lower, "at(timestamp") {
			foundInfoSchema = true
		}
	}

	if !foundTimeTravel {
		t.Fatalf("expected at least one table query to include time travel clause, got: %v", queries)
	}
	if !foundInfoSchema {
		t.Fatalf("expected information_schema query without time travel clause, got: %v", queries)
	}
}
