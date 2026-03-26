package builders

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/snowflake"
)

type postgresCDCQueryWarehouse struct {
	mu      sync.Mutex
	queries []string
}

func (w *postgresCDCQueryWarehouse) Query(ctx context.Context, query string, args ...any) (*snowflake.QueryResult, error) {
	_ = ctx
	_ = args

	w.mu.Lock()
	w.queries = append(w.queries, query)
	w.mu.Unlock()

	lower := strings.ToLower(query)
	if strings.Contains(query, "?") {
		return nil, fmt.Errorf("postgres query used snowflake placeholders: %s", query)
	}
	if strings.Contains(lower, "from cdc_events") && !strings.Contains(lower, "from cerebro.cdc_events") {
		return nil, fmt.Errorf("postgres query used unqualified cdc_events table: %s", query)
	}

	return &snowflake.QueryResult{Rows: []map[string]any{}}, nil
}

func (w *postgresCDCQueryWarehouse) Dialect() string {
	return "postgres"
}

func (w *postgresCDCQueryWarehouse) AppSchema() string {
	return "cerebro"
}

func (w *postgresCDCQueryWarehouse) allQueries() []string {
	w.mu.Lock()
	defer w.mu.Unlock()

	out := make([]string, len(w.queries))
	copy(out, w.queries)
	return out
}

func TestBuilderApplyChanges_PostgresCDCQueriesUseQualifiedTableAndDollarPlaceholders(t *testing.T) {
	warehouse := &postgresCDCQueryWarehouse{}
	builder := NewBuilder(NewSnowflakeSource(warehouse), nil)

	since := time.Date(2026, 3, 26, 12, 0, 0, 0, time.UTC)
	summary, err := builder.ApplyChanges(context.Background(), since)
	if err != nil {
		t.Fatalf("ApplyChanges failed: %v", err)
	}
	if summary.EventsProcessed != 0 {
		t.Fatalf("expected no CDC events, got %d", summary.EventsProcessed)
	}

	queries := warehouse.allQueries()
	foundCDCQuery := false
	for _, query := range queries {
		lower := strings.ToLower(query)
		if !strings.Contains(lower, "cdc_events") {
			continue
		}
		foundCDCQuery = true
		if !strings.Contains(lower, "from cerebro.cdc_events") {
			t.Fatalf("expected Postgres CDC query to qualify cerebro.cdc_events, got %q", query)
		}
		for idx := 1; idx <= 6; idx++ {
			if !strings.Contains(query, fmt.Sprintf("$%d", idx)) {
				t.Fatalf("expected Postgres CDC query to use $%d placeholder, got %q", idx, query)
			}
		}
	}
	if !foundCDCQuery {
		t.Fatalf("expected a CDC query, got %v", queries)
	}
}
