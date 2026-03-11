package api

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/evalops/cerebro/internal/snowflake"
	"github.com/evalops/cerebro/internal/warehouse"
)

func TestListTables_UsesWarehouseInterface(t *testing.T) {
	a := newTestApp(t)
	a.Warehouse = &warehouse.MemoryWarehouse{
		ListTablesFunc: func(_ context.Context) ([]string, error) {
			return []string{"z_table", "a_table"}, nil
		},
	}
	s := NewServer(a)

	w := do(t, s, http.MethodGet, "/api/v1/tables", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	body := decodeJSON(t, w)
	tables, ok := body["tables"].([]interface{})
	if !ok || len(tables) != 2 {
		t.Fatalf("expected 2 tables, got %#v", body["tables"])
	}
	if tables[0] != "a_table" || tables[1] != "z_table" {
		t.Fatalf("expected sorted tables, got %#v", tables)
	}
}

func TestExecuteQuery_UsesWarehouseInterface(t *testing.T) {
	a := newTestApp(t)
	store := &warehouse.MemoryWarehouse{
		QueryFunc: func(_ context.Context, query string, _ ...any) (*snowflake.QueryResult, error) {
			if !strings.Contains(strings.ToLower(query), "limit 10") {
				t.Fatalf("expected bounded query to include limit 10, got %q", query)
			}
			return &snowflake.QueryResult{
				Rows:  []map[string]any{{"id": "row-1"}},
				Count: 1,
			}, nil
		},
	}
	a.Warehouse = store
	s := NewServer(a)

	w := do(t, s, http.MethodPost, "/api/v1/query", map[string]any{
		"query": "select id from assets",
		"limit": 10,
	})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if len(store.Queries) != 1 {
		t.Fatalf("expected 1 warehouse query, got %d", len(store.Queries))
	}
}

func TestListAssets_UsesWarehouseInterface(t *testing.T) {
	a := newTestApp(t)
	a.Warehouse = &warehouse.MemoryWarehouse{
		GetAssetsFunc: func(_ context.Context, table string, filter snowflake.AssetFilter) ([]map[string]interface{}, error) {
			if table != "aws_s3_buckets" {
				t.Fatalf("expected aws_s3_buckets table, got %q", table)
			}
			if filter.Limit != 1 {
				t.Fatalf("expected limit 1, got %d", filter.Limit)
			}
			return []map[string]interface{}{{"id": "bucket-1"}}, nil
		},
	}
	s := NewServer(a)

	w := do(t, s, http.MethodGet, "/api/v1/assets/aws_s3_buckets?limit=1", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	body := decodeJSON(t, w)
	if count, ok := body["count"].(float64); !ok || count != 1 {
		t.Fatalf("expected count 1, got %#v", body["count"])
	}
}
