package agents

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/writer/cerebro/internal/snowflake"
	"github.com/writer/cerebro/internal/warehouse"
)

func TestQueryAssetsRejectsUnsafeQuery(t *testing.T) {
	st := &SecurityTools{}
	args := json.RawMessage(`{"query":"DROP TABLE users"}`)

	_, err := st.queryAssets(context.Background(), args)
	if !errors.Is(err, snowflake.ErrNonSelectQuery) {
		t.Fatalf("expected ErrNonSelectQuery, got %v", err)
	}
}

func TestQueryAssetsRequiresWarehouseForValidQuery(t *testing.T) {
	st := &SecurityTools{}
	args := json.RawMessage(`{"query":"SELECT * FROM users"}`)

	_, err := st.queryAssets(context.Background(), args)
	if err == nil || err.Error() != "warehouse not configured" {
		t.Fatalf("expected warehouse not configured error, got %v", err)
	}
}

func TestQueryAssetsUsesWarehouseQuery(t *testing.T) {
	store := &warehouse.MemoryWarehouse{
		QueryFunc: func(_ context.Context, query string, _ ...any) (*snowflake.QueryResult, error) {
			if query != "SELECT * FROM (SELECT name FROM aws_s3_buckets) AS cerebro_readonly_query LIMIT 25" {
				t.Fatalf("unexpected bounded query %q", query)
			}
			return &snowflake.QueryResult{
				Columns: []string{"name"},
				Rows:    []map[string]interface{}{{"name": "bucket-a"}},
				Count:   1,
			}, nil
		},
	}
	st := NewSecurityTools(store, nil, nil, nil)

	output, err := st.queryAssets(context.Background(), json.RawMessage(`{"query":"SELECT name FROM aws_s3_buckets","limit":25}`))
	if err != nil {
		t.Fatalf("query assets: %v", err)
	}

	var payload map[string]interface{}
	if err := json.Unmarshal([]byte(output), &payload); err != nil {
		t.Fatalf("decode output: %v", err)
	}
	if payload["count"].(float64) != 1 {
		t.Fatalf("expected count=1, got %v", payload["count"])
	}
}

func TestGetAssetContextUsesWarehouse(t *testing.T) {
	store := &warehouse.MemoryWarehouse{
		GetAssetByIDFunc: func(_ context.Context, table, id string) (map[string]interface{}, error) {
			if table != "aws_s3_buckets" || id != "bucket-1" {
				t.Fatalf("unexpected asset lookup %s/%s", table, id)
			}
			return map[string]interface{}{"id": id, "name": "bucket-1"}, nil
		},
	}
	st := NewSecurityTools(store, nil, nil, nil)

	output, err := st.getAssetContext(context.Background(), json.RawMessage(`{"asset_type":"aws_s3_buckets","asset_id":"bucket-1"}`))
	if err != nil {
		t.Fatalf("get asset context: %v", err)
	}
	if output == "" {
		t.Fatal("expected asset payload")
	}
}
