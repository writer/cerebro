package sync

import (
	"context"
	"database/sql"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/evalops/cerebro/internal/snowflake"
	"github.com/evalops/cerebro/internal/warehouse"
)

func TestUpsertScopedRowsWithChangesScopesDeletesAndMerge(t *testing.T) {
	store := &warehouse.MemoryWarehouse{
		QueryFunc: func(_ context.Context, query string, _ ...any) (*snowflake.QueryResult, error) {
			if !strings.Contains(query, "SELECT _CQ_ID, _CQ_HASH FROM GCP_SAMPLE_TABLE") {
				return &snowflake.QueryResult{}, nil
			}
			return &snowflake.QueryResult{
				Rows: []map[string]interface{}{
					{"_CQ_ID": "same", "_CQ_HASH": "same-hash"},
					{"_CQ_ID": "removed", "_CQ_HASH": "removed-hash"},
				},
			}, nil
		},
	}

	rows := []map[string]interface{}{
		{"_cq_id": "same", "project_id": "project-a", "name": "same"},
		{"_cq_id": "added", "project_id": "project-a", "name": "added"},
	}
	changes, err := upsertScopedRowsWithChanges(
		context.Background(),
		store,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		"GCP_SAMPLE_TABLE",
		rows,
		"PROJECT_ID",
		[]string{"project-a"},
		func(row map[string]interface{}) string { return row["name"].(string) + "-hash" },
	)
	if err != nil {
		t.Fatalf("upsertScopedRowsWithChanges returned error: %v", err)
	}
	if len(changes.Added) != 1 || changes.Added[0] != "added" {
		t.Fatalf("unexpected added changes: %#v", changes)
	}
	if len(changes.Removed) != 1 || changes.Removed[0] != "removed" {
		t.Fatalf("unexpected removed changes: %#v", changes)
	}

	var sawMerge, sawScopedDelete bool
	for _, call := range store.Execs {
		if strings.Contains(call.Statement, "MERGE INTO GCP_SAMPLE_TABLE") {
			sawMerge = true
		}
		if strings.Contains(call.Statement, "DELETE FROM GCP_SAMPLE_TABLE WHERE _CQ_ID IN") &&
			strings.Contains(call.Statement, "PROJECT_ID IN (?)") {
			sawScopedDelete = true
		}
	}
	if !sawMerge {
		t.Fatalf("expected merge query, execs=%#v", store.Execs)
	}
	if !sawScopedDelete {
		t.Fatalf("expected scoped delete query, execs=%#v", store.Execs)
	}
}

func TestDeleteScopedRowsByScopeFallsBackFromTruncateToDelete(t *testing.T) {
	store := &warehouse.MemoryWarehouse{
		ExecFunc: func(_ context.Context, query string, _ ...any) (sql.Result, error) {
			if strings.HasPrefix(query, "TRUNCATE TABLE") {
				return nil, context.DeadlineExceeded
			}
			return warehouseResult(0), nil
		},
	}

	if err := deleteScopedRowsByScope(context.Background(), store, "GCP_SAMPLE_TABLE", "", nil); err != nil {
		t.Fatalf("deleteScopedRowsByScope returned error: %v", err)
	}

	if len(store.Execs) != 2 {
		t.Fatalf("expected truncate fallback to issue 2 execs, got %d", len(store.Execs))
	}
	if !strings.HasPrefix(store.Execs[0].Statement, "TRUNCATE TABLE GCP_SAMPLE_TABLE") {
		t.Fatalf("expected truncate attempt, got %q", store.Execs[0].Statement)
	}
	if store.Execs[1].Statement != "DELETE FROM GCP_SAMPLE_TABLE" {
		t.Fatalf("expected delete fallback, got %q", store.Execs[1].Statement)
	}
}

func TestPersistProviderChangeHistoryWritesProviderRows(t *testing.T) {
	store := &warehouse.MemoryWarehouse{}
	syncTime := time.Date(2026, 3, 12, 19, 0, 0, 0, time.UTC)

	err := persistProviderChangeHistory(
		context.Background(),
		store,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		"gcp",
		[]SyncResult{{
			Table:    "GCP_SAMPLE_TABLE",
			Region:   "project-a",
			SyncTime: syncTime,
			Changes: &ChangeSet{
				Added:    []string{"a"},
				Modified: []string{"b"},
				Removed:  []string{"c"},
			},
		}},
	)
	if err != nil {
		t.Fatalf("persistProviderChangeHistory returned error: %v", err)
	}

	insertCount := 0
	for _, call := range store.Execs {
		if strings.Contains(call.Statement, "INSERT INTO _sync_change_history") {
			insertCount++
			if len(call.Args) != 8 {
				t.Fatalf("expected 8 args for change record, got %#v", call.Args)
			}
			if call.Args[6] != "gcp" {
				t.Fatalf("expected provider gcp, got %#v", call.Args)
			}
		}
	}
	if insertCount != 3 {
		t.Fatalf("expected 3 change history inserts, got %d", insertCount)
	}
}

type warehouseResult int64

func (r warehouseResult) LastInsertId() (int64, error) {
	return 0, nil
}

func (r warehouseResult) RowsAffected() (int64, error) {
	return int64(r), nil
}
