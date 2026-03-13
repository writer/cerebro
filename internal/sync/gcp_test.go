package sync

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/evalops/cerebro/internal/snowflake"
	"github.com/evalops/cerebro/internal/warehouse"
)

func TestGCPHashRowContent(t *testing.T) {
	e := &GCPSyncEngine{}

	// Same content should produce same hash
	row1 := map[string]interface{}{
		"name":    "test-bucket",
		"project": "my-project",
	}
	row2 := map[string]interface{}{
		"project": "my-project",
		"name":    "test-bucket",
	}

	hash1 := e.hashRowContent(row1)
	hash2 := e.hashRowContent(row2)

	if hash1 != hash2 {
		t.Errorf("Same content should produce same hash, got %q and %q", hash1, hash2)
	}

	// Different content should produce different hash
	row3 := map[string]interface{}{
		"name":    "different-bucket",
		"project": "my-project",
	}
	hash3 := e.hashRowContent(row3)

	if hash1 == hash3 {
		t.Error("Different content should produce different hash")
	}

	// _cq_id should be excluded from hash
	row4 := map[string]interface{}{
		"_cq_id":  "should-be-ignored",
		"name":    "test-bucket",
		"project": "my-project",
	}
	hash4 := e.hashRowContent(row4)

	if hash1 != hash4 {
		t.Errorf("_cq_id should be excluded from hash, got %q and %q", hash1, hash4)
	}
}

func TestGCPTables(t *testing.T) {
	e := &GCPSyncEngine{}
	tables := e.getGCPTables()

	if len(tables) == 0 {
		t.Error("getGCPTables should return at least one table")
	}

	// Check expected tables exist
	expectedTables := []string{
		"gcp_compute_instances",
		"gcp_storage_buckets",
		"gcp_iam_service_accounts",
		"gcp_compute_firewalls",
		"gcp_sql_instances",
		"gcp_container_clusters",
	}

	tableNames := make(map[string]bool)
	for _, t := range tables {
		tableNames[t.Name] = true
	}

	for _, expected := range expectedTables {
		if !tableNames[expected] {
			t.Errorf("Expected table %q not found in GCP tables", expected)
		}
	}
}

func TestWithGCPProject(t *testing.T) {
	e := &GCPSyncEngine{}
	opt := WithGCPProject("test-project-123")
	opt(e)

	if e.projectID != "test-project-123" {
		t.Errorf("WithGCPProject did not set projectID, got %q", e.projectID)
	}
}

func TestWithGCPConcurrency(t *testing.T) {
	e := &GCPSyncEngine{}
	opt := WithGCPConcurrency(20)
	opt(e)

	if e.concurrency != 20 {
		t.Errorf("WithGCPConcurrency did not set concurrency, got %d", e.concurrency)
	}
}

func TestGCPScopeFilter(t *testing.T) {
	rows := []map[string]interface{}{
		{"project_id": "p2"},
		{"project_id": "p1"},
		{"project_id": "p1"},
	}

	column, values := gcpScopeFilter([]string{"project_id", "name"}, rows, "")
	if column != "PROJECT_ID" {
		t.Fatalf("expected PROJECT_ID column, got %q", column)
	}
	if len(values) != 2 || values[0] != "p1" || values[1] != "p2" {
		t.Fatalf("unexpected values: %#v", values)
	}
}

func TestGCPScopeFilterFallsBackToEngineProject(t *testing.T) {
	column, values := gcpScopeFilter([]string{"project"}, nil, "project-123")
	if column != "PROJECT" {
		t.Fatalf("expected PROJECT column, got %q", column)
	}
	if len(values) != 1 || values[0] != "project-123" {
		t.Fatalf("unexpected values: %#v", values)
	}
}

func TestGCPScopeWhereClause(t *testing.T) {
	where, args := scopedWhereClause("PROJECT_ID", []string{"p1", "p2"})
	if where != " WHERE PROJECT_ID IN (?,?)" {
		t.Fatalf("unexpected where clause: %q", where)
	}
	if len(args) != 2 || args[0] != "p1" || args[1] != "p2" {
		t.Fatalf("unexpected args: %#v", args)
	}
}

func TestGCPProjectIDFromScope(t *testing.T) {
	if got := gcpProjectIDFromScope("projects/test-project"); got != "test-project" {
		t.Fatalf("expected project id, got %q", got)
	}
	if got := gcpProjectIDFromScope("organizations/123456789"); got != "" {
		t.Fatalf("expected empty project id for org scope, got %q", got)
	}
}

func TestGCPSyncTableEmitsCDCEvents(t *testing.T) {
	store := &warehouse.MemoryWarehouse{
		QueryFunc: func(_ context.Context, query string, _ ...any) (*snowflake.QueryResult, error) {
			switch {
			case strings.Contains(query, "INFORMATION_SCHEMA.COLUMNS"):
				return &snowflake.QueryResult{
					Rows: []map[string]interface{}{
						{"COLUMN_NAME": "_CQ_ID"},
						{"COLUMN_NAME": "_CQ_HASH"},
						{"COLUMN_NAME": "PROJECT_ID"},
						{"COLUMN_NAME": "NAME"},
					},
				}, nil
			case strings.Contains(query, "SELECT _CQ_ID, _CQ_HASH FROM GCP_SAMPLE_TABLE"):
				return &snowflake.QueryResult{}, nil
			default:
				return &snowflake.QueryResult{}, nil
			}
		},
	}
	engine := NewGCPSyncEngine(store, slog.New(slog.NewTextHandler(io.Discard, nil)), WithGCPProject("project-a"))

	result, err := engine.syncTable(context.Background(), GCPTableSpec{
		Name:    "GCP_SAMPLE_TABLE",
		Columns: []string{"project_id", "name"},
		Fetch: func(_ context.Context, projectID string) ([]map[string]interface{}, error) {
			if projectID != "project-a" {
				t.Fatalf("expected project-a, got %q", projectID)
			}
			return []map[string]interface{}{
				{"_cq_id": "asset-1", "project_id": "project-a", "name": "vm-1"},
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("syncTable returned error: %v", err)
	}
	if result.Synced != 1 || result.Changes == nil || len(result.Changes.Added) != 1 {
		t.Fatalf("unexpected sync result: %#v", result)
	}
	if len(store.CDCBatches) != 1 || store.CDCBatches[0][0].AccountID != "project-a" {
		t.Fatalf("expected one GCP CDC batch, got %#v", store.CDCBatches)
	}
}

func TestGCPSyncAllRejectsUnknownFilter(t *testing.T) {
	engine := NewGCPSyncEngine(&warehouse.MemoryWarehouse{}, slog.New(slog.NewTextHandler(io.Discard, nil)),
		WithGCPProject("project-a"),
		WithGCPTableFilter([]string{"missing_table"}),
	)

	_, err := engine.SyncAll(context.Background())
	if err == nil || !strings.Contains(err.Error(), "no GCP tables matched filter") {
		t.Fatalf("expected unknown filter error, got %v", err)
	}
}

func TestGCPPersistChangeHistoryUsesSharedProviderHelper(t *testing.T) {
	store := &warehouse.MemoryWarehouse{}
	engine := NewGCPSyncEngine(store, slog.New(slog.NewTextHandler(io.Discard, nil)), WithGCPProject("project-a"))
	syncTime := time.Date(2026, 3, 12, 20, 0, 0, 0, time.UTC)

	err := engine.persistChangeHistory(context.Background(), []SyncResult{{
		Table:    "GCP_SAMPLE_TABLE",
		Region:   "project-a",
		SyncTime: syncTime,
		Changes: &ChangeSet{
			Added: []string{"asset-1"},
		},
	}})
	if err != nil {
		t.Fatalf("persistChangeHistory returned error: %v", err)
	}

	var sawInsert bool
	for _, call := range store.Execs {
		if strings.Contains(call.Statement, "INSERT INTO _sync_change_history") {
			sawInsert = true
			if call.Args[6] != "gcp" {
				t.Fatalf("expected gcp provider arg, got %#v", call.Args)
			}
		}
	}
	if !sawInsert {
		t.Fatalf("expected change-history insert, execs=%#v", store.Execs)
	}
}
