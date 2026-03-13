package sync

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/evalops/cerebro/internal/snowflake"
	"github.com/evalops/cerebro/internal/warehouse"
)

func TestChangeSetSummary(t *testing.T) {
	tests := []struct {
		name     string
		changes  *ChangeSet
		expected string
	}{
		{
			name:     "nil changeset",
			changes:  nil,
			expected: "+0/~0/-0",
		},
		{
			name:     "empty changeset",
			changes:  &ChangeSet{},
			expected: "+0/~0/-0",
		},
		{
			name: "added only",
			changes: &ChangeSet{
				Added: []string{"a", "b", "c"},
			},
			expected: "+3/~0/-0",
		},
		{
			name: "modified only",
			changes: &ChangeSet{
				Modified: []string{"x", "y"},
			},
			expected: "+0/~2/-0",
		},
		{
			name: "removed only",
			changes: &ChangeSet{
				Removed: []string{"z"},
			},
			expected: "+0/~0/-1",
		},
		{
			name: "all changes",
			changes: &ChangeSet{
				Added:    []string{"a", "b"},
				Modified: []string{"c"},
				Removed:  []string{"d", "e", "f"},
			},
			expected: "+2/~1/-3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.changes.Summary()
			if got != tt.expected {
				t.Errorf("Summary() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestChangeSetHasChanges(t *testing.T) {
	tests := []struct {
		name     string
		changes  *ChangeSet
		expected bool
	}{
		{
			name:     "nil changeset",
			changes:  nil,
			expected: false,
		},
		{
			name:     "empty changeset",
			changes:  &ChangeSet{},
			expected: false,
		},
		{
			name: "has added",
			changes: &ChangeSet{
				Added: []string{"a"},
			},
			expected: true,
		},
		{
			name: "has modified",
			changes: &ChangeSet{
				Modified: []string{"b"},
			},
			expected: true,
		},
		{
			name: "has removed",
			changes: &ChangeSet{
				Removed: []string{"c"},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.changes.HasChanges()
			if got != tt.expected {
				t.Errorf("HasChanges() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestDefaultAWSRegions(t *testing.T) {
	if len(DefaultAWSRegions) == 0 {
		t.Error("DefaultAWSRegions should not be empty")
	}

	// Check us-east-1 is included
	found := false
	for _, r := range DefaultAWSRegions {
		if r == "us-east-1" {
			found = true
			break
		}
	}
	if !found {
		t.Error("DefaultAWSRegions should include us-east-1")
	}
}

func TestHashRowContent(t *testing.T) {
	e := &SyncEngine{}

	// Same content should produce same hash
	row1 := map[string]interface{}{
		"name": "test",
		"age":  30,
	}
	row2 := map[string]interface{}{
		"age":  30,
		"name": "test",
	}

	hash1 := hashRowContent(row1)
	hash2 := hashRowContent(row2)

	if hash1 != hash2 {
		t.Errorf("Same content should produce same hash, got %q and %q", hash1, hash2)
	}

	// Different content should produce different hash
	row3 := map[string]interface{}{
		"name": "different",
		"age":  30,
	}
	hash3 := hashRowContent(row3)

	if hash1 == hash3 {
		t.Error("Different content should produce different hash")
	}

	// _cq_id should be excluded from hash
	row4 := map[string]interface{}{
		"_cq_id": "should-be-ignored",
		"name":   "test",
		"age":    30,
	}
	hash4 := hashRowContent(row4)

	if hash1 != hash4 {
		t.Errorf("_cq_id should be excluded from hash, got %q and %q", hash1, hash4)
	}

	_ = e // use e to avoid unused variable
}

func TestBackfillRequestLookup(t *testing.T) {
	requests := map[string]string{
		backfillRequestKey("aws_securityhub_findings", "us-east-1"): "partial page",
	}

	if !hasBackfillRequest(requests, "AWS_SECURITYHUB_FINDINGS", "US-EAST-1") {
		t.Fatalf("expected case-insensitive backfill lookup to match")
	}

	if hasBackfillRequest(requests, "aws_guardduty_findings", "us-east-1") {
		t.Fatalf("did not expect unrelated table to match backfill request")
	}
}

func TestBackfillRequestKeyNormalization(t *testing.T) {
	key := backfillRequestKey(" AWS_SECURITYHUB_FINDINGS ", " US-EAST-1 ")
	if key != "aws_securityhub_findings|us-east-1" {
		t.Fatalf("unexpected key: %s", key)
	}
}

func TestBackfillQueueIDNormalization(t *testing.T) {
	id := backfillQueueID(" 123456789012 ", " AWS_GUARDDUTY_FINDINGS ", " US-EAST-1 ")
	if id != "aws:123456789012:aws_guardduty_findings:us-east-1" {
		t.Fatalf("unexpected id: %s", id)
	}
}

func TestBackfillRequestsFromRows(t *testing.T) {
	rows := []map[string]interface{}{
		{"table_name": " AWS_SECURITYHUB_FINDINGS ", "region": " US-EAST-1 ", "reason": " partial page "},
		{"table_name": "", "region": "us-west-2", "reason": "ignored"},
		{"table_name": "aws_guardduty_findings", "region": "", "reason": "ignored"},
	}

	requests := backfillRequestsFromRows(rows)
	if len(requests) != 1 {
		t.Fatalf("expected 1 request, got %d", len(requests))
	}

	got := requests[backfillRequestKey("aws_securityhub_findings", "us-east-1")]
	if got != "partial page" {
		t.Fatalf("unexpected reason: %q", got)
	}
}

func TestRecordBackfillRequestRejectsInvalidScope(t *testing.T) {
	e := &SyncEngine{}
	err := e.recordBackfillRequest(context.Background(), "", "us-east-1", "partial page")
	if err == nil {
		t.Fatalf("expected invalid scope error")
	}
}

func TestClearBackfillRequestRejectsInvalidScope(t *testing.T) {
	e := &SyncEngine{}
	err := e.clearBackfillRequest(context.Background(), "aws_securityhub_findings", "")
	if err == nil {
		t.Fatalf("expected invalid scope error")
	}
}

func TestSyncTableSuccessClearsBackfillAndEmitsCDC(t *testing.T) {
	store := &warehouse.MemoryWarehouse{
		QueryFunc: func(_ context.Context, query string, args ...any) (*snowflake.QueryResult, error) {
			switch {
			case strings.Contains(query, "INFORMATION_SCHEMA.COLUMNS"):
				return &snowflake.QueryResult{
					Rows: []map[string]interface{}{
						{"COLUMN_NAME": "_CQ_ID"},
						{"COLUMN_NAME": "_CQ_HASH"},
						{"COLUMN_NAME": "NAME"},
					},
				}, nil
			case strings.Contains(query, "SELECT _CQ_ID, _CQ_HASH FROM AWS_SAMPLE_TABLE"):
				return &snowflake.QueryResult{}, nil
			default:
				return &snowflake.QueryResult{}, nil
			}
		},
	}
	engine := NewSyncEngine(store, slog.New(slog.NewTextHandler(io.Discard, nil)))
	engine.accountID = "123456789012"

	table := TableSpec{
		Name:    "AWS_SAMPLE_TABLE",
		Columns: []string{"name"},
		Fetch: func(_ context.Context, _ aws.Config, region string) ([]map[string]interface{}, error) {
			if region != "us-east-1" {
				t.Fatalf("expected region us-east-1, got %q", region)
			}
			return []map[string]interface{}{
				{"_cq_id": "asset-1", "name": "primary"},
			}, nil
		},
	}

	result, err := engine.syncTable(context.Background(), aws.Config{Region: "us-east-1"}, table, "us-east-1", false, "", "gen-1")
	if err != nil {
		t.Fatalf("syncTable returned error: %v", err)
	}
	if result.Synced != 1 {
		t.Fatalf("expected 1 synced row, got %d", result.Synced)
	}
	if result.Changes == nil || len(result.Changes.Added) != 1 || result.Changes.Added[0] != "asset-1" {
		t.Fatalf("unexpected changes: %#v", result.Changes)
	}
	if len(store.CDCBatches) != 1 || len(store.CDCBatches[0]) != 1 {
		t.Fatalf("expected one cdc batch, got %#v", store.CDCBatches)
	}
	if got := store.CDCBatches[0][0].AccountID; got != "123456789012" {
		t.Fatalf("expected cdc event account id to use engine account, got %q", got)
	}

	var sawClear bool
	for _, call := range store.Execs {
		if strings.Contains(call.Statement, "DELETE FROM _sync_backfill_queue WHERE id = ?") {
			sawClear = true
			if len(call.Args) != 1 || call.Args[0] != "aws:123456789012:aws_sample_table:us-east-1" {
				t.Fatalf("unexpected backfill clear args: %#v", call.Args)
			}
		}
	}
	if !sawClear {
		t.Fatalf("expected syncTable to clear backfill request, execs=%#v", store.Execs)
	}
}

func TestSyncTablePartialFetchQueuesBackfill(t *testing.T) {
	store := &warehouse.MemoryWarehouse{
		QueryFunc: func(_ context.Context, query string, args ...any) (*snowflake.QueryResult, error) {
			switch {
			case strings.Contains(query, "INFORMATION_SCHEMA.COLUMNS"):
				return &snowflake.QueryResult{
					Rows: []map[string]interface{}{
						{"COLUMN_NAME": "_CQ_ID"},
						{"COLUMN_NAME": "_CQ_HASH"},
						{"COLUMN_NAME": "NAME"},
					},
				}, nil
			case strings.Contains(query, "SELECT _CQ_ID, _CQ_HASH FROM AWS_SAMPLE_TABLE"):
				return &snowflake.QueryResult{}, nil
			default:
				return &snowflake.QueryResult{}, nil
			}
		},
	}
	engine := NewSyncEngine(store, slog.New(slog.NewTextHandler(io.Discard, nil)))
	engine.accountID = "123456789012"

	table := TableSpec{
		Name:    "AWS_SAMPLE_TABLE",
		Columns: []string{"name"},
		Fetch: func(_ context.Context, _ aws.Config, _ string) ([]map[string]interface{}, error) {
			return []map[string]interface{}{
				{"_cq_id": "asset-1", "name": "partial"},
			}, newPartialFetchError(errors.New("page 2 failed"))
		},
	}

	result, err := engine.syncTable(context.Background(), aws.Config{Region: "us-east-1"}, table, "us-east-1", false, "", "gen-2")
	if err != nil {
		t.Fatalf("expected partial fetch to continue, got error: %v", err)
	}
	if !result.BackfillPending {
		t.Fatalf("expected partial fetch to mark backfill pending")
	}

	var sawMerge bool
	for _, call := range store.Execs {
		if strings.Contains(call.Statement, "MERGE INTO _sync_backfill_queue") {
			sawMerge = true
			if len(call.Args) < 6 || call.Args[0] != "aws:123456789012:aws_sample_table:us-east-1" {
				t.Fatalf("unexpected backfill merge args: %#v", call.Args)
			}
		}
	}
	if !sawMerge {
		t.Fatalf("expected partial fetch to queue backfill request, execs=%#v", store.Execs)
	}
}

func TestPersistChangeHistoryRecordsAllOperations(t *testing.T) {
	store := &warehouse.MemoryWarehouse{}
	engine := &SyncEngine{
		sf:        store,
		logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		accountID: "123456789012",
	}
	syncTime := time.Date(2026, 3, 12, 18, 0, 0, 0, time.UTC)

	err := engine.persistChangeHistory(context.Background(), []SyncResult{{
		Table:    "AWS_SAMPLE_TABLE",
		Region:   "us-east-1",
		SyncTime: syncTime,
		Changes: &ChangeSet{
			Added:    []string{"a"},
			Modified: []string{"b"},
			Removed:  []string{"c"},
		},
	}})
	if err != nil {
		t.Fatalf("persistChangeHistory returned error: %v", err)
	}

	insertCount := 0
	for _, call := range store.Execs {
		if strings.Contains(call.Statement, "INSERT INTO _sync_change_history") {
			insertCount++
			if len(call.Args) != 8 {
				t.Fatalf("expected 8 insert args, got %#v", call.Args)
			}
			if call.Args[5] != "123456789012" || call.Args[6] != "aws" {
				t.Fatalf("expected account/provider args, got %#v", call.Args)
			}
		}
	}
	if insertCount != 3 {
		t.Fatalf("expected 3 change-history inserts, got %d", insertCount)
	}
}
