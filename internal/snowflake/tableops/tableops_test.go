package tableops

import (
	"context"
	"database/sql"
	"strings"
	"testing"
)

type fakeExecClient struct {
	queries []string
	args    [][]interface{}
	err     error
}

func (f *fakeExecClient) Exec(_ context.Context, query string, args ...interface{}) (sql.Result, error) {
	f.queries = append(f.queries, query)
	f.args = append(f.args, args)
	if f.err != nil {
		return nil, f.err
	}
	return fakeResult{}, nil
}

type fakeResult struct{}

func (fakeResult) LastInsertId() (int64, error) { return 0, nil }
func (fakeResult) RowsAffected() (int64, error) { return 0, nil }

func TestMergeVariantRowsBatch_EmptyRows(t *testing.T) {
	client := &fakeExecClient{}
	err := MergeVariantRowsBatch(context.Background(), client, "test_table", nil, nil, 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(client.queries) != 0 {
		t.Fatalf("expected no queries for empty rows, got %d", len(client.queries))
	}
}

func TestMergeVariantRowsBatch_GeneratesMerge(t *testing.T) {
	client := &fakeExecClient{}
	rows := []map[string]interface{}{
		{"_cq_id": "id-1", "_cq_hash": "h1", "region": "us-east-1"},
		{"_cq_id": "id-2", "_cq_hash": "h2", "region": "eu-west-1"},
	}
	err := MergeVariantRowsBatch(context.Background(), client, "aws_ec2_instances", rows, nil, 100)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(client.queries) != 1 {
		t.Fatalf("expected 1 query, got %d", len(client.queries))
	}
	q := client.queries[0]
	if !strings.HasPrefix(q, "MERGE INTO aws_ec2_instances t USING") {
		t.Fatalf("expected MERGE INTO query, got: %s", q)
	}
	if !strings.Contains(q, "WHEN MATCHED THEN UPDATE SET") {
		t.Fatalf("expected UPDATE clause in query: %s", q)
	}
	if !strings.Contains(q, "WHEN NOT MATCHED THEN INSERT") {
		t.Fatalf("expected INSERT clause in query: %s", q)
	}
	// First SELECT should have column aliases.
	if !strings.Contains(q, "? AS _CQ_ID") {
		t.Fatalf("expected first SELECT to use aliases: %s", q)
	}
}

func TestMergeVariantRowsBatch_SkipsEmptyIDs(t *testing.T) {
	client := &fakeExecClient{}
	rows := []map[string]interface{}{
		{"_cq_id": "", "_cq_hash": "h1", "col": "val"},
	}
	err := MergeVariantRowsBatch(context.Background(), client, "test_table", rows, nil, 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(client.queries) != 0 {
		t.Fatalf("expected no queries for empty-ID rows, got %d", len(client.queries))
	}
}

func TestMergeVariantRowsBatch_Batching(t *testing.T) {
	client := &fakeExecClient{}
	rows := make([]map[string]interface{}, 5)
	for i := range rows {
		rows[i] = map[string]interface{}{
			"_cq_id":   "id-" + string(rune('a'+i)),
			"_cq_hash": "h",
			"col":      "v",
		}
	}
	err := MergeVariantRowsBatch(context.Background(), client, "test_table", rows, nil, 2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(client.queries) != 3 {
		t.Fatalf("expected 3 batched MERGE queries for 5 rows with batchSize=2, got %d", len(client.queries))
	}
}

func TestMergeVariantRowsBatch_InvalidTable(t *testing.T) {
	client := &fakeExecClient{}
	rows := []map[string]interface{}{{"_cq_id": "id-1", "_cq_hash": "h"}}
	err := MergeVariantRowsBatch(context.Background(), client, "DROP TABLE; --", rows, nil, 10)
	if err == nil {
		t.Fatal("expected error for invalid table name")
	}
}

func TestMergeVariantRowsBatch_FirstRowSkippedAliasesCorrect(t *testing.T) {
	client := &fakeExecClient{}
	rows := []map[string]interface{}{
		{"_cq_id": "", "_cq_hash": "skip-me", "col": "bad"},    // empty ID, skipped
		{"_cq_id": "id-2", "_cq_hash": "h2", "col": "good"},   // first emitted row
		{"_cq_id": "id-3", "_cq_hash": "h3", "col": "also-ok"},
	}
	err := MergeVariantRowsBatch(context.Background(), client, "test_table", rows, nil, 100)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(client.queries) != 1 {
		t.Fatalf("expected 1 query, got %d", len(client.queries))
	}
	q := client.queries[0]
	if !strings.Contains(q, "? AS _CQ_ID") {
		t.Fatalf("first emitted SELECT must have aliases even when first input row was skipped: %s", q)
	}
	// The second emitted SELECT should NOT have aliases.
	parts := strings.SplitN(q, "UNION ALL", 2)
	if len(parts) != 2 {
		t.Fatalf("expected UNION ALL in query: %s", q)
	}
	secondSelect := parts[1]
	if strings.Contains(secondSelect, "AS _CQ_ID") {
		t.Fatalf("second emitted SELECT should not have aliases: %s", secondSelect)
	}
}
