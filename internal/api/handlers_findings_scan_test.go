package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDecodeScanFindingsRequest_DefaultLimitAndSingleTable(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/findings/scan", strings.NewReader(`{"table":" AWS_S3_BUCKETS "}`))

	decoded, tables, err := decodeScanFindingsRequest(req)
	if err != nil {
		t.Fatalf("decodeScanFindingsRequest returned error: %v", err)
	}
	if decoded.Limit != 100 {
		t.Fatalf("expected default limit=100, got %d", decoded.Limit)
	}
	if len(tables) != 1 || tables[0] != "aws_s3_buckets" {
		t.Fatalf("expected normalized single table, got %v", tables)
	}
}

func TestDecodeScanFindingsRequest_NormalizesAndDeduplicatesTables(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/findings/scan", strings.NewReader(`{
		"tables": ["AWS_S3_BUCKETS", "aws_iam_roles", "aws_s3_buckets", ""],
		"table": "aws_iam_roles",
		"limit": 25
	}`))

	decoded, tables, err := decodeScanFindingsRequest(req)
	if err != nil {
		t.Fatalf("decodeScanFindingsRequest returned error: %v", err)
	}
	if decoded.Limit != 25 {
		t.Fatalf("expected limit=25, got %d", decoded.Limit)
	}
	if len(tables) != 2 {
		t.Fatalf("expected 2 normalized tables, got %v", tables)
	}
	if tables[0] != "aws_s3_buckets" || tables[1] != "aws_iam_roles" {
		t.Fatalf("unexpected normalized table order: %v", tables)
	}
}

func TestDecodeScanFindingsRequest_RequiresTableOrTables(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/findings/scan", strings.NewReader(`{"limit": 10}`))

	if _, _, err := decodeScanFindingsRequest(req); err == nil {
		t.Fatal("expected missing tables error")
		return
	}
}

func TestScanFindings_MissingTablesReturnsBadRequest(t *testing.T) {
	s := newTestServer(t)
	w := do(t, s, http.MethodPost, "/api/v1/findings/scan", map[string]interface{}{"limit": 10})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}
