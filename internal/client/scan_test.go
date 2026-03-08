package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestScanFindings_SendsRequestAndParsesResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/findings/scan" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}

		var req map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		if req["table"] != "aws_s3_buckets" {
			t.Fatalf("expected table aws_s3_buckets, got %#v", req["table"])
		}
		if req["limit"] != float64(25) {
			t.Fatalf("expected limit 25, got %#v", req["limit"])
		}

		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"scanned":    2,
			"violations": 1,
			"duration":   "5ms",
			"findings": []map[string]interface{}{
				{"policy_id": "p1", "severity": "HIGH"},
			},
		})
	}))
	defer server.Close()

	c, err := New(Config{
		BaseURL: server.URL,
		APIKey:  "test-key",
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	resp, err := c.ScanFindings(context.Background(), "aws_s3_buckets", 25)
	if err != nil {
		t.Fatalf("scan findings: %v", err)
	}
	if resp.Scanned != 2 {
		t.Fatalf("expected scanned=2, got %d", resp.Scanned)
	}
	if resp.Violations != 1 {
		t.Fatalf("expected violations=1, got %d", resp.Violations)
	}
	if len(resp.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(resp.Findings))
	}
	if len(resp.Tables) != 0 {
		t.Fatalf("expected no table summaries, got %d", len(resp.Tables))
	}
}

func TestScanFindingsTables_SendsNormalizedTableList(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/findings/scan" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}

		var req map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request body: %v", err)
		}

		rawTables, ok := req["tables"].([]interface{})
		if !ok {
			t.Fatalf("expected tables array, got %#v", req["tables"])
		}
		if len(rawTables) != 2 {
			t.Fatalf("expected 2 normalized tables, got %#v", rawTables)
		}
		if rawTables[0] != "aws_s3_buckets" || rawTables[1] != "aws_iam_roles" {
			t.Fatalf("unexpected tables payload: %#v", rawTables)
		}
		if req["limit"] != float64(50) {
			t.Fatalf("expected limit 50, got %#v", req["limit"])
		}

		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"scanned":    5,
			"violations": 2,
			"duration":   "12ms",
			"findings": []map[string]interface{}{
				{"policy_id": "p1", "severity": "HIGH"},
				{"policy_id": "p2", "severity": "LOW"},
			},
			"tables": []map[string]interface{}{
				{"table": "aws_s3_buckets", "scanned": 3, "violations": 1, "duration": "5ms"},
				{"table": "aws_iam_roles", "scanned": 2, "violations": 1, "duration": "7ms"},
			},
		})
	}))
	defer server.Close()

	c, err := New(Config{
		BaseURL: server.URL,
		APIKey:  "test-key",
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	resp, err := c.ScanFindingsTables(context.Background(), []string{"AWS_S3_BUCKETS", "aws_iam_roles", "aws_s3_buckets"}, 50)
	if err != nil {
		t.Fatalf("scan findings tables: %v", err)
	}
	if resp.Scanned != 5 {
		t.Fatalf("expected scanned=5, got %d", resp.Scanned)
	}
	if resp.Violations != 2 {
		t.Fatalf("expected violations=2, got %d", resp.Violations)
	}
	if len(resp.Tables) != 2 {
		t.Fatalf("expected 2 table summaries, got %d", len(resp.Tables))
	}
}

func TestScanFindingsTables_RequiresAtLeastOneTable(t *testing.T) {
	c, err := New(Config{
		BaseURL: "http://example.com",
		APIKey:  "test-key",
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	if _, err := c.ScanFindingsTables(context.Background(), []string{"   "}, 10); err == nil {
		t.Fatal("expected validation error for empty table list")
	}
}
