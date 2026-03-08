package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestQuery_SendsRequestAndParsesResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/query" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}

		var req map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		if req["query"] != "SELECT * FROM aws_s3_buckets" {
			t.Fatalf("unexpected query payload: %#v", req["query"])
		}
		if req["limit"] != float64(25) {
			t.Fatalf("expected limit=25, got %#v", req["limit"])
		}
		if req["timeout_seconds"] != float64(30) {
			t.Fatalf("expected timeout_seconds=30, got %#v", req["timeout_seconds"])
		}

		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"columns": []string{"name"},
			"rows": []map[string]interface{}{
				{"name": "bucket-a"},
			},
			"count": 1,
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

	result, err := c.Query(context.Background(), QueryRequest{
		Query:          "SELECT * FROM aws_s3_buckets",
		Limit:          25,
		TimeoutSeconds: 30,
	})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.Count != 1 {
		t.Fatalf("expected count=1, got %d", result.Count)
	}
	if len(result.Rows) != 1 || result.Rows[0]["name"] != "bucket-a" {
		t.Fatalf("unexpected rows: %#v", result.Rows)
	}
}
