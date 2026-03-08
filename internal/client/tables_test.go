package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestListTables_SendsPaginationAndParsesResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("expected GET, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/tables" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if r.URL.Query().Get("limit") != "200" {
			t.Fatalf("expected limit=200, got %q", r.URL.Query().Get("limit"))
		}
		if r.URL.Query().Get("offset") != "20" {
			t.Fatalf("expected offset=20, got %q", r.URL.Query().Get("offset"))
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"tables": []string{"aws_s3_buckets", "aws_iam_users"},
			"count":  2,
		})
	}))
	defer server.Close()

	c, err := New(Config{BaseURL: server.URL})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	tables, err := c.ListTables(context.Background(), 200, 20)
	if err != nil {
		t.Fatalf("list tables: %v", err)
	}
	if len(tables) != 2 {
		t.Fatalf("expected 2 tables, got %d", len(tables))
	}
	if tables[0] != "aws_s3_buckets" {
		t.Fatalf("unexpected first table: %q", tables[0])
	}
}

func TestListTables_EmptyListDefaultsToSlice(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{})
	}))
	defer server.Close()

	c, err := New(Config{BaseURL: server.URL})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	tables, err := c.ListTables(context.Background(), 0, 0)
	if err != nil {
		t.Fatalf("list tables: %v", err)
	}
	if tables == nil {
		t.Fatal("expected empty tables slice, got nil")
	}
	if len(tables) != 0 {
		t.Fatalf("expected no tables, got %d", len(tables))
	}
}
