package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAdminHealth_SendsPathAndParsesResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("expected GET, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/admin/health" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-key" {
			t.Fatalf("expected authorization header, got %q", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"snowflake": map[string]interface{}{"status": "healthy", "latency_ms": 3},
			"findings":  map[string]interface{}{"total": 7},
		})
	}))
	defer server.Close()

	c, err := New(Config{BaseURL: server.URL, APIKey: "test-key"})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	resp, err := c.AdminHealth(context.Background())
	if err != nil {
		t.Fatalf("admin health: %v", err)
	}

	snowflake, ok := resp["snowflake"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected snowflake object, got %#v", resp["snowflake"])
	}
	if snowflake["status"] != "healthy" {
		t.Fatalf("unexpected snowflake status: %#v", snowflake["status"])
	}
	findings, ok := resp["findings"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected findings object, got %#v", resp["findings"])
	}
	if findings["total"].(float64) != 7 {
		t.Fatalf("expected findings total=7, got %#v", findings["total"])
	}
}
