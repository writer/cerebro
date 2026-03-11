package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSyncProvider_SendsPathAndParsesResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/providers/okta/sync" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}

		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"provider": "okta",
			"errors":   []string{},
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

	result, err := c.SyncProvider(context.Background(), "okta")
	if err != nil {
		t.Fatalf("sync provider: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.Provider != "okta" {
		t.Fatalf("expected provider okta, got %q", result.Provider)
	}
}

func TestSyncProviderWithOptions_SendsRequestBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/providers/okta/sync" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}

		var req map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		if req["full_sync"] != true {
			t.Fatalf("expected full_sync=true, got %#v", req["full_sync"])
		}
		tables, ok := req["tables"].([]interface{})
		if !ok || len(tables) != 2 || tables[0] != "okta_users" || tables[1] != "okta_groups" {
			t.Fatalf("unexpected tables payload: %#v", req["tables"])
		}

		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"provider": "okta",
			"errors":   []string{},
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

	fullSync := true
	result, err := c.SyncProviderWithOptions(context.Background(), "okta", ProviderSyncOptions{
		FullSync: &fullSync,
		Tables:   []string{"okta_users", "okta_groups"},
	})
	if err != nil {
		t.Fatalf("sync provider: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.Provider != "okta" {
		t.Fatalf("expected provider okta, got %q", result.Provider)
	}
}
