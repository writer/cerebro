package providers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPantherProviderSync_TableParity(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Header.Get("X-API-Key") != "panther-token" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"message":"unauthorized"}`))
			return
		}

		w.Header().Set("Content-Type", "application/json")

		switch req.URL.Path {
		case "/public_api/v1/users":
			cursor := req.URL.Query().Get("cursor")
			if cursor == "" {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"users": []map[string]interface{}{
						{
							"id":         "user-1",
							"email":      "alice@example.com",
							"name":       "Alice Admin",
							"role":       "admin",
							"status":     "active",
							"created_at": "2026-02-24T00:00:00Z",
						},
					},
					"next_cursor": "users-page-2",
				})
				return
			}
			if cursor == "users-page-2" {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"users": []map[string]interface{}{
						{
							"id":         "user-2",
							"email":      "bob@example.com",
							"name":       "Bob Builder",
							"role":       "member",
							"status":     "active",
							"created_at": "2026-02-23T00:00:00Z",
						},
					},
				})
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			return
		case "/public_api/v1/rules":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"rules": []map[string]interface{}{
					{
						"id":            "rule-1",
						"display_name":  "Suspicious Login",
						"severity":      "high",
						"enabled":       true,
						"log_types":     []string{"Okta.SystemLog"},
						"last_modified": "2026-02-22T00:00:00Z",
					},
				},
			})
			return
		case "/public_api/v1/alerts":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"alerts": []map[string]interface{}{
					{
						"id":         "alert-1",
						"title":      "Suspicious Login detected",
						"severity":   "high",
						"status":     "open",
						"rule":       map[string]interface{}{"id": "rule-1", "log_type": "Okta.SystemLog"},
						"created_at": "2026-02-22T01:00:00Z",
						"updated_at": "2026-02-22T01:10:00Z",
					},
				},
			})
			return
		default:
			http.NotFound(w, req)
		}
	}))
	defer server.Close()

	provider := NewPantherProvider()
	if err := provider.Configure(context.Background(), map[string]interface{}{
		"api_token": "panther-token",
		"base_url":  server.URL + "/public_api/v1",
	}); err != nil {
		t.Fatalf("configure failed: %v", err)
	}

	result, err := provider.Sync(context.Background(), SyncOptions{FullSync: true})
	if err != nil {
		t.Fatalf("sync failed: %v", err)
	}
	if len(result.Errors) != 0 {
		t.Fatalf("unexpected sync errors: %v", result.Errors)
	}

	rowsByTable := map[string]int64{}
	for _, table := range result.Tables {
		rowsByTable[table.Name] = table.Rows
	}

	expected := map[string]int64{
		"panther_users":  2,
		"panther_rules":  1,
		"panther_alerts": 1,
	}
	for table, want := range expected {
		if got := rowsByTable[table]; got != want {
			t.Fatalf("%s rows = %d, want %d", table, got, want)
		}
	}
}

func TestPantherProviderSync_IgnoresPermissionDeniedChildTables(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch req.URL.Path {
		case "/public_api/v1/users":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"users": []map[string]interface{}{{"id": "user-1", "email": "alice@example.com"}},
			})
			return
		case "/public_api/v1/rules", "/public_api/v1/alerts":
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"message":"forbidden"}`))
			return
		default:
			http.NotFound(w, req)
		}
	}))
	defer server.Close()

	provider := NewPantherProvider()
	if err := provider.Configure(context.Background(), map[string]interface{}{
		"api_token": "panther-token",
		"base_url":  server.URL + "/public_api/v1",
	}); err != nil {
		t.Fatalf("configure failed: %v", err)
	}

	result, err := provider.Sync(context.Background(), SyncOptions{FullSync: true})
	if err != nil {
		t.Fatalf("sync failed: %v", err)
	}
	if len(result.Errors) != 0 {
		t.Fatalf("unexpected sync errors: %v", result.Errors)
	}

	rowsByTable := map[string]int64{}
	for _, table := range result.Tables {
		rowsByTable[table.Name] = table.Rows
	}

	if rowsByTable["panther_users"] != 1 {
		t.Fatalf("panther_users rows = %d, want 1", rowsByTable["panther_users"])
	}
	if rowsByTable["panther_rules"] != 0 {
		t.Fatalf("panther_rules rows = %d, want 0", rowsByTable["panther_rules"])
	}
	if rowsByTable["panther_alerts"] != 0 {
		t.Fatalf("panther_alerts rows = %d, want 0", rowsByTable["panther_alerts"])
	}
}

func TestPantherProviderListCollection_DetectsPaginationLoop(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch req.URL.Path {
		case "/public_api/v1/users":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"users":       []map[string]interface{}{{"id": "user-1"}},
				"next_cursor": "repeat-token",
			})
			return
		default:
			http.NotFound(w, req)
		}
	}))
	defer server.Close()

	provider := NewPantherProvider()
	if err := provider.Configure(context.Background(), map[string]interface{}{
		"api_token": "panther-token",
		"base_url":  server.URL + "/public_api/v1",
	}); err != nil {
		t.Fatalf("configure failed: %v", err)
	}

	_, err := provider.listUsers(context.Background())
	if err == nil {
		t.Fatal("expected pagination loop error")
		return
	}
	if !strings.Contains(err.Error(), "pagination loop") {
		t.Fatalf("expected pagination loop error, got %v", err)
	}
}

func TestPantherProviderListCollection_RejectsCrossHostPaginationURL(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch req.URL.Path {
		case "/public_api/v1/users":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"users": []map[string]interface{}{{"id": "user-1"}},
				"links": map[string]interface{}{
					"next": "https://evil.example.com/public_api/v1/users?cursor=abc",
				},
			})
			return
		default:
			http.NotFound(w, req)
		}
	}))
	defer server.Close()

	provider := NewPantherProvider()
	if err := provider.Configure(context.Background(), map[string]interface{}{
		"api_token": "panther-token",
		"base_url":  server.URL + "/public_api/v1",
	}); err != nil {
		t.Fatalf("configure failed: %v", err)
	}

	_, err := provider.listUsers(context.Background())
	if err == nil {
		t.Fatal("expected cross-host pagination error")
		return
	}
	if !strings.Contains(err.Error(), "host mismatch") {
		t.Fatalf("expected host mismatch error, got %v", err)
	}
}
