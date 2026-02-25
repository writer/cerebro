package providers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestKolideProviderSync_TableParity(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Header.Get("Authorization") != "Bearer kolide-token" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"message":"unauthorized"}`))
			return
		}

		w.Header().Set("Content-Type", "application/json")

		switch req.URL.Path {
		case "/v1/users":
			cursor := req.URL.Query().Get("cursor")
			if cursor == "" {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"users": []map[string]interface{}{
						{
							"id":           "user-1",
							"email":        "alice@example.com",
							"name":         "Alice Admin",
							"role":         "admin",
							"status":       "active",
							"last_seen_at": "2026-02-24T12:00:00Z",
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
							"id":           "user-2",
							"email":        "bob@example.com",
							"name":         "Bob Builder",
							"role":         "member",
							"status":       "active",
							"last_seen_at": "2026-02-23T12:00:00Z",
						},
					},
				})
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			return
		case "/v1/devices":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"devices": []map[string]interface{}{
					{
						"id":           "device-1",
						"hostname":     "macbook-alice",
						"platform":     "macOS",
						"os_version":   "14.4",
						"owner":        map[string]interface{}{"email": "alice@example.com"},
						"last_seen_at": "2026-02-25T10:00:00Z",
					},
				},
			})
			return
		case "/v1/issues":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"issues": []map[string]interface{}{
					{
						"id":         "issue-1",
						"title":      "Disk encryption disabled",
						"severity":   "high",
						"status":     "open",
						"device":     map[string]interface{}{"id": "device-1"},
						"created_at": "2026-02-20T09:00:00Z",
					},
				},
			})
			return
		default:
			http.NotFound(w, req)
		}
	}))
	defer server.Close()

	provider := NewKolideProvider()
	if err := provider.Configure(context.Background(), map[string]interface{}{
		"api_token": "kolide-token",
		"base_url":  server.URL + "/v1",
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
		"kolide_users":   2,
		"kolide_devices": 1,
		"kolide_issues":  1,
	}
	for table, want := range expected {
		if got := rowsByTable[table]; got != want {
			t.Fatalf("%s rows = %d, want %d", table, got, want)
		}
	}
}

func TestKolideProviderSync_IgnoresPermissionDeniedChildTables(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch req.URL.Path {
		case "/v1/users":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"users": []map[string]interface{}{{"id": "user-1", "email": "alice@example.com"}},
			})
			return
		case "/v1/devices", "/v1/issues":
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"message":"forbidden"}`))
			return
		default:
			http.NotFound(w, req)
		}
	}))
	defer server.Close()

	provider := NewKolideProvider()
	if err := provider.Configure(context.Background(), map[string]interface{}{
		"api_token": "kolide-token",
		"base_url":  server.URL + "/v1",
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

	if rowsByTable["kolide_users"] != 1 {
		t.Fatalf("kolide_users rows = %d, want 1", rowsByTable["kolide_users"])
	}
	if rowsByTable["kolide_devices"] != 0 {
		t.Fatalf("kolide_devices rows = %d, want 0", rowsByTable["kolide_devices"])
	}
	if rowsByTable["kolide_issues"] != 0 {
		t.Fatalf("kolide_issues rows = %d, want 0", rowsByTable["kolide_issues"])
	}
}

func TestKolideProviderListCollection_DetectsPaginationLoop(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch req.URL.Path {
		case "/v1/users":
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

	provider := NewKolideProvider()
	if err := provider.Configure(context.Background(), map[string]interface{}{
		"api_token": "kolide-token",
		"base_url":  server.URL + "/v1",
	}); err != nil {
		t.Fatalf("configure failed: %v", err)
	}

	_, err := provider.listUsers(context.Background())
	if err == nil {
		t.Fatal("expected pagination loop error")
	}
	if !strings.Contains(err.Error(), "pagination loop") {
		t.Fatalf("expected pagination loop error, got %v", err)
	}
}

func TestKolideProviderListCollection_RejectsCrossHostPaginationURL(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch req.URL.Path {
		case "/v1/users":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"users": []map[string]interface{}{{"id": "user-1"}},
				"links": map[string]interface{}{
					"next": "https://evil.example.com/v1/users?cursor=abc",
				},
			})
			return
		default:
			http.NotFound(w, req)
		}
	}))
	defer server.Close()

	provider := NewKolideProvider()
	if err := provider.Configure(context.Background(), map[string]interface{}{
		"api_token": "kolide-token",
		"base_url":  server.URL + "/v1",
	}); err != nil {
		t.Fatalf("configure failed: %v", err)
	}

	_, err := provider.listUsers(context.Background())
	if err == nil {
		t.Fatal("expected cross-host pagination error")
	}
	if !strings.Contains(err.Error(), "host mismatch") {
		t.Fatalf("expected host mismatch error, got %v", err)
	}
}
