package providers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGongProviderSync_TableParity(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		expectedAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("gong-key:gong-secret"))
		if req.Header.Get("Authorization") != expectedAuth {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"message":"unauthorized"}`))
			return
		}

		w.Header().Set("Content-Type", "application/json")

		switch req.URL.Path {
		case "/v2/users":
			cursor := req.URL.Query().Get("cursor")
			if cursor == "" {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"users": []map[string]interface{}{
						{
							"id":         "user-1",
							"email":      "alice@example.com",
							"first_name": "Alice",
							"last_name":  "Admin",
							"active":     true,
							"title":      "Security Engineer",
							"manager_id": "manager-1",
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
							"first_name": "Bob",
							"last_name":  "Builder",
							"active":     true,
							"title":      "Account Executive",
							"manager_id": "manager-2",
						},
					},
				})
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			return
		case "/v2/calls":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"calls": []map[string]interface{}{
					{
						"id":               "call-1",
						"start_time":       "2026-02-25T10:00:00Z",
						"end_time":         "2026-02-25T10:30:00Z",
						"direction":        "inbound",
						"primary_user_id":  "user-1",
						"client_company":   "Writer",
						"duration_seconds": 1800,
						"participants": []map[string]interface{}{
							{
								"id":         "participant-1",
								"user_id":    "user-1",
								"email":      "alice@example.com",
								"role":       "host",
								"join_time":  "2026-02-25T10:00:00Z",
								"leave_time": "2026-02-25T10:30:00Z",
							},
							{
								"user": map[string]interface{}{
									"id":    "user-2",
									"email": "bob@example.com",
								},
								"role":       "guest",
								"join_time":  "2026-02-25T10:05:00Z",
								"leave_time": "2026-02-25T10:28:00Z",
							},
						},
					},
				},
			})
			return
		default:
			http.NotFound(w, req)
		}
	}))
	defer server.Close()

	provider := NewGongProvider()
	if err := provider.Configure(context.Background(), map[string]interface{}{
		"access_key":    "gong-key",
		"access_secret": "gong-secret",
		"base_url":      server.URL,
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
		"gong_users":             2,
		"gong_calls":             1,
		"gong_call_participants": 2,
	}
	for table, want := range expected {
		if got := rowsByTable[table]; got != want {
			t.Fatalf("%s rows = %d, want %d", table, got, want)
		}
	}
}

func TestGongProviderSync_IgnoresPermissionDeniedCalls(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch req.URL.Path {
		case "/v2/users":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"users": []map[string]interface{}{{"id": "user-1", "email": "alice@example.com"}},
			})
			return
		case "/v2/calls":
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"message":"forbidden"}`))
			return
		default:
			http.NotFound(w, req)
		}
	}))
	defer server.Close()

	provider := NewGongProvider()
	if err := provider.Configure(context.Background(), map[string]interface{}{
		"access_key":    "gong-key",
		"access_secret": "gong-secret",
		"base_url":      server.URL,
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

	if rowsByTable["gong_users"] != 1 {
		t.Fatalf("gong_users rows = %d, want 1", rowsByTable["gong_users"])
	}
	if rowsByTable["gong_calls"] != 0 {
		t.Fatalf("gong_calls rows = %d, want 0", rowsByTable["gong_calls"])
	}
	if rowsByTable["gong_call_participants"] != 0 {
		t.Fatalf("gong_call_participants rows = %d, want 0", rowsByTable["gong_call_participants"])
	}
}

func TestGongProviderListCollection_DetectsPaginationLoop(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch req.URL.Path {
		case "/v2/users":
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

	provider := NewGongProvider()
	if err := provider.Configure(context.Background(), map[string]interface{}{
		"access_key":    "gong-key",
		"access_secret": "gong-secret",
		"base_url":      server.URL,
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
