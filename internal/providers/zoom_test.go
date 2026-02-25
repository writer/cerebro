package providers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestZoomProviderSync_TableParity(t *testing.T) {
	t.Parallel()

	var tokenCalls int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/oauth/token":
			if r.Method != http.MethodPost {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			user, pass, ok := r.BasicAuth()
			if !ok || user != "zoom-client-id" || pass != "zoom-client-secret" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if r.URL.Query().Get("grant_type") != "account_credentials" || r.URL.Query().Get("account_id") != "zoom-account-id" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			atomic.AddInt32(&tokenCalls, 1)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "zoom-access-token",
				"expires_in":   3600,
			})
		case "/v2/users":
			if r.Header.Get("Authorization") != "Bearer zoom-access-token" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if r.URL.Query().Get("next_page_token") == "" {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"users": []map[string]interface{}{
						{
							"id":              "user-1",
							"email":           "alice@example.com",
							"first_name":      "Alice",
							"last_name":       "Admin",
							"type":            2,
							"status":          "active",
							"role_id":         "role-1",
							"role_name":       "Owner",
							"last_login_time": "2026-01-01T00:00:00Z",
							"created_at":      "2025-01-01T00:00:00Z",
						},
					},
					"next_page_token": "users-page-2",
				})
				return
			}
			if r.URL.Query().Get("next_page_token") != "users-page-2" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"users": []map[string]interface{}{
					{
						"id":         "user-2",
						"email":      "bob@example.com",
						"first_name": "Bob",
						"last_name":  "Builder",
						"type":       1,
						"status":     "active",
						"role_id":    "role-1",
						"role_name":  "Owner",
					},
				},
			})
		case "/v2/groups":
			if r.Header.Get("Authorization") != "Bearer zoom-access-token" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"groups": []map[string]interface{}{
					{"id": "group-1", "name": "security", "total_members": 1},
				},
			})
		case "/v2/roles":
			if r.Header.Get("Authorization") != "Bearer zoom-access-token" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"roles": []map[string]interface{}{
					{"id": "role-1", "name": "Owner", "description": "Account owner", "total_members": 2},
				},
			})
		case "/v2/groups/group-1/members":
			if r.Header.Get("Authorization") != "Bearer zoom-access-token" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"members": []map[string]interface{}{
					{
						"id":         "user-1",
						"email":      "alice@example.com",
						"first_name": "Alice",
						"last_name":  "Admin",
						"type":       2,
						"status":     "active",
						"role_id":    "role-1",
						"role_name":  "Owner",
					},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	provider := NewZoomProvider()
	if err := provider.Configure(context.Background(), map[string]interface{}{
		"account_id":    "zoom-account-id",
		"client_id":     "zoom-client-id",
		"client_secret": "zoom-client-secret",
		"base_url":      server.URL + "/v2",
		"token_url":     server.URL + "/oauth/token",
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
	if atomic.LoadInt32(&tokenCalls) != 1 {
		t.Fatalf("token endpoint called %d times, want 1", atomic.LoadInt32(&tokenCalls))
	}

	rowsByTable := map[string]int64{}
	for _, table := range result.Tables {
		rowsByTable[table.Name] = table.Rows
	}

	expected := map[string]int64{
		"zoom_users":             2,
		"zoom_groups":            1,
		"zoom_roles":             1,
		"zoom_group_memberships": 1,
	}
	for table, want := range expected {
		if got := rowsByTable[table]; got != want {
			t.Fatalf("%s rows = %d, want %d", table, got, want)
		}
	}
}

func TestZoomProviderSync_IgnoresGroupMembershipPermissionErrors(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/oauth/token":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "zoom-access-token", "expires_in": 3600})
		case "/v2/groups":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"groups": []map[string]interface{}{{"id": "group-1", "name": "security"}},
			})
		case "/v2/groups/group-1/members":
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"message":"forbidden"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	provider := NewZoomProvider()
	if err := provider.Configure(context.Background(), map[string]interface{}{
		"account_id":    "zoom-account-id",
		"client_id":     "zoom-client-id",
		"client_secret": "zoom-client-secret",
		"base_url":      server.URL + "/v2",
		"token_url":     server.URL + "/oauth/token",
	}); err != nil {
		t.Fatalf("configure failed: %v", err)
	}

	table, err := provider.syncGroupMemberships(context.Background())
	if err != nil {
		t.Fatalf("syncGroupMemberships failed: %v", err)
	}
	if table.Rows != 0 {
		t.Fatalf("syncGroupMemberships rows = %d, want 0", table.Rows)
	}
	if table.Inserted != 0 {
		t.Fatalf("syncGroupMemberships inserted = %d, want 0", table.Inserted)
	}
}

func TestZoomProviderListCollection_DetectsPaginationLoop(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/oauth/token":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "zoom-access-token", "expires_in": 3600})
		case "/v2/users":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"users":           []map[string]interface{}{{"id": "user-1", "email": "loop@example.com"}},
				"next_page_token": "repeat-token",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	provider := NewZoomProvider()
	if err := provider.Configure(context.Background(), map[string]interface{}{
		"account_id":    "zoom-account-id",
		"client_id":     "zoom-client-id",
		"client_secret": "zoom-client-secret",
		"base_url":      server.URL + "/v2",
		"token_url":     server.URL + "/oauth/token",
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
