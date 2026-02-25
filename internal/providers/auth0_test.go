package providers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

func TestAuth0ProviderSync_TableParity(t *testing.T) {
	t.Parallel()

	var tokenCalls int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/oauth/token":
			atomic.AddInt32(&tokenCalls, 1)
			if req.Method != http.MethodPost {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"auth0-token","expires_in":3600}`))
			return
		case "/api/v2/users":
			if req.Header.Get("Authorization") != "Bearer auth0-token" {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"message":"unauthorized"}`))
				return
			}

			page := req.URL.Query().Get("page")
			if page == "0" {
				users := make([]map[string]interface{}, 0, auth0DefaultPageSize)
				for i := 0; i < auth0DefaultPageSize; i++ {
					users = append(users, map[string]interface{}{
						"user_id":       "auth0|" + strconv.Itoa(i),
						"email":         "user" + strconv.Itoa(i) + "@example.com",
						"name":          "User " + strconv.Itoa(i),
						"nickname":      "user-" + strconv.Itoa(i),
						"created_at":    "2026-02-24T10:00:00Z",
						"updated_at":    "2026-02-24T12:00:00Z",
						"emailVerified": true,
					})
				}
				_ = json.NewEncoder(w).Encode(users)
				return
			}
			if page == "1" {
				_ = json.NewEncoder(w).Encode([]map[string]interface{}{
					{
						"user_id":       "auth0|100",
						"email":         "user100@example.com",
						"name":          "User 100",
						"nickname":      "user-100",
						"created_at":    "2026-02-24T10:00:00Z",
						"updated_at":    "2026-02-24T12:00:00Z",
						"emailVerified": true,
					},
				})
				return
			}
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{})
			return
		case "/api/v2/roles":
			if req.Header.Get("Authorization") != "Bearer auth0-token" {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"message":"unauthorized"}`))
				return
			}
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{{
				"id":          "role-1",
				"name":        "Admin",
				"description": "Administrators",
			}})
			return
		case "/api/v2/roles/role-1/users":
			if req.Header.Get("Authorization") != "Bearer auth0-token" {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"message":"unauthorized"}`))
				return
			}
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{{
				"user_id":  "auth0|0",
				"email":    "user0@example.com",
				"name":     "User 0",
				"nickname": "user-0",
			}})
			return
		default:
			http.NotFound(w, req)
		}
	}))
	defer server.Close()

	provider := NewAuth0Provider()
	if err := provider.Configure(context.Background(), map[string]interface{}{
		"domain":        server.URL,
		"client_id":     "auth0-client",
		"client_secret": "auth0-secret",
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

	if rowsByTable["auth0_users"] != 101 {
		t.Fatalf("auth0_users rows = %d, want 101", rowsByTable["auth0_users"])
	}
	if rowsByTable["auth0_roles"] != 1 {
		t.Fatalf("auth0_roles rows = %d, want 1", rowsByTable["auth0_roles"])
	}
	if rowsByTable["auth0_role_memberships"] != 1 {
		t.Fatalf("auth0_role_memberships rows = %d, want 1", rowsByTable["auth0_role_memberships"])
	}

	if got := atomic.LoadInt32(&tokenCalls); got != 1 {
		t.Fatalf("token calls = %d, want 1", got)
	}
}

func TestAuth0ProviderSync_IgnoresRoleMembershipPermissionErrors(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/oauth/token":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"auth0-token","expires_in":3600}`))
			return
		case "/api/v2/users":
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{{"user_id": "auth0|1", "email": "user1@example.com"}})
			return
		case "/api/v2/roles":
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{{"id": "role-1", "name": "Admin"}})
			return
		case "/api/v2/roles/role-1/users":
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"message":"forbidden"}`))
			return
		default:
			http.NotFound(w, req)
		}
	}))
	defer server.Close()

	provider := NewAuth0Provider()
	if err := provider.Configure(context.Background(), map[string]interface{}{
		"domain":        server.URL,
		"client_id":     "auth0-client",
		"client_secret": "auth0-secret",
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

	if rowsByTable["auth0_users"] != 1 {
		t.Fatalf("auth0_users rows = %d, want 1", rowsByTable["auth0_users"])
	}
	if rowsByTable["auth0_roles"] != 1 {
		t.Fatalf("auth0_roles rows = %d, want 1", rowsByTable["auth0_roles"])
	}
	if rowsByTable["auth0_role_memberships"] != 0 {
		t.Fatalf("auth0_role_memberships rows = %d, want 0", rowsByTable["auth0_role_memberships"])
	}
}

func TestAuth0ProviderRequest_RefreshesTokenOnUnauthorized(t *testing.T) {
	t.Parallel()

	var tokenCalls int32
	var firstUsersCall int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/oauth/token":
			call := atomic.AddInt32(&tokenCalls, 1)
			token := "auth0-token-1"
			if call > 1 {
				token = "auth0-token-2"
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"` + token + `","expires_in":3600}`))
			return
		case "/api/v2/users":
			if atomic.AddInt32(&firstUsersCall, 1) == 1 {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"message":"expired"}`))
				return
			}
			if req.Header.Get("Authorization") != "Bearer auth0-token-2" {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"message":"unauthorized"}`))
				return
			}
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{{"user_id": "auth0|1", "email": "user1@example.com"}})
			return
		default:
			http.NotFound(w, req)
		}
	}))
	defer server.Close()

	provider := NewAuth0Provider()
	if err := provider.Configure(context.Background(), map[string]interface{}{
		"domain":        server.URL,
		"client_id":     "auth0-client",
		"client_secret": "auth0-secret",
	}); err != nil {
		t.Fatalf("configure failed: %v", err)
	}

	users, err := provider.listUsers(context.Background())
	if err != nil {
		t.Fatalf("list users failed: %v", err)
	}
	if len(users) != 1 {
		t.Fatalf("users len = %d, want 1", len(users))
	}

	if got := atomic.LoadInt32(&tokenCalls); got != 2 {
		t.Fatalf("token calls = %d, want 2", got)
	}

	if got := provider.token; !strings.Contains(got, "token-2") {
		t.Fatalf("expected refreshed token to be cached, got %q", got)
	}
}
