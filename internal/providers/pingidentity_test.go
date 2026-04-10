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

func TestPingIdentityProviderSync_TableParity(t *testing.T) {
	t.Parallel()

	var tokenCalls int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/env-1/as/token":
			atomic.AddInt32(&tokenCalls, 1)
			if req.Method != http.MethodPost {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"ping-token","expires_in":3600}`))
			return

		case "/v1/environments/env-1/users":
			if req.Header.Get("Authorization") != "Bearer ping-token" {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"message":"unauthorized"}`))
				return
			}

			cursor := req.URL.Query().Get("cursor")
			if cursor == "" {
				users := pingIdentityTestUsers(100, 1)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"_embedded": map[string]interface{}{"users": users},
					"_links": map[string]interface{}{
						"next": map[string]interface{}{"href": "/v1/environments/env-1/users?cursor=page-2&limit=100"},
					},
				})
				return
			}

			if cursor == "page-2" {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"_embedded": map[string]interface{}{"users": pingIdentityTestUsers(1, 101)},
				})
				return
			}

			_ = json.NewEncoder(w).Encode(map[string]interface{}{"_embedded": map[string]interface{}{"users": []map[string]interface{}{}}})
			return

		case "/v1/environments/env-1/groups":
			if req.Header.Get("Authorization") != "Bearer ping-token" {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"message":"unauthorized"}`))
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"_embedded": map[string]interface{}{"groups": []map[string]interface{}{{
					"id":          "group-1",
					"name":        "Engineering",
					"description": "Engineering team",
				}}},
			})
			return

		case "/v1/environments/env-1/groups/group-1/members":
			if req.Header.Get("Authorization") != "Bearer ping-token" {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"message":"unauthorized"}`))
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"_embedded": map[string]interface{}{"members": []map[string]interface{}{
					{"id": "membership-1", "user": map[string]interface{}{"id": "user-1", "username": "user-1", "email": "user1@example.com"}},
					{"id": "membership-2", "user": map[string]interface{}{"id": "user-2", "username": "user-2", "email": "user2@example.com"}},
				}},
			})
			return
		default:
			http.NotFound(w, req)
		}
	}))
	defer server.Close()

	provider := NewPingIdentityProvider()
	if err := provider.Configure(context.Background(), map[string]interface{}{
		"api_url":        server.URL,
		"auth_url":       server.URL,
		"environment_id": "env-1",
		"client_id":      "ping-client",
		"client_secret":  "ping-secret",
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

	if rowsByTable["pingidentity_users"] != 101 {
		t.Fatalf("pingidentity_users rows = %d, want 101", rowsByTable["pingidentity_users"])
	}
	if rowsByTable["pingidentity_groups"] != 1 {
		t.Fatalf("pingidentity_groups rows = %d, want 1", rowsByTable["pingidentity_groups"])
	}
	if rowsByTable["pingidentity_group_memberships"] != 2 {
		t.Fatalf("pingidentity_group_memberships rows = %d, want 2", rowsByTable["pingidentity_group_memberships"])
	}

	if got := atomic.LoadInt32(&tokenCalls); got != 1 {
		t.Fatalf("token calls = %d, want 1", got)
	}
}

func TestPingIdentityProviderSync_IgnoresPermissionDeniedMembershipEndpoints(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/env-1/as/token":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"ping-token","expires_in":3600}`))
			return

		case "/v1/environments/env-1/users":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"_embedded": map[string]interface{}{"users": []map[string]interface{}{{
				"id":       "user-1",
				"username": "user-1",
				"email":    "user1@example.com",
			}}}})
			return

		case "/v1/environments/env-1/groups":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"_embedded": map[string]interface{}{"groups": []map[string]interface{}{
				{"id": "group-1", "name": "Engineering"},
				{"id": "group-2", "name": "Security"},
			}}})
			return

		case "/v1/environments/env-1/groups/group-1/members":
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"message":"forbidden"}`))
			return

		case "/v1/environments/env-1/groups/group-2/members":
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message":"not found"}`))
			return

		default:
			http.NotFound(w, req)
		}
	}))
	defer server.Close()

	provider := NewPingIdentityProvider()
	if err := provider.Configure(context.Background(), map[string]interface{}{
		"api_url":        server.URL,
		"auth_url":       server.URL,
		"environment_id": "env-1",
		"client_id":      "ping-client",
		"client_secret":  "ping-secret",
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

	if rowsByTable["pingidentity_users"] != 1 {
		t.Fatalf("pingidentity_users rows = %d, want 1", rowsByTable["pingidentity_users"])
	}
	if rowsByTable["pingidentity_groups"] != 2 {
		t.Fatalf("pingidentity_groups rows = %d, want 2", rowsByTable["pingidentity_groups"])
	}
	if rowsByTable["pingidentity_group_memberships"] != 0 {
		t.Fatalf("pingidentity_group_memberships rows = %d, want 0", rowsByTable["pingidentity_group_memberships"])
	}
}

func TestPingIdentityProviderRequest_RejectsCrossHostURL(t *testing.T) {
	t.Parallel()

	provider := NewPingIdentityProvider()
	if err := provider.Configure(context.Background(), map[string]interface{}{
		"api_url":        "https://api.pingone.com",
		"auth_url":       "https://auth.pingone.com",
		"environment_id": "env-1",
		"client_id":      "ping-client",
		"client_secret":  "ping-secret",
	}); err != nil {
		t.Fatalf("configure failed: %v", err)
	}

	_, err := provider.request(context.Background(), "https://evil.example.com/v1/environments/env-1/users")
	if err == nil {
		t.Fatal("expected cross-host URL rejection")
		return
	}
	if !strings.Contains(err.Error(), "host mismatch") {
		t.Fatalf("expected host mismatch error, got %v", err)
	}
}

func TestPingIdentityProviderRequest_RefreshesTokenOnUnauthorized(t *testing.T) {
	t.Parallel()

	var tokenCalls int32
	var firstUsersCall int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/env-1/as/token":
			call := atomic.AddInt32(&tokenCalls, 1)
			token := "ping-token-1"
			if call > 1 {
				token = "ping-token-2"
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"` + token + `","expires_in":3600}`))
			return

		case "/v1/environments/env-1/users":
			if atomic.AddInt32(&firstUsersCall, 1) == 1 {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"message":"expired"}`))
				return
			}
			if req.Header.Get("Authorization") != "Bearer ping-token-2" {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"message":"unauthorized"}`))
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"_embedded": map[string]interface{}{"users": []map[string]interface{}{{
				"id":       "user-1",
				"username": "user-1",
				"email":    "user1@example.com",
			}}}})
			return

		default:
			http.NotFound(w, req)
		}
	}))
	defer server.Close()

	provider := NewPingIdentityProvider()
	if err := provider.Configure(context.Background(), map[string]interface{}{
		"api_url":        server.URL,
		"auth_url":       server.URL,
		"environment_id": "env-1",
		"client_id":      "ping-client",
		"client_secret":  "ping-secret",
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

func pingIdentityTestUsers(count int, start int) []map[string]interface{} {
	users := make([]map[string]interface{}, 0, count)
	for i := 0; i < count; i++ {
		id := start + i
		users = append(users, map[string]interface{}{
			"id":          "user-" + strconv.Itoa(id),
			"username":    "user-" + strconv.Itoa(id),
			"email":       "user" + strconv.Itoa(id) + "@example.com",
			"given_name":  "User",
			"family_name": strconv.Itoa(id),
			"enabled":     true,
			"status":      "OK",
			"created_at":  "2026-02-25T10:00:00Z",
			"updated_at":  "2026-02-25T12:00:00Z",
		})
	}
	return users
}
