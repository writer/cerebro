package providers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestOneLoginProviderSync_TableParity(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch req.URL.Path {
		case "/auth/oauth2/v2/token":
			username, password, ok := req.BasicAuth()
			if !ok || username != "onelogin-client" || password != "onelogin-secret" {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
				return
			}

			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "onelogin-token",
				"expires_in":   3600,
			})
			return

		case "/api/2/users":
			if req.Header.Get("Authorization") != "Bearer onelogin-token" {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
				return
			}

			page, _ := strconv.Atoi(req.URL.Query().Get("page"))
			users := []map[string]interface{}{}
			switch page {
			case 1:
				users = oneLoginTestUsers(100, 1)
			case 2:
				users = oneLoginTestUsers(1, 101)
			}

			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": users,
			})
			return

		case "/api/2/roles":
			if req.Header.Get("Authorization") != "Bearer onelogin-token" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": []map[string]interface{}{{
					"id":          "role-1",
					"name":        "Security",
					"users_count": 2,
				}},
			})
			return

		case "/api/2/roles/role-1/users":
			if req.Header.Get("Authorization") != "Bearer onelogin-token" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": []map[string]interface{}{
					{
						"id":         "user-1",
						"username":   "user-1",
						"email":      "user1@example.com",
						"status":     1,
						"first_name": "User",
						"last_name":  "1",
					},
					{
						"id":         "user-2",
						"username":   "user-2",
						"email":      "user2@example.com",
						"status":     1,
						"first_name": "User",
						"last_name":  "2",
					},
				},
			})
			return

		default:
			http.NotFound(w, req)
		}
	}))
	defer server.Close()

	provider := NewOneLoginProvider()
	if err := provider.Configure(context.Background(), map[string]interface{}{
		"url":           server.URL,
		"client_id":     "onelogin-client",
		"client_secret": "onelogin-secret",
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

	if rowsByTable["onelogin_users"] != 101 {
		t.Fatalf("onelogin_users rows = %d, want 101", rowsByTable["onelogin_users"])
	}
	if rowsByTable["onelogin_roles"] != 1 {
		t.Fatalf("onelogin_roles rows = %d, want 1", rowsByTable["onelogin_roles"])
	}
	if rowsByTable["onelogin_role_memberships"] != 2 {
		t.Fatalf("onelogin_role_memberships rows = %d, want 2", rowsByTable["onelogin_role_memberships"])
	}
}

func TestOneLoginProviderSync_IgnoresPermissionDeniedRoleEndpoints(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch req.URL.Path {
		case "/auth/oauth2/v2/token":
			username, password, ok := req.BasicAuth()
			if !ok || username != "onelogin-client" || password != "onelogin-secret" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "onelogin-token",
				"expires_in":   3600,
			})
			return

		case "/api/2/users":
			if req.Header.Get("Authorization") != "Bearer onelogin-token" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": []map[string]interface{}{{
					"id":         "user-1",
					"username":   "user-1",
					"email":      "user1@example.com",
					"first_name": "User",
					"last_name":  "1",
					"status":     1,
				}},
			})
			return

		case "/api/2/roles":
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"forbidden"}`))
			return

		default:
			http.NotFound(w, req)
		}
	}))
	defer server.Close()

	provider := NewOneLoginProvider()
	if err := provider.Configure(context.Background(), map[string]interface{}{
		"url":           server.URL,
		"client_id":     "onelogin-client",
		"client_secret": "onelogin-secret",
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

	if rowsByTable["onelogin_users"] != 1 {
		t.Fatalf("onelogin_users rows = %d, want 1", rowsByTable["onelogin_users"])
	}
	if rowsByTable["onelogin_roles"] != 0 {
		t.Fatalf("onelogin_roles rows = %d, want 0", rowsByTable["onelogin_roles"])
	}
	if rowsByTable["onelogin_role_memberships"] != 0 {
		t.Fatalf("onelogin_role_memberships rows = %d, want 0", rowsByTable["onelogin_role_memberships"])
	}
}

func TestOneLoginProviderRequest_RejectsCrossHostURL(t *testing.T) {
	t.Parallel()

	provider := NewOneLoginProvider()
	if err := provider.Configure(context.Background(), map[string]interface{}{
		"url":           "https://api.us.onelogin.com",
		"client_id":     "onelogin-client",
		"client_secret": "onelogin-secret",
	}); err != nil {
		t.Fatalf("configure failed: %v", err)
	}

	_, err := provider.request(context.Background(), "https://evil.example.com/api/2/users")
	if err == nil {
		t.Fatal("expected cross-host URL rejection")
	}
	if !strings.Contains(err.Error(), "host mismatch") {
		t.Fatalf("expected host mismatch error, got %v", err)
	}
}

func oneLoginTestUsers(count int, start int) []map[string]interface{} {
	users := make([]map[string]interface{}, 0, count)
	for i := 0; i < count; i++ {
		id := start + i
		users = append(users, map[string]interface{}{
			"id":                 "user-" + strconv.Itoa(id),
			"username":           "user-" + strconv.Itoa(id),
			"email":              "user" + strconv.Itoa(id) + "@example.com",
			"firstname":          "User",
			"lastname":           strconv.Itoa(id),
			"status":             1,
			"distinguished_name": "CN=User " + strconv.Itoa(id),
			"department":         "Security",
			"title":              "Engineer",
			"last_login":         "2026-02-25T09:00:00Z",
			"activated_at":       "2026-02-20T09:00:00Z",
			"created_at":         "2026-02-15T09:00:00Z",
			"updated_at":         "2026-02-25T10:00:00Z",
		})
	}
	return users
}
