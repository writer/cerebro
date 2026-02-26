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

func TestSailPointProviderSync_TableParity(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Header.Get("Authorization") != "Bearer sailpoint-token" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"message":"unauthorized"}`))
			return
		}

		w.Header().Set("Content-Type", "application/json")

		switch req.URL.Path {
		case "/scim/v2/Users":
			startIndex, _ := strconv.Atoi(req.URL.Query().Get("startIndex"))
			if startIndex == 1 {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"Resources":    sailPointTestUsers(100, 1),
					"totalResults": 101,
					"itemsPerPage": 100,
					"startIndex":   1,
				})
				return
			}
			if startIndex == 101 {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"Resources":    sailPointTestUsers(1, 101),
					"totalResults": 101,
					"itemsPerPage": 100,
					"startIndex":   101,
				})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"Resources": []map[string]interface{}{}})
			return

		case "/scim/v2/Groups":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"Resources": []map[string]interface{}{
					{
						"id":          "group-1",
						"displayName": "Engineering",
						"members": []map[string]interface{}{
							{"value": "user-1", "display": "user-1", "$ref": "/scim/v2/Users/user-1", "type": "User"},
							{"value": "user-2", "display": "user-2", "$ref": "/scim/v2/Users/user-2", "type": "User"},
						},
					},
					{
						"id":          "group-2",
						"displayName": "Security",
					},
				},
				"totalResults": 2,
				"itemsPerPage": 100,
				"startIndex":   1,
			})
			return

		case "/scim/v2/Groups/group-2", "/scim/v2/Groups/group-2/members":
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message":"not found"}`))
			return

		default:
			http.NotFound(w, req)
		}
	}))
	defer server.Close()

	provider := NewSailPointProvider()
	if err := provider.Configure(context.Background(), map[string]interface{}{
		"url":       server.URL,
		"api_token": "sailpoint-token",
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

	if rowsByTable["sailpoint_users"] != 101 {
		t.Fatalf("sailpoint_users rows = %d, want 101", rowsByTable["sailpoint_users"])
	}
	if rowsByTable["sailpoint_groups"] != 2 {
		t.Fatalf("sailpoint_groups rows = %d, want 2", rowsByTable["sailpoint_groups"])
	}
	if rowsByTable["sailpoint_group_memberships"] != 2 {
		t.Fatalf("sailpoint_group_memberships rows = %d, want 2", rowsByTable["sailpoint_group_memberships"])
	}
}

func TestSailPointProviderSync_GroupMembershipFallbackEndpoint(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Header.Get("Authorization") != "Bearer sailpoint-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")

		switch req.URL.Path {
		case "/scim/v2/Users":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"Resources": []map[string]interface{}{sailPointTestUsers(1, 1)[0]},
			})
			return

		case "/scim/v2/Groups":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"Resources": []map[string]interface{}{{"id": "group-1", "displayName": "Engineering"}},
			})
			return

		case "/scim/v2/Groups/group-1":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"id":          "group-1",
				"displayName": "Engineering",
				"members": []map[string]interface{}{
					{"value": "user-1", "display": "user-1", "type": "User"},
				},
			})
			return

		default:
			http.NotFound(w, req)
		}
	}))
	defer server.Close()

	provider := NewSailPointProvider()
	if err := provider.Configure(context.Background(), map[string]interface{}{
		"url":       server.URL,
		"api_token": "sailpoint-token",
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

	if rowsByTable["sailpoint_group_memberships"] != 1 {
		t.Fatalf("sailpoint_group_memberships rows = %d, want 1", rowsByTable["sailpoint_group_memberships"])
	}
}

func TestSailPointProviderSync_IgnoresPermissionDeniedMembershipEndpoints(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Header.Get("Authorization") != "Bearer sailpoint-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")

		switch req.URL.Path {
		case "/scim/v2/Users":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"Resources": []map[string]interface{}{sailPointTestUsers(1, 1)[0]}})
			return

		case "/scim/v2/Groups":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"Resources": []map[string]interface{}{
					{"id": "group-1", "displayName": "Engineering"},
					{"id": "group-2", "displayName": "Security"},
				},
			})
			return

		case "/scim/v2/Groups/group-1", "/scim/v2/Groups/group-1/members":
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"message":"forbidden"}`))
			return

		case "/scim/v2/Groups/group-2", "/scim/v2/Groups/group-2/members":
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message":"not found"}`))
			return

		default:
			http.NotFound(w, req)
		}
	}))
	defer server.Close()

	provider := NewSailPointProvider()
	if err := provider.Configure(context.Background(), map[string]interface{}{
		"url":       server.URL,
		"api_token": "sailpoint-token",
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

	if rowsByTable["sailpoint_users"] != 1 {
		t.Fatalf("sailpoint_users rows = %d, want 1", rowsByTable["sailpoint_users"])
	}
	if rowsByTable["sailpoint_groups"] != 2 {
		t.Fatalf("sailpoint_groups rows = %d, want 2", rowsByTable["sailpoint_groups"])
	}
	if rowsByTable["sailpoint_group_memberships"] != 0 {
		t.Fatalf("sailpoint_group_memberships rows = %d, want 0", rowsByTable["sailpoint_group_memberships"])
	}
}

func TestSailPointProviderRequest_RejectsCrossHostURL(t *testing.T) {
	t.Parallel()

	provider := NewSailPointProvider()
	if err := provider.Configure(context.Background(), map[string]interface{}{
		"url":       "https://tenant.id.sailpoint.cloud/scim/v2",
		"api_token": "sailpoint-token",
	}); err != nil {
		t.Fatalf("configure failed: %v", err)
	}

	_, err := provider.request(context.Background(), "https://evil.example.com/scim/v2/Users")
	if err == nil {
		t.Fatal("expected cross-host URL rejection")
	}
	if !strings.Contains(err.Error(), "host mismatch") {
		t.Fatalf("expected host mismatch error, got %v", err)
	}
}

func sailPointTestUsers(count int, start int) []map[string]interface{} {
	users := make([]map[string]interface{}, 0, count)
	for i := 0; i < count; i++ {
		id := start + i
		users = append(users, map[string]interface{}{
			"id":          "user-" + strconv.Itoa(id),
			"userName":    "user-" + strconv.Itoa(id),
			"displayName": "User " + strconv.Itoa(id),
			"name": map[string]interface{}{
				"givenName":  "User",
				"familyName": strconv.Itoa(id),
			},
			"emails": []map[string]interface{}{{
				"value":   "user" + strconv.Itoa(id) + "@example.com",
				"primary": true,
			}},
			"active": true,
			"meta": map[string]interface{}{
				"created":      "2026-02-26T10:00:00Z",
				"lastModified": "2026-02-26T11:00:00Z",
			},
		})
	}
	return users
}
