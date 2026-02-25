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

func TestWorkdayProviderSync_TableParity(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Header.Get("Authorization") != "Bearer workday-token" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
			return
		}

		w.Header().Set("Content-Type", "application/json")

		switch req.URL.Path {
		case "/scim/v2/Users":
			startIndex, _ := strconv.Atoi(req.URL.Query().Get("startIndex"))
			resources := []map[string]interface{}{}
			switch startIndex {
			case 1:
				resources = workdayTestUsers(100, 1)
			case 101:
				resources = workdayTestUsers(1, 101)
			}

			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"totalResults": 101,
				"startIndex":   startIndex,
				"itemsPerPage": len(resources),
				"Resources":    resources,
			})
			return

		case "/scim/v2/Groups":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"totalResults": 1,
				"startIndex":   1,
				"itemsPerPage": 1,
				"Resources": []map[string]interface{}{{
					"id":          "group-1",
					"displayName": "Security",
					"externalId":  "sec-group",
					"members": []map[string]interface{}{
						{"value": "user-1"},
						{"value": "user-2"},
					},
					"meta": map[string]interface{}{
						"created":      "2026-02-24T08:00:00Z",
						"lastModified": "2026-02-25T09:00:00Z",
					},
				}},
			})
			return
		default:
			http.NotFound(w, req)
		}
	}))
	defer server.Close()

	provider := NewWorkdayProvider()
	if err := provider.Configure(context.Background(), map[string]interface{}{
		"url":   server.URL,
		"token": "workday-token",
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

	if rowsByTable["workday_users"] != 101 {
		t.Fatalf("workday_users rows = %d, want 101", rowsByTable["workday_users"])
	}
	if rowsByTable["workday_groups"] != 1 {
		t.Fatalf("workday_groups rows = %d, want 1", rowsByTable["workday_groups"])
	}
	if rowsByTable["workday_group_memberships"] != 2 {
		t.Fatalf("workday_group_memberships rows = %d, want 2", rowsByTable["workday_group_memberships"])
	}
}

func TestWorkdayProviderSync_IgnoresPermissionDeniedGroupEndpoints(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Header.Get("Authorization") != "Bearer workday-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")

		switch req.URL.Path {
		case "/scim/v2/Users":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"totalResults": 1,
				"startIndex":   1,
				"itemsPerPage": 1,
				"Resources": []map[string]interface{}{{
					"id":          "user-1",
					"userName":    "user-1",
					"displayName": "User 1",
					"emails": []map[string]interface{}{
						{"value": "user1@example.com", "primary": true},
					},
					"active": true,
				}},
			})
			return

		case "/scim/v2/Groups":
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"forbidden"}`))
			return
		default:
			http.NotFound(w, req)
		}
	}))
	defer server.Close()

	provider := NewWorkdayProvider()
	if err := provider.Configure(context.Background(), map[string]interface{}{
		"url":   server.URL,
		"token": "workday-token",
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

	if rowsByTable["workday_users"] != 1 {
		t.Fatalf("workday_users rows = %d, want 1", rowsByTable["workday_users"])
	}
	if rowsByTable["workday_groups"] != 0 {
		t.Fatalf("workday_groups rows = %d, want 0", rowsByTable["workday_groups"])
	}
	if rowsByTable["workday_group_memberships"] != 0 {
		t.Fatalf("workday_group_memberships rows = %d, want 0", rowsByTable["workday_group_memberships"])
	}
}

func TestWorkdayProviderRequest_RejectsCrossHostURL(t *testing.T) {
	t.Parallel()

	provider := NewWorkdayProvider()
	if err := provider.Configure(context.Background(), map[string]interface{}{
		"url":   "https://writer.workday.com",
		"token": "workday-token",
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

func workdayTestUsers(count int, start int) []map[string]interface{} {
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
			"emails": []map[string]interface{}{
				{"value": "user" + strconv.Itoa(id) + "@example.com", "primary": true},
			},
			"active":         true,
			"employeeNumber": "EMP-" + strconv.Itoa(id),
			"department":     "Security",
			"title":          "Engineer",
			"meta": map[string]interface{}{
				"created":      "2026-02-24T08:00:00Z",
				"lastModified": "2026-02-25T09:00:00Z",
			},
		})
	}
	return users
}
