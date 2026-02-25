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

func TestJumpCloudProviderSync_TableParity(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Header.Get("x-api-key") != "jumpcloud-token" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
			return
		}
		if req.Header.Get("x-org-id") != "org-123" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"missing org"}`))
			return
		}

		w.Header().Set("Content-Type", "application/json")

		switch req.URL.Path {
		case "/api/systemusers":
			skip, _ := strconv.Atoi(req.URL.Query().Get("skip"))
			users := []map[string]interface{}{}
			switch skip {
			case 0:
				users = jumpCloudTestUsers(100, 1)
			case 100:
				users = jumpCloudTestUsers(1, 101)
			}

			_ = json.NewEncoder(w).Encode(map[string]interface{}{"results": users})
			return

		case "/api/v2/usergroups":
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{
					"id":                   "group-1",
					"name":                 "Engineering",
					"description":          "Engineering team",
					"membershipMethod":     "MANUAL",
					"type":                 "user_group",
					"organizationObjectId": "org-123",
				},
				{
					"id":               "group-2",
					"name":             "Security",
					"membershipMethod": "MANUAL",
					"type":             "user_group",
				},
			})
			return

		case "/api/v2/usergroups/group-1/members":
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{
					"from": map[string]interface{}{"id": "group-1", "type": "user_group"},
					"to":   map[string]interface{}{"id": "user-1", "type": "user"},
				},
				{
					"from": map[string]interface{}{"id": "group-1", "type": "user_group"},
					"to":   map[string]interface{}{"id": "user-2", "type": "user"},
				},
			})
			return

		case "/api/v2/usergroups/group-2/members":
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{})
			return

		default:
			http.NotFound(w, req)
		}
	}))
	defer server.Close()

	provider := NewJumpCloudProvider()
	if err := provider.Configure(context.Background(), map[string]interface{}{
		"url":       server.URL,
		"api_token": "jumpcloud-token",
		"org_id":    "org-123",
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

	if rowsByTable["jumpcloud_users"] != 101 {
		t.Fatalf("jumpcloud_users rows = %d, want 101", rowsByTable["jumpcloud_users"])
	}
	if rowsByTable["jumpcloud_groups"] != 2 {
		t.Fatalf("jumpcloud_groups rows = %d, want 2", rowsByTable["jumpcloud_groups"])
	}
	if rowsByTable["jumpcloud_group_memberships"] != 2 {
		t.Fatalf("jumpcloud_group_memberships rows = %d, want 2", rowsByTable["jumpcloud_group_memberships"])
	}
}

func TestJumpCloudProviderSync_IgnoresPermissionDeniedMembershipEndpoints(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Header.Get("x-api-key") != "jumpcloud-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")

		switch req.URL.Path {
		case "/api/systemusers":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"results": []map[string]interface{}{jumpCloudTestUsers(1, 1)[0]},
			})
			return

		case "/api/v2/usergroups":
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{"id": "group-1", "name": "Engineering", "type": "user_group"},
				{"id": "group-2", "name": "Security", "type": "user_group"},
			})
			return

		case "/api/v2/usergroups/group-1/members":
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"forbidden"}`))
			return

		case "/api/v2/usergroups/group-2/members":
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"not found"}`))
			return

		default:
			http.NotFound(w, req)
		}
	}))
	defer server.Close()

	provider := NewJumpCloudProvider()
	if err := provider.Configure(context.Background(), map[string]interface{}{
		"url":       server.URL,
		"api_token": "jumpcloud-token",
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

	if rowsByTable["jumpcloud_users"] != 1 {
		t.Fatalf("jumpcloud_users rows = %d, want 1", rowsByTable["jumpcloud_users"])
	}
	if rowsByTable["jumpcloud_groups"] != 2 {
		t.Fatalf("jumpcloud_groups rows = %d, want 2", rowsByTable["jumpcloud_groups"])
	}
	if rowsByTable["jumpcloud_group_memberships"] != 0 {
		t.Fatalf("jumpcloud_group_memberships rows = %d, want 0", rowsByTable["jumpcloud_group_memberships"])
	}
}

func TestJumpCloudProviderRequest_RejectsCrossHostURL(t *testing.T) {
	t.Parallel()

	provider := NewJumpCloudProvider()
	if err := provider.Configure(context.Background(), map[string]interface{}{
		"url":       "https://console.jumpcloud.com",
		"api_token": "jumpcloud-token",
	}); err != nil {
		t.Fatalf("configure failed: %v", err)
	}

	_, err := provider.requestV2(context.Background(), "https://evil.example.com/api/v2/usergroups")
	if err == nil {
		t.Fatal("expected cross-host URL rejection")
	}
	if !strings.Contains(err.Error(), "host mismatch") {
		t.Fatalf("expected host mismatch error, got %v", err)
	}
}

func jumpCloudTestUsers(count int, start int) []map[string]interface{} {
	users := make([]map[string]interface{}, 0, count)
	for i := 0; i < count; i++ {
		id := start + i
		users = append(users, map[string]interface{}{
			"_id":                            "user-" + strconv.Itoa(id),
			"username":                       "user-" + strconv.Itoa(id),
			"email":                          "user" + strconv.Itoa(id) + "@example.com",
			"firstname":                      "User",
			"lastname":                       strconv.Itoa(id),
			"displayname":                    "User " + strconv.Itoa(id),
			"department":                     "Engineering",
			"jobTitle":                       "Engineer",
			"location":                       "Remote",
			"employeeIdentifier":             "E" + strconv.Itoa(1000+id),
			"employeeType":                   "employee",
			"suspended":                      false,
			"activated":                      true,
			"enable_user_portal_multifactor": true,
			"password_never_expires":         false,
			"created":                        "2026-02-15T09:00:00Z",
			"password_expiration_date":       "2026-05-15T09:00:00Z",
			"updated":                        "2026-02-25T10:00:00Z",
		})
	}
	return users
}
