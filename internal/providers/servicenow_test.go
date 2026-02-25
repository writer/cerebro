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

func TestServiceNowProviderSync_TableParity(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Header.Get("Authorization") != "Bearer servicenow-token" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
			return
		}

		w.Header().Set("Content-Type", "application/json")

		switch req.URL.Path {
		case "/api/now/table/sys_user":
			offset, _ := strconv.Atoi(req.URL.Query().Get("sysparm_offset"))
			if offset == 0 {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"result": serviceNowTestUsers(200, 1),
				})
				return
			}
			if offset == 200 {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"result": serviceNowTestUsers(1, 201),
				})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"result": []map[string]interface{}{}})
			return
		case "/api/now/table/sys_user_group":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"result": []map[string]interface{}{{
					"sys_id":         "group-1",
					"name":           "Security",
					"description":    "Security team",
					"manager":        map[string]interface{}{"value": "user-1"},
					"active":         true,
					"sys_created_on": "2026-02-24 08:00:00",
					"sys_updated_on": "2026-02-25 09:00:00",
				}},
			})
			return
		case "/api/now/table/sys_user_grmember":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"result": []map[string]interface{}{
					{
						"sys_id":         "membership-1",
						"user":           map[string]interface{}{"value": "user-1"},
						"group":          map[string]interface{}{"value": "group-1"},
						"active":         true,
						"sys_created_on": "2026-02-24 08:00:00",
						"sys_updated_on": "2026-02-25 09:00:00",
					},
					{
						"sys_id":         "membership-2",
						"user":           map[string]interface{}{"value": "user-2"},
						"group":          map[string]interface{}{"value": "group-1"},
						"active":         true,
						"sys_created_on": "2026-02-24 08:00:00",
						"sys_updated_on": "2026-02-25 09:00:00",
					},
				},
			})
			return
		default:
			http.NotFound(w, req)
		}
	}))
	defer server.Close()

	provider := NewServiceNowProvider()
	if err := provider.Configure(context.Background(), map[string]interface{}{
		"url":   server.URL,
		"token": "servicenow-token",
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

	if rowsByTable["servicenow_users"] != 201 {
		t.Fatalf("servicenow_users rows = %d, want 201", rowsByTable["servicenow_users"])
	}
	if rowsByTable["servicenow_groups"] != 1 {
		t.Fatalf("servicenow_groups rows = %d, want 1", rowsByTable["servicenow_groups"])
	}
	if rowsByTable["servicenow_group_memberships"] != 2 {
		t.Fatalf("servicenow_group_memberships rows = %d, want 2", rowsByTable["servicenow_group_memberships"])
	}
}

func TestServiceNowProviderSync_IgnoresPermissionDeniedChildTables(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Header.Get("Authorization") != "Bearer servicenow-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")

		switch req.URL.Path {
		case "/api/now/table/sys_user":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"result": []map[string]interface{}{{
					"sys_id":         "user-1",
					"name":           "User 1",
					"user_name":      "user-1",
					"email":          "user1@example.com",
					"active":         true,
					"sys_created_on": "2026-02-24 08:00:00",
					"sys_updated_on": "2026-02-25 09:00:00",
				}},
			})
			return
		case "/api/now/table/sys_user_group":
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"forbidden"}`))
			return
		case "/api/now/table/sys_user_grmember":
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"forbidden"}`))
			return
		default:
			http.NotFound(w, req)
		}
	}))
	defer server.Close()

	provider := NewServiceNowProvider()
	if err := provider.Configure(context.Background(), map[string]interface{}{
		"url":   server.URL,
		"token": "servicenow-token",
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

	if rowsByTable["servicenow_users"] != 1 {
		t.Fatalf("servicenow_users rows = %d, want 1", rowsByTable["servicenow_users"])
	}
	if rowsByTable["servicenow_groups"] != 0 {
		t.Fatalf("servicenow_groups rows = %d, want 0", rowsByTable["servicenow_groups"])
	}
	if rowsByTable["servicenow_group_memberships"] != 0 {
		t.Fatalf("servicenow_group_memberships rows = %d, want 0", rowsByTable["servicenow_group_memberships"])
	}
}

func TestServiceNowProviderRequest_RejectsCrossHostURL(t *testing.T) {
	t.Parallel()

	provider := NewServiceNowProvider()
	if err := provider.Configure(context.Background(), map[string]interface{}{
		"url":   "https://writer.service-now.com",
		"token": "servicenow-token",
	}); err != nil {
		t.Fatalf("configure failed: %v", err)
	}

	_, err := provider.request(context.Background(), "https://evil.example.com/api/now/table/sys_user")
	if err == nil {
		t.Fatal("expected cross-host URL rejection")
	}
	if !strings.Contains(err.Error(), "host mismatch") {
		t.Fatalf("expected host mismatch error, got %v", err)
	}
}

func serviceNowTestUsers(count int, start int) []map[string]interface{} {
	users := make([]map[string]interface{}, 0, count)
	for i := 0; i < count; i++ {
		id := start + i
		users = append(users, map[string]interface{}{
			"sys_id":          "user-" + strconv.Itoa(id),
			"name":            "User " + strconv.Itoa(id),
			"user_name":       "user-" + strconv.Itoa(id),
			"email":           "user" + strconv.Itoa(id) + "@example.com",
			"title":           "Engineer",
			"department":      map[string]interface{}{"value": "dept-security", "display_value": "Security"},
			"active":          true,
			"last_login_time": "2026-02-25 10:00:00",
			"sys_created_on":  "2026-02-24 08:00:00",
			"sys_updated_on":  "2026-02-25 09:00:00",
		})
	}
	return users
}
