package providers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAtlassianProviderSync_TableParity(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, token, ok := r.BasicAuth()
		if !ok || user != "admin@example.com" || token != "token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/rest/api/3/project/search":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"values": []map[string]interface{}{
					{
						"id":             "10000",
						"key":            "SEC",
						"name":           "Security",
						"projectTypeKey": "software",
						"simplified":     true,
						"style":          "next-gen",
						"isPrivate":      false,
						"archived":       false,
						"lead": map[string]interface{}{
							"accountId": "acct-1",
						},
					},
				},
				"isLast":     true,
				"startAt":    0,
				"maxResults": 50,
			})
		case "/rest/api/3/users/search":
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{
					"accountId":    "acct-1",
					"displayName":  "Alice Admin",
					"emailAddress": "alice@example.com",
					"active":       true,
					"accountType":  "atlassian",
				},
			})
		case "/rest/api/3/group/bulk":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"values": []map[string]interface{}{
					{"groupId": "group-1", "name": "jira-admins", "self": "https://example.atlassian.net/rest/api/3/group?groupId=group-1"},
				},
				"isLast":     true,
				"startAt":    0,
				"maxResults": 100,
			})
		case "/rest/api/3/group/member":
			if r.URL.Query().Get("groupId") != "group-1" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"values": []map[string]interface{}{
					{
						"accountId":    "acct-1",
						"displayName":  "Alice Admin",
						"emailAddress": "alice@example.com",
						"active":       true,
						"accountType":  "atlassian",
					},
				},
				"isLast":     true,
				"startAt":    0,
				"maxResults": 100,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	provider := NewAtlassianProvider()
	if err := provider.Configure(context.Background(), map[string]interface{}{
		"base_url":  server.URL,
		"email":     "admin@example.com",
		"api_token": "token",
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
		"atlassian_projects":          1,
		"atlassian_users":             1,
		"atlassian_groups":            1,
		"atlassian_group_memberships": 1,
	}
	for table, want := range expected {
		if got := rowsByTable[table]; got != want {
			t.Fatalf("%s rows = %d, want %d", table, got, want)
		}
	}
}

func TestAtlassianProviderSync_IgnoresGroupMembershipPermissionErrors(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/rest/api/3/group/bulk":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"values": []map[string]interface{}{{"groupId": "group-1", "name": "jira-admins"}},
				"isLast": true,
			})
		case "/rest/api/3/group/member":
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"forbidden"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	provider := NewAtlassianProvider()
	if err := provider.Configure(context.Background(), map[string]interface{}{
		"base_url":  server.URL,
		"email":     "admin@example.com",
		"api_token": "token",
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
