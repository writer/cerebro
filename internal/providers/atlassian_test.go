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

	searchCalls := 0

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
		case "/rest/api/3/search":
			searchCalls++
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"issues": []map[string]interface{}{
					{
						"id":  "10001",
						"key": "SEC-1",
						"fields": map[string]interface{}{
							"project": map[string]interface{}{
								"key":  "SEC",
								"name": "Security",
							},
							"summary": "Investigate access review gaps",
							"status": map[string]interface{}{
								"name": "In Progress",
								"statusCategory": map[string]interface{}{
									"name": "In Progress",
								},
							},
							"issueType": map[string]interface{}{
								"name": "Task",
							},
							"priority": map[string]interface{}{
								"name": "High",
							},
							"assignee": map[string]interface{}{
								"accountId":    "acct-1",
								"emailAddress": "alice@example.com",
							},
							"reporter": map[string]interface{}{
								"accountId":    "acct-2",
								"emailAddress": "bob@example.com",
							},
							"created":        "2026-02-01T00:00:00.000+0000",
							"updated":        "2026-02-02T00:00:00.000+0000",
							"resolutiondate": nil,
							"duedate":        "2026-02-15",
							"labels":         []string{"security", "identity"},
							"components": []map[string]interface{}{
								{"name": "Identity"},
							},
							"comment": map[string]interface{}{
								"comments": []map[string]interface{}{
									{
										"id":      "20001",
										"created": "2026-02-02T01:00:00.000+0000",
										"updated": "2026-02-02T01:05:00.000+0000",
										"author": map[string]interface{}{
											"accountId":    "acct-3",
											"emailAddress": "carol@example.com",
										},
									},
								},
							},
						},
						"changelog": map[string]interface{}{
							"histories": []map[string]interface{}{
								{
									"id":      "30001",
									"created": "2026-02-02T02:00:00.000+0000",
									"author": map[string]interface{}{
										"accountId":    "acct-4",
										"emailAddress": "dave@example.com",
									},
									"items": []map[string]interface{}{
										{
											"field":      "status",
											"fromString": "To Do",
											"toString":   "In Progress",
										},
									},
								},
							},
						},
					},
				},
				"startAt":    0,
				"maxResults": 50,
				"total":      1,
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
		"atlassian_issues":            1,
		"atlassian_issue_comments":    1,
		"atlassian_issue_changelogs":  1,
	}
	for table, want := range expected {
		if got := rowsByTable[table]; got != want {
			t.Fatalf("%s rows = %d, want %d", table, got, want)
		}
	}
	if searchCalls != 1 {
		t.Fatalf("expected issue activity search to be fetched once, got %d calls", searchCalls)
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
