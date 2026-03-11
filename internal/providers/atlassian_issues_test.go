package providers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAtlassianProviderListIssueActivity_NormalizesRowsAndAppliesLookback(t *testing.T) {
	since := time.Date(2026, time.January, 5, 10, 0, 0, 0, time.UTC)
	sinceDate := since.UTC().Format("2006-01-02")

	searchCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/rest/api/3/search":
			searchCalls++
			if got := r.URL.Query().Get("startAt"); got != "0" {
				t.Fatalf("expected startAt=0, got %q", got)
			}
			if got := r.URL.Query().Get("maxResults"); got != "50" {
				t.Fatalf("expected maxResults=50, got %q", got)
			}
			if got := r.URL.Query().Get("expand"); got != "changelog" {
				t.Fatalf("expected expand=changelog, got %q", got)
			}
			if got := r.URL.Query().Get("fields"); !strings.Contains(got, "comment") || !strings.Contains(got, "resolutiondate") {
				t.Fatalf("expected fields to include comment and resolutiondate, got %q", got)
			}
			if got := r.URL.Query().Get("jql"); !strings.Contains(got, sinceDate) {
				t.Fatalf("expected jql to include since date %q, got %q", sinceDate, got)
			}

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"issues": []map[string]interface{}{
					{
						"id":  "10001",
						"key": "SEC-42",
						"fields": map[string]interface{}{
							"project": map[string]interface{}{"key": "SEC", "name": "Security"},
							"summary": "Lock down service account scopes",
							"status": map[string]interface{}{
								"name":           "Done",
								"statusCategory": map[string]interface{}{"name": "Done"},
							},
							"issueType": map[string]interface{}{"name": "Story"},
							"priority":  map[string]interface{}{"name": "Highest"},
							"assignee": map[string]interface{}{
								"accountId":    "acct-1",
								"emailAddress": "alice@example.com",
							},
							"reporter": map[string]interface{}{
								"accountId":    "acct-2",
								"emailAddress": "bob@example.com",
							},
							"created":        "2026-01-01T00:00:00.000+0000",
							"updated":        "2026-01-06T00:00:00.000+0000",
							"resolutiondate": "2026-01-07T00:00:00.000+0000",
							"duedate":        "2026-01-20",
							"labels":         []string{"security", "iam"},
							"components": []map[string]interface{}{
								{"name": "Identity"},
								{"name": "Platform"},
							},
							"comment": map[string]interface{}{
								"comments": []map[string]interface{}{
									{
										"id":      "5001",
										"created": "2026-01-06T03:00:00.000+0000",
										"updated": "2026-01-06T03:05:00.000+0000",
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
									"id":      "7001",
									"created": "2026-01-06T04:00:00.000+0000",
									"author": map[string]interface{}{
										"accountId":    "acct-4",
										"emailAddress": "dave@example.com",
									},
									"items": []map[string]interface{}{
										{"field": "status", "fromString": "In Progress", "toString": "Done"},
										{"field": "assignee", "fromString": "Bob", "toString": "Alice"},
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
	provider.baseURL = server.URL
	provider.email = "admin@example.com"
	provider.apiToken = "token"
	provider.client = server.Client()

	issueRows, commentRows, changelogRows, err := provider.listIssueActivity(context.Background(), since)
	if err != nil {
		t.Fatalf("listIssueActivity failed: %v", err)
	}
	if searchCalls != 1 {
		t.Fatalf("expected one search call, got %d", searchCalls)
	}
	if len(issueRows) != 1 {
		t.Fatalf("expected 1 issue row, got %d", len(issueRows))
	}
	if len(commentRows) != 1 {
		t.Fatalf("expected 1 issue comment row, got %d", len(commentRows))
	}
	if len(changelogRows) != 2 {
		t.Fatalf("expected 2 changelog rows, got %d", len(changelogRows))
	}

	issue := issueRows[0]
	if got := asString(issue["id"]); got != "10001" {
		t.Fatalf("expected issue id 10001, got %q", got)
	}
	if got := asString(issue["key"]); got != "SEC-42" {
		t.Fatalf("expected issue key SEC-42, got %q", got)
	}
	if got := asString(issue["project_key"]); got != "SEC" {
		t.Fatalf("expected project_key SEC, got %q", got)
	}
	if got := asString(issue["status_category"]); got != "Done" {
		t.Fatalf("expected status_category Done, got %q", got)
	}
	if got := asString(issue["assignee_account_id"]); got != "acct-1" {
		t.Fatalf("expected assignee account id acct-1, got %q", got)
	}
	if got := asString(issue["reporter_email"]); got != "bob@example.com" {
		t.Fatalf("expected reporter email bob@example.com, got %q", got)
	}

	labels, ok := issue["labels"].([]string)
	if !ok {
		t.Fatalf("expected labels as []string, got %T", issue["labels"])
	}
	if len(labels) != 2 || labels[0] != "security" || labels[1] != "iam" {
		t.Fatalf("unexpected labels: %#v", labels)
	}
	components, ok := issue["components"].([]string)
	if !ok {
		t.Fatalf("expected components as []string, got %T", issue["components"])
	}
	if len(components) != 2 || components[0] != "Identity" || components[1] != "Platform" {
		t.Fatalf("unexpected components: %#v", components)
	}

	comment := commentRows[0]
	if got := asString(comment["issue_key"]); got != "SEC-42" {
		t.Fatalf("expected issue_key SEC-42 for comment, got %q", got)
	}
	if got := asString(comment["author_account_id"]); got != "acct-3" {
		t.Fatalf("expected author_account_id acct-3, got %q", got)
	}

	firstChange := changelogRows[0]
	if got := asString(firstChange["id"]); got != "7001-0" {
		t.Fatalf("expected first changelog id 7001-0, got %q", got)
	}
	if got := asString(firstChange["field"]); got != "status" {
		t.Fatalf("expected first changelog field=status, got %q", got)
	}
	if got := asString(firstChange["from_value"]); got != "In Progress" {
		t.Fatalf("expected first changelog from_value=In Progress, got %q", got)
	}
	if got := asString(firstChange["to_value"]); got != "Done" {
		t.Fatalf("expected first changelog to_value=Done, got %q", got)
	}
}

func TestAtlassianProviderListIssueActivity_IgnoresPermissionErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rest/api/3/search" {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer server.Close()

	provider := NewAtlassianProvider()
	provider.baseURL = server.URL
	provider.email = "admin@example.com"
	provider.apiToken = "token"
	provider.client = server.Client()

	issueRows, commentRows, changelogRows, err := provider.listIssueActivity(context.Background(), time.Now().AddDate(0, 0, -30))
	if err != nil {
		t.Fatalf("expected permission error to be ignored, got %v", err)
	}
	if len(issueRows) != 0 || len(commentRows) != 0 || len(changelogRows) != 0 {
		t.Fatalf("expected no rows for ignored permission errors, got issues=%d comments=%d changelogs=%d", len(issueRows), len(commentRows), len(changelogRows))
	}
}
