package providers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestGitHubProviderFetchPullRequestsAndReviews(t *testing.T) {
	now := time.Now().UTC().Format(time.RFC3339)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/acme/platform/pulls":
			if r.URL.Query().Get("state") != "all" {
				t.Fatalf("expected state=all, got %q", r.URL.Query().Get("state"))
			}
			if r.URL.Query().Get("sort") != "updated" {
				t.Fatalf("expected sort=updated, got %q", r.URL.Query().Get("sort"))
			}
			page := r.URL.Query().Get("page")
			if page == "1" {
				writeJSON(t, w, []map[string]interface{}{
					{
						"id":         101,
						"number":     1,
						"updated_at": now,
					},
				})
				return
			}
			writeJSON(t, w, []map[string]interface{}{})
		case "/repos/acme/platform/pulls/1":
			writeJSON(t, w, map[string]interface{}{
				"id":              101,
				"number":          1,
				"user":            map[string]interface{}{"login": "alice"},
				"title":           "Harden branch protections",
				"state":           "closed",
				"draft":           false,
				"created_at":      now,
				"updated_at":      now,
				"merged_at":       now,
				"closed_at":       now,
				"merged_by":       map[string]interface{}{"login": "bob"},
				"additions":       12,
				"deletions":       3,
				"changed_files":   2,
				"review_comments": 5,
				"commits":         2,
			})
		case "/repos/acme/platform/pulls/1/reviews":
			writeJSON(t, w, []map[string]interface{}{
				{
					"id":           9001,
					"user":         map[string]interface{}{"login": "carol"},
					"state":        "APPROVED",
					"submitted_at": now,
					"body":         "Looks good",
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	provider := NewGitHubProvider()
	provider.org = "acme"
	provider.token = "test-token"
	provider.baseURL = server.URL
	provider.client = server.Client()

	rows, reviewRows, err := provider.fetchPullRequests(context.Background(), githubRepoInfo{Name: "platform", FullName: "acme/platform"}, time.Now().AddDate(0, 0, -180))
	if err != nil {
		t.Fatalf("fetchPullRequests failed: %v", err)
	}

	if len(rows) != 1 {
		t.Fatalf("expected 1 pull request row, got %d", len(rows))
	}
	if len(reviewRows) != 1 {
		t.Fatalf("expected 1 review row, got %d", len(reviewRows))
	}

	pr := rows[0]
	if got := asString(pr["repository"]); got != "acme/platform" {
		t.Fatalf("expected repository acme/platform, got %q", got)
	}
	if got := asString(pr["author_login"]); got != "alice" {
		t.Fatalf("expected author_login alice, got %q", got)
	}
	if got := asString(pr["merged_by_login"]); got != "bob" {
		t.Fatalf("expected merged_by_login bob, got %q", got)
	}
	if got, ok := asInt(pr["review_comments"]); !ok || got != 5 {
		t.Fatalf("expected review_comments 5, got %v (ok=%v)", pr["review_comments"], ok)
	}

	review := reviewRows[0]
	if got := asString(review["reviewer_login"]); got != "carol" {
		t.Fatalf("expected reviewer_login carol, got %q", got)
	}
	if got := asString(review["author_login"]); got != "alice" {
		t.Fatalf("expected review author_login alice, got %q", got)
	}
	if got := asString(review["state"]); got != "approved" {
		t.Fatalf("expected normalized review state approved, got %q", got)
	}
}

func TestGitHubProviderFetchPullRequests_AppliesLookbackCutoff(t *testing.T) {
	old := time.Now().UTC().AddDate(-1, 0, 0).Format(time.RFC3339)
	detailCalls := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/acme/platform/pulls":
			writeJSON(t, w, []map[string]interface{}{
				{
					"id":         555,
					"number":     99,
					"updated_at": old,
				},
			})
		case "/repos/acme/platform/pulls/99":
			detailCalls++
			writeJSON(t, w, map[string]interface{}{})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	provider := NewGitHubProvider()
	provider.org = "acme"
	provider.token = "test-token"
	provider.baseURL = server.URL
	provider.client = server.Client()

	rows, reviewRows, err := provider.fetchPullRequests(context.Background(), githubRepoInfo{Name: "platform"}, time.Now().AddDate(0, 0, -180))
	if err != nil {
		t.Fatalf("fetchPullRequests failed: %v", err)
	}
	if len(rows) != 0 || len(reviewRows) != 0 {
		t.Fatalf("expected no pull-request data after cutoff, got prs=%d reviews=%d", len(rows), len(reviewRows))
	}
	if detailCalls != 0 {
		t.Fatalf("expected no pull request detail fetches for stale entries, got %d", detailCalls)
	}
}

func TestGitHubProviderFetchPullRequests_IgnoresMissingReviewsEndpoint(t *testing.T) {
	now := time.Now().UTC().Format(time.RFC3339)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/acme/platform/pulls":
			writeJSON(t, w, []map[string]interface{}{
				{
					"id":         301,
					"number":     7,
					"updated_at": now,
				},
			})
		case "/repos/acme/platform/pulls/7":
			writeJSON(t, w, map[string]interface{}{
				"id":         301,
				"number":     7,
				"user":       map[string]interface{}{"login": "dana"},
				"title":      "Adjust IAM policy",
				"state":      "open",
				"created_at": now,
				"updated_at": now,
			})
		case "/repos/acme/platform/pulls/7/reviews":
			http.Error(w, "not found", http.StatusNotFound)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	provider := NewGitHubProvider()
	provider.org = "acme"
	provider.token = "test-token"
	provider.baseURL = server.URL
	provider.client = server.Client()

	rows, reviewRows, err := provider.fetchPullRequests(context.Background(), githubRepoInfo{Name: "platform"}, time.Now().AddDate(0, 0, -180))
	if err != nil {
		t.Fatalf("fetchPullRequests failed: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected pull request row despite missing reviews endpoint, got %d", len(rows))
	}
	if len(reviewRows) != 0 {
		t.Fatalf("expected no review rows when endpoint is unavailable, got %d", len(reviewRows))
	}
}

func writeJSON(t *testing.T, w http.ResponseWriter, value interface{}) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Fatalf("encode response: %v", err)
	}
}
