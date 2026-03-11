package providers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestGitHubProviderFetchCommits(t *testing.T) {
	since := time.Date(2025, time.January, 10, 15, 0, 0, 0, time.FixedZone("PST", -8*60*60))
	sinceExpected := since.UTC().Format(time.RFC3339)
	committedAt := time.Now().UTC().Format(time.RFC3339)

	listCalls := 0
	detailCalls := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/acme/platform/commits":
			if r.URL.Query().Get("per_page") != "100" {
				t.Fatalf("expected per_page=100, got %q", r.URL.Query().Get("per_page"))
			}
			if r.URL.Query().Get("page") != "1" {
				t.Fatalf("expected page=1, got %q", r.URL.Query().Get("page"))
			}
			if got := r.URL.Query().Get("since"); got != sinceExpected {
				t.Fatalf("expected since=%q, got %q", sinceExpected, got)
			}

			listCalls++
			writeJSON(t, w, []map[string]interface{}{
				{"sha": "abc123"},
			})
		case "/repos/acme/platform/commits/abc123":
			detailCalls++
			writeJSON(t, w, map[string]interface{}{
				"node_id": "C_kwDOAAABc8wAKGFiYzEyMw",
				"sha":     "abc123",
				"author": map[string]interface{}{
					"login": "alice",
				},
				"committer": map[string]interface{}{
					"login": "ci-bot",
				},
				"commit": map[string]interface{}{
					"author": map[string]interface{}{
						"email": "alice@example.com",
						"date":  committedAt,
					},
					"committer": map[string]interface{}{
						"email": "ci-bot@example.com",
						"date":  committedAt,
					},
					"message": "harden branch protections",
				},
				"stats": map[string]interface{}{
					"additions": 14,
					"deletions": 3,
				},
				"files": []map[string]interface{}{
					{"filename": "internal/policy/rules.go"},
					{"filename": "internal/policy/engine.go"},
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

	rows, err := provider.fetchCommits(context.Background(), githubRepoInfo{Name: "platform"}, since)
	if err != nil {
		t.Fatalf("fetchCommits failed: %v", err)
	}

	if listCalls != 1 {
		t.Fatalf("expected one list call, got %d", listCalls)
	}
	if detailCalls != 1 {
		t.Fatalf("expected one detail call, got %d", detailCalls)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 commit row, got %d", len(rows))
	}

	row := rows[0]
	if got := asString(row["id"]); got != "C_kwDOAAABc8wAKGFiYzEyMw" {
		t.Fatalf("expected node_id id, got %q", got)
	}
	if got := asString(row["sha"]); got != "abc123" {
		t.Fatalf("expected sha abc123, got %q", got)
	}
	if got := asString(row["repository"]); got != "acme/platform" {
		t.Fatalf("expected repository acme/platform, got %q", got)
	}
	if got := asString(row["author_login"]); got != "alice" {
		t.Fatalf("expected author_login alice, got %q", got)
	}
	if got := asString(row["author_email"]); got != "alice@example.com" {
		t.Fatalf("expected author_email alice@example.com, got %q", got)
	}
	if got := asString(row["committer_login"]); got != "ci-bot" {
		t.Fatalf("expected committer_login ci-bot, got %q", got)
	}
	if got := asString(row["committer_email"]); got != "ci-bot@example.com" {
		t.Fatalf("expected committer_email ci-bot@example.com, got %q", got)
	}
	if got := asString(row["message"]); got != "harden branch protections" {
		t.Fatalf("expected message to be captured, got %q", got)
	}
	if got, ok := asInt(row["files_changed"]); !ok || got != 2 {
		t.Fatalf("expected files_changed=2, got %v (ok=%v)", row["files_changed"], ok)
	}
	if got, ok := asInt(row["additions"]); !ok || got != 14 {
		t.Fatalf("expected additions=14, got %v (ok=%v)", row["additions"], ok)
	}
	if got, ok := asInt(row["deletions"]); !ok || got != 3 {
		t.Fatalf("expected deletions=3, got %v (ok=%v)", row["deletions"], ok)
	}
	if got := asString(row["committed_at"]); got != committedAt {
		t.Fatalf("expected committed_at %q, got %q", committedAt, got)
	}
}

func TestGitHubProviderFetchCommits_IgnoresMissingCommitDetails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/acme/platform/commits":
			writeJSON(t, w, []map[string]interface{}{
				{"sha": "missing"},
				{"sha": "present"},
			})
		case "/repos/acme/platform/commits/missing":
			http.Error(w, "not found", http.StatusNotFound)
		case "/repos/acme/platform/commits/present":
			writeJSON(t, w, map[string]interface{}{
				"sha": "present",
				"commit": map[string]interface{}{
					"author": map[string]interface{}{
						"date": "2026-01-01T00:00:00Z",
					},
					"message": "keep coverage high",
				},
				"stats": map[string]interface{}{
					"additions": 1,
					"deletions": 0,
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

	rows, err := provider.fetchCommits(context.Background(), githubRepoInfo{Name: "platform"}, time.Now().AddDate(0, 0, -90))
	if err != nil {
		t.Fatalf("fetchCommits failed: %v", err)
	}

	if len(rows) != 1 {
		t.Fatalf("expected only one commit row after skipping 404 detail fetch, got %d", len(rows))
	}
	if got := asString(rows[0]["sha"]); got != "present" {
		t.Fatalf("expected surviving commit sha=present, got %q", got)
	}
}

func TestGitHubProviderFetchCommitDetails_FallsBackToSHAAndCommitterDate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/acme/platform/commits/fallback":
			writeJSON(t, w, map[string]interface{}{
				"sha": "fallback",
				"commit": map[string]interface{}{
					"author": map[string]interface{}{
						"email": "owner@example.com",
					},
					"committer": map[string]interface{}{
						"date":  "2026-02-20T10:20:30Z",
						"email": "bot@example.com",
					},
					"message": "fallback behavior",
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

	row, err := provider.fetchCommitDetails(context.Background(), githubRepoInfo{Name: "platform"}, "fallback")
	if err != nil {
		t.Fatalf("fetchCommitDetails failed: %v", err)
	}

	if got := asString(row["id"]); got != "fallback" {
		t.Fatalf("expected id to fall back to sha, got %q", got)
	}
	if got := asString(row["committed_at"]); got != "2026-02-20T10:20:30Z" {
		t.Fatalf("expected committed_at to fall back to committer date, got %q", got)
	}
}

func TestGitHubProviderFetchCommits_EmptyRepositoryName(t *testing.T) {
	provider := NewGitHubProvider()

	rows, err := provider.fetchCommits(context.Background(), githubRepoInfo{}, time.Now())
	if err != nil {
		t.Fatalf("expected no error for empty repository name, got %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("expected no rows for empty repository name, got %d", len(rows))
	}
}
