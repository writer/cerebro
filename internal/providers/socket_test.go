package providers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSocketProviderSync_TableParity(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer socket-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/v0/orgs":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"orgs": []map[string]interface{}{{"id": "org-1", "slug": "writer", "name": "Writer"}},
			})
		case "/v0/orgs/writer/repos":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"repos": []map[string]interface{}{
					{"id": "repo-1", "name": "cerebro", "full_name": "writer/cerebro", "default_branch": "main", "visibility": "private", "archived": false},
					{"id": "repo-2", "name": "infra", "full_name": "writer/infra", "default_branch": "main", "visibility": "private", "archived": false},
				},
			})
		case "/v0/orgs/writer/alerts":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"alerts": []map[string]interface{}{
					{
						"id":        "alert-1",
						"repo_id":   "repo-1",
						"repo_name": "writer/cerebro",
						"type":      "malicious-package",
						"severity":  "high",
						"status":    "open",
						"package": map[string]interface{}{
							"name":      "bad-package",
							"ecosystem": "npm",
						},
						"created_at": "2026-01-10T00:00:00Z",
						"updated_at": "2026-01-11T00:00:00Z",
					},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	provider := NewSocketProvider()
	if err := provider.Configure(context.Background(), map[string]interface{}{
		"api_token": "socket-token",
		"api_url":   server.URL + "/v0",
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
		"socket_orgs":   1,
		"socket_repos":  2,
		"socket_alerts": 1,
	}
	for table, want := range expected {
		if got := rowsByTable[table]; got != want {
			t.Fatalf("%s rows = %d, want %d", table, got, want)
		}
	}
}

func TestSocketProviderSync_IgnoresOrgPermissionErrors(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/v0/orgs":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"orgs": []map[string]interface{}{{"id": "org-1", "slug": "writer", "name": "Writer"}},
			})
		case "/v0/orgs/writer/repos":
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"message":"forbidden"}`))
		case "/v0/orgs/writer/alerts":
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"message":"forbidden"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	provider := NewSocketProvider()
	if err := provider.Configure(context.Background(), map[string]interface{}{
		"api_token": "socket-token",
		"api_url":   server.URL + "/v0",
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
	if rowsByTable["socket_repos"] != 0 {
		t.Fatalf("socket_repos rows = %d, want 0", rowsByTable["socket_repos"])
	}
	if rowsByTable["socket_alerts"] != 0 {
		t.Fatalf("socket_alerts rows = %d, want 0", rowsByTable["socket_alerts"])
	}
}

func TestSocketProviderListCollection_DetectsPaginationLoop(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/v0/orgs":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"orgs":        []map[string]interface{}{{"id": "org-1", "slug": "writer"}},
				"next_cursor": "repeat-token",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	provider := NewSocketProvider()
	if err := provider.Configure(context.Background(), map[string]interface{}{
		"api_token": "socket-token",
		"api_url":   server.URL + "/v0",
	}); err != nil {
		t.Fatalf("configure failed: %v", err)
	}

	_, err := provider.listOrganizations(context.Background())
	if err == nil {
		t.Fatal("expected pagination loop error")
	}
	if !strings.Contains(err.Error(), "pagination loop") {
		t.Fatalf("expected pagination loop error, got %v", err)
	}
}
