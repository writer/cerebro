package providers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFigmaProviderSync_TableParity(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Figma-Token") != "figma-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/v1/teams/team-1/projects":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"projects": []map[string]interface{}{
					{"id": "project-1", "name": "Security"},
					{"id": "project-2", "name": "Platform"},
				},
			})
		case "/v1/projects/project-1/files":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"files": []map[string]interface{}{
					{"key": "file-1", "name": "Threat Model", "thumbnail_url": "https://example.com/file-1.png", "last_modified": "2026-01-10T00:00:00Z"},
				},
			})
		case "/v1/projects/project-2/files":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"files": []map[string]interface{}{
					{"key": "file-2", "name": "Architecture", "thumbnail_url": "https://example.com/file-2.png", "last_modified": "2026-01-11T00:00:00Z"},
				},
			})
		case "/v1/teams/team-1/members":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"members": []map[string]interface{}{
					{"id": "member-1", "email": "owner@example.com", "handle": "owner", "status": "active", "role": "owner", "img_url": "https://example.com/avatar.png"},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	provider := NewFigmaProvider()
	if err := provider.Configure(context.Background(), map[string]interface{}{
		"api_token": "figma-token",
		"team_id":   "team-1",
		"base_url":  server.URL,
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
		"figma_projects":     2,
		"figma_files":        2,
		"figma_team_members": 1,
	}
	for table, want := range expected {
		if got := rowsByTable[table]; got != want {
			t.Fatalf("%s rows = %d, want %d", table, got, want)
		}
	}
}

func TestFigmaProviderSync_IgnoresProjectFilePermissionErrors(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/v1/teams/team-1/projects":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"projects": []map[string]interface{}{{"id": "project-1", "name": "Security"}},
			})
		case "/v1/projects/project-1/files":
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"message":"forbidden"}`))
		case "/v1/teams/team-1/members":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"members": []map[string]interface{}{}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	provider := NewFigmaProvider()
	if err := provider.Configure(context.Background(), map[string]interface{}{
		"api_token": "figma-token",
		"team_id":   "team-1",
		"base_url":  server.URL,
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
	if rowsByTable["figma_files"] != 0 {
		t.Fatalf("figma_files rows = %d, want 0", rowsByTable["figma_files"])
	}
}

func TestFigmaProviderListCollection_DetectsPaginationLoop(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/v1/teams/team-1/projects":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"projects": []map[string]interface{}{{"id": "project-1", "name": "Security"}},
				"cursor":   "repeat",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	provider := NewFigmaProvider()
	if err := provider.Configure(context.Background(), map[string]interface{}{
		"api_token": "figma-token",
		"team_id":   "team-1",
		"base_url":  server.URL,
	}); err != nil {
		t.Fatalf("configure failed: %v", err)
	}

	_, err := provider.listProjects(context.Background())
	if err == nil {
		t.Fatal("expected pagination loop error")
		return
	}
	if !strings.Contains(err.Error(), "pagination loop") {
		t.Fatalf("expected pagination loop error, got %v", err)
	}
}
