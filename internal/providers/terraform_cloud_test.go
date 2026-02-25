package providers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestTerraformCloudProviderSync_TableParity(t *testing.T) {
	t.Parallel()

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Header.Get("Authorization") != "Bearer tfc-token" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"errors":[{"detail":"unauthorized"}]}`))
			return
		}

		w.Header().Set("Content-Type", "application/vnd.api+json")

		switch req.URL.Path {
		case "/api/v2/organizations":
			page := req.URL.Query().Get("page[number]")
			if page == "" {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"data": []map[string]interface{}{
						{
							"id": "org-1",
							"attributes": map[string]interface{}{
								"name":       "org-one",
								"email":      "admin@org-one.example",
								"created-at": "2026-02-24T10:00:00Z",
							},
						},
					},
					"links": map[string]interface{}{
						"next": server.URL + "/api/v2/organizations?page[number]=2&page[size]=100",
					},
				})
				return
			}

			if page == "2" {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"data": []map[string]interface{}{
						{
							"id": "org-2",
							"attributes": map[string]interface{}{
								"name":       "org-two",
								"email":      "admin@org-two.example",
								"created-at": "2026-02-25T10:00:00Z",
							},
						},
					},
					"links": map[string]interface{}{},
				})
				return
			}

			w.WriteHeader(http.StatusBadRequest)
			return
		case "/api/v2/organizations/org-one/workspaces":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": []map[string]interface{}{
					{
						"id": "ws-1",
						"attributes": map[string]interface{}{
							"name":              "workspace-one",
							"terraform-version": "1.10.0",
							"execution-mode":    "remote",
							"auto-apply":        true,
							"locked":            false,
							"resource-count":    12,
							"created-at":        "2026-02-24T10:05:00Z",
							"updated-at":        "2026-02-24T11:05:00Z",
						},
					},
				},
				"links": map[string]interface{}{},
			})
			return
		case "/api/v2/organizations/org-two/workspaces":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": []map[string]interface{}{
					{
						"id": "ws-2",
						"attributes": map[string]interface{}{
							"name":              "workspace-two",
							"terraform-version": "1.10.1",
							"execution-mode":    "agent",
							"auto-apply":        false,
							"locked":            true,
							"resource-count":    4,
							"created-at":        "2026-02-25T10:05:00Z",
							"updated-at":        "2026-02-25T11:05:00Z",
						},
					},
				},
				"links": map[string]interface{}{},
			})
			return
		case "/api/v2/workspaces/ws-1/runs":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": []map[string]interface{}{
					{
						"id": "run-1",
						"attributes": map[string]interface{}{
							"status":         "applied",
							"message":        "run one",
							"is-destroy":     false,
							"trigger-reason": "manual",
							"source":         "tfe-api",
							"created-at":     "2026-02-24T12:00:00Z",
						},
					},
				},
				"links": map[string]interface{}{},
			})
			return
		case "/api/v2/workspaces/ws-2/runs":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": []map[string]interface{}{
					{
						"id": "run-2",
						"attributes": map[string]interface{}{
							"status":         "planned",
							"message":        "run two",
							"is-destroy":     true,
							"trigger-reason": "push",
							"source":         "vcs",
							"created-at":     "2026-02-25T12:00:00Z",
						},
					},
				},
				"links": map[string]interface{}{},
			})
			return
		default:
			http.NotFound(w, req)
		}
	}))
	defer server.Close()

	provider := NewTerraformCloudProvider()
	if err := provider.Configure(context.Background(), map[string]interface{}{
		"token":    "tfc-token",
		"base_url": server.URL + "/api/v2",
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

	if rowsByTable["terraform_cloud_organizations"] != 2 {
		t.Fatalf("terraform_cloud_organizations rows = %d, want 2", rowsByTable["terraform_cloud_organizations"])
	}
	if rowsByTable["terraform_cloud_workspaces"] != 2 {
		t.Fatalf("terraform_cloud_workspaces rows = %d, want 2", rowsByTable["terraform_cloud_workspaces"])
	}
	if rowsByTable["terraform_cloud_runs"] != 2 {
		t.Fatalf("terraform_cloud_runs rows = %d, want 2", rowsByTable["terraform_cloud_runs"])
	}
}

func TestTerraformCloudProviderSync_IgnoresPermissionDeniedChildTables(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Header.Get("Authorization") != "Bearer tfc-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/vnd.api+json")

		switch req.URL.Path {
		case "/api/v2/organizations":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": []map[string]interface{}{{
					"id": "org-1",
					"attributes": map[string]interface{}{
						"name": "org-one",
					},
				}},
				"links": map[string]interface{}{},
			})
			return
		case "/api/v2/organizations/org-one/workspaces":
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"errors":[{"detail":"forbidden"}]}`))
			return
		default:
			http.NotFound(w, req)
		}
	}))
	defer server.Close()

	provider := NewTerraformCloudProvider()
	if err := provider.Configure(context.Background(), map[string]interface{}{
		"token":    "tfc-token",
		"base_url": server.URL + "/api/v2",
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

	if rowsByTable["terraform_cloud_organizations"] != 1 {
		t.Fatalf("terraform_cloud_organizations rows = %d, want 1", rowsByTable["terraform_cloud_organizations"])
	}
	if rowsByTable["terraform_cloud_workspaces"] != 0 {
		t.Fatalf("terraform_cloud_workspaces rows = %d, want 0", rowsByTable["terraform_cloud_workspaces"])
	}
	if rowsByTable["terraform_cloud_runs"] != 0 {
		t.Fatalf("terraform_cloud_runs rows = %d, want 0", rowsByTable["terraform_cloud_runs"])
	}
}

func TestTerraformCloudProviderListOrganizations_RejectsCrossHostPaginationURL(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Header.Get("Authorization") != "Bearer tfc-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/vnd.api+json")

		switch req.URL.Path {
		case "/api/v2/organizations":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": []map[string]interface{}{{
					"id": "org-1",
					"attributes": map[string]interface{}{
						"name": "org-one",
					},
				}},
				"links": map[string]interface{}{
					"next": "https://evil.example.com/api/v2/organizations?page[number]=2",
				},
			})
			return
		default:
			http.NotFound(w, req)
		}
	}))
	defer server.Close()

	provider := NewTerraformCloudProvider()
	if err := provider.Configure(context.Background(), map[string]interface{}{
		"token":    "tfc-token",
		"base_url": server.URL + "/api/v2",
	}); err != nil {
		t.Fatalf("configure failed: %v", err)
	}

	_, err := provider.listOrganizations(context.Background())
	if err == nil {
		t.Fatal("expected cross-host pagination error")
	}
	if !strings.Contains(err.Error(), "host mismatch") {
		t.Fatalf("expected host mismatch error, got %v", err)
	}
}
