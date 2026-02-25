package providers

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestWizProviderConfigureValidation(t *testing.T) {
	provider := NewWizProvider()

	err := provider.Configure(context.Background(), map[string]interface{}{})
	if err == nil || !strings.Contains(err.Error(), "client_id and client_secret") {
		t.Fatalf("expected missing credentials error, got %v", err)
	}

	err = provider.Configure(context.Background(), map[string]interface{}{
		"client_id":     "id",
		"client_secret": "secret",
	})
	if err == nil || !strings.Contains(err.Error(), "api_url") {
		t.Fatalf("expected missing api_url error, got %v", err)
	}
}

func TestWizProviderSync(t *testing.T) {
	tokenRequests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			tokenRequests++
			if r.Method != http.MethodPost {
				t.Fatalf("expected POST token request, got %s", r.Method)
			}
			body, _ := io.ReadAll(r.Body)
			values, _ := url.ParseQuery(string(body))
			if values.Get("client_id") != "wiz-client" || values.Get("client_secret") != "wiz-secret" {
				t.Fatalf("unexpected token request credentials: %v", values)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"test-token","expires_in":3600}`))
		case "/graphql":
			if r.Header.Get("Authorization") != "Bearer test-token" {
				t.Fatalf("unexpected authorization header: %q", r.Header.Get("Authorization"))
			}

			var req struct {
				Query     string                 `json:"query"`
				Variables map[string]interface{} `json:"variables"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode graphql request: %v", err)
			}

			w.Header().Set("Content-Type", "application/json")
			if strings.Contains(req.Query, "projects(") {
				after := ""
				if value, ok := req.Variables["after"].(string); ok {
					after = value
				}

				if after == "" {
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"data": map[string]interface{}{
							"projects": map[string]interface{}{
								"nodes": []map[string]interface{}{
									{
										"id":        "proj-1",
										"name":      "Project One",
										"archived":  false,
										"createdAt": "2026-02-20T00:00:00Z",
										"updatedAt": "2026-02-21T00:00:00Z",
										"cloudAccount": map[string]interface{}{
											"id":            "acct-1",
											"name":          "Production",
											"cloudProvider": "aws",
										},
									},
								},
								"pageInfo": map[string]interface{}{
									"hasNextPage": true,
									"endCursor":   "cursor-1",
								},
							},
						},
					})
					return
				}

				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"data": map[string]interface{}{
						"projects": map[string]interface{}{
							"nodes": []map[string]interface{}{
								{
									"id":        "proj-2",
									"name":      "Project Two",
									"archived":  true,
									"createdAt": "2026-02-22T00:00:00Z",
									"updatedAt": "2026-02-23T00:00:00Z",
									"cloudAccount": map[string]interface{}{
										"id":            "acct-1",
										"name":          "Production",
										"cloudProvider": "aws",
									},
								},
							},
							"pageInfo": map[string]interface{}{
								"hasNextPage": false,
								"endCursor":   "",
							},
						},
					},
				})
				return
			}

			if strings.Contains(req.Query, "issues(") {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"data": map[string]interface{}{
						"issues": map[string]interface{}{
							"nodes": []map[string]interface{}{
								{
									"id":        "issue-1",
									"title":     "Public bucket",
									"severity":  "HIGH",
									"status":    "OPEN",
									"type":      "CONFIGURATION",
									"dueAt":     "2026-03-01T00:00:00Z",
									"createdAt": "2026-02-23T00:00:00Z",
									"updatedAt": "2026-02-24T00:00:00Z",
									"project": map[string]interface{}{
										"id":   "proj-1",
										"name": "Project One",
									},
									"control": map[string]interface{}{
										"id":   "ctrl-1",
										"name": "S3 Public Access",
									},
									"entitySnapshot": map[string]interface{}{
										"id":            "resource-1",
										"name":          "bucket-1",
										"type":          "S3Bucket",
										"region":        "us-east-1",
										"cloudPlatform": "aws",
									},
								},
								{
									"id":        "issue-2",
									"title":     "Admin role exposed",
									"severity":  "CRITICAL",
									"status":    "OPEN",
									"type":      "IDENTITY",
									"createdAt": "2026-02-24T00:00:00Z",
									"updatedAt": "2026-02-24T01:00:00Z",
									"project": map[string]interface{}{
										"id":   "proj-2",
										"name": "Project Two",
									},
									"entitySnapshot": map[string]interface{}{
										"providerUniqueId": "resource-2",
										"name":             "role/admin",
										"type":             "IAMRole",
										"cloudProvider":    "aws",
									},
								},
							},
							"pageInfo": map[string]interface{}{
								"hasNextPage": false,
								"endCursor":   "",
							},
						},
					},
				})
				return
			}

			t.Fatalf("unexpected graphql query: %s", req.Query)
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	provider := NewWizProvider()
	err := provider.Configure(context.Background(), map[string]interface{}{
		"client_id":     "wiz-client",
		"client_secret": "wiz-secret",
		"api_url":       server.URL + "/graphql",
		"token_url":     server.URL + "/oauth/token",
		"audience":      "wiz-api",
	})
	if err != nil {
		t.Fatalf("configure provider: %v", err)
	}

	result, err := provider.Sync(context.Background(), SyncOptions{FullSync: true})
	if err != nil {
		t.Fatalf("sync provider: %v", err)
	}
	if tokenRequests != 1 {
		t.Fatalf("expected 1 token request, got %d", tokenRequests)
	}

	rowCountByTable := make(map[string]int64)
	for _, table := range result.Tables {
		rowCountByTable[table.Name] = table.Rows
	}

	if rowCountByTable["wiz_projects"] != 2 {
		t.Fatalf("expected 2 wiz_projects rows, got %d", rowCountByTable["wiz_projects"])
	}
	if rowCountByTable["wiz_cloud_accounts"] != 1 {
		t.Fatalf("expected deduped 1 wiz_cloud_accounts row, got %d", rowCountByTable["wiz_cloud_accounts"])
	}
	if rowCountByTable["wiz_issues"] != 2 {
		t.Fatalf("expected 2 wiz_issues rows, got %d", rowCountByTable["wiz_issues"])
	}
	if result.TotalRows != 5 {
		t.Fatalf("expected total rows 5, got %d", result.TotalRows)
	}
}
