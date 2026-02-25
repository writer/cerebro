package providers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSnykProviderSync(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/rest/orgs/org-1/projects":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": []map[string]interface{}{
					{
						"id": "proj-1",
						"attributes": map[string]interface{}{
							"name":            "container-project",
							"origin":          "container",
							"type":            "container",
							"targetReference": "registry.example.com/app/backend:1.2.3",
							"branch":          "main",
							"created":         "2026-02-01T00:00:00Z",
						},
						"relationships": map[string]interface{}{
							"organization": map[string]interface{}{
								"data": map[string]interface{}{"id": "org-1"},
							},
						},
					},
					{
						"id": "proj-2",
						"attributes": map[string]interface{}{
							"name":            "iac-project",
							"origin":          "github",
							"type":            "iac",
							"targetReference": "infra/main.tf",
						},
						"relationships": map[string]interface{}{
							"organization": map[string]interface{}{
								"data": map[string]interface{}{"id": "org-1"},
							},
						},
					},
				},
			})
		case "/v1/org/org-1/project/proj-1/aggregated-issues":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"issues": []map[string]interface{}{
					{
						"id":              "vuln-1",
						"issueType":       "package_vulnerability",
						"pkgName":         "lodash",
						"pkgVersion":      "4.17.20",
						"severity":        "high",
						"title":           "Prototype pollution",
						"identifiers":     map[string]interface{}{"CVE": []string{"CVE-2026-0001"}},
						"cvssScore":       8.2,
						"exploitMaturity": "mature",
						"isFixable":       true,
						"introducedDate":  "2026-01-01T00:00:00Z",
						"licenses":        []string{"MIT"},
						"from":            []string{"root", "lodash"},
					},
					{
						"id":                "code-1",
						"issueType":         "code",
						"severity":          "medium",
						"title":             "SQL injection",
						"displayTargetFile": "cmd/app/main.go",
						"lineNumber":        42,
						"identifiers":       map[string]interface{}{"CWE": []string{"CWE-89"}},
					},
				},
			})
		case "/v1/org/org-1/project/proj-2/aggregated-issues":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"issues": []map[string]interface{}{
					{
						"id":           "iac-1",
						"issueType":    "iac",
						"severity":     "low",
						"title":        "Unrestricted SSH",
						"targetFile":   "infra/main.tf",
						"resourceType": "aws_security_group",
						"resourceName": "sg-1234",
						"isIgnored":    true,
					},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	provider := NewSnykProvider()
	err := provider.Configure(context.Background(), map[string]interface{}{
		"api_token": "token",
		"org_id":    "org-1",
		"base_url":  server.URL,
	})
	if err != nil {
		t.Fatalf("configure failed: %v", err)
	}

	result, err := provider.Sync(context.Background(), SyncOptions{FullSync: true})
	if err != nil {
		t.Fatalf("sync failed: %v", err)
	}
	if len(result.Errors) != 0 {
		t.Fatalf("unexpected sync errors: %v", result.Errors)
	}

	expectedRows := map[string]int64{
		"snyk_projects":         2,
		"snyk_issues":           3,
		"snyk_dependencies":     1,
		"snyk_code_issues":      1,
		"snyk_container_images": 1,
		"snyk_iac_issues":       1,
	}
	if len(result.Tables) != len(expectedRows) {
		t.Fatalf("expected %d table results, got %d", len(expectedRows), len(result.Tables))
	}

	for _, table := range result.Tables {
		want, ok := expectedRows[table.Name]
		if !ok {
			t.Fatalf("unexpected table in result: %s", table.Name)
		}
		if table.Rows != want {
			t.Fatalf("table %s expected %d rows, got %d", table.Name, want, table.Rows)
		}
	}

	if result.TotalRows != 9 {
		t.Fatalf("expected total rows 9, got %d", result.TotalRows)
	}
}

func TestExtractSnykIssuesGroupedPayload(t *testing.T) {
	t.Parallel()

	payload := map[string]interface{}{
		"issues": map[string]interface{}{
			"license": []interface{}{map[string]interface{}{"id": "license-1"}},
			"vulns":   []interface{}{map[string]interface{}{"id": "vuln-1"}},
		},
	}

	issues := extractSnykIssues(payload)
	if len(issues) != 2 {
		t.Fatalf("expected 2 issues, got %d", len(issues))
	}
}

func TestSnykProviderFetchProjectsPagination(t *testing.T) {
	t.Parallel()

	baseURL := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rest/orgs/org-1/projects" {
			http.NotFound(w, r)
			return
		}

		switch r.URL.Query().Get("starting_after") {
		case "":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": []map[string]interface{}{{"id": "proj-1"}},
				"links": map[string]interface{}{
					"next": baseURL + "/rest/orgs/org-1/projects?version=2024-01-04&limit=100&starting_after=proj-1",
				},
			})
		case "proj-1":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data":  []map[string]interface{}{{"id": "proj-2"}},
				"links": map[string]interface{}{"next": ""},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	baseURL = server.URL
	defer server.Close()

	provider := NewSnykProvider()
	err := provider.Configure(context.Background(), map[string]interface{}{
		"api_token": "token",
		"org_id":    "org-1",
		"base_url":  server.URL,
	})
	if err != nil {
		t.Fatalf("configure failed: %v", err)
	}

	projects, err := provider.fetchProjects(context.Background())
	if err != nil {
		t.Fatalf("fetch projects failed: %v", err)
	}
	if len(projects) != 2 {
		t.Fatalf("expected 2 projects, got %d", len(projects))
	}
}

func TestSnykNextPagePathRejectsForeignHost(t *testing.T) {
	t.Parallel()

	_, err := snykNextPagePath("https://api.snyk.io", "https://evil.example.com/rest/orgs/org-1/projects?starting_after=abc")
	if err == nil {
		t.Fatal("expected host validation error")
	}
}

func TestSnykProviderSync_IgnoresPermissionDeniedIssues(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/rest/orgs/org-1/projects":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": []map[string]interface{}{
					{"id": "proj-1", "attributes": map[string]interface{}{"name": "first"}},
					{"id": "proj-2", "attributes": map[string]interface{}{"name": "second"}},
				},
			})
		case "/v1/org/org-1/project/proj-1/aggregated-issues":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"issues": []map[string]interface{}{
					{
						"id":         "issue-1",
						"issueType":  "package_vulnerability",
						"pkgName":    "openssl",
						"pkgVersion": "3.0.0",
						"severity":   "high",
						"title":      "Issue one",
					},
				},
			})
		case "/v1/org/org-1/project/proj-2/aggregated-issues":
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"forbidden"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	provider := NewSnykProvider()
	err := provider.Configure(context.Background(), map[string]interface{}{
		"api_token": "token",
		"org_id":    "org-1",
		"base_url":  server.URL,
	})
	if err != nil {
		t.Fatalf("configure failed: %v", err)
	}

	result, err := provider.Sync(context.Background(), SyncOptions{FullSync: true})
	if err != nil {
		t.Fatalf("sync failed: %v", err)
	}
	if len(result.Errors) != 0 {
		t.Fatalf("unexpected sync errors: %v", result.Errors)
	}

	counts := map[string]int64{}
	for _, table := range result.Tables {
		counts[table.Name] = table.Rows
	}
	if counts["snyk_projects"] != 2 || counts["snyk_issues"] != 1 || counts["snyk_dependencies"] != 1 {
		t.Fatalf("unexpected row counts: %+v", counts)
	}
}
