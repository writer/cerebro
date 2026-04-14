package providers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestSemgrepProviderSync_TableParity(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Header.Get("Authorization") != "Bearer semgrep-token" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
			return
		}

		w.Header().Set("Content-Type", "application/json")

		switch req.URL.Path {
		case "/api/v1/deployments":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"deployments": []map[string]interface{}{
					{
						"id":   1,
						"slug": "writer",
						"name": "Writer Deployment",
						"findings": map[string]interface{}{
							"url": "/api/v1/deployments/writer/findings",
						},
					},
					{
						"id":   2,
						"slug": "corp",
						"name": "Corp Deployment",
						"findings": map[string]interface{}{
							"url": "/api/v1/deployments/corp/findings",
						},
					},
				},
			})
			return
		case "/api/v1/deployments/writer/projects":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"projects": []map[string]interface{}{
					{
						"id":              "proj-1",
						"name":            "repo-one",
						"repository_name": "github.com/writer/repo-one",
						"branch":          "main",
						"last_scan_at":    "2026-02-25T12:00:00Z",
						"archived":        false,
					},
				},
			})
			return
		case "/api/v1/deployments/corp/projects":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"projects": []map[string]interface{}{
					{
						"id":              "proj-2",
						"name":            "repo-two",
						"repository_name": "github.com/writer/repo-two",
						"branch":          "develop",
						"last_scan_at":    "2026-02-25T13:00:00Z",
						"archived":        false,
					},
				},
			})
			return
		case "/api/v1/deployments/writer/findings":
			page, _ := strconv.Atoi(req.URL.Query().Get("page"))
			switch page {
			case 0:
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"findings": semgrepTestFindings(100, 1, "proj-1", "repo-one"),
				})
			case 1:
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"findings": semgrepTestFindings(1, 101, "proj-1", "repo-one"),
				})
			default:
				_ = json.NewEncoder(w).Encode(map[string]interface{}{"findings": []map[string]interface{}{}})
			}
			return
		case "/api/v1/deployments/corp/findings":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"findings": []map[string]interface{}{}})
			return
		default:
			http.NotFound(w, req)
		}
	}))
	defer server.Close()

	provider := NewSemgrepProvider()
	if err := provider.Configure(context.Background(), map[string]interface{}{
		"token":    "semgrep-token",
		"base_url": server.URL + "/api/v1",
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

	if rowsByTable["semgrep_deployments"] != 2 {
		t.Fatalf("semgrep_deployments rows = %d, want 2", rowsByTable["semgrep_deployments"])
	}
	if rowsByTable["semgrep_projects"] != 2 {
		t.Fatalf("semgrep_projects rows = %d, want 2", rowsByTable["semgrep_projects"])
	}
	if rowsByTable["semgrep_findings"] != 101 {
		t.Fatalf("semgrep_findings rows = %d, want 101", rowsByTable["semgrep_findings"])
	}
}

func TestSemgrepProviderSync_IgnoresPermissionDeniedChildTables(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Header.Get("Authorization") != "Bearer semgrep-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")

		switch req.URL.Path {
		case "/api/v1/deployments":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"deployments": []map[string]interface{}{{
					"id":   1,
					"slug": "writer",
					"name": "Writer Deployment",
				}},
			})
			return
		case "/api/v1/deployments/writer/projects":
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"forbidden"}`))
			return
		case "/api/v1/deployments/writer/findings":
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"forbidden"}`))
			return
		default:
			http.NotFound(w, req)
		}
	}))
	defer server.Close()

	provider := NewSemgrepProvider()
	if err := provider.Configure(context.Background(), map[string]interface{}{
		"token":    "semgrep-token",
		"base_url": server.URL + "/api/v1",
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

	if rowsByTable["semgrep_deployments"] != 1 {
		t.Fatalf("semgrep_deployments rows = %d, want 1", rowsByTable["semgrep_deployments"])
	}
	if rowsByTable["semgrep_projects"] != 0 {
		t.Fatalf("semgrep_projects rows = %d, want 0", rowsByTable["semgrep_projects"])
	}
	if rowsByTable["semgrep_findings"] != 0 {
		t.Fatalf("semgrep_findings rows = %d, want 0", rowsByTable["semgrep_findings"])
	}
}

func TestSemgrepProviderRequest_RejectsCrossHostURL(t *testing.T) {
	t.Parallel()

	provider := NewSemgrepProvider()
	if err := provider.Configure(context.Background(), map[string]interface{}{
		"token":    "semgrep-token",
		"base_url": "https://semgrep.dev/api/v1",
	}); err != nil {
		t.Fatalf("configure failed: %v", err)
	}

	_, err := provider.request(context.Background(), "https://evil.example.com/api/v1/deployments")
	if err == nil {
		t.Fatal("expected cross-host URL rejection")
		return
	}
	if !strings.Contains(err.Error(), "host mismatch") {
		t.Fatalf("expected host mismatch error, got %v", err)
	}
}

func semgrepTestFindings(count int, start int, projectID string, projectName string) []map[string]interface{} {
	findings := make([]map[string]interface{}, 0, count)
	for i := 0; i < count; i++ {
		id := start + i
		findings = append(findings, map[string]interface{}{
			"id":           "finding-" + strconv.Itoa(id),
			"project_id":   projectID,
			"project_name": projectName,
			"rule_id":      "rule.sast.sql-injection",
			"severity":     "HIGH",
			"confidence":   "MEDIUM",
			"state":        "open",
			"triage_state": "to_review",
			"title":        "Potential SQL injection",
			"path":         "src/service/user.go",
			"line":         42,
			"created_at":   "2026-02-24T10:00:00Z",
			"updated_at":   "2026-02-25T10:00:00Z",
		})
	}
	return findings
}
