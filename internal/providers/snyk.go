package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// SnykProvider syncs vulnerability and code security data from Snyk
type SnykProvider struct {
	*BaseProvider
	apiToken string
	orgID    string
	baseURL  string
	client   *http.Client
}

func NewSnykProvider() *SnykProvider {
	return &SnykProvider{
		BaseProvider: NewBaseProvider("snyk", ProviderTypeSaaS),
		baseURL:      "https://api.snyk.io",
		client:       &http.Client{Timeout: 30 * time.Second},
	}
}

func (s *SnykProvider) Configure(ctx context.Context, config map[string]interface{}) error {
	if err := s.BaseProvider.Configure(ctx, config); err != nil {
		return err
	}

	s.apiToken = s.GetConfigString("api_token")
	s.orgID = s.GetConfigString("org_id")
	if baseURL := s.GetConfigString("base_url"); baseURL != "" {
		s.baseURL = baseURL
	}

	return nil
}

func (s *SnykProvider) Test(ctx context.Context) error {
	_, err := s.request(ctx, fmt.Sprintf("/rest/orgs/%s?version=2024-01-04", s.orgID))
	return err
}

func (s *SnykProvider) Schema() []TableSchema {
	return []TableSchema{
		{
			Name:        "snyk_projects",
			Description: "Snyk projects (monitored repositories/targets)",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "name", Type: "string"},
				{Name: "origin", Type: "string"},
				{Name: "type", Type: "string"},
				{Name: "target_reference", Type: "string"},
				{Name: "branch", Type: "string"},
				{Name: "created", Type: "timestamp"},
				{Name: "org_id", Type: "string"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "snyk_issues",
			Description: "Snyk vulnerability issues",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "project_id", Type: "string"},
				{Name: "issue_type", Type: "string"},
				{Name: "pkg_name", Type: "string"},
				{Name: "pkg_version", Type: "string"},
				{Name: "severity", Type: "string"},
				{Name: "title", Type: "string"},
				{Name: "cve", Type: "string"},
				{Name: "cvss_score", Type: "float"},
				{Name: "exploit_maturity", Type: "string"},
				{Name: "is_fixable", Type: "boolean"},
				{Name: "introduced_date", Type: "timestamp"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "snyk_dependencies",
			Description: "Snyk project dependencies",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "project_id", Type: "string"},
				{Name: "name", Type: "string"},
				{Name: "version", Type: "string"},
				{Name: "type", Type: "string"},
				{Name: "is_direct", Type: "boolean"},
				{Name: "licenses", Type: "array"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "snyk_code_issues",
			Description: "Snyk Code (SAST) issues",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "project_id", Type: "string"},
				{Name: "rule_id", Type: "string"},
				{Name: "severity", Type: "string"},
				{Name: "title", Type: "string"},
				{Name: "file_path", Type: "string"},
				{Name: "line_number", Type: "integer"},
				{Name: "cwe", Type: "array"},
				{Name: "is_ignored", Type: "boolean"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "snyk_container_images",
			Description: "Snyk Container scanned images",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "project_id", Type: "string"},
				{Name: "image_name", Type: "string"},
				{Name: "image_tag", Type: "string"},
				{Name: "platform", Type: "string"},
				{Name: "base_image", Type: "string"},
				{Name: "dockerfile_path", Type: "string"},
				{Name: "critical_count", Type: "integer"},
				{Name: "high_count", Type: "integer"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "snyk_iac_issues",
			Description: "Snyk IaC (Infrastructure as Code) issues",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "project_id", Type: "string"},
				{Name: "rule_id", Type: "string"},
				{Name: "severity", Type: "string"},
				{Name: "title", Type: "string"},
				{Name: "file_path", Type: "string"},
				{Name: "resource_type", Type: "string"},
				{Name: "resource_name", Type: "string"},
				{Name: "is_ignored", Type: "boolean"},
			},
			PrimaryKey: []string{"id"},
		},
	}
}

func (s *SnykProvider) Sync(ctx context.Context, opts SyncOptions) (*SyncResult, error) {
	start := time.Now()
	result := &SyncResult{
		Provider:  s.Name(),
		StartedAt: start,
	}

	// Sync projects
	projects, err := s.syncProjects(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "projects: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *projects)
		result.TotalRows += projects.Rows
	}

	// Get project IDs for issue sync
	projectIDs, _ := s.getProjectIDs(ctx)

	// Sync issues for each project
	for _, projectID := range projectIDs {
		issues, err := s.syncProjectIssues(ctx, projectID)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("issues[%s]: %s", projectID, err.Error()))
		} else {
			result.TotalRows += issues.Rows
		}
	}

	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(start)

	return result, nil
}

func (s *SnykProvider) request(ctx context.Context, path string) ([]byte, error) {
	url := s.baseURL + path

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "token "+s.apiToken)
	req.Header.Set("Content-Type", "application/vnd.api+json")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("snyk API error %d: %s", resp.StatusCode, string(body))
	}

	return io.ReadAll(resp.Body)
}

func (s *SnykProvider) syncProjects(ctx context.Context) (*TableResult, error) {
	result := &TableResult{Name: "snyk_projects"}

	path := fmt.Sprintf("/rest/orgs/%s/projects?version=2024-01-04&limit=100", s.orgID)
	body, err := s.request(ctx, path)
	if err != nil {
		return result, err
	}

	var response struct {
		Data []map[string]interface{} `json:"data"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return result, err
	}

	result.Rows = int64(len(response.Data))
	result.Inserted = result.Rows
	return result, nil
}

func (s *SnykProvider) getProjectIDs(ctx context.Context) ([]string, error) {
	path := fmt.Sprintf("/rest/orgs/%s/projects?version=2024-01-04&limit=100", s.orgID)
	body, err := s.request(ctx, path)
	if err != nil {
		return nil, err
	}

	var response struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, err
	}

	ids := make([]string, len(response.Data))
	for i, p := range response.Data {
		ids[i] = p.ID
	}
	return ids, nil
}

func (s *SnykProvider) syncProjectIssues(ctx context.Context, projectID string) (*TableResult, error) {
	result := &TableResult{Name: "snyk_issues"}

	// Using legacy API for issues as REST API is paginated differently
	path := fmt.Sprintf("/v1/org/%s/project/%s/aggregated-issues", s.orgID, projectID)
	body, err := s.request(ctx, path)
	if err != nil {
		return result, err
	}

	var response struct {
		Issues []map[string]interface{} `json:"issues"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return result, err
	}

	result.Rows = int64(len(response.Issues))
	result.Inserted = result.Rows
	return result, nil
}
