package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// GitLabProvider syncs DevSecOps data from GitLab
type GitLabProvider struct {
	*BaseProvider
	token   string
	baseURL string
	client  *http.Client
}

func NewGitLabProvider() *GitLabProvider {
	return &GitLabProvider{
		BaseProvider: NewBaseProvider("gitlab", ProviderTypeSaaS),
		baseURL:      "https://gitlab.com",
		client:       &http.Client{Timeout: 30 * time.Second},
	}
}

func (g *GitLabProvider) Configure(ctx context.Context, config map[string]interface{}) error {
	if err := g.BaseProvider.Configure(ctx, config); err != nil {
		return err
	}

	g.token = g.GetConfigString("token")
	if baseURL := g.GetConfigString("base_url"); baseURL != "" {
		g.baseURL = baseURL
	}

	return nil
}

func (g *GitLabProvider) Test(ctx context.Context) error {
	_, err := g.request(ctx, "/api/v4/user")
	return err
}

func (g *GitLabProvider) Schema() []TableSchema {
	return []TableSchema{
		{
			Name:        "gitlab_projects",
			Description: "GitLab projects",
			Columns: []ColumnSchema{
				{Name: "id", Type: "integer", Required: true},
				{Name: "name", Type: "string"},
				{Name: "path_with_namespace", Type: "string"},
				{Name: "visibility", Type: "string"},
				{Name: "default_branch", Type: "string"},
				{Name: "archived", Type: "boolean"},
				{Name: "created_at", Type: "timestamp"},
				{Name: "last_activity_at", Type: "timestamp"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "gitlab_groups",
			Description: "GitLab groups",
			Columns: []ColumnSchema{
				{Name: "id", Type: "integer", Required: true},
				{Name: "name", Type: "string"},
				{Name: "path", Type: "string"},
				{Name: "full_path", Type: "string"},
				{Name: "visibility", Type: "string"},
				{Name: "created_at", Type: "timestamp"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "gitlab_vulnerabilities",
			Description: "GitLab security vulnerabilities",
			Columns: []ColumnSchema{
				{Name: "id", Type: "integer", Required: true},
				{Name: "project_id", Type: "integer"},
				{Name: "title", Type: "string"},
				{Name: "severity", Type: "string"},
				{Name: "state", Type: "string"},
				{Name: "report_type", Type: "string"},
				{Name: "scanner_name", Type: "string"},
				{Name: "location", Type: "object"},
				{Name: "detected_at", Type: "timestamp"},
				{Name: "dismissed_at", Type: "timestamp"},
				{Name: "resolved_at", Type: "timestamp"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "gitlab_pipelines",
			Description: "GitLab CI/CD pipelines",
			Columns: []ColumnSchema{
				{Name: "id", Type: "integer", Required: true},
				{Name: "project_id", Type: "integer"},
				{Name: "status", Type: "string"},
				{Name: "ref", Type: "string"},
				{Name: "sha", Type: "string"},
				{Name: "source", Type: "string"},
				{Name: "created_at", Type: "timestamp"},
				{Name: "updated_at", Type: "timestamp"},
				{Name: "started_at", Type: "timestamp"},
				{Name: "finished_at", Type: "timestamp"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "gitlab_merge_requests",
			Description: "GitLab merge requests",
			Columns: []ColumnSchema{
				{Name: "id", Type: "integer", Required: true},
				{Name: "iid", Type: "integer"},
				{Name: "project_id", Type: "integer"},
				{Name: "title", Type: "string"},
				{Name: "state", Type: "string"},
				{Name: "source_branch", Type: "string"},
				{Name: "target_branch", Type: "string"},
				{Name: "author_id", Type: "integer"},
				{Name: "merged_by_id", Type: "integer"},
				{Name: "created_at", Type: "timestamp"},
				{Name: "merged_at", Type: "timestamp"},
			},
			PrimaryKey: []string{"id"},
		},
	}
}

func (g *GitLabProvider) Sync(ctx context.Context, opts SyncOptions) (*SyncResult, error) {
	start := time.Now()
	result := &SyncResult{
		Provider:  g.Name(),
		StartedAt: start,
	}

	// Sync projects
	projects, err := g.syncProjects(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "projects: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *projects)
		result.TotalRows += projects.Rows
	}

	// Sync groups
	groups, err := g.syncGroups(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "groups: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *groups)
		result.TotalRows += groups.Rows
	}

	// Sync vulnerabilities
	vulns, err := g.syncVulnerabilities(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "vulnerabilities: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *vulns)
		result.TotalRows += vulns.Rows
	}

	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(start)

	return result, nil
}

func (g *GitLabProvider) request(ctx context.Context, path string) ([]byte, error) {
	url := g.baseURL + path

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("PRIVATE-TOKEN", g.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := g.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("gitlab API error %d: %s", resp.StatusCode, string(body))
	}

	return io.ReadAll(resp.Body)
}

func (g *GitLabProvider) syncProjects(ctx context.Context) (*TableResult, error) {
	result := &TableResult{Name: "gitlab_projects"}

	body, err := g.request(ctx, "/api/v4/projects?per_page=100&membership=true")
	if err != nil {
		return result, err
	}

	var projects []map[string]interface{}
	if err := json.Unmarshal(body, &projects); err != nil {
		return result, err
	}

	result.Rows = int64(len(projects))
	result.Inserted = result.Rows
	return result, nil
}

func (g *GitLabProvider) syncGroups(ctx context.Context) (*TableResult, error) {
	result := &TableResult{Name: "gitlab_groups"}

	body, err := g.request(ctx, "/api/v4/groups?per_page=100")
	if err != nil {
		return result, err
	}

	var groups []map[string]interface{}
	if err := json.Unmarshal(body, &groups); err != nil {
		return result, err
	}

	result.Rows = int64(len(groups))
	result.Inserted = result.Rows
	return result, nil
}

func (g *GitLabProvider) syncVulnerabilities(ctx context.Context) (*TableResult, error) {
	result := &TableResult{Name: "gitlab_vulnerabilities"}

	// Get all projects first, then fetch vulnerabilities for each
	body, err := g.request(ctx, "/api/v4/projects?per_page=100&membership=true")
	if err != nil {
		return result, err
	}

	var projects []struct {
		ID int `json:"id"`
	}
	if err := json.Unmarshal(body, &projects); err != nil {
		return result, err
	}

	var totalVulns int64
	for _, p := range projects {
		vulnBody, err := g.request(ctx, fmt.Sprintf("/api/v4/projects/%d/vulnerabilities?per_page=100", p.ID))
		if err != nil {
			continue // Some projects may not have vulnerability reports enabled
		}

		var vulns []map[string]interface{}
		if err := json.Unmarshal(vulnBody, &vulns); err != nil {
			continue
		}
		totalVulns += int64(len(vulns))
	}

	result.Rows = totalVulns
	result.Inserted = result.Rows
	return result, nil
}
