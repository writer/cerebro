package providers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// GitLabProvider syncs DevSecOps data from GitLab
type GitLabProvider struct {
	*BaseProvider
	token   string
	baseURL string
	client  *http.Client
}

type gitlabAPIError struct {
	StatusCode int
	Body       string
}

func (e *gitlabAPIError) Error() string {
	return fmt.Sprintf("gitlab API error %d: %s", e.StatusCode, e.Body)
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
			Name:        "gitlab_runners",
			Description: "GitLab runners",
			Columns: []ColumnSchema{
				{Name: "id", Type: "integer", Required: true},
				{Name: "description", Type: "string"},
				{Name: "name", Type: "string"},
				{Name: "status", Type: "string"},
				{Name: "active", Type: "boolean"},
				{Name: "is_shared", Type: "boolean"},
				{Name: "run_untagged", Type: "boolean"},
				{Name: "locked", Type: "boolean"},
				{Name: "ip_address", Type: "string"},
				{Name: "created_at", Type: "timestamp"},
				{Name: "contacted_at", Type: "timestamp"},
				{Name: "tag_list", Type: "object"},
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

func (g *GitLabProvider) schemaFor(name string) (TableSchema, error) {
	schema, ok := schemaByName(g.Schema(), name)
	if !ok {
		return TableSchema{}, fmt.Errorf("schema not found: %s", name)
	}
	return schema, nil
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

	// Sync runners
	runners, err := g.syncRunners(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "runners: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *runners)
		result.TotalRows += runners.Rows
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
	body, _, err := g.requestWithHeaders(ctx, path)
	return body, err
}

func (g *GitLabProvider) requestWithHeaders(ctx context.Context, path string) ([]byte, http.Header, error) {
	url := g.baseURL + path

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("PRIVATE-TOKEN", g.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := g.client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}

	if resp.StatusCode >= 400 {
		return nil, nil, &gitlabAPIError{StatusCode: resp.StatusCode, Body: string(body)}
	}

	return body, resp.Header, nil
}

func (g *GitLabProvider) requestAll(ctx context.Context, path string) ([]map[string]interface{}, error) {
	items := make([]map[string]interface{}, 0)
	nextPath := path

	for nextPath != "" {
		body, headers, err := g.requestWithHeaders(ctx, nextPath)
		if err != nil {
			return nil, err
		}

		var page []map[string]interface{}
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, err
		}
		items = append(items, page...)

		nextPage := headers.Get("X-Next-Page")
		if nextPage == "" || nextPage == "0" {
			nextPath = ""
			continue
		}

		updated, err := updateGitLabPage(path, nextPage)
		if err != nil {
			return nil, err
		}
		nextPath = updated
	}

	return items, nil
}

func updateGitLabPage(path string, page string) (string, error) {
	parsed, err := url.Parse(path)
	if err != nil {
		return path, err
	}
	query := parsed.Query()
	query.Set("page", page)
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

func (g *GitLabProvider) syncProjects(ctx context.Context) (*TableResult, error) {
	schema, err := g.schemaFor("gitlab_projects")
	result := &TableResult{Name: "gitlab_projects"}
	if err != nil {
		return result, err
	}

	projects, err := g.requestAll(ctx, "/api/v4/projects?per_page=100&membership=true")
	if err != nil {
		return result, err
	}

	rows := make([]map[string]interface{}, 0, len(projects))
	for _, project := range projects {
		rows = append(rows, normalizeGitLabRow(project))
	}

	return g.syncTable(ctx, schema, rows)
}

func (g *GitLabProvider) syncGroups(ctx context.Context) (*TableResult, error) {
	schema, err := g.schemaFor("gitlab_groups")
	result := &TableResult{Name: "gitlab_groups"}
	if err != nil {
		return result, err
	}

	groups, err := g.requestAll(ctx, "/api/v4/groups?per_page=100")
	if err != nil {
		return result, err
	}

	rows := make([]map[string]interface{}, 0, len(groups))
	for _, group := range groups {
		rows = append(rows, normalizeGitLabRow(group))
	}

	return g.syncTable(ctx, schema, rows)
}

func (g *GitLabProvider) syncRunners(ctx context.Context) (*TableResult, error) {
	schema, err := g.schemaFor("gitlab_runners")
	result := &TableResult{Name: "gitlab_runners"}
	if err != nil {
		return result, err
	}

	runners, err := g.requestAll(ctx, "/api/v4/runners?per_page=100")
	if err != nil {
		var apiErr *gitlabAPIError
		if errors.As(err, &apiErr) && (apiErr.StatusCode == http.StatusForbidden || apiErr.StatusCode == http.StatusNotFound) {
			fallback, fallbackErr := g.fetchProjectRunners(ctx)
			if fallbackErr != nil {
				result.Error = fmt.Sprintf("runners admin endpoint denied (%d): %v", apiErr.StatusCode, fallbackErr)
				return result, nil
			}
			result.Error = fmt.Sprintf("runners admin endpoint denied (%d): using project-level runners", apiErr.StatusCode)
			runners = fallback
		} else {
			return result, err
		}
	}

	rows := make([]map[string]interface{}, 0, len(runners))
	for _, runner := range runners {
		rows = append(rows, normalizeGitLabRow(runner))
	}

	return g.syncTable(ctx, schema, rows)
}

func (g *GitLabProvider) fetchProjectRunners(ctx context.Context) ([]map[string]interface{}, error) {
	projects, err := g.requestAll(ctx, "/api/v4/projects?per_page=100&membership=true")
	if err != nil {
		return nil, err
	}

	runnerByID := make(map[string]map[string]interface{})
	fallback := make([]map[string]interface{}, 0)

	for _, project := range projects {
		projectIDValue, ok := asFloat(project["id"])
		if !ok || projectIDValue == 0 {
			continue
		}
		projectID := int(projectIDValue)
		projectRunners, err := g.requestAll(ctx, fmt.Sprintf("/api/v4/projects/%d/runners?per_page=100", projectID))
		if err != nil {
			continue
		}
		for _, runner := range projectRunners {
			id := asString(runner["id"])
			if id == "" {
				fallback = append(fallback, runner)
				continue
			}
			if _, exists := runnerByID[id]; exists {
				continue
			}
			runnerByID[id] = runner
		}
	}

	results := make([]map[string]interface{}, 0, len(runnerByID)+len(fallback))
	for _, runner := range runnerByID {
		results = append(results, runner)
	}
	results = append(results, fallback...)
	return results, nil
}

func (g *GitLabProvider) syncVulnerabilities(ctx context.Context) (*TableResult, error) {
	schema, err := g.schemaFor("gitlab_vulnerabilities")
	result := &TableResult{Name: "gitlab_vulnerabilities"}
	if err != nil {
		return result, err
	}

	projects, err := g.requestAll(ctx, "/api/v4/projects?per_page=100&membership=true")
	if err != nil {
		return result, err
	}

	rows := make([]map[string]interface{}, 0)
	for _, project := range projects {
		projectIDValue, ok := asFloat(project["id"])
		if !ok || projectIDValue == 0 {
			continue
		}
		projectID := int(projectIDValue)
		vulns, err := g.requestAll(ctx, fmt.Sprintf("/api/v4/projects/%d/vulnerabilities?per_page=100", projectID))
		if err != nil {
			continue // Some projects may not have vulnerability reports enabled
		}
		for _, vuln := range vulns {
			row := normalizeGitLabRow(vuln)
			if row["project_id"] == nil {
				row["project_id"] = projectID
			}
			rows = append(rows, row)
		}
	}

	return g.syncTable(ctx, schema, rows)
}

func normalizeGitLabRow(row map[string]interface{}) map[string]interface{} {
	normalized, ok := normalizeMapKeys(row).(map[string]interface{})
	if !ok {
		return map[string]interface{}{}
	}
	return normalized
}
