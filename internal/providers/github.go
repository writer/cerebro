package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// GitHubProvider syncs security and DevSecOps data from GitHub
type GitHubProvider struct {
	*BaseProvider
	token   string
	org     string
	baseURL string
	client  *http.Client
}

func NewGitHubProvider() *GitHubProvider {
	return &GitHubProvider{
		BaseProvider: NewBaseProvider("github", ProviderTypeSaaS),
		baseURL:      "https://api.github.com",
		client:       &http.Client{Timeout: 30 * time.Second},
	}
}

func (g *GitHubProvider) Configure(ctx context.Context, config map[string]interface{}) error {
	if err := g.BaseProvider.Configure(ctx, config); err != nil {
		return err
	}

	g.token = g.GetConfigString("token")
	g.org = g.GetConfigString("org")
	if baseURL := g.GetConfigString("base_url"); baseURL != "" {
		g.baseURL = baseURL
	}

	return nil
}

func (g *GitHubProvider) Test(ctx context.Context) error {
	_, err := g.request(ctx, "/user")
	return err
}

func (g *GitHubProvider) Schema() []TableSchema {
	return []TableSchema{
		{
			Name:        "github_repositories",
			Description: "GitHub repositories",
			Columns: []ColumnSchema{
				{Name: "id", Type: "integer", Required: true},
				{Name: "name", Type: "string"},
				{Name: "full_name", Type: "string"},
				{Name: "private", Type: "boolean"},
				{Name: "visibility", Type: "string"},
				{Name: "default_branch", Type: "string"},
				{Name: "archived", Type: "boolean"},
				{Name: "disabled", Type: "boolean"},
				{Name: "fork", Type: "boolean"},
				{Name: "language", Type: "string"},
				{Name: "topics", Type: "array"},
				{Name: "created_at", Type: "timestamp"},
				{Name: "updated_at", Type: "timestamp"},
				{Name: "pushed_at", Type: "timestamp"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "github_dependabot_alerts",
			Description: "GitHub Dependabot vulnerability alerts",
			Columns: []ColumnSchema{
				{Name: "number", Type: "integer", Required: true},
				{Name: "repository", Type: "string", Required: true},
				{Name: "state", Type: "string"},
				{Name: "severity", Type: "string"},
				{Name: "package_name", Type: "string"},
				{Name: "package_ecosystem", Type: "string"},
				{Name: "vulnerable_version_range", Type: "string"},
				{Name: "patched_version", Type: "string"},
				{Name: "cve_id", Type: "string"},
				{Name: "ghsa_id", Type: "string"},
				{Name: "cvss_score", Type: "float"},
				{Name: "created_at", Type: "timestamp"},
				{Name: "updated_at", Type: "timestamp"},
				{Name: "fixed_at", Type: "timestamp"},
			},
			PrimaryKey: []string{"repository", "number"},
		},
		{
			Name:        "github_code_scanning_alerts",
			Description: "GitHub Code Scanning (SAST) alerts",
			Columns: []ColumnSchema{
				{Name: "number", Type: "integer", Required: true},
				{Name: "repository", Type: "string", Required: true},
				{Name: "state", Type: "string"},
				{Name: "rule_id", Type: "string"},
				{Name: "rule_severity", Type: "string"},
				{Name: "rule_description", Type: "string"},
				{Name: "tool_name", Type: "string"},
				{Name: "tool_version", Type: "string"},
				{Name: "path", Type: "string"},
				{Name: "start_line", Type: "integer"},
				{Name: "end_line", Type: "integer"},
				{Name: "created_at", Type: "timestamp"},
				{Name: "updated_at", Type: "timestamp"},
				{Name: "fixed_at", Type: "timestamp"},
			},
			PrimaryKey: []string{"repository", "number"},
		},
		{
			Name:        "github_secret_scanning_alerts",
			Description: "GitHub Secret Scanning alerts",
			Columns: []ColumnSchema{
				{Name: "number", Type: "integer", Required: true},
				{Name: "repository", Type: "string", Required: true},
				{Name: "state", Type: "string"},
				{Name: "secret_type", Type: "string"},
				{Name: "secret_type_display_name", Type: "string"},
				{Name: "resolution", Type: "string"},
				{Name: "resolved_by", Type: "string"},
				{Name: "resolved_at", Type: "timestamp"},
				{Name: "push_protection_bypassed", Type: "boolean"},
				{Name: "created_at", Type: "timestamp"},
				{Name: "updated_at", Type: "timestamp"},
			},
			PrimaryKey: []string{"repository", "number"},
		},
		{
			Name:        "github_actions_workflows",
			Description: "GitHub Actions workflows",
			Columns: []ColumnSchema{
				{Name: "id", Type: "integer", Required: true},
				{Name: "repository", Type: "string"},
				{Name: "name", Type: "string"},
				{Name: "path", Type: "string"},
				{Name: "state", Type: "string"},
				{Name: "created_at", Type: "timestamp"},
				{Name: "updated_at", Type: "timestamp"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "github_branch_protections",
			Description: "GitHub branch protection rules",
			Columns: []ColumnSchema{
				{Name: "repository", Type: "string", Required: true},
				{Name: "branch", Type: "string", Required: true},
				{Name: "required_status_checks", Type: "boolean"},
				{Name: "enforce_admins", Type: "boolean"},
				{Name: "required_pull_request_reviews", Type: "boolean"},
				{Name: "required_approving_review_count", Type: "integer"},
				{Name: "dismiss_stale_reviews", Type: "boolean"},
				{Name: "require_code_owner_reviews", Type: "boolean"},
				{Name: "required_signatures", Type: "boolean"},
				{Name: "allow_force_pushes", Type: "boolean"},
				{Name: "allow_deletions", Type: "boolean"},
			},
			PrimaryKey: []string{"repository", "branch"},
		},
		{
			Name:        "github_organization_members",
			Description: "GitHub organization members",
			Columns: []ColumnSchema{
				{Name: "id", Type: "integer", Required: true},
				{Name: "login", Type: "string"},
				{Name: "role", Type: "string"},
				{Name: "two_factor_enabled", Type: "boolean"},
				{Name: "site_admin", Type: "boolean"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "github_teams",
			Description: "GitHub organization teams",
			Columns: []ColumnSchema{
				{Name: "id", Type: "integer", Required: true},
				{Name: "name", Type: "string"},
				{Name: "slug", Type: "string"},
				{Name: "description", Type: "string"},
				{Name: "privacy", Type: "string"},
				{Name: "permission", Type: "string"},
				{Name: "members_count", Type: "integer"},
				{Name: "repos_count", Type: "integer"},
			},
			PrimaryKey: []string{"id"},
		},
	}
}

func (g *GitHubProvider) Sync(ctx context.Context, opts SyncOptions) (*SyncResult, error) {
	start := time.Now()
	result := &SyncResult{
		Provider:  g.Name(),
		StartedAt: start,
	}

	// Sync repositories
	repos, err := g.syncRepositories(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "repositories: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *repos)
		result.TotalRows += repos.Rows
	}

	// Get repo names for alert syncing
	repoNames, _ := g.getRepoNames(ctx)

	// Sync Dependabot alerts
	for _, repo := range repoNames {
		alerts, depErr := g.syncDependabotAlerts(ctx, repo)
		if depErr != nil {
			// Some repos may not have Dependabot enabled
			continue
		}
		result.TotalRows += alerts.Rows
	}

	// Sync code scanning alerts
	for _, repo := range repoNames {
		alerts, codeErr := g.syncCodeScanningAlerts(ctx, repo)
		if codeErr != nil {
			continue
		}
		result.TotalRows += alerts.Rows
	}

	// Sync secret scanning alerts
	for _, repo := range repoNames {
		alerts, secErr := g.syncSecretScanningAlerts(ctx, repo)
		if secErr != nil {
			continue
		}
		result.TotalRows += alerts.Rows
	}

	// Sync org members
	members, err := g.syncOrgMembers(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "members: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *members)
		result.TotalRows += members.Rows
	}

	// Sync teams
	teams, err := g.syncTeams(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "teams: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *teams)
		result.TotalRows += teams.Rows
	}

	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(start)

	return result, nil
}

func (g *GitHubProvider) request(ctx context.Context, path string) ([]byte, error) {
	url := g.baseURL + path

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+g.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := g.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("github API error %d: %s", resp.StatusCode, string(body))
	}

	return io.ReadAll(resp.Body)
}

func (g *GitHubProvider) syncRepositories(ctx context.Context) (*TableResult, error) {
	result := &TableResult{Name: "github_repositories"}

	path := fmt.Sprintf("/orgs/%s/repos?per_page=100", g.org)
	body, err := g.request(ctx, path)
	if err != nil {
		return result, err
	}

	var repos []map[string]interface{}
	if err := json.Unmarshal(body, &repos); err != nil {
		return result, err
	}

	result.Rows = int64(len(repos))
	result.Inserted = result.Rows
	return result, nil
}

func (g *GitHubProvider) getRepoNames(ctx context.Context) ([]string, error) {
	path := fmt.Sprintf("/orgs/%s/repos?per_page=100", g.org)
	body, err := g.request(ctx, path)
	if err != nil {
		return nil, err
	}

	var repos []struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(body, &repos); err != nil {
		return nil, err
	}

	names := make([]string, len(repos))
	for i, r := range repos {
		names[i] = r.Name
	}
	return names, nil
}

func (g *GitHubProvider) syncDependabotAlerts(ctx context.Context, repo string) (*TableResult, error) {
	result := &TableResult{Name: "github_dependabot_alerts"}

	path := fmt.Sprintf("/repos/%s/%s/dependabot/alerts?per_page=100", g.org, repo)
	body, err := g.request(ctx, path)
	if err != nil {
		return result, err
	}

	var alerts []map[string]interface{}
	if err := json.Unmarshal(body, &alerts); err != nil {
		return result, err
	}

	result.Rows = int64(len(alerts))
	result.Inserted = result.Rows
	return result, nil
}

func (g *GitHubProvider) syncCodeScanningAlerts(ctx context.Context, repo string) (*TableResult, error) {
	result := &TableResult{Name: "github_code_scanning_alerts"}

	path := fmt.Sprintf("/repos/%s/%s/code-scanning/alerts?per_page=100", g.org, repo)
	body, err := g.request(ctx, path)
	if err != nil {
		return result, err
	}

	var alerts []map[string]interface{}
	if err := json.Unmarshal(body, &alerts); err != nil {
		return result, err
	}

	result.Rows = int64(len(alerts))
	result.Inserted = result.Rows
	return result, nil
}

func (g *GitHubProvider) syncSecretScanningAlerts(ctx context.Context, repo string) (*TableResult, error) {
	result := &TableResult{Name: "github_secret_scanning_alerts"}

	path := fmt.Sprintf("/repos/%s/%s/secret-scanning/alerts?per_page=100", g.org, repo)
	body, err := g.request(ctx, path)
	if err != nil {
		return result, err
	}

	var alerts []map[string]interface{}
	if err := json.Unmarshal(body, &alerts); err != nil {
		return result, err
	}

	result.Rows = int64(len(alerts))
	result.Inserted = result.Rows
	return result, nil
}

func (g *GitHubProvider) syncOrgMembers(ctx context.Context) (*TableResult, error) {
	result := &TableResult{Name: "github_organization_members"}

	path := fmt.Sprintf("/orgs/%s/members?per_page=100", g.org)
	body, err := g.request(ctx, path)
	if err != nil {
		return result, err
	}

	var members []map[string]interface{}
	if err := json.Unmarshal(body, &members); err != nil {
		return result, err
	}

	result.Rows = int64(len(members))
	result.Inserted = result.Rows
	return result, nil
}

func (g *GitHubProvider) syncTeams(ctx context.Context) (*TableResult, error) {
	result := &TableResult{Name: "github_teams"}

	path := fmt.Sprintf("/orgs/%s/teams?per_page=100", g.org)
	body, err := g.request(ctx, path)
	if err != nil {
		return result, err
	}

	var teams []map[string]interface{}
	if err := json.Unmarshal(body, &teams); err != nil {
		return result, err
	}

	result.Rows = int64(len(teams))
	result.Inserted = result.Rows
	return result, nil
}
