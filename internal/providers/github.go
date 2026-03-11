package providers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
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

type githubRepoInfo struct {
	Name          string
	FullName      string
	DefaultBranch string
	Visibility    string
}

type githubMembership struct {
	Role  string
	State string
}

type githubAPIError struct {
	StatusCode int
	Body       string
}

const githubPullRequestLookbackDays = 180

func (e *githubAPIError) Error() string {
	return fmt.Sprintf("github API error %d: %s", e.StatusCode, e.Body)
}

func NewGitHubProvider() *GitHubProvider {
	return &GitHubProvider{
		BaseProvider: NewBaseProvider("github", ProviderTypeSaaS),
		baseURL:      "https://api.github.com",
		client:       newProviderHTTPClient(30 * time.Second),
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
			Name:        "github_organizations",
			Description: "GitHub organizations",
			Columns: []ColumnSchema{
				{Name: "id", Type: "integer", Required: true},
				{Name: "login", Type: "string"},
				{Name: "name", Type: "string"},
				{Name: "two_factor_requirement_enabled", Type: "boolean"},
				{Name: "actions_permissions", Type: "json"},
			},
			PrimaryKey: []string{"id"},
		},
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
			Name:        "github_pull_requests",
			Description: "GitHub pull requests",
			Columns: []ColumnSchema{
				{Name: "id", Type: "integer", Required: true},
				{Name: "number", Type: "integer", Required: true},
				{Name: "repository", Type: "string", Required: true},
				{Name: "author_login", Type: "string"},
				{Name: "title", Type: "string"},
				{Name: "state", Type: "string"},
				{Name: "draft", Type: "boolean"},
				{Name: "created_at", Type: "timestamp"},
				{Name: "updated_at", Type: "timestamp"},
				{Name: "merged_at", Type: "timestamp"},
				{Name: "closed_at", Type: "timestamp"},
				{Name: "merged_by_login", Type: "string"},
				{Name: "additions", Type: "integer"},
				{Name: "deletions", Type: "integer"},
				{Name: "changed_files", Type: "integer"},
				{Name: "review_comments", Type: "integer"},
				{Name: "commits", Type: "integer"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "github_pull_request_reviews",
			Description: "GitHub pull request reviews",
			Columns: []ColumnSchema{
				{Name: "id", Type: "integer", Required: true},
				{Name: "pull_request_id", Type: "integer", Required: true},
				{Name: "repository", Type: "string", Required: true},
				{Name: "reviewer_login", Type: "string"},
				{Name: "author_login", Type: "string"},
				{Name: "state", Type: "string"},
				{Name: "submitted_at", Type: "timestamp"},
				{Name: "body", Type: "string"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "github_commits",
			Description: "GitHub commit activity",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "sha", Type: "string", Required: true},
				{Name: "repository", Type: "string", Required: true},
				{Name: "author_login", Type: "string"},
				{Name: "author_email", Type: "string"},
				{Name: "committer_login", Type: "string"},
				{Name: "committer_email", Type: "string"},
				{Name: "message", Type: "string"},
				{Name: "files_changed", Type: "integer"},
				{Name: "additions", Type: "integer"},
				{Name: "deletions", Type: "integer"},
				{Name: "committed_at", Type: "timestamp"},
			},
			PrimaryKey: []string{"repository", "sha"},
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
				{Name: "email", Type: "string"},
				{Name: "role", Type: "string"},
				{Name: "org_membership_state", Type: "string"},
				{Name: "two_factor_enabled", Type: "boolean"},
				{Name: "site_admin", Type: "boolean"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "github_runner_groups",
			Description: "GitHub Actions runner groups",
			Columns: []ColumnSchema{
				{Name: "id", Type: "integer", Required: true},
				{Name: "name", Type: "string"},
				{Name: "visibility", Type: "string"},
				{Name: "allows_public_repositories", Type: "boolean"},
				{Name: "selected_repositories_count", Type: "integer"},
				{Name: "default", Type: "boolean"},
				{Name: "restricted_to_workflows", Type: "boolean"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "github_runners",
			Description: "GitHub self-hosted runners",
			Columns: []ColumnSchema{
				{Name: "id", Type: "integer", Required: true},
				{Name: "name", Type: "string"},
				{Name: "os", Type: "string"},
				{Name: "status", Type: "string"},
				{Name: "busy", Type: "boolean"},
				{Name: "labels", Type: "array"},
				{Name: "runner_group_id", Type: "integer"},
				{Name: "runner_group_name", Type: "string"},
				{Name: "runner_group", Type: "json"},
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

	schemas := g.Schema()
	syncTable := func(name string, rows []map[string]interface{}) {
		schema, ok := schemaByName(schemas, name)
		if !ok {
			result.Errors = append(result.Errors, name+": schema not found")
			return
		}
		table, err := g.syncTable(ctx, schema, rows)
		if err != nil {
			result.Errors = append(result.Errors, name+": "+err.Error())
			return
		}
		result.Tables = append(result.Tables, *table)
		result.TotalRows += table.Rows
	}

	orgRows, err := g.fetchOrganization(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "organizations: "+err.Error())
	} else {
		syncTable("github_organizations", orgRows)
	}

	repoRows, repos, err := g.fetchRepositories(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "repositories: "+err.Error())
	} else {
		syncTable("github_repositories", repoRows)
	}

	var dependabotRows []map[string]interface{}
	var codeScanningRows []map[string]interface{}
	var secretRows []map[string]interface{}
	var workflowRows []map[string]interface{}
	var branchRows []map[string]interface{}
	var pullRequestRows []map[string]interface{}
	var pullRequestReviewRows []map[string]interface{}
	var commitRows []map[string]interface{}
	pullRequestSince := time.Now().AddDate(0, 0, -githubPullRequestLookbackDays)
	for _, repo := range repos {
		rows, depErr := g.fetchDependabotAlerts(ctx, repo)
		if depErr != nil {
			result.Errors = append(result.Errors, "dependabot_alerts: "+depErr.Error())
		} else {
			dependabotRows = append(dependabotRows, rows...)
		}

		rows, codeErr := g.fetchCodeScanningAlerts(ctx, repo)
		if codeErr != nil {
			result.Errors = append(result.Errors, "code_scanning_alerts: "+codeErr.Error())
		} else {
			codeScanningRows = append(codeScanningRows, rows...)
		}

		rows, secErr := g.fetchSecretScanningAlerts(ctx, repo)
		if secErr != nil {
			result.Errors = append(result.Errors, "secret_scanning_alerts: "+secErr.Error())
		} else {
			secretRows = append(secretRows, rows...)
		}

		rows, workflowErr := g.fetchWorkflows(ctx, repo)
		if workflowErr != nil {
			result.Errors = append(result.Errors, "actions_workflows: "+workflowErr.Error())
		} else {
			workflowRows = append(workflowRows, rows...)
		}

		rows, branchErr := g.fetchBranchProtections(ctx, repo)
		if branchErr != nil {
			result.Errors = append(result.Errors, "branch_protections: "+branchErr.Error())
		} else {
			branchRows = append(branchRows, rows...)
		}

		prRows, reviewRows, pullErr := g.fetchPullRequests(ctx, repo, pullRequestSince)
		if pullErr != nil {
			result.Errors = append(result.Errors, "pull_requests: "+pullErr.Error())
		} else {
			pullRequestRows = append(pullRequestRows, prRows...)
			pullRequestReviewRows = append(pullRequestReviewRows, reviewRows...)
		}

		rows, commitErr := g.fetchCommits(ctx, repo, pullRequestSince)
		if commitErr != nil {
			result.Errors = append(result.Errors, "commits: "+commitErr.Error())
		} else {
			commitRows = append(commitRows, rows...)
		}
	}

	syncTable("github_dependabot_alerts", dependabotRows)
	syncTable("github_code_scanning_alerts", codeScanningRows)
	syncTable("github_secret_scanning_alerts", secretRows)
	syncTable("github_actions_workflows", workflowRows)
	syncTable("github_branch_protections", branchRows)
	syncTable("github_pull_requests", pullRequestRows)
	syncTable("github_pull_request_reviews", pullRequestReviewRows)
	syncTable("github_commits", commitRows)

	memberRows, err := g.fetchOrgMembers(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "members: "+err.Error())
	} else {
		syncTable("github_organization_members", memberRows)
	}

	runnerGroupRows, runnerGroups, err := g.fetchRunnerGroups(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "runner_groups: "+err.Error())
	} else {
		syncTable("github_runner_groups", runnerGroupRows)
	}

	runnerRows, err := g.fetchRunners(ctx, runnerGroups)
	if err != nil {
		result.Errors = append(result.Errors, "runners: "+err.Error())
	} else {
		syncTable("github_runners", runnerRows)
	}

	teamRows, err := g.fetchTeams(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "teams: "+err.Error())
	} else {
		syncTable("github_teams", teamRows)
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
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return nil, &githubAPIError{StatusCode: resp.StatusCode, Body: string(body)}
	}

	return io.ReadAll(resp.Body)
}

func (g *GitHubProvider) listAll(ctx context.Context, path string) ([]map[string]interface{}, error) {
	page := 1
	var allItems []map[string]interface{}
	for {
		paged := addQueryParams(path, map[string]string{
			"per_page": "100",
			"page":     strconv.Itoa(page),
		})
		body, err := g.request(ctx, paged)
		if err != nil {
			return nil, err
		}

		var items []map[string]interface{}
		if err := json.Unmarshal(body, &items); err != nil {
			return nil, err
		}

		allItems = append(allItems, items...)
		if len(items) < 100 {
			break
		}
		page++
	}
	return allItems, nil
}

func (g *GitHubProvider) listAllWithKey(ctx context.Context, path string, key string) ([]map[string]interface{}, error) {
	page := 1
	var allItems []map[string]interface{}
	for {
		paged := addQueryParams(path, map[string]string{
			"per_page": "100",
			"page":     strconv.Itoa(page),
		})
		body, err := g.request(ctx, paged)
		if err != nil {
			return nil, err
		}

		var payload map[string]interface{}
		if err := json.Unmarshal(body, &payload); err != nil {
			return nil, err
		}

		rawItems, ok := payload[key].([]interface{})
		if !ok || len(rawItems) == 0 {
			break
		}

		items := make([]map[string]interface{}, 0, len(rawItems))
		for _, item := range rawItems {
			if m, ok := item.(map[string]interface{}); ok {
				items = append(items, m)
			}
		}

		allItems = append(allItems, items...)
		if len(items) < 100 {
			break
		}
		page++
	}

	return allItems, nil
}

func (g *GitHubProvider) fetchOrganization(ctx context.Context) ([]map[string]interface{}, error) {
	path := fmt.Sprintf("/orgs/%s", g.org)
	body, err := g.request(ctx, path)
	if err != nil {
		return nil, err
	}

	var org map[string]interface{}
	if err := json.Unmarshal(body, &org); err != nil {
		return nil, err
	}

	normalized := normalizeGitHubMap(org)
	actionsPermissions := map[string]interface{}{}
	workflowPath := fmt.Sprintf("/orgs/%s/actions/permissions/workflow", g.org)
	workflowBody, err := g.request(ctx, workflowPath)
	if err == nil {
		var workflow map[string]interface{}
		if err := json.Unmarshal(workflowBody, &workflow); err != nil {
			return nil, err
		}
		workflowNormalized := normalizeGitHubMap(workflow)
		if value, ok := workflowNormalized["default_workflow_permissions"]; ok {
			actionsPermissions["default_workflow_permissions"] = value
		}
		if value, ok := workflowNormalized["can_approve_pull_request_reviews"]; ok {
			actionsPermissions["can_approve_pull_request_reviews"] = value
		}
	} else if !isGitHubIgnorable(err) {
		return nil, err
	}

	row := map[string]interface{}{
		"id":                             normalized["id"],
		"login":                          normalized["login"],
		"name":                           normalized["name"],
		"two_factor_requirement_enabled": normalized["two_factor_requirement_enabled"],
		"actions_permissions":            actionsPermissions,
	}

	return []map[string]interface{}{row}, nil
}

func (g *GitHubProvider) fetchRepositories(ctx context.Context) ([]map[string]interface{}, []githubRepoInfo, error) {
	repos, err := g.listAll(ctx, fmt.Sprintf("/orgs/%s/repos", g.org))
	if err != nil {
		return nil, nil, err
	}

	rows := make([]map[string]interface{}, 0, len(repos))
	infos := make([]githubRepoInfo, 0, len(repos))
	for _, repo := range repos {
		normalized := normalizeGitHubMap(repo)
		row := map[string]interface{}{
			"id":             normalized["id"],
			"name":           normalized["name"],
			"full_name":      normalized["full_name"],
			"private":        normalized["private"],
			"visibility":     normalized["visibility"],
			"default_branch": normalized["default_branch"],
			"archived":       normalized["archived"],
			"disabled":       normalized["disabled"],
			"fork":           normalized["fork"],
			"language":       normalized["language"],
			"topics":         normalized["topics"],
			"created_at":     normalized["created_at"],
			"updated_at":     normalized["updated_at"],
			"pushed_at":      normalized["pushed_at"],
		}
		rows = append(rows, row)

		info := githubRepoInfo{
			Name:          asString(normalized["name"]),
			FullName:      asString(normalized["full_name"]),
			DefaultBranch: asString(normalized["default_branch"]),
			Visibility:    asString(normalized["visibility"]),
		}
		info.FullName = buildRepoFullName(g.org, info)
		infos = append(infos, info)
	}

	return rows, infos, nil
}

func (g *GitHubProvider) fetchRunnerGroups(ctx context.Context) ([]map[string]interface{}, map[string]map[string]interface{}, error) {
	path := fmt.Sprintf("/orgs/%s/actions/runner-groups", g.org)
	groups, err := g.listAllWithKey(ctx, path, "runner_groups")
	if err != nil {
		if isGitHubIgnorable(err) {
			return nil, map[string]map[string]interface{}{}, nil
		}
		return nil, nil, err
	}

	rows := make([]map[string]interface{}, 0, len(groups))
	groupInfo := make(map[string]map[string]interface{}, len(groups))
	for _, group := range groups {
		normalized := normalizeGitHubMap(group)
		groupID := asString(normalized["id"])
		count := normalized["selected_repositories_count"]
		visibility := asString(normalized["visibility"])
		if count == nil && visibility == "selected" {
			repoCount, countErr := g.fetchRunnerGroupRepositoryCount(ctx, groupID)
			if countErr != nil {
				if !isGitHubIgnorable(countErr) {
					return nil, nil, countErr
				}
			} else {
				count = repoCount
			}
		}

		row := map[string]interface{}{
			"id":                          normalized["id"],
			"name":                        normalized["name"],
			"visibility":                  normalized["visibility"],
			"allows_public_repositories":  normalized["allows_public_repositories"],
			"selected_repositories_count": count,
			"default":                     normalized["default"],
			"restricted_to_workflows":     normalized["restricted_to_workflows"],
		}
		rows = append(rows, row)

		if groupID != "" {
			groupInfo[groupID] = map[string]interface{}{
				"id":                          normalized["id"],
				"name":                        normalized["name"],
				"visibility":                  normalized["visibility"],
				"allows_public_repositories":  normalized["allows_public_repositories"],
				"selected_repositories_count": count,
				"default":                     normalized["default"],
				"restricted_to_workflows":     normalized["restricted_to_workflows"],
			}
		}
	}

	return rows, groupInfo, nil
}

func (g *GitHubProvider) fetchRunnerGroupRepositoryCount(ctx context.Context, groupID string) (int, error) {
	if groupID == "" {
		return 0, nil
	}

	path := fmt.Sprintf("/orgs/%s/actions/runner-groups/%s/repositories", g.org, groupID)
	repos, err := g.listAllWithKey(ctx, path, "repositories")
	if err != nil {
		return 0, err
	}

	return len(repos), nil
}

func (g *GitHubProvider) fetchRunners(ctx context.Context, runnerGroups map[string]map[string]interface{}) ([]map[string]interface{}, error) {
	path := fmt.Sprintf("/orgs/%s/actions/runners", g.org)
	runners, err := g.listAllWithKey(ctx, path, "runners")
	if err != nil {
		if isGitHubIgnorable(err) {
			return nil, nil
		}
		return nil, err
	}

	rows := make([]map[string]interface{}, 0, len(runners))
	for _, runner := range runners {
		normalized := normalizeGitHubMap(runner)
		groupID := asString(normalized["runner_group_id"])
		row := map[string]interface{}{
			"id":                normalized["id"],
			"name":              normalized["name"],
			"os":                normalized["os"],
			"status":            normalized["status"],
			"busy":              normalized["busy"],
			"labels":            normalized["labels"],
			"runner_group_id":   normalized["runner_group_id"],
			"runner_group_name": normalized["runner_group_name"],
		}
		if groupID != "" {
			if group, ok := runnerGroups[groupID]; ok {
				row["runner_group"] = group
			}
		}
		rows = append(rows, row)
	}

	return rows, nil
}

func (g *GitHubProvider) fetchDependabotAlerts(ctx context.Context, repo githubRepoInfo) ([]map[string]interface{}, error) {
	if repo.Name == "" {
		return nil, nil
	}
	path := fmt.Sprintf("/repos/%s/%s/dependabot/alerts", g.org, repo.Name)
	alerts, err := g.listAll(ctx, path)
	if err != nil {
		if isGitHubIgnorable(err) {
			return nil, nil
		}
		return nil, err
	}

	rows := make([]map[string]interface{}, 0, len(alerts))
	for _, alert := range alerts {
		normalized := normalizeGitHubMap(alert)
		row := map[string]interface{}{
			"number":                   normalized["number"],
			"repository":               buildRepoFullName(g.org, repo),
			"state":                    normalized["state"],
			"severity":                 firstNonEmptyString(getNestedString(normalized, "security_vulnerability", "severity"), getNestedString(normalized, "security_advisory", "severity")),
			"package_name":             getNestedString(normalized, "dependency", "package", "name"),
			"package_ecosystem":        getNestedString(normalized, "dependency", "package", "ecosystem"),
			"vulnerable_version_range": getNestedString(normalized, "security_vulnerability", "vulnerable_version_range"),
			"patched_version":          getNestedString(normalized, "security_vulnerability", "first_patched_version", "identifier"),
			"cve_id":                   getNestedString(normalized, "security_advisory", "cve_id"),
			"ghsa_id":                  getNestedString(normalized, "security_advisory", "ghsa_id"),
			"created_at":               normalized["created_at"],
			"updated_at":               normalized["updated_at"],
			"fixed_at":                 normalized["fixed_at"],
		}
		if score, ok := getNestedFloat(normalized, "security_advisory", "cvss", "score"); ok {
			row["cvss_score"] = score
		}
		rows = append(rows, row)
	}

	return rows, nil
}

func (g *GitHubProvider) fetchCodeScanningAlerts(ctx context.Context, repo githubRepoInfo) ([]map[string]interface{}, error) {
	if repo.Name == "" {
		return nil, nil
	}
	path := fmt.Sprintf("/repos/%s/%s/code-scanning/alerts", g.org, repo.Name)
	alerts, err := g.listAll(ctx, path)
	if err != nil {
		if isGitHubIgnorable(err) {
			return nil, nil
		}
		return nil, err
	}

	rows := make([]map[string]interface{}, 0, len(alerts))
	for _, alert := range alerts {
		normalized := normalizeGitHubMap(alert)
		row := map[string]interface{}{
			"number":           normalized["number"],
			"repository":       buildRepoFullName(g.org, repo),
			"state":            normalized["state"],
			"rule_id":          getNestedString(normalized, "rule", "id"),
			"rule_severity":    getNestedString(normalized, "rule", "severity"),
			"rule_description": getNestedString(normalized, "rule", "description"),
			"tool_name":        getNestedString(normalized, "tool", "name"),
			"tool_version":     getNestedString(normalized, "tool", "version"),
			"path":             getNestedString(normalized, "most_recent_instance", "location", "path"),
			"start_line":       getNestedValue(normalized, "most_recent_instance", "location", "start_line"),
			"end_line":         getNestedValue(normalized, "most_recent_instance", "location", "end_line"),
			"created_at":       normalized["created_at"],
			"updated_at":       normalized["updated_at"],
			"fixed_at":         normalized["fixed_at"],
		}
		rows = append(rows, row)
	}

	return rows, nil
}

func (g *GitHubProvider) fetchSecretScanningAlerts(ctx context.Context, repo githubRepoInfo) ([]map[string]interface{}, error) {
	if repo.Name == "" {
		return nil, nil
	}
	path := fmt.Sprintf("/repos/%s/%s/secret-scanning/alerts", g.org, repo.Name)
	alerts, err := g.listAll(ctx, path)
	if err != nil {
		if isGitHubIgnorable(err) {
			return nil, nil
		}
		return nil, err
	}

	rows := make([]map[string]interface{}, 0, len(alerts))
	for _, alert := range alerts {
		normalized := normalizeGitHubMap(alert)
		row := map[string]interface{}{
			"number":                   normalized["number"],
			"repository":               buildRepoFullName(g.org, repo),
			"state":                    normalized["state"],
			"secret_type":              normalized["secret_type"],
			"secret_type_display_name": normalized["secret_type_display_name"],
			"resolution":               normalized["resolution"],
			"resolved_by":              getNestedString(normalized, "resolved_by", "login"),
			"resolved_at":              normalized["resolved_at"],
			"push_protection_bypassed": normalized["push_protection_bypassed"],
			"created_at":               normalized["created_at"],
			"updated_at":               normalized["updated_at"],
		}
		rows = append(rows, row)
	}

	return rows, nil
}

func (g *GitHubProvider) fetchWorkflows(ctx context.Context, repo githubRepoInfo) ([]map[string]interface{}, error) {
	if repo.Name == "" {
		return nil, nil
	}
	var workflows []map[string]interface{}
	page := 1
	for {
		path := fmt.Sprintf("/repos/%s/%s/actions/workflows", g.org, repo.Name)
		paged := addQueryParams(path, map[string]string{
			"per_page": "100",
			"page":     strconv.Itoa(page),
		})
		body, err := g.request(ctx, paged)
		if err != nil {
			if isGitHubIgnorable(err) {
				return nil, nil
			}
			return nil, err
		}

		var resp struct {
			Workflows []map[string]interface{} `json:"workflows"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, err
		}
		workflows = append(workflows, resp.Workflows...)
		if len(resp.Workflows) < 100 {
			break
		}
		page++
	}

	rows := make([]map[string]interface{}, 0, len(workflows))
	for _, workflow := range workflows {
		normalized := normalizeGitHubMap(workflow)
		row := map[string]interface{}{
			"id":         normalized["id"],
			"repository": buildRepoFullName(g.org, repo),
			"name":       normalized["name"],
			"path":       normalized["path"],
			"state":      normalized["state"],
			"created_at": normalized["created_at"],
			"updated_at": normalized["updated_at"],
		}
		rows = append(rows, row)
	}

	return rows, nil
}

func (g *GitHubProvider) fetchBranchProtections(ctx context.Context, repo githubRepoInfo) ([]map[string]interface{}, error) {
	if repo.Name == "" || repo.DefaultBranch == "" {
		return nil, nil
	}

	branch := url.PathEscape(repo.DefaultBranch)
	path := fmt.Sprintf("/repos/%s/%s/branches/%s/protection", g.org, repo.Name, branch)
	body, err := g.request(ctx, path)
	if err != nil {
		if isGitHubIgnorable(err) {
			return nil, nil
		}
		return nil, err
	}

	var protection map[string]interface{}
	if err := json.Unmarshal(body, &protection); err != nil {
		return nil, err
	}

	normalized := normalizeGitHubMap(protection)
	row := map[string]interface{}{
		"repository":                      buildRepoFullName(g.org, repo),
		"branch":                          repo.DefaultBranch,
		"required_status_checks":          normalized["required_status_checks"] != nil,
		"enforce_admins":                  getNestedBool(normalized, "enforce_admins", "enabled"),
		"required_pull_request_reviews":   normalized["required_pull_request_reviews"] != nil,
		"required_approving_review_count": getNestedValue(normalized, "required_pull_request_reviews", "required_approving_review_count"),
		"dismiss_stale_reviews":           getNestedBool(normalized, "required_pull_request_reviews", "dismiss_stale_reviews"),
		"require_code_owner_reviews":      getNestedBool(normalized, "required_pull_request_reviews", "require_code_owner_reviews"),
		"required_signatures":             getNestedBool(normalized, "required_signatures", "enabled"),
		"allow_force_pushes":              getNestedBool(normalized, "allow_force_pushes", "enabled"),
		"allow_deletions":                 getNestedBool(normalized, "allow_deletions", "enabled"),
	}

	return []map[string]interface{}{row}, nil
}

func (g *GitHubProvider) fetchPullRequests(ctx context.Context, repo githubRepoInfo, since time.Time) ([]map[string]interface{}, []map[string]interface{}, error) {
	if repo.Name == "" {
		return nil, nil, nil
	}

	path := fmt.Sprintf("/repos/%s/%s/pulls", g.org, repo.Name)
	page := 1
	var pullRequestRows []map[string]interface{}
	var reviewRows []map[string]interface{}

	for {
		paged := addQueryParams(path, map[string]string{
			"state":     "all",
			"sort":      "updated",
			"direction": "desc",
			"per_page":  "100",
			"page":      strconv.Itoa(page),
		})

		body, err := g.request(ctx, paged)
		if err != nil {
			if isGitHubIgnorable(err) {
				return nil, nil, nil
			}
			return nil, nil, err
		}

		var pulls []map[string]interface{}
		if err := json.Unmarshal(body, &pulls); err != nil {
			return nil, nil, err
		}
		if len(pulls) == 0 {
			break
		}

		stopPagination := false
		for _, pull := range pulls {
			normalized := normalizeGitHubMap(pull)
			updatedAt := parseGitHubTime(asString(normalized["updated_at"]))
			if !since.IsZero() && !updatedAt.IsZero() && updatedAt.Before(since) {
				stopPagination = true
				break
			}

			number, ok := asInt(normalized["number"])
			if !ok {
				continue
			}

			detailRow, err := g.fetchPullRequestDetails(ctx, repo, number)
			if err != nil {
				if isGitHubIgnorable(err) {
					continue
				}
				return nil, nil, err
			}
			pullRequestRows = append(pullRequestRows, detailRow)

			reviews, err := g.fetchPullRequestReviews(ctx, repo, number, detailRow["id"], asString(detailRow["author_login"]))
			if err != nil {
				return nil, nil, err
			}
			reviewRows = append(reviewRows, reviews...)
		}

		if stopPagination || len(pulls) < 100 {
			break
		}
		page++
	}

	return pullRequestRows, reviewRows, nil
}

func (g *GitHubProvider) fetchPullRequestDetails(ctx context.Context, repo githubRepoInfo, number int) (map[string]interface{}, error) {
	path := fmt.Sprintf("/repos/%s/%s/pulls/%d", g.org, repo.Name, number)
	body, err := g.request(ctx, path)
	if err != nil {
		return nil, err
	}

	var pull map[string]interface{}
	if err := json.Unmarshal(body, &pull); err != nil {
		return nil, err
	}

	normalized := normalizeGitHubMap(pull)
	row := map[string]interface{}{
		"id":              normalized["id"],
		"number":          normalized["number"],
		"repository":      buildRepoFullName(g.org, repo),
		"author_login":    getNestedString(normalized, "user", "login"),
		"title":           normalized["title"],
		"state":           normalized["state"],
		"draft":           normalized["draft"],
		"created_at":      normalized["created_at"],
		"updated_at":      normalized["updated_at"],
		"merged_at":       normalized["merged_at"],
		"closed_at":       normalized["closed_at"],
		"merged_by_login": getNestedString(normalized, "merged_by", "login"),
		"additions":       normalized["additions"],
		"deletions":       normalized["deletions"],
		"changed_files":   normalized["changed_files"],
		"review_comments": normalized["review_comments"],
		"commits":         normalized["commits"],
	}

	return row, nil
}

func (g *GitHubProvider) fetchPullRequestReviews(ctx context.Context, repo githubRepoInfo, number int, pullRequestID interface{}, authorLogin string) ([]map[string]interface{}, error) {
	path := fmt.Sprintf("/repos/%s/%s/pulls/%d/reviews", g.org, repo.Name, number)
	reviews, err := g.listAll(ctx, path)
	if err != nil {
		if isGitHubIgnorable(err) {
			return nil, nil
		}
		return nil, err
	}

	rows := make([]map[string]interface{}, 0, len(reviews))
	for _, review := range reviews {
		normalized := normalizeGitHubMap(review)
		row := map[string]interface{}{
			"id":              normalized["id"],
			"pull_request_id": pullRequestID,
			"repository":      buildRepoFullName(g.org, repo),
			"reviewer_login":  getNestedString(normalized, "user", "login"),
			"author_login":    authorLogin,
			"state":           strings.ToLower(asString(normalized["state"])),
			"submitted_at":    normalized["submitted_at"],
			"body":            normalized["body"],
		}
		rows = append(rows, row)
	}

	return rows, nil
}

func (g *GitHubProvider) fetchCommits(ctx context.Context, repo githubRepoInfo, since time.Time) ([]map[string]interface{}, error) {
	if repo.Name == "" {
		return nil, nil
	}

	path := fmt.Sprintf("/repos/%s/%s/commits", g.org, repo.Name)
	page := 1
	var rows []map[string]interface{}

	for {
		params := map[string]string{
			"per_page": "100",
			"page":     strconv.Itoa(page),
		}
		if !since.IsZero() {
			params["since"] = since.UTC().Format(time.RFC3339)
		}

		paged := addQueryParams(path, params)
		body, err := g.request(ctx, paged)
		if err != nil {
			if isGitHubIgnorable(err) {
				return nil, nil
			}
			return nil, err
		}

		var commits []map[string]interface{}
		if err := json.Unmarshal(body, &commits); err != nil {
			return nil, err
		}
		if len(commits) == 0 {
			break
		}

		for _, commit := range commits {
			normalized := normalizeGitHubMap(commit)
			sha := asString(normalized["sha"])
			if sha == "" {
				continue
			}

			row, err := g.fetchCommitDetails(ctx, repo, sha)
			if err != nil {
				if isGitHubIgnorable(err) {
					continue
				}
				return nil, err
			}
			rows = append(rows, row)
		}

		if len(commits) < 100 {
			break
		}
		page++
	}

	return rows, nil
}

func (g *GitHubProvider) fetchCommitDetails(ctx context.Context, repo githubRepoInfo, sha string) (map[string]interface{}, error) {
	path := fmt.Sprintf("/repos/%s/%s/commits/%s", g.org, repo.Name, sha)
	body, err := g.request(ctx, path)
	if err != nil {
		return nil, err
	}

	var commit map[string]interface{}
	if err := json.Unmarshal(body, &commit); err != nil {
		return nil, err
	}

	normalized := normalizeGitHubMap(commit)
	filesChanged := 0
	if files, ok := getNestedValue(normalized, "files").([]interface{}); ok {
		filesChanged = len(files)
	}

	row := map[string]interface{}{
		"id":              firstNonEmptyString(asString(normalized["node_id"]), sha),
		"sha":             sha,
		"repository":      buildRepoFullName(g.org, repo),
		"author_login":    getNestedString(normalized, "author", "login"),
		"author_email":    getNestedString(normalized, "commit", "author", "email"),
		"committer_login": getNestedString(normalized, "committer", "login"),
		"committer_email": getNestedString(normalized, "commit", "committer", "email"),
		"message":         getNestedString(normalized, "commit", "message"),
		"files_changed":   filesChanged,
		"additions":       getNestedValue(normalized, "stats", "additions"),
		"deletions":       getNestedValue(normalized, "stats", "deletions"),
		"committed_at": firstNonEmptyString(
			getNestedString(normalized, "commit", "author", "date"),
			getNestedString(normalized, "commit", "committer", "date"),
		),
	}

	return row, nil
}

func (g *GitHubProvider) fetchOrgMembers(ctx context.Context) ([]map[string]interface{}, error) {
	members, err := g.listAll(ctx, fmt.Sprintf("/orgs/%s/members", g.org))
	if err != nil {
		return nil, err
	}

	disabled := make(map[string]bool)
	disabledMembers, err := g.listAll(ctx, fmt.Sprintf("/orgs/%s/members?filter=2fa_disabled", g.org))
	if err == nil {
		for _, member := range disabledMembers {
			normalized := normalizeGitHubMap(member)
			login := asString(normalized["login"])
			if login != "" {
				disabled[login] = true
			}
		}
	} else if !isGitHubIgnorable(err) {
		return nil, err
	}

	rows := make([]map[string]interface{}, 0, len(members))
	for _, member := range members {
		normalized := normalizeGitHubMap(member)
		login := asString(normalized["login"])
		row := map[string]interface{}{
			"id":         normalized["id"],
			"login":      login,
			"email":      normalized["email"],
			"site_admin": normalized["site_admin"],
		}
		if login != "" {
			if membership, roleErr := g.fetchMembership(ctx, login); roleErr == nil {
				if membership.Role != "" {
					row["role"] = membership.Role
				}
				if membership.State != "" {
					row["org_membership_state"] = membership.State
				}
			}
			if len(disabled) > 0 {
				row["two_factor_enabled"] = !disabled[login]
			}
		}
		rows = append(rows, row)
	}

	return rows, nil
}

func (g *GitHubProvider) fetchTeams(ctx context.Context) ([]map[string]interface{}, error) {
	teams, err := g.listAll(ctx, fmt.Sprintf("/orgs/%s/teams", g.org))
	if err != nil {
		return nil, err
	}

	rows := make([]map[string]interface{}, 0, len(teams))
	for _, team := range teams {
		normalized := normalizeGitHubMap(team)
		row := map[string]interface{}{
			"id":            normalized["id"],
			"name":          normalized["name"],
			"slug":          normalized["slug"],
			"description":   normalized["description"],
			"privacy":       normalized["privacy"],
			"permission":    normalized["permission"],
			"members_count": normalized["members_count"],
			"repos_count":   normalized["repos_count"],
		}
		rows = append(rows, row)
	}

	return rows, nil
}

func (g *GitHubProvider) fetchMembership(ctx context.Context, login string) (githubMembership, error) {
	path := fmt.Sprintf("/orgs/%s/memberships/%s", g.org, login)
	body, err := g.request(ctx, path)
	if err != nil {
		return githubMembership{}, err
	}

	var membership map[string]interface{}
	if err := json.Unmarshal(body, &membership); err != nil {
		return githubMembership{}, err
	}

	normalized := normalizeGitHubMap(membership)
	return githubMembership{
		Role:  asString(normalized["role"]),
		State: asString(normalized["state"]),
	}, nil
}

func buildRepoFullName(org string, repo githubRepoInfo) string {
	if repo.FullName != "" {
		return repo.FullName
	}
	if repo.Name == "" {
		return ""
	}
	return org + "/" + repo.Name
}

func addQueryParams(path string, params map[string]string) string {
	parsed, err := url.Parse(path)
	if err != nil {
		return path
	}

	query := parsed.Query()
	for key, value := range params {
		if key == "page" || query.Get(key) == "" {
			query.Set(key, value)
		}
	}
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func normalizeGitHubMap(value map[string]interface{}) map[string]interface{} {
	normalized, ok := normalizeMapKeys(value).(map[string]interface{})
	if !ok {
		return map[string]interface{}{}
	}
	return normalized
}

func getNestedValue(data map[string]interface{}, path ...string) interface{} {
	var current interface{} = data
	for _, key := range path {
		asMap, ok := current.(map[string]interface{})
		if !ok {
			return nil
		}
		current = asMap[key]
	}
	return current
}

func getNestedString(data map[string]interface{}, path ...string) string {
	return asString(getNestedValue(data, path...))
}

func getNestedBool(data map[string]interface{}, path ...string) bool {
	return asBool(getNestedValue(data, path...))
}

func getNestedFloat(data map[string]interface{}, path ...string) (float64, bool) {
	return asFloat(getNestedValue(data, path...))
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func asString(value interface{}) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return typed
	case fmt.Stringer:
		return typed.String()
	default:
		return fmt.Sprint(typed)
	}
}

func asBool(value interface{}) bool {
	switch typed := value.(type) {
	case bool:
		return typed
	case string:
		return strings.EqualFold(typed, "true")
	default:
		return false
	}
}

func asFloat(value interface{}) (float64, bool) {
	switch typed := value.(type) {
	case float64:
		return typed, true
	case float32:
		return float64(typed), true
	case int:
		return float64(typed), true
	case int64:
		return float64(typed), true
	case json.Number:
		value, err := typed.Float64()
		return value, err == nil
	case string:
		value, err := strconv.ParseFloat(typed, 64)
		return value, err == nil
	default:
		return 0, false
	}
}

func asInt(value interface{}) (int, bool) {
	switch typed := value.(type) {
	case int:
		return typed, true
	case int64:
		return int(typed), true
	case float64:
		return int(typed), true
	case float32:
		return int(typed), true
	case json.Number:
		parsed, err := typed.Int64()
		return int(parsed), err == nil
	case string:
		parsed, err := strconv.Atoi(typed)
		return parsed, err == nil
	default:
		return 0, false
	}
}

func parseGitHubTime(value string) time.Time {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}
	}
	return parsed
}

func isGitHubIgnorable(err error) bool {
	var apiErr *githubAPIError
	if errors.As(err, &apiErr) {
		return apiErr.StatusCode == http.StatusNotFound || apiErr.StatusCode == http.StatusForbidden
	}
	return false
}
