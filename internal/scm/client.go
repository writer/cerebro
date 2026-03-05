package scm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
)

// Client defines the interface for SCM interactions
type Client interface {
	Clone(ctx context.Context, repoURL string, dest string) error
	GetFileContent(ctx context.Context, repoURL, path string) (string, error)
}

func NewConfiguredClient(githubToken, gitlabToken, gitlabBaseURL string) Client {
	var githubClient *GitHubClient
	if githubToken != "" {
		githubClient = NewGitHubClient(githubToken)
	}

	var gitlabClient *GitLabClient
	if gitlabToken != "" {
		gitlabClient = NewGitLabClient(gitlabToken, gitlabBaseURL)
	}

	switch {
	case githubClient != nil && gitlabClient != nil:
		return NewMultiClient(githubClient, gitlabClient)
	case githubClient != nil:
		return githubClient
	case gitlabClient != nil:
		return gitlabClient
	default:
		return nil
	}
}

// GitHubClient implements Client using the 'gh' CLI
type GitHubClient struct {
	Token string
}

func NewGitHubClient(token string) *GitHubClient {
	return &GitHubClient{Token: token}
}

func (c *GitHubClient) Clone(ctx context.Context, repoURL string, dest string) error {
	// Parse repo URL to get "owner/repo"
	// Support https://github.com/owner/repo or owner/repo
	repo := strings.TrimPrefix(repoURL, "https://github.com/")
	repo = strings.TrimSuffix(repo, ".git")

	cmd := exec.CommandContext(ctx, "gh", "repo", "clone", repo, dest) //#nosec G204 -- args are sanitized repo/dest strings
	// Pass token via env if needed, but gh CLI usually manages its own auth state
	// If token is provided explicitly, we can set GH_TOKEN
	if c.Token != "" {
		cmd.Env = append(os.Environ(), "GH_TOKEN="+c.Token)
	}

	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("gh clone failed: %s: %w", string(out), err)
	}
	return nil
}

func (c *GitHubClient) GetFileContent(ctx context.Context, repoURL, path string) (string, error) {
	// Use gh api to fetch file content
	repo := strings.TrimPrefix(repoURL, "https://github.com/")
	repo = strings.TrimSuffix(repo, ".git")

	// API endpoint: /repos/{owner}/{repo}/contents/{path}
	apiPath := fmt.Sprintf("repos/%s/contents/%s", repo, path)

	cmd := exec.CommandContext(ctx, "gh", "api", apiPath, "-q", ".content") //#nosec G204 -- args are sanitized repo/path strings
	if c.Token != "" {
		cmd.Env = append(os.Environ(), "GH_TOKEN="+c.Token)
	}

	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("gh api failed: %s: %w", string(out), err)
	}

	// gh api returns base64 encoded content
	// We need to decode it. However, the output includes newlines which base64.StdEncoding might not like
	// Let's use `gh api ... --raw-field` if possible, or just decode here.
	// Actually, gh api has media type param to get raw content: -H "Accept: application/vnd.github.v3.raw"

	cmdRaw := exec.CommandContext(ctx, "gh", "api", apiPath, "-H", "Accept: application/vnd.github.v3.raw") //#nosec G204 -- args are sanitized repo/path strings
	if c.Token != "" {
		cmdRaw.Env = append(os.Environ(), "GH_TOKEN="+c.Token)
	}

	outRaw, err := cmdRaw.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("gh api raw failed: %s: %w", string(outRaw), err)
	}

	return string(outRaw), nil
}

type GitLabClient struct {
	Token      string
	BaseURL    string
	httpClient *http.Client
}

func NewGitLabClient(token, baseURL string) *GitLabClient {
	if strings.TrimSpace(baseURL) == "" {
		baseURL = "https://gitlab.com"
	}
	return &GitLabClient{Token: token, BaseURL: strings.TrimRight(baseURL, "/")}
}

func (c *GitLabClient) Clone(ctx context.Context, repoURL string, dest string) error {
	cloneURL, err := c.cloneURL(repoURL)
	if err != nil {
		return err
	}

	cmd := exec.CommandContext(ctx, "git", "clone", cloneURL, dest) //#nosec G204 -- args are sanitized repo/dest strings
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	cleanup := func() {}
	if c.Token != "" {
		askPassPath, err := gitAskPassScript("GITLAB_TOKEN")
		if err != nil {
			return err
		}
		cleanup = func() { _ = os.Remove(askPassPath) }
		cmd.Env = append(cmd.Env,
			"GITLAB_TOKEN="+c.Token,
			"GIT_ASKPASS="+askPassPath,
			"GIT_ASKPASS_REQUIRE=force",
		)
	}
	defer cleanup()
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("git clone failed: %s: %w", c.redactToken(string(out)), err)
	}
	return nil
}

func (c *GitLabClient) GetFileContent(ctx context.Context, repoURL, filePath string) (string, error) {
	if strings.TrimSpace(filePath) == "" {
		return "", errors.New("file path is required")
	}
	projectPath, err := c.projectPath(repoURL)
	if err != nil {
		return "", err
	}

	branch, err := c.defaultBranch(ctx, projectPath)
	if err != nil {
		return "", err
	}

	return c.rawFile(ctx, projectPath, filePath, branch)
}

func (c *GitLabClient) defaultBranch(ctx context.Context, projectPath string) (string, error) {
	endpoint, err := c.apiURL(fmt.Sprintf("api/v4/projects/%s", url.PathEscape(projectPath)), nil)
	if err != nil {
		return "", err
	}

	resp, err := c.doRequest(ctx, endpoint)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return "", fmt.Errorf("gitlab project lookup failed: %d (body unreadable: %w)", resp.StatusCode, readErr)
		}
		return "", fmt.Errorf("gitlab project lookup failed: %d %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var payload struct {
		DefaultBranch string `json:"default_branch"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", fmt.Errorf("gitlab project decode failed: %w", err)
	}
	if payload.DefaultBranch == "" {
		return "", errors.New("gitlab default branch not found")
	}
	return payload.DefaultBranch, nil
}

func (c *GitLabClient) rawFile(ctx context.Context, projectPath, filePath, ref string) (string, error) {
	endpoint, err := c.apiURL(
		fmt.Sprintf("api/v4/projects/%s/repository/files/%s/raw", url.PathEscape(projectPath), url.PathEscape(filePath)),
		url.Values{"ref": []string{ref}},
	)
	if err != nil {
		return "", err
	}

	resp, err := c.doRequest(ctx, endpoint)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read response body: %w", err)
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return "", fmt.Errorf("gitlab file lookup failed: %d %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	return string(body), nil
}

func (c *GitLabClient) projectPath(repoURL string) (string, error) {
	repoURL = strings.TrimSpace(repoURL)
	if repoURL == "" {
		return "", errors.New("repo URL is required")
	}

	repoURL = strings.TrimSuffix(repoURL, ".git")
	base, err := c.baseURL()
	if err != nil {
		return "", err
	}
	baseHost := base.Hostname()

	if strings.HasPrefix(repoURL, "git@") && strings.Contains(repoURL, ":") {
		parts := strings.SplitN(strings.TrimPrefix(repoURL, "git@"), ":", 2)
		if len(parts) != 2 || parts[1] == "" {
			return "", errors.New("invalid gitlab repo URL")
		}
		if !strings.EqualFold(parts[0], baseHost) {
			return "", fmt.Errorf("repo host %q does not match gitlab base host %q", parts[0], baseHost)
		}
		return strings.TrimPrefix(parts[1], "/"), nil
	}

	if strings.HasPrefix(repoURL, "http://") || strings.HasPrefix(repoURL, "https://") || strings.HasPrefix(repoURL, "ssh://") {
		parsed, err := url.Parse(repoURL)
		if err != nil {
			return "", fmt.Errorf("invalid gitlab repo URL: %w", err)
		}
		if parsed.Hostname() != "" && !strings.EqualFold(parsed.Hostname(), baseHost) {
			return "", fmt.Errorf("repo host %q does not match gitlab base host %q", parsed.Hostname(), baseHost)
		}
		pathPart := strings.TrimPrefix(parsed.Path, strings.TrimRight(base.Path, "/"))
		pathPart = strings.TrimPrefix(pathPart, "/")
		if pathPart == "" {
			return "", errors.New("repo URL missing path")
		}
		return pathPart, nil
	}

	if strings.Contains(repoURL, "/") && strings.Contains(repoURL, ".") {
		parts := strings.SplitN(repoURL, "/", 2)
		if strings.EqualFold(parts[0], baseHost) && len(parts) == 2 {
			repoURL = parts[1]
		}
	}

	repoURL = strings.TrimPrefix(repoURL, "/")
	if repoURL == "" {
		return "", errors.New("repo URL missing path")
	}
	return repoURL, nil
}

func (c *GitLabClient) cloneURL(repoURL string) (string, error) {
	projectPath, err := c.projectPath(repoURL)
	if err != nil {
		return "", err
	}

	base, err := c.baseURL()
	if err != nil {
		return "", err
	}

	basePath := strings.TrimRight(base.Path, "/")
	if basePath == "" {
		base.Path = "/" + strings.TrimPrefix(projectPath, "/")
	} else {
		base.Path = path.Join(basePath, strings.TrimPrefix(projectPath, "/"))
	}
	if !strings.HasSuffix(base.Path, ".git") {
		base.Path += ".git"
	}

	return base.String(), nil
}

func gitAskPassScript(tokenEnv string) (string, error) {
	file, err := os.CreateTemp("", "gitlab-askpass-*")
	if err != nil {
		return "", fmt.Errorf("create askpass script: %w", err)
	}
	path := file.Name()
	script := fmt.Sprintf(`#!/bin/sh
case "$1" in
*Username*) echo "oauth2" ;;
*Password*) echo "${%s}" ;;
*) echo "" ;;
esac
`, tokenEnv)
	if _, err := file.WriteString(script); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return "", fmt.Errorf("write askpass script: %w", err)
	}
	if err := file.Chmod(0o700); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return "", fmt.Errorf("chmod askpass script: %w", err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return "", fmt.Errorf("close askpass script: %w", err)
	}
	return path, nil
}

func (c *GitLabClient) doRequest(ctx context.Context, endpoint string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	if c.Token != "" {
		req.Header.Set("PRIVATE-TOKEN", c.Token)
	}
	client := c.httpClient
	if client == nil {
		client = http.DefaultClient
	}
	return client.Do(req)
}

func (c *GitLabClient) apiURL(apiPath string, query url.Values) (string, error) {
	base, err := c.baseURL()
	if err != nil {
		return "", err
	}
	apiPath = strings.TrimPrefix(apiPath, "/")
	basePath := strings.TrimRight(base.Path, "/")
	if basePath == "" {
		base.Path = "/" + apiPath
	} else {
		base.Path = path.Join(basePath, apiPath)
	}
	if query != nil {
		base.RawQuery = query.Encode()
	}
	return base.String(), nil
}

func (c *GitLabClient) baseURL() (*url.URL, error) {
	parsed, err := url.Parse(c.BaseURL)
	if err != nil || parsed.Hostname() == "" {
		return nil, fmt.Errorf("invalid gitlab base URL: %q", c.BaseURL)
	}
	return parsed, nil
}

func (c *GitLabClient) redactToken(output string) string {
	if c.Token == "" || output == "" {
		return output
	}
	redacted := strings.ReplaceAll(output, c.Token, "[REDACTED]")
	redacted = strings.ReplaceAll(redacted, url.QueryEscape(c.Token), "[REDACTED]")
	return redacted
}

type MultiClient struct {
	GitHub *GitHubClient
	GitLab *GitLabClient
}

func NewMultiClient(github *GitHubClient, gitlab *GitLabClient) *MultiClient {
	return &MultiClient{GitHub: github, GitLab: gitlab}
}

func (c *MultiClient) Clone(ctx context.Context, repoURL string, dest string) error {
	client, err := c.clientForRepo(repoURL)
	if err != nil {
		return err
	}
	return client.Clone(ctx, repoURL, dest)
}

func (c *MultiClient) GetFileContent(ctx context.Context, repoURL, filePath string) (string, error) {
	client, err := c.clientForRepo(repoURL)
	if err != nil {
		return "", err
	}
	return client.GetFileContent(ctx, repoURL, filePath)
}

func (c *MultiClient) clientForRepo(repoURL string) (Client, error) {
	if strings.TrimSpace(repoURL) == "" {
		return nil, errors.New("repo URL is required")
	}

	repoHost := hostFromRepoURL(repoURL)
	if repoHost != "" {
		if c.GitHub != nil && isGitHubHost(repoHost) {
			return c.GitHub, nil
		}
		if c.GitLab != nil {
			gitlabHost, _ := hostFromBaseURL(c.GitLab.BaseURL)
			if gitlabHost != "" && strings.EqualFold(repoHost, gitlabHost) {
				return c.GitLab, nil
			}
			if strings.Contains(strings.ToLower(repoHost), "gitlab") {
				return c.GitLab, nil
			}
		}
	}

	if c.GitHub != nil {
		return c.GitHub, nil
	}
	if c.GitLab != nil {
		return c.GitLab, nil
	}
	return nil, errors.New("SCM integration not configured")
}

func hostFromRepoURL(repoURL string) string {
	if strings.HasPrefix(repoURL, "git@") && strings.Contains(repoURL, ":") {
		parts := strings.SplitN(strings.TrimPrefix(repoURL, "git@"), ":", 2)
		if len(parts) > 0 {
			return parts[0]
		}
	}
	if strings.HasPrefix(repoURL, "http://") || strings.HasPrefix(repoURL, "https://") || strings.HasPrefix(repoURL, "ssh://") {
		parsed, err := url.Parse(repoURL)
		if err == nil {
			return parsed.Hostname()
		}
	}
	if strings.HasPrefix(repoURL, "github.com/") || strings.HasPrefix(repoURL, "gitlab.com/") {
		parts := strings.SplitN(repoURL, "/", 2)
		return parts[0]
	}
	return ""
}

func hostFromBaseURL(baseURL string) (string, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}
	return parsed.Hostname(), nil
}

func isGitHubHost(host string) bool {
	host = strings.ToLower(host)
	return host == "github.com" || host == "www.github.com"
}

// LocalClient implements Client for local filesystem (mocking real git for now)
type LocalClient struct {
	BasePath string
}

func NewLocalClient(basePath string) *LocalClient {
	return &LocalClient{BasePath: basePath}
}

func (c *LocalClient) Clone(ctx context.Context, repoURL, dest string) error {
	cmd := exec.CommandContext(ctx, "git", "clone", repoURL, dest) //#nosec G204 -- args are sanitized repo/dest strings
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("git clone failed: %s: %w", string(out), err)
	}
	return nil
}

func (c *LocalClient) GetFileContent(ctx context.Context, repoURL, path string) (string, error) {
	repoPath, err := c.localRepoPath(repoURL)
	if err != nil {
		return "", err
	}

	cleanPath := filepath.Clean(strings.TrimSpace(path))
	if cleanPath == "" || cleanPath == "." {
		return "", errors.New("path is required")
	}
	if filepath.IsAbs(cleanPath) || cleanPath == ".." || strings.HasPrefix(cleanPath, ".."+string(os.PathSeparator)) {
		return "", errors.New("path must stay within repository")
	}

	repoAbs, err := filepath.Abs(repoPath)
	if err != nil {
		return "", fmt.Errorf("failed to resolve repo path: %w", err)
	}

	fullPath := filepath.Join(repoAbs, cleanPath)
	fullAbs, err := filepath.Abs(fullPath)
	if err != nil {
		return "", fmt.Errorf("failed to resolve file path: %w", err)
	}
	if fullAbs != repoAbs && !strings.HasPrefix(fullAbs, repoAbs+string(os.PathSeparator)) {
		return "", errors.New("path escapes repository")
	}

	content, err := os.ReadFile(fullAbs) // #nosec G304 -- fullAbs is constrained to repoAbs above
	if err != nil {
		return "", fmt.Errorf("failed to read file %s: %w", fullAbs, err)
	}
	return string(content), nil
}

func (c *LocalClient) localRepoPath(repoURL string) (string, error) {
	repoURL = strings.TrimSpace(repoURL)
	if repoURL == "" {
		return "", errors.New("repo URL is required")
	}

	if strings.HasPrefix(repoURL, "file://") {
		parsed, err := url.Parse(repoURL)
		if err != nil {
			return "", fmt.Errorf("invalid file repo URL: %w", err)
		}
		if parsed.Path != "" {
			repoURL = parsed.Path
		}
	}

	if !isRemoteRepoURL(repoURL) {
		if info, err := os.Stat(repoURL); err == nil && info.IsDir() {
			return repoURL, nil
		}
	}

	if c.BasePath == "" {
		return "", fmt.Errorf("local repo path not found for %q", repoURL)
	}
	repoName := strings.TrimSuffix(filepath.Base(repoURL), ".git")
	return filepath.Join(c.BasePath, repoName), nil
}

func isRemoteRepoURL(repoURL string) bool {
	switch {
	case strings.HasPrefix(repoURL, "http://"):
		return true
	case strings.HasPrefix(repoURL, "https://"):
		return true
	case strings.HasPrefix(repoURL, "ssh://"):
		return true
	case strings.HasPrefix(repoURL, "git@"):
		return true
	default:
		return false
	}
}

// AnalysisResult represents findings from code analysis
type AnalysisResult struct {
	RepoURL      string    `json:"repo_url"`
	FilesScanned int       `json:"files_scanned"`
	Findings     []Finding `json:"findings"`
}

type Finding struct {
	Type        string `json:"type"`
	File        string `json:"file"`
	Line        int    `json:"line"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	CodeSnippet string `json:"code_snippet"`
}
