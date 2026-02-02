package scm

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Client defines the interface for SCM interactions
type Client interface {
	Clone(ctx context.Context, repoURL string, dest string) error
	GetFileContent(ctx context.Context, repoURL, path string) (string, error)
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
	fullPath := filepath.Join(repoPath, path)

	content, err := os.ReadFile(fullPath)
	if err != nil {
		return "", fmt.Errorf("failed to read file %s: %w", fullPath, err)
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
