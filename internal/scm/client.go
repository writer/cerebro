package scm

import (
	"context"
	"fmt"
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

	cmd := exec.CommandContext(ctx, "gh", "repo", "clone", repo, dest)
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
	
	cmd := exec.CommandContext(ctx, "gh", "api", apiPath, "-q", ".content")
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
	
	cmdRaw := exec.CommandContext(ctx, "gh", "api", apiPath, "-H", "Accept: application/vnd.github.v3.raw")
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
	// In a real implementation, this would run `git clone`
	// For simulation, we'll assume the repo is already mapped or mocked
	return os.MkdirAll(dest, 0755)
}

func (c *LocalClient) GetFileContent(ctx context.Context, repoURL, path string) (string, error) {
	// Mock implementation
	// "https://github.com/org/payment-service" -> /base/payment-service
	repoName := strings.TrimSuffix(filepath.Base(repoURL), ".git")
	fullPath := filepath.Join(c.BasePath, repoName, path)
	
	content, err := os.ReadFile(fullPath)
	if err != nil {
		return "", fmt.Errorf("failed to read file %s: %w", fullPath, err)
	}
	return string(content), nil
}

// AnalysisResult represents findings from code analysis
type AnalysisResult struct {
	RepoURL     string   `json:"repo_url"`
	FilesScanned int      `json:"files_scanned"`
	Findings    []Finding `json:"findings"`
}

type Finding struct {
	Type        string `json:"type"`
	File        string `json:"file"`
	Line        int    `json:"line"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	CodeSnippet string `json:"code_snippet"`
}
