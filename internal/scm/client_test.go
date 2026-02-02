package scm

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func createTestRepo(t *testing.T) string {
	t.Helper()
	repoDir := t.TempDir()
	runGit(t, repoDir, "init")
	runGit(t, repoDir, "config", "user.email", "test@example.com")
	runGit(t, repoDir, "config", "user.name", "Test")

	contentPath := filepath.Join(repoDir, "README.md")
	if err := os.WriteFile(contentPath, []byte("hello"), 0600); err != nil {
		t.Fatalf("failed to write content: %v", err)
	}
	runGit(t, repoDir, "add", "README.md")
	runGit(t, repoDir, "commit", "-m", "init")

	return repoDir
}

func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...) //#nosec G204 -- test helper
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v failed: %s: %v", args, string(out), err)
	}
}

func TestLocalClientCloneCreatesDir(t *testing.T) {
	repoDir := createTestRepo(t)
	client := NewLocalClient("")
	dest := filepath.Join(t.TempDir(), "repo")

	if err := client.Clone(context.Background(), repoDir, dest); err != nil {
		t.Fatalf("Clone returned error: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dest, "README.md")); err != nil {
		t.Fatalf("expected cloned file to exist: %v", err)
	}
}

func TestLocalClientGetFileContent(t *testing.T) {
	repoDir := createTestRepo(t)
	client := NewLocalClient("")
	content, err := client.GetFileContent(context.Background(), repoDir, "README.md")
	if err != nil {
		t.Fatalf("GetFileContent returned error: %v", err)
	}
	if content != "hello" {
		t.Fatalf("expected content %q, got %q", "hello", content)
	}
}
