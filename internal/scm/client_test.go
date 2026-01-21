package scm

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestLocalClientCloneCreatesDir(t *testing.T) {
	base := t.TempDir()
	client := NewLocalClient(base)
	dest := filepath.Join(base, "repo")

	if err := client.Clone(context.Background(), "https://github.com/org/repo", dest); err != nil {
		t.Fatalf("Clone returned error: %v", err)
	}
	if _, err := os.Stat(dest); err != nil {
		t.Fatalf("expected clone directory to exist: %v", err)
	}
}

func TestLocalClientGetFileContent(t *testing.T) {
	base := t.TempDir()
	repoDir := filepath.Join(base, "repo")
	if err := os.MkdirAll(repoDir, 0750); err != nil {
		t.Fatalf("failed to create repo dir: %v", err)
	}

	contentPath := filepath.Join(repoDir, "README.md")
	if err := os.WriteFile(contentPath, []byte("hello"), 0600); err != nil {
		t.Fatalf("failed to write content: %v", err)
	}

	client := NewLocalClient(base)
	content, err := client.GetFileContent(context.Background(), "https://github.com/org/repo.git", "README.md")
	if err != nil {
		t.Fatalf("GetFileContent returned error: %v", err)
	}
	if content != "hello" {
		t.Fatalf("expected content %q, got %q", "hello", content)
	}
}
