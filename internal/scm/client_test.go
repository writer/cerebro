package scm

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

func TestGitLabClientGetFileContent(t *testing.T) {
	var gotToken string
	var gotRef string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotToken = r.Header.Get("PRIVATE-TOKEN")
		switch r.URL.Path {
		case "/api/v4/projects/group%2Fproject":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"default_branch":"main"}`))
		case "/api/v4/projects/group%2Fproject/repository/files/README.md/raw":
			gotRef = r.URL.Query().Get("ref")
			_, _ = w.Write([]byte("hello"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := NewGitLabClient("token", server.URL)
	content, err := client.GetFileContent(context.Background(), server.URL+"/group/project.git", "README.md")
	if err != nil {
		t.Fatalf("GetFileContent returned error: %v", err)
	}
	if content != "hello" {
		t.Fatalf("expected content %q, got %q", "hello", content)
	}
	if gotToken != "token" {
		t.Fatalf("expected token header to be set")
	}
	if gotRef != "main" {
		t.Fatalf("expected ref %q, got %q", "main", gotRef)
	}
}

func TestGitLabClientGetFileContentFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer server.Close()

	client := NewGitLabClient("token", server.URL)
	_, err := client.GetFileContent(context.Background(), server.URL+"/group/project", "README.md")
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Fatalf("expected status code in error, got %v", err)
	}
}

func TestMultiClientSelectsGitLab(t *testing.T) {
	github := NewGitHubClient("gh")
	gitlab := NewGitLabClient("gl", "https://gitlab.example.com")
	client := NewMultiClient(github, gitlab)

	selected, err := client.clientForRepo("https://gitlab.example.com/group/project")
	if err != nil {
		t.Fatalf("clientForRepo returned error: %v", err)
	}
	if selected != gitlab {
		t.Fatalf("expected GitLab client")
	}

	selected, err = client.clientForRepo("owner/repo")
	if err != nil {
		t.Fatalf("clientForRepo returned error: %v", err)
	}
	if selected != github {
		t.Fatalf("expected GitHub client")
	}
}
