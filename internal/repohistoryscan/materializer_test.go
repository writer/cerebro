package repohistoryscan

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/scm"
)

func TestLocalMaterializerReusesRepositoryCacheAndFetchesNewCommits(t *testing.T) {
	repoDir, _, secondCommit := createHistoryRepo(t)
	basePath := filepath.Join(t.TempDir(), "history-scan")
	materializer := NewLocalMaterializer(basePath, scm.NewLocalClient(""))

	descriptor1, checkout1, err := materializer.Materialize(context.Background(), "repo_history_scan:first", ScanTarget{RepoURL: repoDir})
	if err != nil {
		t.Fatalf("first materialize: %v", err)
	}
	if descriptor1.CommitSHA != secondCommit {
		t.Fatalf("expected first checkout at %q, got %#v", secondCommit, descriptor1)
	}
	if got, _ := checkout1.Metadata["cache_strategy"].(string); got != "clone" {
		t.Fatalf("expected first cache strategy clone, got %#v", checkout1.Metadata)
	}
	cachePath1, _ := checkout1.Metadata["cache_path"].(string)
	if cachePath1 == "" {
		t.Fatalf("expected cache path metadata, got %#v", checkout1.Metadata)
	}
	if err := materializer.Cleanup(context.Background(), checkout1); err != nil {
		t.Fatalf("cleanup first checkout: %v", err)
	}
	if _, err := os.Stat(cachePath1); err != nil {
		t.Fatalf("expected cache to survive checkout cleanup: %v", err)
	}

	mustWriteRepoFile(t, filepath.Join(repoDir, "secrets.txt"), "TOKEN=latest\n")
	runGit(t, repoDir, "add", "secrets.txt")
	runGit(t, repoDir, "commit", "-m", "latest secret")
	thirdCommit := stringsTrimSpace(runGitOutput(t, repoDir, "rev-parse", "HEAD"))

	descriptor2, checkout2, err := materializer.Materialize(context.Background(), "repo_history_scan:second", ScanTarget{RepoURL: repoDir})
	if err != nil {
		t.Fatalf("second materialize: %v", err)
	}
	if descriptor2.CommitSHA != thirdCommit {
		t.Fatalf("expected fetched checkout at %q, got %#v", thirdCommit, descriptor2)
	}
	if got, _ := checkout2.Metadata["cache_strategy"].(string); got != "fetch" {
		t.Fatalf("expected second cache strategy fetch, got %#v", checkout2.Metadata)
	}
	cachePath2, _ := checkout2.Metadata["cache_path"].(string)
	if cachePath2 != cachePath1 {
		t.Fatalf("expected cache path reuse, got %q and %q", cachePath1, cachePath2)
	}
}

func stringsTrimSpace(value string) string {
	return strings.TrimSpace(value)
}
