package repohistoryscan

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/scm"
)

func TestValidateRequestRejectsUnsafeGitParameters(t *testing.T) {
	tests := []struct {
		name string
		req  ScanRequest
		want string
	}{
		{
			name: "ref",
			req: ScanRequest{
				Target: ScanTarget{
					RepoURL: "https://github.com/acme/platform.git",
					Ref:     "--upload-pack=/tmp/helper.sh",
				},
			},
			want: "git ref",
		},
		{
			name: "since_commit",
			req: ScanRequest{
				Target: ScanTarget{
					RepoURL:     "https://github.com/acme/platform.git",
					SinceCommit: "deadbeef --upload-pack=/tmp/helper.sh",
				},
			},
			want: "sinceCommit",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRequest(tt.req)
			if err == nil {
				t.Fatal("expected validation error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("expected error containing %q, got %v", tt.want, err)
			}
		})
	}
}

func TestLocalMaterializerRejectsUnsafeRef(t *testing.T) {
	repoDir, _, _ := createHistoryRepo(t)
	materializer := NewLocalMaterializer(filepath.Join(t.TempDir(), "history-scan"), scm.NewLocalClient(""))

	_, _, err := materializer.Materialize(context.Background(), "repo_history_scan:unsafe", ScanTarget{
		RepoURL: repoDir,
		Ref:     "--upload-pack=/tmp/helper.sh",
	})
	if err == nil {
		t.Fatal("expected validation error")
	}
	if !strings.Contains(err.Error(), "git ref") {
		t.Fatalf("expected git ref validation error, got %v", err)
	}
}
