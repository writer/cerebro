package reposcan

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

func TestLocalMaterializerRejectsUnsafeGitParameters(t *testing.T) {
	repoDir, _ := createIaCTestRepo(t)
	materializer := NewLocalMaterializer(filepath.Join(t.TempDir(), "checkouts"), scm.NewLocalClient(""))

	tests := []struct {
		name   string
		target ScanTarget
		want   string
	}{
		{
			name: "ref",
			target: ScanTarget{
				RepoURL: repoDir,
				Ref:     "--upload-pack=/tmp/helper.sh",
			},
			want: "git ref",
		},
		{
			name: "since_commit",
			target: ScanTarget{
				RepoURL:     repoDir,
				SinceCommit: "deadbeef --upload-pack=/tmp/helper.sh",
			},
			want: "sinceCommit",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := materializer.Materialize(context.Background(), "repo_scan:unsafe", tt.target)
			if err == nil {
				t.Fatal("expected validation error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("expected error containing %q, got %v", tt.want, err)
			}
		})
	}
}
