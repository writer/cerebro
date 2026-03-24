package scm

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateGitRefRejectsOptionLikeValue(t *testing.T) {
	err := ValidateGitRef("--upload-pack=/tmp/helper.sh")
	if err == nil {
		t.Fatal("expected validation error")
	}
	if !strings.Contains(err.Error(), "must not start with '-'") {
		t.Fatalf("expected option injection error, got %v", err)
	}
}

func TestValidateGitRefAllowsBranchTagAndCommit(t *testing.T) {
	values := []string{
		"main",
		"release/v1.2.3",
		"refs/tags/v1.0.0",
		"0b6b2132",
	}
	for _, value := range values {
		if err := ValidateGitRef(value); err != nil {
			t.Fatalf("expected %q to be accepted, got %v", value, err)
		}
	}
}

func TestValidateSinceCommitRejectsNonHexValue(t *testing.T) {
	err := ValidateSinceCommit("deadbeef --upload-pack=/tmp/helper.sh")
	if err == nil {
		t.Fatal("expected validation error")
	}
	if !strings.Contains(err.Error(), "must match") {
		t.Fatalf("expected commit pattern error, got %v", err)
	}
}

func TestLocalClientCloneWithOptionsRejectsUnsafeRef(t *testing.T) {
	repoDir := createTestRepo(t)
	client := NewLocalClient("")
	dest := filepath.Join(t.TempDir(), "repo")

	err := client.CloneWithOptions(context.Background(), repoDir, dest, CloneOptions{Depth: 1, Ref: "--upload-pack=/tmp/helper.sh"})
	if err == nil {
		t.Fatal("expected clone validation error")
	}
	if !strings.Contains(err.Error(), "must not start with '-'") {
		t.Fatalf("expected option injection error, got %v", err)
	}
}
