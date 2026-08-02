package archtests

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDeterministicReviewIsExactShaScopedAndReadOnly(t *testing.T) {
	root := repoRoot(t)
	body, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "deterministic-review.yml"))
	if err != nil {
		t.Fatalf("read deterministic review workflow: %v", err)
	}
	workflow := string(body)

	required := []string{
		"name: Deterministic Review",
		"permissions:\n  contents: read",
		`ref: ${{ github.event.pull_request.head.sha }}`,
		`git merge-base --is-ancestor "${BASE_SHA}" "${HEAD_SHA}"`,
		`REVIEW_BASE: ${{ github.event.pull_request.base.sha }}`,
		`REVIEW_HEAD: ${{ github.event.pull_request.head.sha }}`,
		"actionlint .github/workflows/deterministic-review.yml",
		"zizmor .github/workflows/deterministic-review.yml",
		"make deterministic-review",
		"semgrep scan",
		"make govulncheck",
		`./scripts/leak_check.sh range`,
		"shellcheck",
	}
	for _, marker := range required {
		if !strings.Contains(workflow, marker) {
			t.Fatalf("deterministic review workflow missing guardrail %q", marker)
		}
	}

	for _, forbidden := range []string{
		"Factory-AI/droid-action",
		"FACTORY_API_KEY",
		"secrets.",
		"pull-requests: write",
		"issues: write",
		"id-token: write",
		"Droid",
	} {
		if strings.Contains(workflow, forbidden) {
			t.Fatalf("deterministic review workflow must not contain %q", forbidden)
		}
	}
}
