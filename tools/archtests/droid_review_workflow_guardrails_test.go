package archtests

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDroidReviewUsesIncrementalScopeAfterTheInitialReview(t *testing.T) {
	root := repoRoot(t)
	body, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "droid-review.yml"))
	if err != nil {
		t.Fatalf("read Droid review workflow: %v", err)
	}
	workflow := string(body)

	required := []string{
		`review_base: ${{ steps.scope.outputs.review_base }}`,
		`review_mode: ${{ steps.scope.outputs.review_mode }}`,
		`git merge-base --is-ancestor "${PREVIOUS_HEAD}" "${PR_HEAD_SHA}"`,
		`review_base="${PREVIOUS_HEAD}"`,
		`review_mode="incremental"`,
		`DROID_REVIEW_BASE: ${{ steps.scope.outputs.review_base }}`,
		`automatic_security_review: ${{ needs.droid-review-preflight.outputs.review_mode == 'full' }}`,
		`review_depth: ${{ needs.droid-review-preflight.outputs.review_mode == 'incremental' && 'shallow' || 'deep' }}`,
	}
	for _, marker := range required {
		if !strings.Contains(workflow, marker) {
			t.Fatalf("Droid review workflow missing incremental review marker %q", marker)
		}
	}

	deepSecFullOnly := `steps.preflight.outputs.run_droid_review == 'true' && steps.scope.outputs.review_mode == 'full'`
	if count := strings.Count(workflow, deepSecFullOnly); count != 2 {
		t.Fatalf("DeepSec setup must be full-review-only in both setup steps; found %d guards", count)
	}
	if count := strings.Count(
		workflow,
		`automatic_security_review: ${{ needs.droid-review-preflight.outputs.review_mode == 'full' }}`,
	); count != 2 {
		t.Fatalf("primary and retry reviews must both keep security review full-only; found %d", count)
	}
}
