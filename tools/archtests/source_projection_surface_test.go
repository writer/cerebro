package archtests

import (
	"path/filepath"
	"testing"
)

const sourceProjectionRegistryLineBudget = 350

func TestSourceProjectionRegistryBehaviorDoesNotAbsorbBuiltinData(t *testing.T) {
	root := repoRoot(t)
	path := filepath.Join(root, "internal", "sourceprojection", "registry.go")
	lines := countLines(t, path)
	if lines > sourceProjectionRegistryLineBudget {
		t.Fatalf(
			"internal/sourceprojection/registry.go grew to %d lines, budget %d; keep static event-kind wiring in registry_builtins.go and registry lifecycle, dispatch, overlays, and tenant validation here",
			lines,
			sourceProjectionRegistryLineBudget,
		)
	}
}
