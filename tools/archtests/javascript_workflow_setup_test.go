package archtests

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWorkflowsUseSharedJavaScriptSetup(t *testing.T) {
	root := repoRoot(t)
	actionPath := filepath.Join(root, ".github", "actions", "setup-javascript-workspaces", "action.yml")
	actionBytes, err := os.ReadFile(actionPath)
	if err != nil {
		t.Fatalf("read shared JavaScript setup action: %v", err)
	}
	action := string(actionBytes)
	for _, required := range []string{
		"actions/setup-node@820762786026740c76f36085b0efc47a31fe5020",
		"node-version: 22",
		"run: make workspace-install",
	} {
		if !strings.Contains(action, required) {
			t.Errorf("%s must contain %q", actionPath, required)
		}
	}

	workflows, err := filepath.Glob(filepath.Join(root, ".github", "workflows", "*.yml"))
	if err != nil {
		t.Fatalf("list GitHub workflows: %v", err)
	}
	for _, path := range workflows {
		contents, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if strings.Contains(string(contents), "actions/setup-node@") {
			t.Errorf("%s configures Node.js directly; use ./.github/actions/setup-javascript-workspaces", path)
		}
	}
}
