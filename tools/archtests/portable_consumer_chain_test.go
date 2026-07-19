package archtests

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPortableConsumerChainKeepsDependencyOrder(t *testing.T) {
	root := repoRoot(t)
	scriptBody, err := os.ReadFile(filepath.Join(root, "scripts", "release", "verify_portable_consumer_chain.sh"))
	if err != nil {
		t.Fatalf("read portable consumer chain: %v", err)
	}
	script := string(scriptBody)
	orderedMarkers := []string{
		"make agent-service-lifecycle-check openapi-check openapi-ts-check",
		"npm run check --workspace @writer/cerebro-sdk",
		"npm run check --workspace @writer/cerebro-web",
		"npm run build --workspace @writer/cerebro-web",
		"npm run check --workspace @writer/cerebro-slack-companion",
		"npm run build --workspace @writer/cerebro-slack-companion",
		"npm pack --workspace @writer/cerebro-sdk",
		"npm pack --workspace @writer/cerebro-slack-companion",
		"python3 scripts/release/product_release.py build",
		"python3 scripts/release/product_release.py validate",
	}
	previous := -1
	for _, marker := range orderedMarkers {
		index := strings.Index(script, marker)
		if index == -1 {
			t.Fatalf("portable consumer chain missing %q", marker)
		}
		if index <= previous {
			t.Fatalf("portable consumer chain marker %q is out of dependency order", marker)
		}
		previous = index
	}

	workflowBody, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "portable-consumer-chain.yml"))
	if err != nil {
		t.Fatalf("read portable consumer workflow: %v", err)
	}
	workflow := string(workflowBody)
	for _, marker := range []string{
		"api/openapi.yaml",
		"schemas/agent-service-lifecycle*.json",
		"internal/agentplatform/**",
		"sdk/typescript/**",
		"apps/web/**",
		"apps/slack-companion/**",
		"scripts/release/product_release.py",
		"scripts/release/verify_portable_consumer_chain.sh",
		"permissions:\n  contents: read",
	} {
		if !strings.Contains(workflow, marker) {
			t.Fatalf("portable consumer workflow missing %q", marker)
		}
	}
	for _, forbidden := range []string{
		"environment:",
		"secrets.",
		"id-token: write",
		"packages: write",
		"deploy",
		"terraform",
		"pulumi",
	} {
		if strings.Contains(strings.ToLower(workflow), forbidden) {
			t.Fatalf("portable consumer workflow contains operational marker %q", forbidden)
		}
	}
}
