package archtests

import (
	"bytes"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestAgentServiceLifecycleContractHasNoInfrastructureDependencies(t *testing.T) {
	for _, path := range []string{
		"../../internal/agentplatform/agent_service_lifecycle.go",
		"../../internal/agentplatform/agent_service_lifecycle_generated.go",
		"../../internal/agentplatform/lifecyclecontract/generated.go",
	} {
		parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, imported := range parsed.Imports {
			name, err := strconv.Unquote(imported.Path.Value)
			if err != nil {
				t.Fatalf("decode import in %s: %v", path, err)
			}
			if strings.Contains(name, ".") {
				t.Fatalf("portable lifecycle contract imports non-standard package %q in %s", name, path)
			}
		}
	}
}

func TestAgentServiceLifecycleArtifactsContainNoDeploymentOverlayTerms(t *testing.T) {
	paths := []string{
		"../../schemas/agent-service-lifecycle.schema.json",
		"../../schemas/agent-service-lifecycle-contract.schema.json",
		"../../internal/agentplatform/agent_service_lifecycle.go",
	}
	for _, path := range paths {
		payload, err := os.ReadFile(path) // #nosec G304 -- fixed repository path.
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		lower := bytes.ToLower(payload)
		for _, forbidden := range []string{"socket mode", "private dns", "cloud account", "kubernetes", "slack"} {
			if bytes.Contains(lower, []byte(forbidden)) {
				t.Fatalf("portable lifecycle artifact %s contains deployment or transport term %q", path, forbidden)
			}
		}
	}
}
