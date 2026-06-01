package archtests

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDockerComposeUsesBootstrapRuntimeDependencies(t *testing.T) {
	root := repoRoot(t)
	for _, name := range []string{"docker-compose.yml", "docker-compose.platform.yml"} {
		body, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		text := string(body)
		for _, stale := range []string{
			"SNOWFLAKE_",
			"API_PORT",
			"CEDAR_POLICIES_PATH",
			"JETSTREAM_URLS",
			"NATS_CONSUMER_ENABLED",
			"ensemble",
			"clickhouse",
			"redis",
		} {
			if strings.Contains(text, stale) {
				t.Fatalf("%s contains stale local-runtime marker %q", name, stale)
			}
		}
	}
	compose, err := os.ReadFile(filepath.Join(root, "docker-compose.yml"))
	if err != nil {
		t.Fatalf("read docker-compose.yml: %v", err)
	}
	for _, current := range []string{
		"CEREBRO_JETSTREAM_URL",
		"CEREBRO_POSTGRES_DSN",
		"CEREBRO_NEO4J_URI",
		"nats:",
		"postgres:",
		"neo4j:",
	} {
		if !strings.Contains(string(compose), current) {
			t.Fatalf("docker-compose.yml missing bootstrap runtime marker %q", current)
		}
	}
}

func TestDockerfileCanBuildCurrentBootstrapBinary(t *testing.T) {
	root := repoRoot(t)
	body, err := os.ReadFile(filepath.Join(root, "Dockerfile"))
	if err != nil {
		t.Fatalf("read Dockerfile: %v", err)
	}
	text := string(body)
	for _, current := range []string{
		"ARG GO_VERSION=",
		"ARG GO_BUILD_PARALLELISM=",
		"COPY internal/eventregistry/go.mod ./internal/eventregistry/go.mod",
		"COPY api ./api",
		"COPY cmd ./cmd",
		"COPY gen ./gen",
		"COPY internal ./internal",
		"COPY sources ./sources",
		"go build -p=${GO_BUILD_PARALLELISM}",
	} {
		if !strings.Contains(text, current) {
			t.Fatalf("Dockerfile missing required build marker %q", current)
		}
	}
}

func TestSDKDoesNotReferenceRetiredAgentSDKRoutes(t *testing.T) {
	root := repoRoot(t)
	for _, rel := range []string{
		filepath.Join("sdk", "python", "cerebro_sdk", "client.py"),
		filepath.Join("sdk", "typescript", "src", "index.ts"),
		filepath.Join("sdk", "typescript", "src", "index.js"),
	} {
		body, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		text := string(body)
		for _, retired := range []string{
			"/api/v1/agent-sdk",
			"/api/v1/admin/agent-sdk",
			"/api/v1/mcp",
			"/.well-known/oauth-protected-resource",
		} {
			if strings.Contains(text, retired) {
				t.Fatalf("%s references retired route %q", rel, retired)
			}
		}
	}
}
