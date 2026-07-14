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

func TestReleaseWorkflowKeepsCIParityAndStableLatestGuard(t *testing.T) {
	root := repoRoot(t)
	releaseBody, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatalf("read release workflow: %v", err)
	}
	release := string(releaseBody)
	for _, marker := range []string{
		"command: make sdk-test",
		"command: make proto-lint proto-generate-check proto-breaking",
		"command: make docker-smoke",
		"is_stable_release:",
		`if [ "${{ needs.resolve-tag.outputs.is_stable_release }}" = "true" ]; then`,
		"Skipping latest tag for prerelease",
		"target_environment: sec-dev",
		"apply_mode: direct_push",
		"target_environment: go-prod",
		"apply_mode: pull_request",
		"TARGET_ENVIRONMENT: ${{ matrix.target_environment }}",
		"name: Check Infisical bootstrap",
		`echo "configured=false" >> "$GITHUB_OUTPUT"`,
		`payload_keys="$(jq '.client_payload | length' <<<"${payload}")"`,
		"GitHub allows at most 10",
		`gh api --method POST "repos/${INFRA_REPOSITORY}/dispatches" --input - <<<"${payload}"`,
		`target_environment: [sec-dev, go-prod]`,
		`-env "${TARGET_ENVIRONMENT}"`,
		"cerebro-runtime-contract-sec-dev.json",
		"cerebro-runtime-contract-go-prod.json",
	} {
		if !strings.Contains(release, marker) {
			t.Fatalf("release workflow missing required marker %q", marker)
		}
	}
	for _, stale := range []string{
		`--arg runtime_contract `,
		`--arg runtime_contract_signature `,
		`--arg runtime_contract_certificate `,
		`runtime_contract: $runtime_contract`,
		`runtime_contract_signature: $runtime_contract_signature`,
		`runtime_contract_certificate: $runtime_contract_certificate`,
	} {
		if strings.Contains(release, stale) {
			t.Fatalf("release dispatch payload contains stale contract marker %q", stale)
		}
	}
	if strings.Contains(release, "-env sec-dev") {
		t.Fatal("runtime deploy contract must not be pinned to sec-dev when release dispatches multiple environments")
	}
	latestIndex := strings.Index(release, `docker buildx imagetools create -t "${IMAGE_BASE}:latest"`)
	stableGuardIndex := strings.Index(release, `if [ "${{ needs.resolve-tag.outputs.is_stable_release }}" = "true" ]; then`)
	if latestIndex == -1 || stableGuardIndex == -1 || stableGuardIndex > latestIndex {
		t.Fatal("release workflow must guard latest image publication behind stable-release check")
	}
	dispatchIndex := strings.Index(release, "Dispatch release deployment request")
	matrixIndex := strings.Index(release, "target_environment: sec-dev")
	if dispatchIndex == -1 || matrixIndex == -1 || matrixIndex > dispatchIndex {
		t.Fatal("release workflow must fan out infra dispatches before the dispatch step")
	}
	orgSecretsIndex := strings.Index(release, "name: Fetch org-level secrets from Infisical")
	repoSecretsIndex := strings.Index(release, "name: Fetch repo-level secrets from Infisical")
	bootstrapIndex := strings.Index(release, "name: Check Infisical bootstrap")
	if bootstrapIndex == -1 || orgSecretsIndex == -1 || repoSecretsIndex == -1 || bootstrapIndex > orgSecretsIndex || orgSecretsIndex > repoSecretsIndex {
		t.Fatal("release workflow must check Infisical bootstrap before fetching deployment credentials")
	}
	for name, section := range map[string]string{
		"org":  release[orgSecretsIndex:repoSecretsIndex],
		"repo": release[repoSecretsIndex:dispatchIndex],
	} {
		if !strings.Contains(section, "if: steps.infisical.outputs.configured == 'true'") {
			t.Fatalf("release workflow must guard %s secret fetch behind the bootstrap check", name)
		}
	}

	makefile, err := os.ReadFile(filepath.Join(root, "Makefile"))
	if err != nil {
		t.Fatalf("read Makefile: %v", err)
	}
	if !strings.Contains(string(makefile), `docker run --rm "$(DOCKER_SMOKE_IMAGE)" version`) {
		t.Fatal("docker-smoke must run the built image entrypoint, not only build it")
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
