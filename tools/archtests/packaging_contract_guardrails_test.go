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

func TestReleaseWorkflowsKeepCandidateAndStableBoundaries(t *testing.T) {
	root := repoRoot(t)
	makefileBody, err := os.ReadFile(filepath.Join(root, "Makefile"))
	if err != nil {
		t.Fatalf("read Makefile: %v", err)
	}
	makefileText := string(makefileBody)
	if strings.Contains(strings.ToLower(makefileText), "goreleaser") {
		t.Fatal("release-smoke must not validate unused GoReleaser configuration")
	}
	if !strings.Contains(makefileText, "release-smoke: release-train-test ## Validate release-train configuration.") {
		t.Fatal("release-smoke must keep the release-train contract validation dependency")
	}
	releaseBody, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatalf("read release workflow: %v", err)
	}
	release := string(releaseBody)
	for _, marker := range []string{
		"environment: stable-release",
		"candidate_run_id:",
		"smoke_receipt_url:",
		"scripts/release/validate_release_notes.sh",
		"cosign verify",
		`docker buildx imagetools create -t "${image_base}:${RELEASE_TAG}"`,
		`docker buildx imagetools create -t "${image_base}:latest"`,
		"target_environment: sec-dev",
		"apply_mode: direct_push",
		"target_environment: go-prod",
		"apply_mode: pull_request",
		"name: Check Infisical bootstrap",
		`echo "configured=false" >> "$GITHUB_OUTPUT"`,
		"Dispatch stable deployment request",
		"for target in sec-dev go-prod; do",
		`cerebro-runtime-contract-${target}.json`,
		"TARGET_ENVIRONMENT: ${{ matrix.target_environment }}",
		`test "$(jq '.client_payload | length' "${payload}")" -le 10`,
		`gh api --method POST "repos/${infra_repository}/dispatches" --input "${payload}"`,
		`requested_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"`,
		"--workflow propose-image-tag.yml",
		"--event repository_dispatch",
		"deadline=$((SECONDS + 120))",
		"no matching propose-image-tag.yml run appeared",
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
	verifyIndex := strings.Index(release, "  verify-candidate:")
	promoteIndex := strings.Index(release, "  promote:")
	if verifyIndex == -1 || promoteIndex == -1 || verifyIndex >= promoteIndex {
		t.Fatal("release workflow must define verify-candidate before promote")
	}
	verifyCandidate := release[verifyIndex:promoteIndex]
	for _, marker := range []string{
		"fetch-depth: 0",
		"actions/setup-go@",
		"go-version-file: go.mod",
		`actions/runs/${CANDIDATE_RUN_ID}/artifacts?per_page=100`,
		`^cerebro-candidate-[0-9a-f]{40}$`,
		`sha="${artifact_name#cerebro-candidate-}"`,
	} {
		if !strings.Contains(verifyCandidate, marker) {
			t.Fatalf("verify-candidate job missing required marker %q", marker)
		}
	}
	if strings.Contains(verifyCandidate, "\n          sha=\"$(jq -r .head_sha") {
		t.Fatal("verify-candidate must derive the candidate commit from the run artifact, not the branch head")
	}
	if strings.Contains(release, "-env sec-dev") {
		t.Fatal("runtime deploy contract must not be pinned to sec-dev when release dispatches multiple environments")
	}
	dispatchIndex := strings.Index(release, "Dispatch stable deployment request")
	matrixIndex := strings.Index(release, "target_environment: sec-dev")
	if dispatchIndex == -1 || matrixIndex == -1 || matrixIndex > dispatchIndex {
		t.Fatal("release workflow must fan out infra dispatches before the dispatch step")
	}
	orgSecretsIndex := strings.Index(release, "name: Fetch organization release credentials")
	repoSecretsIndex := strings.Index(release, "name: Fetch repository release credentials")
	bootstrapIndex := strings.Index(release, "name: Check Infisical bootstrap")
	if bootstrapIndex == -1 || orgSecretsIndex == -1 || repoSecretsIndex == -1 || bootstrapIndex > orgSecretsIndex || orgSecretsIndex > repoSecretsIndex || repoSecretsIndex > dispatchIndex {
		t.Fatal("release workflow must check Infisical bootstrap before fetching deployment credentials and dispatching the release")
	}
	for name, section := range map[string]string{
		"organization": release[orgSecretsIndex:repoSecretsIndex],
		"repository":   release[repoSecretsIndex:dispatchIndex],
	} {
		if !strings.Contains(section, "if: steps.infisical.outputs.configured == 'true'") {
			t.Fatalf("release workflow must guard %s secret fetch behind the bootstrap check", name)
		}
	}
	candidateBody, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "cut-release.yml"))
	if err != nil {
		t.Fatalf("read candidate workflow: %v", err)
	}
	candidate := string(candidateBody)
	for _, marker := range []string{
		"name: Candidate Build",
		"branches: [main]",
		"Require successful CI for candidate commit",
		"image_tag=candidate-${sha}",
		"--provenance=mode=max --sbom=true --push",
		"cosign sign --yes",
		"cerebro.release-candidate/v1",
		"bundle-checksums.txt",
		"| head -n 1 || true",
	} {
		if !strings.Contains(candidate, marker) {
			t.Fatalf("candidate workflow missing required marker %q", marker)
		}
	}
	for _, forbidden := range []string{"git tag", "gh release create", `:${RELEASE_TAG}`, `:latest`} {
		if strings.Contains(candidate, forbidden) {
			t.Fatalf("candidate workflow contains stable publication marker %q", forbidden)
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
