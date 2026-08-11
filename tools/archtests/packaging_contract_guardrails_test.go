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
	if _, err := os.Stat(filepath.Join(root, ".goreleaser.yaml")); err == nil {
		t.Fatal("retired GoReleaser configuration must not remain in the repository")
	} else if !os.IsNotExist(err) {
		t.Fatalf("stat retired GoReleaser configuration: %v", err)
	}
	codeownersBody, err := os.ReadFile(filepath.Join(root, ".github", "CODEOWNERS"))
	if err != nil {
		t.Fatalf("read CODEOWNERS: %v", err)
	}
	if strings.Contains(strings.ToLower(string(codeownersBody)), "goreleaser") {
		t.Fatal("CODEOWNERS must not retain ownership for retired GoReleaser configuration")
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
		"cerebro-product-release.json",
		"WEB_CANDIDATE_IMAGE",
		"cosign verify-blob candidate/cerebro-product-release.json",
		"  notify-release-consumer:",
		"RELEASE_CONSUMER_TOKEN",
		"RELEASE_CONSUMER_REPOSITORY",
		`{event_type:"product-release-published",client_payload:$payload[0]}`,
		`test "$(jq '.client_payload | length' dispatch.json)" -eq 6`,
		`gh api --method POST "repos/${RELEASE_CONSUMER_REPOSITORY}/dispatches" --input dispatch.json`,
	} {
		if !strings.Contains(release, marker) {
			t.Fatalf("release workflow missing required marker %q", marker)
		}
	}
	for _, privateMarker := range []string{
		"  notify-infra:",
		"target_environment",
		"apply_mode",
		"credential bootstrap",
		"secrets-action@",
		"identity-id:",
		"project-slug:",
		"env-slug:",
		"/contents/.github/workflows/",
		"propose-image-tag",
		"--event repository_dispatch",
		"deadline=$((",
		"request_id",
		"runtime_contract",
		"runtime-contract-",
		"-format contract-json",
	} {
		if strings.Contains(strings.ToLower(release), privateMarker) {
			t.Fatalf("public release workflow contains deployment-specific marker %q", privateMarker)
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
	notifyIndex := strings.Index(release, "  notify-release-consumer:")
	if notifyIndex == -1 || notifyIndex <= promoteIndex {
		t.Fatal("release consumer notification must follow stable promotion")
	}
	notify := release[notifyIndex:]
	if !strings.Contains(notify, "    permissions:\n      contents: read\n") || strings.Contains(notify, "id-token: write") {
		t.Fatal("release consumer notification must use read-only repository permissions")
	}
	for _, marker := range []string{
		`if [ -z "${RELEASE_CONSUMER_TOKEN}" ] && [ -z "${RELEASE_CONSUMER_REPOSITORY}" ]`,
		`if [ -z "${RELEASE_CONSUMER_TOKEN}" ] || [ -z "${RELEASE_CONSUMER_REPOSITORY}" ]`,
		"python3 scripts/release/product_release.py event",
		"python3 scripts/release/product_release.py validate-event",
	} {
		if !strings.Contains(notify, marker) {
			t.Fatalf("release consumer notification missing boundary marker %q", marker)
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
		"cerebro.product-release/v1",
		"Build and publish candidate web image",
		"Verify candidate image platforms",
		"Scan candidate images",
		"rust-organizational-e2e:",
		"cerebro.rust-organizational-e2e/v1",
		"Prove process liveness and backend readiness split",
		`readiness_code="$(curl --max-time 90`,
		`.code == "graph_unavailable"`,
		"Attach the Rust E2E receipt to the candidate digest",
		"rust_e2e_receipt_sha256",
		`test "${platforms}" = '["linux/amd64","linux/arm64"]'`,
		"aquasec/trivy:0.66.0@sha256:",
		"--severity CRITICAL --ignore-unfixed --exit-code 1",
		"Build portable Slack companion and SDK archives",
		"Sign candidate product release",
		"product-release-published.schema.json",
		"bundle-checksums.txt",
		"| head -n 1 || true",
		"path: .dist/release\n          if-no-files-found: error\n          include-hidden-files: true",
	} {
		if !strings.Contains(candidate, marker) {
			t.Fatalf("candidate workflow missing required marker %q", marker)
		}
	}
	for _, forbidden := range []string{
		"git tag",
		"gh release create",
		`:${RELEASE_TAG}`,
		`:latest`,
		"  contracts:\n",
		"target_environment",
		"runtime-contract-",
		"-format contract-json",
	} {
		if strings.Contains(candidate, forbidden) {
			t.Fatalf("candidate workflow contains forbidden release marker %q", forbidden)
		}
	}
	receiptIndex := strings.Index(candidate, "  receipt:\n")
	if receiptIndex == -1 {
		t.Fatal("candidate workflow must define the receipt job")
	}
	receipt := candidate[receiptIndex:]
	if !strings.Contains(receipt, "needs: [resolve, ci-gate, binaries, manifest, rust-organizational-e2e, web-manifest, scan-images, product-release]") {
		t.Fatal("candidate receipt must wait for CI, both image scans, and the exact-image Rust proof")
	}
	if !strings.Contains(candidate, "group: candidate-build-main") ||
		!strings.Contains(candidate, "cancel-in-progress: true") {
		t.Fatal("candidate workflow must cancel stale main builds")
	}
	resolveIndex := strings.Index(candidate, "  resolve:\n")
	ciGateIndex := strings.Index(candidate, "  ci-gate:\n")
	binaryIndex := strings.Index(candidate, "  binary:\n")
	if resolveIndex == -1 || ciGateIndex <= resolveIndex || binaryIndex <= ciGateIndex {
		t.Fatal("candidate workflow must define resolve, CI gate, and binary jobs in order")
	}
	resolveJob := candidate[resolveIndex:ciGateIndex]
	ciGateJob := candidate[ciGateIndex:binaryIndex]
	if strings.Contains(resolveJob, "Require successful CI") {
		t.Fatal("candidate resolution must not wait for CI before builds can start")
	}
	if !strings.Contains(ciGateJob, "needs: resolve") ||
		!strings.Contains(ciGateJob, "Require successful CI") {
		t.Fatal("candidate workflow must enforce CI in a parallel gate")
	}
	if !strings.Contains(receipt, "    permissions:\n      actions: read\n      contents: read\n") {
		t.Fatal("candidate receipt job must allow artifact discovery with actions: read")
	}
	imageStart := strings.Index(candidate, "\n  image:\n")
	manifestStart := strings.Index(candidate, "\n  manifest:\n")
	if imageStart < 0 || manifestStart <= imageStart {
		t.Fatal("candidate workflow must define image and manifest jobs")
	}
	imageJob := candidate[imageStart:manifestStart]
	for _, required := range []string{
		"runs-on: ${{ matrix.runner }}",
		"needs: resolve",
		"runner: ubuntu-24.04",
		"runner: ubuntu-24.04-arm",
		"name: Build runtime binary",
	} {
		if !strings.Contains(imageJob, required) {
			t.Fatalf("candidate image job must contain %q", required)
		}
	}
	for _, forbidden := range []string{
		"needs: [resolve, binaries]",
		"actions/download-artifact",
		"docker/setup-qemu-action",
	} {
		if strings.Contains(imageJob, forbidden) {
			t.Fatalf("candidate image job must not contain serialized or emulated build step %q", forbidden)
		}
	}
	makefile, err := os.ReadFile(filepath.Join(root, "Makefile"))
	if err != nil {
		t.Fatalf("read Makefile: %v", err)
	}
	makefileText = string(makefile)
	if !strings.Contains(makefileText, `docker run --rm "$(DOCKER_SMOKE_IMAGE)" version`) {
		t.Fatal("docker-smoke must run the built image entrypoint, not only build it")
	}
	if !strings.Contains(makefileText, `go build -trimpath -ldflags="-s -w" -o .dist/cerebro`) {
		t.Fatal("docker-smoke must strip the runtime binary before loading the image")
	}
}

func TestRustOnlyCandidateAllowsReadinessDeadlineToExpire(t *testing.T) {
	root := repoRoot(t)
	workflow, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "rust-only-candidate.yml"))
	if err != nil {
		t.Fatalf("read Rust-only candidate workflow: %v", err)
	}
	if !strings.Contains(string(workflow), `curl --max-time 90`) {
		t.Fatal("Rust-only candidate readiness client must outlive the 75-second backend deadline")
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
