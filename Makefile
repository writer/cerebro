.DEFAULT_GOAL := help

.PHONY: help build serve serve-dev test test-race cover test-coverage sdk-test sdk-go-test sdk-python-test sdk-python-build-check sdk-typescript-test sdk-typescript-check sdk-dependency-audit script-test workflow-e2e-test workflow-replay-test finding-rule-test finding-rule-scaffold-test sourcegen-test openapi-definition-gen-test agent-platform-eval github-findings-e2e github-findings-graph-preview github-audit-findings-graph-preview workflow-replay workflow-neighborhood graph-rebuild-dryrun candidate-smoke mcp-contract-check mcp-smoke mcp-sdk-compat lint lint-bootstrap proto-lint proto-generate proto-generate-check proto-breaking openapi-check openapi-lint openapi-sync catalog-check control-index-generate control-index-check sourcegen-check graph-action-generate graph-action-check finding-dsl-migrate finding-dsl-test finding-dsl-lint finding-dsl-schema-generate finding-dsl-schema-check finding-dsl-check policy-rule-generate policy-rule-check detection-catalog-generate detection-catalog-check new-aws-collector docs-autogen docs-drift-check readme-check oss-audit govulncheck contracts-check changed-check docker-smoke release-smoke load-smoke doctor droid-review-preflight droid-review-sast droid-ci-context droid-review-context droid-post-merge-health droid-feedback land-pr clean hooks pre-commit verify check check-structural check-structural-build check-structural-test check-arch check-hook-integrity

GO_BIN ?= $(shell go env GOPATH)/bin
PYTHON ?= python3
GOLANGCI_LINT := $(GO_BIN)/golangci-lint
GOLANGCI_LINT_VERSION ?= v2.11.4
BUF := GOFLAGS= GOTOOLCHAIN=go1.26.4 go run github.com/bufbuild/buf/cmd/buf@v1.59.0
GOVULNCHECK := GOFLAGS= GOTOOLCHAIN=go1.26.4 go run golang.org/x/vuln/cmd/govulncheck@v1.1.4
SPECTRAL := npx --yes @stoplight/spectral-cli@6.15.0
GORELEASER := GOFLAGS= GOTOOLCHAIN=go1.26.4 go run github.com/goreleaser/goreleaser/v2@v2.16.0
PROTO_BREAKING_BASE ?= origin/main
README_CHECK_BASE ?= origin/main
DOCKER_SMOKE_IMAGE ?= cerebro-runtime-smoke:local
DOCKER_SMOKE_GOARCH ?= amd64
DOCKER_RUNTIME_BASE_IMAGE ?= alpine:3.24
DOCKER_SMOKE_BASE_IMAGES ?= $(DOCKER_RUNTIME_BASE_IMAGE) public.ecr.aws/docker/library/alpine:3.24 mirror.gcr.io/library/alpine:3.24
DOCKER_BUILD_ATTEMPTS ?= 3
DOCKER_BUILD_RETRY_SLEEP ?= 10
APP_PACKAGES := ./api/... ./cmd/... ./internal/... ./sources/...
COVER_PACKAGES ?= ./internal/runtimeresponse ./internal/graphagent ./internal/deviceauth ./internal/sourceprojection ./internal/findings
COVERAGE_OUT ?= tmp/coverage.out
SDK_PYTHON_VENV ?= tmp/sdk-python-test-venv
SDK_PYTHON_BUILD_VENV ?= tmp/sdk-python-build-venv
SDK_PYTHON_DIST ?= tmp/sdk-python-dist
SDK_AUDIT_VENV ?= tmp/sdk-audit-venv
LINTER_MODULE := ./tools/linters
LINTER_BIN := $(GO_BIN)/cerebrolint
WORKFLOW_E2E_PACKAGES := ./internal/workflowevents ./internal/workflowprojection ./internal/knowledge ./internal/findings ./internal/bootstrap
WORKFLOW_E2E_TESTS := Test(NewDecisionRecordedEventIsStableAndDecodable|ProjectKnowledgeWorkflowEvents|ProjectFindingWorkflowEvents|ReplayProjectsWorkflowEvents|WriteDecisionAppendsWorkflowEventBeforeProjection|WriteDecisionAppendFailurePreventsGraphProjection|WriteActionProjectionFailureLeavesAppendedWorkflowEvent|ResolveFindingBridgesDecisionAndOutcomeWhenGraphConfigured|AddFindingNoteUpdatesPersistedWorkflow|LinkFindingTicketUpdatesPersistedWorkflow|PlatformKnowledgeDecisionAndOutcomeEndpoints|FindingEndpoints|WorkflowReplayEndpoint|GraphNeighborhoodEndpoints)
WORKFLOW_REPLAY_TESTS := Test(ReplayProjectsWorkflowEvents|ReplayFiltersWorkflowEventsByKindPrefixTenantAndAttribute|WorkflowReplayEndpoint)
FINDING_RULE_TESTS := Test(EventRuleScaffold|RuleDefinition|.*Fixture|EvaluateSourceRuntimeFindings|EvaluateSourceRuntimeRules|ListRulesReturnsBuiltinCatalog)
GITHUB_FINDINGS_OWNER ?=
GITHUB_FINDINGS_REPO ?=
GITHUB_FINDINGS_GRAPH_PREVIEW ?= tmp/github-findings-graph-preview.json
GITHUB_AUDIT_FINDINGS_GRAPH_PREVIEW ?= tmp/github-audit-findings-graph-preview.json
CEREBRO_BASE_URL ?= http://127.0.0.1:8080
export CEREBRO_BASE_URL
WORKFLOW_REPLAY_KIND_PREFIX ?= workflow.v1.
WORKFLOW_REPLAY_KIND ?= knowledge_decision
WORKFLOW_REPLAY_TENANT ?= writer
WORKFLOW_REPLAY_LIMIT ?= 100
ROOT_URN ?=
WORKFLOW_NEIGHBORHOOD_LIMIT ?= 10
RUNTIME_ID ?=
GRAPH_REBUILD_MODE ?= replay
GRAPH_REBUILD_PAGE_LIMIT ?= 1
GRAPH_REBUILD_EVENT_LIMIT ?= 100
GRAPH_REBUILD_PREVIEW_LIMIT ?= 10
CANDIDATE_SMOKE_EVENT_LIMIT ?= 25
LOAD_SMOKE_DURATION ?= 30
LOAD_SMOKE_RPS ?= 2
LOAD_SMOKE_CONCURRENCY ?= 4
LOAD_SMOKE_TIMEOUT ?= 5
LOAD_SMOKE_PATHS ?= /health
LOAD_SMOKE_MAX_P95_MS ?= 750
LOAD_SMOKE_MAX_ERROR_RATE ?= 0.01
LOAD_SMOKE_MAX_5XX_RATE ?= 0
LOAD_SMOKE_JSON_OUT ?= tmp/load-smoke.json
LOAD_SMOKE_MARKDOWN_OUT ?= tmp/load-smoke.md
MCP_SDK_ROOT ?= tmp/mcp-sdk-compat
MCP_SDK_PACKAGE ?= @modelcontextprotocol/sdk@latest
MCP_SDK_TEST_TOKEN ?= mcp-sdk-test-key
DROID_REVIEW_BASE ?= origin/main
DROID_REVIEW_HEAD ?= HEAD
DROID_PREFLIGHT_JSON_OUT ?= tmp/droid-preflight.json
DROID_PR ?=
DROID_FEEDBACK_OUT ?=
DROID_FEEDBACK_JSON_OUT ?= tmp/droid-feedback.json
DROID_SAST_OUT ?= tmp/droid-sast-context.md
DROID_SAST_JSON_OUT ?= tmp/droid-sast-context.json
DROID_CI_OUT ?= tmp/droid-ci-context.md
DROID_CI_JSON_OUT ?= tmp/droid-ci-context.json
DROID_CONTEXT_OUT ?= tmp/droid-review-context.md
DROID_CONTEXT_JSON_OUT ?= tmp/droid-review-context.json
DROID_POST_MERGE_OUT ?= tmp/droid-post-merge-health.md
DROID_POST_MERGE_JSON_OUT ?= tmp/droid-post-merge-health.json
DROID_SAST_POST_COMMENT ?= false
LAND_PR_REPO ?= writer/cerebro
LAND_PR_ADMIN ?= false
LAND_PR_KEEP_BRANCH ?= false
LAND_PR_ALLOW_LARGE ?= false

help: ## Show this help message.
	@awk 'BEGIN {FS = ":.*##"; printf "Usage: make <target>\n"} /^##@/ {printf "\n%s\n", substr($$0, 5); next} /^[A-Za-z0-9_.-]+:.*##/ {printf "  %-34s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# ==== Build ====
##@ Build
build: ## Build the Cerebro CLI binary.
	go build -o bin/cerebro ./cmd/cerebro

serve: build ## Build and run the local HTTP server.
	./bin/cerebro serve

serve-dev: build ## Build and run the local HTTP server with acknowledged dev-mode auth/rate-limit opt-out.
	CEREBRO_DEV_MODE=1 CEREBRO_DEV_MODE_ACK=1 ./bin/cerebro serve

test: ## Run all Go tests.
	go test ./...

test-race: ## Run all Go tests with the race detector.
	go test -race -timeout 20m ./...

cover: ## Run Go coverage for high-stakes packages.
	mkdir -p "$(dir $(COVERAGE_OUT))"
	go test -covermode=atomic -coverprofile="$(COVERAGE_OUT)" $(COVER_PACKAGES)
	go tool cover -func="$(COVERAGE_OUT)"

test-coverage: cover ## Alias for coverage validation.

sdk-test: sdk-go-test sdk-python-test sdk-python-build-check sdk-typescript-test sdk-typescript-check ## Run all SDK tests and type checks.

sdk-go-test: ## Run Go SDK unit tests and vet.
	go -C sdk/go/cerebroapi test ./...
	go -C sdk/go/cerebroapi vet ./...

sdk-python-test: ## Run Python SDK unit tests.
	$(PYTHON) -m venv "$(SDK_PYTHON_VENV)"
	"$(SDK_PYTHON_VENV)/bin/python" -m pip install --upgrade pip
	"$(SDK_PYTHON_VENV)/bin/python" -m pip install 'protobuf>=5.29.5,<8'
	PYTHONPATH=sdk/python "$(SDK_PYTHON_VENV)/bin/python" -m unittest discover -s sdk/python/tests

sdk-python-build-check: ## Build and validate the Python SDK package artifacts.
	rm -rf "$(SDK_PYTHON_DIST)"
	$(PYTHON) -m venv "$(SDK_PYTHON_BUILD_VENV)"
	"$(SDK_PYTHON_BUILD_VENV)/bin/python" -m pip install --upgrade pip build twine
	"$(SDK_PYTHON_BUILD_VENV)/bin/python" -m build --sdist --wheel --outdir "$(SDK_PYTHON_DIST)" sdk/python
	"$(SDK_PYTHON_BUILD_VENV)/bin/python" -m twine check "$(SDK_PYTHON_DIST)"/*

sdk-typescript-test: ## Run TypeScript SDK tests.
	cd sdk/typescript && npm test

sdk-typescript-check: ## Install TypeScript SDK dependencies and run type checks.
	cd sdk/typescript && npm ci && npm run typecheck

sdk-dependency-audit: ## Audit SDK dependencies for known vulnerabilities.
	$(PYTHON) -m unittest scripts.test_sdk_dependency_audit
	$(PYTHON) -m venv "$(SDK_AUDIT_VENV)"
	"$(SDK_AUDIT_VENV)/bin/python" -m pip install --upgrade pip pip-audit
	"$(SDK_AUDIT_VENV)/bin/python" scripts/sdk_dependency_audit.py

script-test: ## Run Python utility tests.
	$(PYTHON) -m unittest discover scripts/tests

# ==== Focused Tests ====
##@ Focused Tests
workflow-e2e-test: ## Run workflow event end-to-end tests.
	go test $(WORKFLOW_E2E_PACKAGES) -run '$(WORKFLOW_E2E_TESTS)$$' -count=1 -v

workflow-replay-test: ## Run workflow replay focused tests.
	go test ./internal/workflowprojection ./internal/appendlog/jetstream ./internal/bootstrap -run '$(WORKFLOW_REPLAY_TESTS)$$' -count=1 -v

finding-rule-test: ## Run finding rule focused tests.
	go test ./internal/findings -run '$(FINDING_RULE_TESTS)' -count=1 -v

finding-rule-scaffold-test: ## Run finding rule scaffold generator tests.
	go test ./cmd/cerebro -run 'Test(ParseFindingRuleNewArgs|ScaffoldFindingRule|FindingRuleScaffold|RenderFindingRuleGo)' -count=1 -v

sourcegen-test: ## Run source generator and generated runtime projection tests.
	go test ./internal/sourcegen ./internal/connectordefinitions ./internal/connectordefinitions/openapigen ./internal/connectorcatalog ./sources/internal/catalogruntime ./internal/sourceregistry ./internal/sourceprojection ./tools/openapidefgen -count=1

openapi-definition-gen-test: ## Run OpenAPI connector definition generator tests.
	go test ./internal/connectordefinitions/openapigen ./tools/openapidefgen -count=1 -v

agent-platform-eval: ## Run agent platform protocol, webhook, idempotency, security, and Graph Ask eval fixtures.
	go test ./internal/agentplatform -run 'TestRun(SecurityAgent|AgentPlatform)EvalSuiteFixture|Test(SecurityAgentEvalFixtureCoversSecurityScenarios|AgentPlatformEvalFixtureCoversControlPlane)' -count=1 -v
	go test ./internal/graphagent -run 'TestAskTrajectoryGoldenEvals|TestScoreAskEvents' -count=1 -v

github-findings-e2e: ## Run GitHub findings end-to-end test against configured repo.
	CEREBRO_RUN_GITHUB_FINDINGS_E2E=1 CEREBRO_GITHUB_FINDINGS_OWNER="$(GITHUB_FINDINGS_OWNER)" CEREBRO_GITHUB_FINDINGS_REPO="$(GITHUB_FINDINGS_REPO)" go test ./cmd/cerebro -run '^TestGitHubDependabotFindingsEndToEndWithGHCLI$$' -count=1 -v

github-findings-graph-preview: ## Generate a GitHub findings graph preview fixture.
	@mkdir -p "$(dir $(GITHUB_FINDINGS_GRAPH_PREVIEW))"
	CEREBRO_RUN_GITHUB_FINDINGS_E2E=1 CEREBRO_GITHUB_FINDINGS_OWNER="$(GITHUB_FINDINGS_OWNER)" CEREBRO_GITHUB_FINDINGS_REPO="$(GITHUB_FINDINGS_REPO)" CEREBRO_GITHUB_FINDINGS_GRAPH_PREVIEW_OUT="$(GITHUB_FINDINGS_GRAPH_PREVIEW)" go test ./cmd/cerebro -run '^TestGitHubDependabotFindingsEndToEndWithGHCLI$$' -count=1 -v
	@test -s "$(GITHUB_FINDINGS_GRAPH_PREVIEW)"
	python3 -m json.tool "$(GITHUB_FINDINGS_GRAPH_PREVIEW)"

github-audit-findings-graph-preview: ## Generate a GitHub audit findings graph preview fixture.
	@mkdir -p "$(dir $(GITHUB_AUDIT_FINDINGS_GRAPH_PREVIEW))"
	CEREBRO_RUN_GITHUB_AUDIT_FINDINGS_E2E=1 CEREBRO_GITHUB_AUDIT_FINDINGS_OWNER="$(GITHUB_FINDINGS_OWNER)" CEREBRO_GITHUB_AUDIT_FINDINGS_GRAPH_PREVIEW_OUT="$(GITHUB_AUDIT_FINDINGS_GRAPH_PREVIEW)" go test ./cmd/cerebro -run '^TestGitHubAuditFindingsGraphPreviewWithGHCLI$$' -count=1 -v
	@test -s "$(GITHUB_AUDIT_FINDINGS_GRAPH_PREVIEW)"
	python3 -m json.tool "$(GITHUB_AUDIT_FINDINGS_GRAPH_PREVIEW)"

# ==== Runtime Utilities ====
##@ Runtime Utilities
workflow-replay: ## Replay workflow events through the platform endpoint.
	curl -sS -X POST "$(CEREBRO_BASE_URL)/platform/workflow/replay" \
		-H 'Content-Type: application/json' \
		-d '{"kind_prefix":"$(WORKFLOW_REPLAY_KIND_PREFIX)","tenant_id":"$(WORKFLOW_REPLAY_TENANT)","attribute_equals":{"workflow_kind":"$(WORKFLOW_REPLAY_KIND)"},"limit":$(WORKFLOW_REPLAY_LIMIT)}' \
		| python3 -m json.tool

workflow-neighborhood: ## Fetch graph neighborhood for ROOT_URN.
	@if [ -z "$(ROOT_URN)" ]; then echo "ROOT_URN is required, e.g. make workflow-neighborhood ROOT_URN=urn:cerebro:writer:decision:decision-1" >&2; exit 2; fi
	curl -sS --get "$(CEREBRO_BASE_URL)/platform/graph/neighborhood" \
		--data-urlencode "root_urn=$(ROOT_URN)" \
		--data-urlencode "limit=$(WORKFLOW_NEIGHBORHOOD_LIMIT)" \
		| python3 -m json.tool

graph-rebuild-dryrun: build ## Preview a graph rebuild for RUNTIME_ID.
	@if [ -z "$(RUNTIME_ID)" ]; then echo "RUNTIME_ID is required, e.g. make graph-rebuild-dryrun RUNTIME_ID=writer-okta-audit" >&2; exit 2; fi
	./bin/cerebro graph rebuild "$(RUNTIME_ID)" dry_run=true mode="$(GRAPH_REBUILD_MODE)" page_limit="$(GRAPH_REBUILD_PAGE_LIMIT)" event_limit="$(GRAPH_REBUILD_EVENT_LIMIT)" preview_limit="$(GRAPH_REBUILD_PREVIEW_LIMIT)"

candidate-smoke: ## Run source candidate smoke checks for RUNTIME_ID.
	@if [ -z "$(RUNTIME_ID)" ]; then echo "RUNTIME_ID is required, e.g. make candidate-smoke RUNTIME_ID=writer-okta-audit RULE_ID=rule-id CEREBRO_BASE_URL=https://..." >&2; exit 2; fi
	CEREBRO_CANDIDATE_SMOKE_RUNTIME_ID="$(RUNTIME_ID)" CEREBRO_CANDIDATE_SMOKE_RULE_ID="$(RULE_ID)" CEREBRO_CANDIDATE_SMOKE_EVENT_LIMIT="$(CANDIDATE_SMOKE_EVENT_LIMIT)" python3 scripts/candidate_smoke.py

# ==== MCP ====
##@ MCP
mcp-contract-check: ## Validate MCP contract fixtures.
	python3 scripts/mcp_contract_check.py

mcp-smoke: ## Run MCP smoke checks.
	python3 scripts/mcp_smoke.py

mcp-sdk-compat: build ## Check MCP SDK compatibility against local server.
	@set -e; \
	mkdir -p "$(MCP_SDK_ROOT)"; \
	if [ ! -f "$(MCP_SDK_ROOT)/package.json" ]; then printf '%s\n' '{"type":"module","private":true}' > "$(MCP_SDK_ROOT)/package.json"; fi; \
	npm install --prefix "$(MCP_SDK_ROOT)" --no-audit --no-fund "$(MCP_SDK_PACKAGE)"; \
	port=$$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'); \
	log="tmp/mcp-sdk-compat-server.log"; \
	CEREBRO_HTTP_ADDR="127.0.0.1:$$port" CEREBRO_API_AUTH_ENABLED=true CEREBRO_API_KEYS="$(MCP_SDK_TEST_TOKEN):mcp-sdk:writer" ./bin/cerebro serve > "$$log" 2>&1 & pid=$$!; \
	trap 'kill "$$pid" >/dev/null 2>&1 || true; wait "$$pid" >/dev/null 2>&1 || true' EXIT; \
	for _ in $$(seq 1 50); do python3 -c 'import sys, urllib.request; url=sys.argv[1]; urllib.request.urlopen(url, timeout=0.5).read()' "http://127.0.0.1:$$port/health" >/dev/null 2>&1 && break; sleep 0.1; done; \
	CEREBRO_BASE_URL="http://127.0.0.1:$$port" CEREBRO_MCP_BEARER_TOKEN="$(MCP_SDK_TEST_TOKEN)" python3 scripts/mcp_smoke.py --skip-unauthenticated-check; \
	CEREBRO_MCP_URL="http://127.0.0.1:$$port/api/v1/mcp" CEREBRO_MCP_BEARER_TOKEN="$(MCP_SDK_TEST_TOKEN)" CEREBRO_MCP_SDK_ROOT="$(CURDIR)/$(MCP_SDK_ROOT)" node scripts/mcp_sdk_compat.mjs

# ==== Lint and Contracts ====
##@ Lint and Contracts
lint: lint-bootstrap ## Run golangci-lint over application packages.
	$(GOLANGCI_LINT) run --timeout 10m $(APP_PACKAGES)

lint-bootstrap: ## Install golangci-lint if missing.
	@if [ ! -x "$(GOLANGCI_LINT)" ]; then 		GOFLAGS= GOTOOLCHAIN=go1.26.4 go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION); 	fi

proto-lint: ## Lint protobuf definitions.
	$(BUF) lint

proto-generate: ## Generate protobuf-derived code.
	$(BUF) generate
	$(BUF) generate --template buf.gen.sdk.yaml --path proto/cerebro/v1/primitives.proto

proto-generate-check: proto-generate ## Verify protobuf generated files are current.
	git diff --exit-code -- gen sdk/python/cerebro/v1 sdk/go/cerebroapi/genproto

proto-breaking: ## Check protobuf compatibility against PROTO_BREAKING_BASE.
	$(BUF) breaking --against '.git#branch=$(PROTO_BREAKING_BASE)'

openapi-check: ## Verify OpenAPI routes match implementation.
	go run ./scripts/openapi_route_parity.go

openapi-lint: ## Lint the OpenAPI spec with Spectral.
	$(SPECTRAL) lint api/openapi.yaml

openapi-sync: ## Update OpenAPI route parity metadata.
	go run ./scripts/openapi_route_parity.go --write

catalog-check: ## Verify source, connector, and compliance catalogs are current.
	go run ./tools/catalogcheck
	go run ./tools/controlindex --check

control-index-generate: ## Regenerate compliance control coverage index.
	go run ./tools/controlindex --write

control-index-check: ## Verify compliance control coverage index is current.
	go run ./tools/controlindex --check

sourcegen-check: ## Verify connector definitions remain sourcegen-ready.
	go run ./tools/catalogcheck -require-sourcegen-ready -summary=true

graph-action-generate: ## Regenerate graph action registry from the action catalog.
	go run ./tools/graphactiongen --write

graph-action-check: ## Verify generated graph action registry is current.
	go run ./tools/graphactiongen --check

finding-dsl-migrate: ## Convert legacy JSON policy files to PolicyFindingRule DSL YAML.
	go run ./tools/findingdsl --migrate-policies --write

finding-dsl-test: ## Run PolicyFindingRule fixture suites.
	go run ./tools/findingdsl test

finding-dsl-lint: ## Run semantic PolicyFindingRule authoring lints.
	go run ./tools/findingdsl lint

finding-dsl-schema-generate: ## Regenerate PolicyFindingRule JSON Schema.
	go run ./tools/findingdsl schema --write

finding-dsl-schema-check: ## Verify PolicyFindingRule JSON Schema is current.
	go run ./tools/findingdsl schema --check

finding-dsl-check: finding-dsl-schema-check finding-dsl-test finding-dsl-lint ## Validate PolicyFindingRule DSL authoring files.
	go run ./tools/findingdsl --check

policy-rule-generate: ## Regenerate generated policy rule catalog.
	go run ./tools/policyrulegen --write

policy-rule-check: finding-dsl-check ## Verify generated policy rule catalog is current.
	go run ./tools/policyrulegen --check

detection-catalog-generate: ## Regenerate public detection catalog.
	go run ./tools/detectioncatalog --write

detection-catalog-check: ## Verify public detection catalog is current.
	go run ./tools/detectioncatalog --check

new-aws-collector: ## Wire an implemented AWS collector (FAMILY=foo_bar RECORD_TYPE=awsFooBar LIST_FUNC=listFooBars EVENT_FUNC=fooBarEvent URN_EXPR=record.ID).
	@test -n "$(FAMILY)" || (echo "FAMILY is required, e.g. make new-aws-collector FAMILY=ec2_transit_gateway" && exit 1)
	@test -n "$(RECORD_TYPE)" || (echo "RECORD_TYPE is required" && exit 1)
	@test -n "$(LIST_FUNC)" || (echo "LIST_FUNC is required" && exit 1)
	@test -n "$(EVENT_FUNC)" || (echo "EVENT_FUNC is required" && exit 1)
	@test -n "$(URN_EXPR)" || (echo "URN_EXPR is required" && exit 1)
	go run ./tools/awscollectorgen --family="$(FAMILY)" --title="$(TITLE)" --label="$(LABEL)" --const-name="$(CONST_NAME)" --record-type="$(RECORD_TYPE)" --list-func="$(LIST_FUNC)" --event-func="$(EVENT_FUNC)" --urn-type="$(URN_TYPE)" --urn-expr="$(URN_EXPR)" --cursor-expr="$(CURSOR_EXPR)" --projector="$(PROJECTOR)" $(if $(DRY_RUN),--dry-run,)

docs-autogen: openapi-sync proto-generate graph-action-generate policy-rule-generate control-index-generate detection-catalog-generate ## Regenerate checked-in generated docs and catalogs.

docs-drift-check: ## Check documentation drift rules.
	python3 scripts/docs_drift_check.py

readme-check: ## Check README formatting and changed-line whitespace.
	@base_ref="$(README_CHECK_BASE)"; \
	if git rev-parse --verify "$$base_ref" >/dev/null 2>&1; then \
		base="$$(git merge-base HEAD "$$base_ref")"; \
	else \
		base="$$(git rev-list --max-parents=0 HEAD)"; \
	fi; \
	git diff --check "$$base"..HEAD -- README.md
	python3 scripts/readme_check.py

oss-audit: ## Run repository OSS hygiene audit.
	python3 scripts/oss_audit.py

govulncheck: ## Run govulncheck gate for reachable vulnerabilities.
	python3 scripts/govulncheck_gate.py

contracts-check: ## Run contract and compatibility checks with a final summary.
	python3 scripts/contracts_check.py

changed-check: ## Run validation selected from changed paths.
	python3 scripts/changed_checks.py --base "$(DROID_REVIEW_BASE)" --head "$(DROID_REVIEW_HEAD)" --run

# ==== Release and Environment ====
##@ Release and Environment
docker-smoke: ## Build and smoke-test the runtime Docker image.
	@command -v docker >/dev/null || { echo "docker is required for docker-smoke" >&2; exit 2; }
	mkdir -p .dist
	CGO_ENABLED=0 GOOS=linux GOARCH="$(DOCKER_SMOKE_GOARCH)" go build -trimpath -o .dist/cerebro ./cmd/cerebro
	@build_ok=0; \
	for base_image in $(DOCKER_SMOKE_BASE_IMAGES); do \
		attempt=1; \
		while :; do \
			echo "building runtime image with base $$base_image (attempt $$attempt/$(DOCKER_BUILD_ATTEMPTS))"; \
			if docker build --build-arg RUNTIME_BASE_IMAGE="$$base_image" -f Dockerfile.runtime -t "$(DOCKER_SMOKE_IMAGE)" .; then \
				build_ok=1; \
				break 2; \
			fi; \
			if [ "$$attempt" -ge "$(DOCKER_BUILD_ATTEMPTS)" ]; then \
				echo "docker build failed with base $$base_image after $(DOCKER_BUILD_ATTEMPTS) attempts" >&2; \
				break; \
			fi; \
			echo "docker build failed; retrying in $(DOCKER_BUILD_RETRY_SLEEP)s" >&2; \
			attempt=$$((attempt + 1)); \
			sleep "$(DOCKER_BUILD_RETRY_SLEEP)"; \
		done; \
	done; \
	if [ "$$build_ok" != "1" ]; then \
		echo "docker build failed for all runtime base images: $(DOCKER_SMOKE_BASE_IMAGES)" >&2; \
		exit 1; \
	fi
	@test -n "$$(docker run --rm "$(DOCKER_SMOKE_IMAGE)" version)"

release-smoke: ## Validate GoReleaser configuration.
	$(GORELEASER) check

load-smoke: ## Run bounded capacity/load smoke checks against CEREBRO_BASE_URL.
	$(PYTHON) scripts/load_smoke.py \
		$(foreach path,$(LOAD_SMOKE_PATHS),--path "$(path)") \
		--duration "$(LOAD_SMOKE_DURATION)" \
		--rps "$(LOAD_SMOKE_RPS)" \
		--concurrency "$(LOAD_SMOKE_CONCURRENCY)" \
		--timeout "$(LOAD_SMOKE_TIMEOUT)" \
		--max-p95-ms "$(LOAD_SMOKE_MAX_P95_MS)" \
		--max-error-rate "$(LOAD_SMOKE_MAX_ERROR_RATE)" \
		--max-5xx-rate "$(LOAD_SMOKE_MAX_5XX_RATE)" \
		--json-out "$(LOAD_SMOKE_JSON_OUT)" \
		--markdown-out "$(LOAD_SMOKE_MARKDOWN_OUT)"

doctor: ## Check local development toolchain availability.
	@command -v git >/dev/null || { echo "missing required tool: git" >&2; exit 2; }
	@command -v go >/dev/null || { echo "missing required tool: go" >&2; exit 2; }
	@command -v python3 >/dev/null || { echo "missing required tool: python3" >&2; exit 2; }
	@command -v npm >/dev/null || { echo "missing required tool: npm" >&2; exit 2; }
	@command -v docker >/dev/null || echo "optional tool missing: docker (needed for make docker-smoke)"
	@command -v gh >/dev/null || echo "optional tool missing: gh (needed for PR/release triage)"
	@go version
	@python3 --version
	@npm --version
	@echo "developer toolchain looks ready"

# ==== Droid Review ====
##@ Droid Review
droid-review-preflight: ## Build Droid review preflight context.
	go test ./tools/droidreview/...
	go run ./tools/droidreview --base "$(DROID_REVIEW_BASE)" --head "$(DROID_REVIEW_HEAD)" --json-out "$(DROID_PREFLIGHT_JSON_OUT)"

droid-review-sast: ## Build Droid security scanner context.
	python3 scripts/droid_sast_context.py --base "$(DROID_REVIEW_BASE)" --head "$(DROID_REVIEW_HEAD)" --markdown-out "$(DROID_SAST_OUT)" --json-out "$(DROID_SAST_JSON_OUT)" $(if $(filter true,$(DROID_SAST_POST_COMMENT)),--post-comment,)

droid-ci-context: ## Build Droid CI context from the current head.
	python3 scripts/droid_ci_context.py --head "$(DROID_REVIEW_HEAD)" --markdown-out "$(DROID_CI_OUT)" --json-out "$(DROID_CI_JSON_OUT)"

droid-review-context: ## Combine Droid review context inputs.
	python3 scripts/droid_review_context.py --base "$(DROID_REVIEW_BASE)" --head "$(DROID_REVIEW_HEAD)" --preflight-json "$(DROID_PREFLIGHT_JSON_OUT)" --sast-json "$(DROID_SAST_JSON_OUT)" --ci-json "$(DROID_CI_JSON_OUT)" --feedback-json "$(DROID_FEEDBACK_JSON_OUT)" --markdown-out "$(DROID_CONTEXT_OUT)" --json-out "$(DROID_CONTEXT_JSON_OUT)"

droid-post-merge-health: ## Build Droid post-merge health summary.
	python3 scripts/droid_post_merge_health.py --markdown-out "$(DROID_POST_MERGE_OUT)" --json-out "$(DROID_POST_MERGE_JSON_OUT)" $(if $(filter true,$(DROID_POST_MERGE_STRICT)),--strict,)

droid-feedback: ## Fetch and normalize Droid feedback for DROID_PR.
	@if [ -z "$(DROID_PR)" ]; then echo "DROID_PR is required, e.g. make droid-feedback DROID_PR=719" >&2; exit 2; fi
	python3 scripts/droid_feedback_harness.py "$(DROID_PR)" $(if $(DROID_FEEDBACK_OUT),--markdown-out "$(DROID_FEEDBACK_OUT)") --json-out "$(DROID_FEEDBACK_JSON_OUT)"

land-pr: ## Wait for core/Droid gates, merge PR, then delete the PR branch.
	@if [ -z "$(PR)" ]; then echo "PR is required, e.g. make land-pr PR=719" >&2; exit 2; fi
	python3 scripts/land_pr.py "$(PR)" --repo "$(LAND_PR_REPO)" $(if $(filter true,$(LAND_PR_ADMIN)),--admin,) $(if $(filter true,$(LAND_PR_KEEP_BRANCH)),--keep-branch,) $(if $(filter true,$(LAND_PR_ALLOW_LARGE)),--allow-large-pr,)

ci-poll: ## Poll PR checks until complete or timeout (PR required, optional INTERVAL and TIMEOUT).
	@if [ -z "$(PR)" ]; then echo "PR is required, e.g. make ci-poll PR=719" >&2; exit 2; fi
	@interval="$(INTERVAL)"; timeout_s="$(TIMEOUT)"; \
	if [ -z "$$interval" ]; then interval=60; fi; \
	if [ -z "$$timeout_s" ]; then timeout_s=1800; fi; \
	elapsed=0; \
	while [ $$elapsed -lt $$timeout_s ]; do \
		gh pr checks $(PR) --repo writer/cerebro 2>&1; rc=$$?; \
		if [ $$rc -eq 1 ]; then echo "CI failed"; exit 1; fi; \
		if [ $$rc -eq 0 ]; then echo "All checks passed"; exit 0; fi; \
		sleep $$interval; elapsed=$$((elapsed + interval)); \
	done; \
	echo "CI polling timed out after $$timeout_s seconds"; exit 1

# ==== Project Hygiene ====
##@ Project Hygiene
clean: ## Remove build artifacts.
	rm -rf bin/

hooks: ## Install repository git hooks.
	./scripts/install_hooks.sh

pre-commit: ## Run local pre-commit checks.
	./scripts/pre_commit_checks.sh

check: build test script-test sdk-test lint proto-lint proto-generate-check graph-action-check finding-dsl-check policy-rule-check docs-drift-check check-structural check-structural-test check-arch ## Run the main local validation suite.

check-structural: check-structural-build ## Run custom structural lints.
	@$(LINTER_BIN) $(APP_PACKAGES)

check-structural-build: ## Build the custom structural linter.
	@cd $(LINTER_MODULE) && GOFLAGS= go build -o $(LINTER_BIN) ./cerebrolint

check-structural-test: ## Test the custom structural linter.
	@cd $(LINTER_MODULE) && GOFLAGS= go test ./...

check-arch: ## Run architectural guardrail tests.
	go test ./tools/archtests/...

check-hook-integrity: check-arch ## Verify hook-integrity guardrails.

verify: build test test-race cover script-test sdk-test sdk-dependency-audit mcp-contract-check mcp-sdk-compat lint proto-lint proto-generate-check proto-breaking openapi-check openapi-lint catalog-check graph-action-check finding-dsl-check policy-rule-check detection-catalog-check docs-drift-check readme-check oss-audit release-smoke check-structural check-structural-test check-arch ## Run full CI-equivalent validation suite.
