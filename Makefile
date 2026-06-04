.PHONY: build serve test sdk-test sdk-python-test sdk-typescript-test sdk-typescript-check workflow-e2e-test workflow-replay-test finding-rule-test github-findings-e2e github-findings-graph-preview github-audit-findings-graph-preview workflow-replay workflow-neighborhood graph-rebuild-dryrun candidate-smoke lint lint-bootstrap proto-lint proto-generate proto-generate-check proto-breaking openapi-check openapi-lint openapi-sync catalog-check detection-catalog-generate detection-catalog-check readme-check oss-audit govulncheck docker-smoke release-smoke doctor droid-review-preflight droid-review-sast droid-ci-context droid-review-context droid-post-merge-health droid-feedback clean hooks pre-commit verify check check-structural check-structural-build check-structural-test check-arch check-hook-integrity

GO_BIN ?= $(shell go env GOPATH)/bin
GOLANGCI_LINT := $(GO_BIN)/golangci-lint
GOLANGCI_LINT_VERSION ?= v2.11.4
BUF := GOFLAGS= GOTOOLCHAIN=go1.26.3 go run github.com/bufbuild/buf/cmd/buf@v1.59.0
GOVULNCHECK := GOFLAGS= GOTOOLCHAIN=go1.26.3 go run golang.org/x/vuln/cmd/govulncheck@v1.1.4
SPECTRAL := npx --yes @stoplight/spectral-cli@6.15.0
GORELEASER := GOFLAGS= GOTOOLCHAIN=go1.26.3 go run github.com/goreleaser/goreleaser/v2@v2.16.0
PROTO_BREAKING_BASE ?= origin/main
README_CHECK_BASE ?= origin/main
DOCKER_SMOKE_IMAGE ?= cerebro-runtime-smoke:local
DOCKER_SMOKE_GOARCH ?= amd64
APP_PACKAGES := ./api/... ./cmd/... ./internal/... ./sources/...
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

build:
	go build -o bin/cerebro ./cmd/cerebro

serve: build
	./bin/cerebro serve

test:
	go test ./...

sdk-test: sdk-python-test sdk-typescript-test sdk-typescript-check

sdk-python-test:
	cd sdk/python && python3 -m pip install 'protobuf>=5.29.5,<6' && python3 -m unittest discover -s tests

sdk-typescript-test:
	cd sdk/typescript && npm test

sdk-typescript-check:
	cd sdk/typescript && npm ci && npm run typecheck

workflow-e2e-test:
	go test $(WORKFLOW_E2E_PACKAGES) -run '$(WORKFLOW_E2E_TESTS)$$' -count=1 -v

workflow-replay-test:
	go test ./internal/workflowprojection ./internal/appendlog/jetstream ./internal/bootstrap -run '$(WORKFLOW_REPLAY_TESTS)$$' -count=1 -v

finding-rule-test:
	go test ./internal/findings -run '$(FINDING_RULE_TESTS)' -count=1 -v

github-findings-e2e:
	CEREBRO_RUN_GITHUB_FINDINGS_E2E=1 CEREBRO_GITHUB_FINDINGS_OWNER="$(GITHUB_FINDINGS_OWNER)" CEREBRO_GITHUB_FINDINGS_REPO="$(GITHUB_FINDINGS_REPO)" go test ./cmd/cerebro -run '^TestGitHubDependabotFindingsEndToEndWithGHCLI$$' -count=1 -v

github-findings-graph-preview:
	@mkdir -p "$(dir $(GITHUB_FINDINGS_GRAPH_PREVIEW))"
	CEREBRO_RUN_GITHUB_FINDINGS_E2E=1 CEREBRO_GITHUB_FINDINGS_OWNER="$(GITHUB_FINDINGS_OWNER)" CEREBRO_GITHUB_FINDINGS_REPO="$(GITHUB_FINDINGS_REPO)" CEREBRO_GITHUB_FINDINGS_GRAPH_PREVIEW_OUT="$(GITHUB_FINDINGS_GRAPH_PREVIEW)" go test ./cmd/cerebro -run '^TestGitHubDependabotFindingsEndToEndWithGHCLI$$' -count=1 -v
	@test -s "$(GITHUB_FINDINGS_GRAPH_PREVIEW)"
	python3 -m json.tool "$(GITHUB_FINDINGS_GRAPH_PREVIEW)"

github-audit-findings-graph-preview:
	@mkdir -p "$(dir $(GITHUB_AUDIT_FINDINGS_GRAPH_PREVIEW))"
	CEREBRO_RUN_GITHUB_AUDIT_FINDINGS_E2E=1 CEREBRO_GITHUB_AUDIT_FINDINGS_OWNER="$(GITHUB_FINDINGS_OWNER)" CEREBRO_GITHUB_AUDIT_FINDINGS_GRAPH_PREVIEW_OUT="$(GITHUB_AUDIT_FINDINGS_GRAPH_PREVIEW)" go test ./cmd/cerebro -run '^TestGitHubAuditFindingsGraphPreviewWithGHCLI$$' -count=1 -v
	@test -s "$(GITHUB_AUDIT_FINDINGS_GRAPH_PREVIEW)"
	python3 -m json.tool "$(GITHUB_AUDIT_FINDINGS_GRAPH_PREVIEW)"

workflow-replay:
	curl -sS -X POST "$(CEREBRO_BASE_URL)/platform/workflow/replay" \
		-H 'Content-Type: application/json' \
		-d '{"kind_prefix":"$(WORKFLOW_REPLAY_KIND_PREFIX)","tenant_id":"$(WORKFLOW_REPLAY_TENANT)","attribute_equals":{"workflow_kind":"$(WORKFLOW_REPLAY_KIND)"},"limit":$(WORKFLOW_REPLAY_LIMIT)}' \
		| python3 -m json.tool

workflow-neighborhood:
	@if [ -z "$(ROOT_URN)" ]; then echo "ROOT_URN is required, e.g. make workflow-neighborhood ROOT_URN=urn:cerebro:writer:decision:decision-1" >&2; exit 2; fi
	curl -sS --get "$(CEREBRO_BASE_URL)/platform/graph/neighborhood" \
		--data-urlencode "root_urn=$(ROOT_URN)" \
		--data-urlencode "limit=$(WORKFLOW_NEIGHBORHOOD_LIMIT)" \
		| python3 -m json.tool

graph-rebuild-dryrun: build
	@if [ -z "$(RUNTIME_ID)" ]; then echo "RUNTIME_ID is required, e.g. make graph-rebuild-dryrun RUNTIME_ID=writer-okta-audit" >&2; exit 2; fi
	./bin/cerebro graph rebuild "$(RUNTIME_ID)" dry_run=true mode="$(GRAPH_REBUILD_MODE)" page_limit="$(GRAPH_REBUILD_PAGE_LIMIT)" event_limit="$(GRAPH_REBUILD_EVENT_LIMIT)" preview_limit="$(GRAPH_REBUILD_PREVIEW_LIMIT)"

candidate-smoke:
	@if [ -z "$(RUNTIME_ID)" ]; then echo "RUNTIME_ID is required, e.g. make candidate-smoke RUNTIME_ID=writer-okta-audit RULE_ID=rule-id CEREBRO_BASE_URL=https://..." >&2; exit 2; fi
	CEREBRO_CANDIDATE_SMOKE_RUNTIME_ID="$(RUNTIME_ID)" CEREBRO_CANDIDATE_SMOKE_RULE_ID="$(RULE_ID)" CEREBRO_CANDIDATE_SMOKE_EVENT_LIMIT="$(CANDIDATE_SMOKE_EVENT_LIMIT)" python3 scripts/candidate_smoke.py

lint: lint-bootstrap
	$(GOLANGCI_LINT) run --timeout 5m $(APP_PACKAGES)

lint-bootstrap:
	@if [ ! -x "$(GOLANGCI_LINT)" ]; then 		GOFLAGS= GOTOOLCHAIN=go1.26.3 go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION); 	fi

proto-lint:
	$(BUF) lint

proto-generate:
	$(BUF) generate

proto-generate-check: proto-generate
	git diff --exit-code -- gen sdk/python/cerebro/v1

proto-breaking:
	$(BUF) breaking --against '.git#branch=$(PROTO_BREAKING_BASE)'

openapi-check:
	go run ./scripts/openapi_route_parity.go

openapi-lint:
	$(SPECTRAL) lint api/openapi.yaml

openapi-sync:
	go run ./scripts/openapi_route_parity.go --write

catalog-check:
	go run ./tools/catalogcheck

detection-catalog-generate:
	go run ./tools/detectioncatalog --write

detection-catalog-check:
	go run ./tools/detectioncatalog --check

readme-check:
	@base_ref="$(README_CHECK_BASE)"; \
	if git rev-parse --verify "$$base_ref" >/dev/null 2>&1; then \
		base="$$(git merge-base HEAD "$$base_ref")"; \
	else \
		base="$$(git rev-list --max-parents=0 HEAD)"; \
	fi; \
	git diff --check "$$base"..HEAD -- README.md
	python3 scripts/readme_check.py

oss-audit:
	python3 scripts/oss_audit.py

govulncheck:
	$(GOVULNCHECK) ./...

docker-smoke:
	@command -v docker >/dev/null || { echo "docker is required for docker-smoke" >&2; exit 2; }
	mkdir -p .dist
	CGO_ENABLED=0 GOOS=linux GOARCH="$(DOCKER_SMOKE_GOARCH)" go build -trimpath -o .dist/cerebro ./cmd/cerebro
	docker build -f Dockerfile.runtime -t "$(DOCKER_SMOKE_IMAGE)" .

release-smoke:
	$(GORELEASER) check

doctor:
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

droid-review-preflight:
	go test ./tools/droidreview/...
	go run ./tools/droidreview --base "$(DROID_REVIEW_BASE)" --head "$(DROID_REVIEW_HEAD)" --json-out "$(DROID_PREFLIGHT_JSON_OUT)"

droid-review-sast:
	python3 scripts/droid_sast_context.py --base "$(DROID_REVIEW_BASE)" --head "$(DROID_REVIEW_HEAD)" --markdown-out "$(DROID_SAST_OUT)" --json-out "$(DROID_SAST_JSON_OUT)" $(if $(filter true,$(DROID_SAST_POST_COMMENT)),--post-comment,)

droid-ci-context:
	python3 scripts/droid_ci_context.py --head "$(DROID_REVIEW_HEAD)" --markdown-out "$(DROID_CI_OUT)" --json-out "$(DROID_CI_JSON_OUT)"

droid-review-context:
	python3 scripts/droid_review_context.py --base "$(DROID_REVIEW_BASE)" --head "$(DROID_REVIEW_HEAD)" --preflight-json "$(DROID_PREFLIGHT_JSON_OUT)" --sast-json "$(DROID_SAST_JSON_OUT)" --ci-json "$(DROID_CI_JSON_OUT)" --feedback-json "$(DROID_FEEDBACK_JSON_OUT)" --markdown-out "$(DROID_CONTEXT_OUT)" --json-out "$(DROID_CONTEXT_JSON_OUT)"

droid-post-merge-health:
	python3 scripts/droid_post_merge_health.py --markdown-out "$(DROID_POST_MERGE_OUT)" --json-out "$(DROID_POST_MERGE_JSON_OUT)"

droid-feedback:
	@if [ -z "$(DROID_PR)" ]; then echo "DROID_PR is required, e.g. make droid-feedback DROID_PR=719" >&2; exit 2; fi
	python3 scripts/droid_feedback_harness.py "$(DROID_PR)" $(if $(DROID_FEEDBACK_OUT),--markdown-out "$(DROID_FEEDBACK_OUT)") --json-out "$(DROID_FEEDBACK_JSON_OUT)"

clean:
	rm -rf bin/

hooks:
	./scripts/install_hooks.sh

pre-commit:
	./scripts/pre_commit_checks.sh

check: build test sdk-test lint proto-lint proto-generate-check check-structural check-structural-test check-arch

check-structural: check-structural-build
	@$(LINTER_BIN) $(APP_PACKAGES)

check-structural-build:
	@cd $(LINTER_MODULE) && GOFLAGS= go build -o $(LINTER_BIN) ./cerebrolint

check-structural-test:
	@cd $(LINTER_MODULE) && GOFLAGS= go test ./...

check-arch:
	go test ./tools/archtests/...

check-hook-integrity: check-arch

verify: build test sdk-test lint proto-lint proto-generate-check proto-breaking openapi-check openapi-lint catalog-check detection-catalog-check readme-check oss-audit release-smoke check-structural check-structural-test check-arch
