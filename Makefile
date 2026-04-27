.PHONY: build serve test workflow-e2e-test workflow-replay-test finding-rule-test github-findings-e2e github-findings-graph-preview workflow-replay workflow-neighborhood graph-rebuild-dryrun lint lint-bootstrap proto-lint proto-generate clean hooks pre-commit verify check check-structural check-structural-build check-structural-test check-arch check-hook-integrity

GO_BIN ?= $(shell go env GOPATH)/bin
GOLANGCI_LINT := $(GO_BIN)/golangci-lint
BUF := GOTOOLCHAIN=go1.26.2 go run github.com/bufbuild/buf/cmd/buf@latest
APP_PACKAGES := ./cmd/... ./internal/... ./sources/...
LINTER_MODULE := ./tools/linters
LINTER_BIN := $(GO_BIN)/cerebrolint
WORKFLOW_E2E_PACKAGES := ./internal/workflowevents ./internal/workflowprojection ./internal/knowledge ./internal/findings ./internal/bootstrap
WORKFLOW_E2E_TESTS := Test(NewDecisionRecordedEventIsStableAndDecodable|ProjectKnowledgeWorkflowEvents|ProjectFindingWorkflowEvents|ReplayProjectsWorkflowEvents|WriteDecisionAppendsWorkflowEventBeforeProjection|WriteDecisionAppendFailurePreventsGraphProjection|WriteActionProjectionFailureLeavesAppendedWorkflowEvent|ResolveFindingBridgesDecisionAndOutcomeWhenGraphConfigured|AddFindingNoteUpdatesPersistedWorkflow|LinkFindingTicketUpdatesPersistedWorkflow|PlatformKnowledgeDecisionAndOutcomeEndpoints|FindingEndpoints|WorkflowReplayEndpoint|GraphNeighborhoodEndpoints)
WORKFLOW_REPLAY_TESTS := Test(ReplayProjectsWorkflowEvents|ReplayFiltersWorkflowEventsByKindPrefixTenantAndAttribute|WorkflowReplayEndpoint)
FINDING_RULE_TESTS := Test(EventRuleScaffold|RuleDefinition|.*Fixture|EvaluateSourceRuntimeFindings|EvaluateSourceRuntimeRules|ListRulesReturnsBuiltinCatalog)
GITHUB_FINDINGS_OWNER ?=
GITHUB_FINDINGS_REPO ?=
GITHUB_FINDINGS_GRAPH_PREVIEW ?= tmp/github-findings-graph-preview.json
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

build:
	go build -o bin/cerebro ./cmd/cerebro

serve: build
	./bin/cerebro serve

test:
	go test ./...

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

workflow-replay:
	curl -sS -X POST "$(CEREBRO_BASE_URL)/platform/workflow/replay" \
		-H 'Content-Type: application/json' \
		-d '{"kind_prefix":"$(WORKFLOW_REPLAY_KIND_PREFIX)","tenant_id":"$(WORKFLOW_REPLAY_TENANT)","attribute_equals":{"workflow_kind":"$(WORKFLOW_REPLAY_KIND)"},"limit":$(WORKFLOW_REPLAY_LIMIT)}' \
		| python3 -m json.tool

workflow-neighborhood:
	@if [ -z "$(ROOT_URN)" ]; then echo "ROOT_URN is required, e.g. make workflow-neighborhood ROOT_URN=urn:cerebro:writer:decision:decision-1" >&2; exit 2; fi
	curl -sS --get "$(CEREBRO_BASE_URL)/graph/neighborhood" \
		--data-urlencode "root_urn=$(ROOT_URN)" \
		--data-urlencode "limit=$(WORKFLOW_NEIGHBORHOOD_LIMIT)" \
		| python3 -m json.tool

graph-rebuild-dryrun: build
	@if [ -z "$(RUNTIME_ID)" ]; then echo "RUNTIME_ID is required, e.g. make graph-rebuild-dryrun RUNTIME_ID=writer-okta-audit" >&2; exit 2; fi
	./bin/cerebro graph rebuild "$(RUNTIME_ID)" dry_run=true mode="$(GRAPH_REBUILD_MODE)" page_limit="$(GRAPH_REBUILD_PAGE_LIMIT)" event_limit="$(GRAPH_REBUILD_EVENT_LIMIT)" preview_limit="$(GRAPH_REBUILD_PREVIEW_LIMIT)"

lint: lint-bootstrap
	$(GOLANGCI_LINT) run --timeout 5m $(APP_PACKAGES)

lint-bootstrap:
	@if [ ! -x "$(GOLANGCI_LINT)" ]; then 		GOTOOLCHAIN=go1.26.2 go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest; 	fi

proto-lint:
	$(BUF) lint

proto-generate:
	$(BUF) generate

clean:
	rm -rf bin/

hooks:
	./scripts/install_hooks.sh

pre-commit:
	./scripts/pre_commit_checks.sh

check: build test lint proto-lint check-structural check-structural-test check-arch

check-structural: check-structural-build
	@$(LINTER_BIN) $(APP_PACKAGES)

check-structural-build:
	@GOFLAGS= cd $(LINTER_MODULE) && go build -o $(LINTER_BIN) ./cerebrolint

check-structural-test:
	@GOFLAGS= cd $(LINTER_MODULE) && go test ./...

check-arch:
	go test ./tools/archtests/...

check-hook-integrity: check-arch

verify: build test lint proto-lint check-structural check-structural-test check-arch
