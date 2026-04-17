.PHONY: build run test sync clean dev serve policy-list docker-build trivy-db security-scan security-scan-built security-scan-source vendor vendor-check oss-audit openapi-check openapi-sync api-contract-docs api-contract-docs-check api-contract-compat config-docs config-docs-check ontology-docs ontology-docs-check cloudevents-docs cloudevents-docs-check cloudevents-contract-compat report-contract-docs report-contract-docs-check report-contract-compat entity-facet-docs entity-facet-docs-check entity-facet-contract-compat agent-sdk-docs agent-sdk-docs-check agent-sdk-contract-compat agent-sdk-packages agent-sdk-packages-check connector-docs connector-docs-check graph-ontology-guardrails gosec govulncheck devex-codegen devex-codegen-check devex-changed devex-pr platform-up platform-down platform-logs platform-smoke hooks pre-commit verify

# Version info
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE    ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS := -ldflags "-X github.com/writer/cerebro/internal/cli.Version=$(VERSION) \
                     -X github.com/writer/cerebro/internal/cli.Commit=$(COMMIT) \
                     -X github.com/writer/cerebro/internal/cli.BuildDate=$(DATE)"

TRIVY_IMAGE ?= aquasec/trivy:0.34.0
TRIVY_CACHE_DIR ?= $(HOME)/.cache/trivy
SECURITY_SCAN_IMAGE ?= cerebro:ci
GO_BIN ?= $(shell go env GOPATH)/bin
GO_VERSION ?= $(shell ./scripts/go_version.sh)

export GOFLAGS

# Build the cerebro binary
build:
	go build $(LDFLAGS) -o bin/cerebro ./cmd/cerebro

# Run the API server
serve: build
	./bin/cerebro serve

# Run tests
test:
	go test -v ./...

# Lint code
lint:
	golangci-lint run --timeout 5m ./...

gosec:
	$(GO_BIN)/gosec -quiet -severity medium -confidence medium -exclude-generated ./...

govulncheck: build
	go build -o bin/policy-enhancer ./cmd/policy-enhancer
	$(GO_BIN)/govulncheck -mode binary ./bin/cerebro
	$(GO_BIN)/govulncheck -mode binary ./bin/policy-enhancer

# Format code
fmt:
	goimports -w $$(find . -name '*.go' -not -path './vendor/*')
	gofmt -w $$(find . -name '*.go' -not -path './vendor/*')

# Sync cloud assets via native scanners
sync: build
	./bin/cerebro sync

# List policies
policy-list: build
	CEREBRO_CLI_MODE=direct ./bin/cerebro policy list

# Validate policies
policy-validate: build
	CEREBRO_CLI_MODE=direct ./bin/cerebro policy validate

# Execute a query (usage: make query SQL="SELECT * FROM aws_s3_buckets")
query: build
	./bin/cerebro query $(SQL)

# Install all dependencies
install-deps:
	go mod download

# Sync vendored dependencies
vendor:
	go mod tidy
	go mod vendor

# Verify Go module metadata is in sync
vendor-check:
	go mod tidy
	git diff --exit-code -- go.mod go.sum

# Clean build artifacts
clean:
	rm -rf bin/

# Development: run API with hot reload
dev:
	go run ./cmd/cerebro serve

# Docker build
docker-build:
	docker build --build-arg GO_VERSION=$(GO_VERSION) -t cerebro:latest .

# Download/update Trivy vulnerability database cache
trivy-db:
	mkdir -p "$(TRIVY_CACHE_DIR)"
	docker run --rm \
		-v /var/run/docker.sock:/var/run/docker.sock \
		-v "$(TRIVY_CACHE_DIR):/root/.cache" \
		$(TRIVY_IMAGE) image --download-db-only

# Fast local security check on built artifact (avoids heavy source-wide static analysis)
security-scan: security-scan-built

security-scan-built: trivy-db
	docker build --build-arg GO_VERSION=$(GO_VERSION) -f Dockerfile -t $(SECURITY_SCAN_IMAGE) .
	docker run --rm \
		-v /var/run/docker.sock:/var/run/docker.sock \
		-v "$(TRIVY_CACHE_DIR):/root/.cache" \
		$(TRIVY_IMAGE) image \
		--security-checks vuln \
		--format table \
		--exit-code 1 \
		--ignore-unfixed \
		--vuln-type os,library \
		--severity CRITICAL,HIGH \
		$(SECURITY_SCAN_IMAGE)

# Optional heavier security scan (kept explicit to avoid default local laptop instability)
security-scan-source: build
	go build -o bin/policy-enhancer ./cmd/policy-enhancer
	# govulncheck source mode can fail on this dependency graph; binary mode is deterministic.
	$(GO_BIN)/govulncheck -mode binary ./bin/cerebro
	$(GO_BIN)/govulncheck -mode binary ./bin/policy-enhancer
	$(GO_BIN)/gosec -severity medium -confidence medium -exclude-generated ./...

oss-audit:
	python3 scripts/oss_audit.py

openapi-check:
	go run ./scripts/openapi_route_parity.go
	@if grep -n "x-cerebro-generated" api/openapi.yaml; then \
		echo "OpenAPI contains generated placeholders (x-cerebro-generated). Replace with real operation docs."; \
		exit 1; \
	fi
	@if grep -n "Undocumented" api/openapi.yaml; then \
		echo "OpenAPI contains undocumented operation tags. Replace with endpoint contracts."; \
		exit 1; \
	fi
	$(MAKE) openapi-lint

openapi-sync:
	go run ./scripts/openapi_route_parity.go --write

openapi-lint:
	npx --yes @stoplight/spectral-cli@6 lint --ruleset .spectral.yaml api/openapi.yaml

api-contract-docs:
	go run ./scripts/generate_api_contract_docs/main.go

api-contract-docs-check: api-contract-docs
	git diff --exit-code -- docs/API_CONTRACTS_AUTOGEN.md docs/API_CONTRACTS.json

api-contract-compat:
	go run ./scripts/check_api_contract_compat/main.go

config-docs:
	go run ./scripts/generate_config_docs/main.go

config-docs-check: config-docs
	git diff --exit-code -- docs/CONFIG_ENV_VARS.md

ontology-docs:
	go run ./scripts/generate_graph_ontology_docs/main.go

ontology-docs-check: ontology-docs
	git diff --exit-code -- docs/GRAPH_ONTOLOGY_AUTOGEN.md

cloudevents-docs:
	go run ./scripts/generate_cloudevents_docs/main.go

cloudevents-docs-check: cloudevents-docs
	git diff --exit-code -- docs/CLOUDEVENTS_AUTOGEN.md docs/CLOUDEVENTS_CONTRACTS.json

cloudevents-contract-compat:
	go run ./scripts/check_cloudevents_contract_compat/main.go

report-contract-docs:
	go run ./scripts/generate_report_contract_docs/main.go

report-contract-docs-check: report-contract-docs
	git diff --exit-code -- docs/GRAPH_REPORT_CONTRACTS_AUTOGEN.md docs/GRAPH_REPORT_CONTRACTS.json

report-contract-compat:
	go run ./scripts/check_report_contract_compat/main.go

entity-facet-docs:
	go run ./scripts/generate_entity_facet_docs/main.go

entity-facet-docs-check: entity-facet-docs
	git diff --exit-code -- docs/GRAPH_ENTITY_FACETS_AUTOGEN.md docs/GRAPH_ENTITY_FACETS.json

entity-facet-contract-compat:
	go run ./scripts/check_entity_facet_compat/main.go

agent-sdk-docs:
	go run ./scripts/generate_agent_sdk_docs/main.go

agent-sdk-docs-check: agent-sdk-docs
	git diff --exit-code -- docs/AGENT_SDK_AUTOGEN.md docs/AGENT_SDK_CONTRACTS.json

agent-sdk-contract-compat:
	go run ./scripts/check_agent_sdk_contract_compat/main.go

agent-sdk-packages:
	go run ./scripts/generate_agent_sdk_packages/main.go

agent-sdk-packages-check: agent-sdk-packages
	git diff --exit-code -- docs/AGENT_SDK_PACKAGES_AUTOGEN.md sdk/go/cerebro/client.go sdk/python/cerebro_sdk/__init__.py sdk/python/cerebro_sdk/client.py sdk/python/pyproject.toml sdk/typescript/package.json sdk/typescript/src/index.ts sdk/typescript/tsconfig.json
	go test ./sdk/go/cerebro
	python3 -m py_compile sdk/python/cerebro_sdk/*.py
	python3 ./scripts/validate_toml.py sdk/python/pyproject.toml
	npx --yes -p typescript tsc -p sdk/typescript/tsconfig.json --noEmit

connector-docs:
	go run ./scripts/generate_connector_docs/main.go

connector-docs-check: connector-docs
	git diff --exit-code -- docs/CONNECTOR_PROVISIONING_AUTOGEN.md docs/CONNECTOR_PROVISIONING_CATALOG.json

graph-ontology-guardrails:
	go test ./internal/graphingest -run 'TestMapperContractFixtures|TestMapperSourceDomainCoverageGuardrails' -count=1

devex-codegen:
	go run ./scripts/generate_devex_codegen_docs/main.go

devex-codegen-check: devex-codegen
	git diff --exit-code -- docs/DEVEX_CODEGEN_AUTOGEN.md docs/DEVEX_CODEGEN_CATALOG.json

devex-changed:
	python3 ./scripts/devex.py run --mode changed

devex-pr:
	python3 ./scripts/devex.py run --mode pr

# Docker run
docker-run:
	docker run -p 8080:8080 -v $(PWD)/policies:/app/policies cerebro:latest serve

platform-up:
	docker compose -f docker-compose.platform.yml up -d --build

platform-down:
	docker compose -f docker-compose.platform.yml down -v

platform-logs:
	docker compose -f docker-compose.platform.yml logs -f

platform-smoke:
	docker compose -f docker-compose.platform.yml ps
	curl -fsS http://localhost:8222/healthz >/dev/null
	curl -fsS http://localhost:8080/health >/dev/null
	curl -fsS http://localhost:8081/health >/dev/null || curl -fsS http://localhost:8081/healthz >/dev/null
	curl -fsS http://localhost:3999/health >/dev/null || curl -fsS http://localhost:3999/healthz >/dev/null
	@echo "platform smoke checks passed"

# Install git hooks
hooks:
	./scripts/install_hooks.sh

pre-commit:
	./scripts/pre_commit_checks.sh

verify:
	go test -race ./...
	$(MAKE) lint
	$(MAKE) api-contract-compat
	$(MAKE) cloudevents-contract-compat
	$(MAKE) report-contract-compat
	$(MAKE) entity-facet-contract-compat
	$(MAKE) agent-sdk-contract-compat
	$(MAKE) graph-ontology-guardrails

# Full local setup
setup: install-deps build hooks
	@echo "Cerebro ready. Run 'make serve' to start the API."
