.PHONY: build run test sync clean dev serve policy-list docker-build trivy-db security-scan security-scan-built security-scan-source vendor vendor-check oss-audit openapi-check openapi-sync

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
GOFLAGS ?= -mod=vendor

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

# Format code
fmt:
	goimports -w $$(find . -name '*.go' -not -path './vendor/*')
	gofmt -w $$(find . -name '*.go' -not -path './vendor/*')

# Sync cloud assets via native scanners
sync: build
	./bin/cerebro sync

# List policies
policy-list: build
	./bin/cerebro policy list

# Validate policies
policy-validate: build
	./bin/cerebro policy validate

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

# Verify vendored dependencies are in sync
vendor-check:
	go mod tidy
	go mod vendor
	git diff --exit-code -- go.mod go.sum vendor/modules.txt vendor

# Clean build artifacts
clean:
	rm -rf bin/

# Development: run API with hot reload
dev:
	go run ./cmd/cerebro serve

# Docker build
docker-build:
	docker build -t cerebro:latest .

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
	docker build -f Dockerfile -t $(SECURITY_SCAN_IMAGE) .
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

# Optional heavier source scan (kept explicit to avoid default local laptop instability)
security-scan-source:
	$(GO_BIN)/govulncheck ./...
	$(GO_BIN)/gosec -severity medium -confidence medium -exclude-generated ./...

oss-audit:
	python3 scripts/oss_audit.py

openapi-check:
	go run ./scripts/openapi_route_parity.go

openapi-sync:
	go run ./scripts/openapi_route_parity.go --write

# Docker run
docker-run:
	docker run -p 8080:8080 -v $(PWD)/policies:/app/policies cerebro:latest serve

# Full local setup
setup: install-deps build
	@echo "Cerebro ready. Run 'make serve' to start the API."
