.PHONY: build run test sync clean dev serve policy-list docker-build

# Version info
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE    ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS := -ldflags "-X github.com/writerinternal/cerebro/internal/cli.Version=$(VERSION) \
                     -X github.com/writerinternal/cerebro/internal/cli.Commit=$(COMMIT) \
                     -X github.com/writerinternal/cerebro/internal/cli.BuildDate=$(DATE)"

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

# Sync cloud assets via CloudQuery
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

# Install CloudQuery CLI
install-cloudquery:
	brew install cloudquery/tap/cloudquery

# Install all dependencies
install-deps: install-cloudquery
	go mod download

# Clean build artifacts
clean:
	rm -rf bin/

# Development: run API with hot reload
dev:
	go run ./cmd/cerebro serve

# Docker build
docker-build:
	docker build -t cerebro:latest .

# Docker run
docker-run:
	docker run -p 8080:8080 -v $(PWD)/policies:/app/policies cerebro:latest serve

# Full local setup
setup: install-deps build
	@echo "Cerebro ready. Run 'make serve' to start the API."
