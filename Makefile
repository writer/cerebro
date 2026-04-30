.PHONY: build serve test lint lint-bootstrap proto-lint proto-generate clean hooks pre-commit verify check check-structural check-structural-build check-structural-test check-arch check-hook-integrity

GO_BIN ?= $(shell go env GOPATH)/bin
GOLANGCI_LINT := $(GO_BIN)/golangci-lint
GOLANGCI_LINT_VERSION := v2.11.4
BUF := GOFLAGS= GOTOOLCHAIN=go1.26.2 go run github.com/bufbuild/buf/cmd/buf@v1.59.0
APP_PACKAGES := ./cmd/... ./internal/...
LINTER_MODULE := ./tools/linters
LINTER_BIN := $(GO_BIN)/cerebrolint

build:
	go build -o bin/cerebro ./cmd/cerebro

serve: build
	./bin/cerebro serve

test:
	go test ./...

lint: lint-bootstrap
	$(GOLANGCI_LINT) run --timeout 5m $(APP_PACKAGES)

lint-bootstrap:
	@if [ ! -x "$(GOLANGCI_LINT)" ]; then 		GOTOOLCHAIN=go1.26.2 go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION); 	fi

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
