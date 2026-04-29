.PHONY: build serve test lint lint-bootstrap clean hooks pre-commit verify check check-structural check-structural-build check-structural-test

GO_BIN ?= $(shell go env GOPATH)/bin
GOLANGCI_LINT := $(GO_BIN)/golangci-lint
LINTER_MODULE := ./tools/linters
LINTER_BIN := $(GO_BIN)/cerebrolint

build:
	go build -o bin/cerebro ./cmd/cerebro

serve: build
	./bin/cerebro serve

test:
	go test ./...

lint: lint-bootstrap
	$(GOLANGCI_LINT) run --timeout 5m ./cmd/...

lint-bootstrap:
	@if [ ! -x "$(GOLANGCI_LINT)" ]; then \
		GOTOOLCHAIN=go1.26.2 go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest; \
	fi

clean:
	rm -rf bin/

hooks:
	./scripts/install_hooks.sh

pre-commit:
	./scripts/pre_commit_checks.sh

check: build test lint check-structural check-structural-test

check-structural: check-structural-build
	@$(LINTER_BIN) ./cmd/...

check-structural-build:
	@GOFLAGS= cd $(LINTER_MODULE) && go build -o $(LINTER_BIN) ./cerebrolint

check-structural-test:
	@GOFLAGS= cd $(LINTER_MODULE) && go test ./...

verify: build test lint check-structural check-structural-test
