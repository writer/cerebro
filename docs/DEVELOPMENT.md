# Cerebro Development Guide

This document describes the current bootstrap service on `main`. Historical warehouse, Cedar runtime, and legacy port-variable workflows are retired; use the Makefile and `README.md` as the source of truth.

## Prerequisites

- Go 1.26+; the repository pins `go1.26.4` in `go.mod`.
- Docker and Docker Compose for the durable local stack.
- Make.

## Local Setup

```bash
git clone https://github.com/writer/cerebro.git
cd cerebro
make doctor
make build
```

Run the lightweight server without durable stores:

```bash
make serve-dev
```

Run the durable local stack with NATS JetStream, Postgres, Neo4j, Cerebro, and the local bearer key `local-dev-key`:

```bash
docker compose up --build
```

The compose stack uses service-local `CEREBRO_*` variables. For a standalone local template, start from `.env.example`.

## Common Commands

```bash
make build          # compile ./bin/cerebro
make serve-dev      # run local server with acknowledged dev-mode opt-out
make test           # go test ./...
make lint           # golangci-lint over app packages
make proto-lint     # buf lint
make check          # build, tests, lint, proto lint, structural checks, arch tests
make verify         # CI-parity validation
make readme-check   # README drift checks
make docs-drift-check  # generated docs drift checks
make oss-audit      # public repository hygiene scan
make clean          # remove bin/
```

Focused validation:

```bash
make workflow-e2e-test
make workflow-replay-test
make finding-rule-test
make graph-rebuild-dryrun
```

## Architecture Notes

- External data enters through source packages under `sources/`.
- Source runtime state is stored in Postgres when configured.
- Append-log-backed sync and replay use NATS JetStream.
- Graph projection and query operations use Neo4j/Aura.
- Runtime finding behavior lives in Go rule packages under `internal/findings/`.
- JSON policy files under `policies/` are the authoring catalog for generated policy rules. Run `make policy-rule-generate` after policy edits, then `make detection-catalog-generate`.

## Before Opening A PR

Run the narrowest relevant package tests while developing, then run:

```bash
make check
```

For public config, docs, or packaging changes, also run:

```bash
make oss-audit
```

For generated docs changes, also run:

```bash
make docs-drift-check
```
