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
docker compose pull
docker compose up -d
```

Plain Compose initializes the local Postgres volume with the compose-file password. The onboarding Make targets use `tmp/local-postgres-password`. Before switching from plain Compose to `make agent-onboard-e2e` or `make github-business-demo`, run `docker compose down -v` to recreate local volumes, or run the Make target with `CEREBRO_LOCAL_POSTGRES_PASSWORD=cerebro` to reuse that volume. `docker compose down -v` deletes local stack data.

Use `docker compose -f docker-compose.yml -f docker-compose.build.yml up --build -d` when you need the durable stack to run the current checkout instead of the published image.

The compose stack uses service-local `CEREBRO_*` variables. For a standalone local template, start from `.env.example`.

## Common Commands

```bash
make build          # compile ./bin/cerebro
make serve-dev      # run local server with acknowledged dev-mode opt-out
make test           # go test ./...
make lint           # golangci-lint over app packages
make changed-check  # changed-path validation for local iteration and hooks
make proto-lint     # buf lint
make check          # build, tests, lint, proto lint, structural checks, arch tests
make verify         # CI-parity validation
make sourcegen-check # connector definition sourcegen readiness
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
- `PolicyFindingRule` YAML files under `policies/` are the authoring DSL for generated policy rules. Run `make finding-dsl-check`, `make policy-rule-generate`, and `make detection-catalog-generate` after policy edits.

## Before Opening A PR

Run the narrowest relevant package tests while developing, then run changed-path
validation:

```bash
make changed-check
```

`make changed-check` maps touched paths to focused package tests and contract
checks such as `sourcegen-check`, `catalog-check`, policy-rule checks, OpenAPI
checks, protobuf checks, script tests, and structural checks. The pre-commit
hook uses it by default to keep local iteration fast. Set
`CEREBRO_PRE_COMMIT_FULL_VERIFY=1` when you want the hook to run full
CI-equivalent validation locally.

Before broad PRs or before handing off a change with high blast radius, run:

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
