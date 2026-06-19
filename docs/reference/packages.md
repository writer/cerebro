# Cerebro Package Overview

This is a current map of the bootstrap-centered Go repository. Treat generated files under `gen/` and generated docs as outputs of their Makefile targets.

## Top-Level Layout

```text
cmd/cerebro/        CLI and server entrypoint
internal/           Bootstrap services, stores, rules, projections, and shared ports
sources/            Built-in Source CDK integrations
proto/              Source protobuf contracts
gen/                Generated Go protobuf/connect code
api/                OpenAPI contract artifacts
policies/           Security policy and control-mapping catalog metadata
sdk/                Python and TypeScript helper clients for supported bootstrap routes
tools/              Structural linters, arch tests, and catalog checks
```

## Core Runtime Packages

- `internal/bootstrap` composes the HTTP server, Connect service, auth middleware, route handlers, and dependency wiring.
- `internal/config` loads `CEREBRO_*` environment configuration and rejects unsupported legacy stores.
- `internal/ports` defines store, graph, projection, append-log, finding, report, claim, and GRC interfaces.
- `internal/sourceruntime` validates and stores runtime definitions, syncs runtime pages, appends events, and coordinates runtime leases.
- `internal/sourceops` runs source `check`, `discover`, and `read` preview operations.
- `internal/sourceprojection` converts source events into current-state projections.
- `internal/findings` owns built-in finding rules, rule metadata, evaluation, lifecycle, correlation, closeout, and endpoint vulnerability findings.
- `internal/knowledge` and `internal/workflowprojection` write and project workflow decisions, actions, and outcomes.
- `internal/graphingest`, `internal/graphquery`, `internal/graphstore`, and `internal/graphrebuild` own graph projection, query, and rebuild flows.
- `internal/deviceauth` owns first-party device enrollment, token issuance, DPoP verification, and device risk inputs.

## Source Packages

Sources live under `sources/<source_id>` and should stay behind the Source CDK contract. New sources should fit within the 300 LOC source budget unless shared CDK functionality is added first. Existing larger sources are grandfathered with ratcheting budgets enforced by arch tests.

Shared source helpers belong under `sources/internal` or `internal/sourcecdk` rather than in individual integrations.

## Store Boundaries

- NATS JetStream is the append log for sync/replay workflows.
- Postgres is the current-state and finding/report store.
- Neo4j/Aura is the graph projection and query store.

Adding another long-lived store crosses the repository non-goals and requires updating `docs/engineering/non-goals.md`.

## Catalogs And Contracts

- `policies/` is validated catalog/control metadata, not a runtime Cedar engine.
- `api/openapi.yaml` describes the JSON HTTP surface.
- `proto/cerebro/v1/bootstrap.proto` describes the Connect surface.
- `tools/archtests` and `tools/linters` enforce package and architecture guardrails.
