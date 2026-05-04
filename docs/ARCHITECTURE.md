# Cerebro Architecture

## Current implementation

Cerebro `main` is a compact bootstrap service, not the older Snowflake-centered monolith described by historical docs. Treat these files as the source of truth for runtime behavior:

- `cmd/cerebro` for CLI entry points.
- `internal/bootstrap` for HTTP and Connect handlers.
- `internal/config` for supported environment variables.
- `proto/cerebro/v1/bootstrap.proto` for the typed RPC contract.
- `api/openapi.yaml` for the current JSON HTTP contract.
- `sources/*` for Source CDK integrations.

## Runtime shape

```text
CLI / JSON HTTP / Connect clients
              |
              v
      Bootstrap service
              |
              +--> Source CDK registry and previews
              +--> Source runtime sync and append-log replay
              +--> Claims, findings, reports, workflow events
              +--> Graph projection and graph query operations
              |
              +--> NATS JetStream append log (optional)
              +--> Postgres state store (optional)
              +--> Neo4j/Aura graph store (optional)
```

The service can start without optional stores and serve lightweight routes such as `/health`, `/healthz`, `/openapi.yaml`, and `/sources`. Durable runtime, claim, finding, report, replay, and graph operations require the configured store for that operation.

## Store boundaries

| Store | Role |
| --- | --- |
| NATS JetStream | Append log for sync/replay/workflow events. |
| Postgres | Durable current state for source runtimes, claims, findings, evidence, evaluations, reports, and projections. |
| Neo4j/Aura | Graph projection/query backend. Neo4j is the only approved graph backend. |

Kuzu and embedded/in-memory database backends are intentionally rejected by config and arch tests.

## API boundaries

- Connect RPCs live under the generated `BootstrapService` path from `proto/cerebro/v1/bootstrap.proto`.
- Current platform routes prefer `/platform/*` for shared platform resources.
- Legacy `/graph/*` aliases are retained only for compatibility and emit deprecation headers.
- Public unauthenticated routes are limited to `/health`, `/healthz`, and `/openapi.yaml` when API auth is enabled.

## Auth and tenant scope

Set `CEREBRO_API_AUTH_ENABLED=true` and provide `CEREBRO_API_KEYS` to require bearer/API-key auth. API keys may bind a principal to one tenant using `key:principal:tenant`. When a request body or query includes `tenant_id`, the bootstrap layer rejects cross-tenant access before invoking service logic.

## Source CDK

Sources live under `sources/<id>` and must include:

- `catalog.yaml`
- unit/replay tests
- fixtures under `testdata/`
- no direct store writes

Arch tests and custom linters are the enforcement mechanism for keeping future sources inside the Source CDK and preventing regressions toward the older god-object architecture.
