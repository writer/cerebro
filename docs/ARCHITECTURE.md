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

The service can start without optional stores and serve lightweight routes such as `/health`, `/healthz`, `/livez`, `/openapi.yaml`, and `/sources`. `/health` reports dependency-aware readiness; `/healthz` and `/livez` are liveness-only. Durable runtime, claim, finding, report, replay, and graph operations require the configured store for that operation.

## Store boundaries

| Store | Role |
| --- | --- |
| NATS JetStream | Append log for sync/replay/workflow events. |
| Postgres | Durable current state for source runtimes, claims, findings, evidence, evaluations, reports, and projections. |
| Neo4j/Aura | Graph projection/query backend. Neo4j is the only approved graph backend. |

Kuzu and embedded/in-memory database backends are intentionally rejected by config and arch tests.

See [`DURABILITY_CONTRACT.md`](./DURABILITY_CONTRACT.md) for the current
write-path contract. Source runtime sync and workflow writes are event-backed
before projection. SDK/runtime claim writes are currently Postgres-backed and
project from persisted claim state until a `claim.v1.*` event family exists.
Neo4j remains a projection in both cases; it is not a source of truth.

## API boundaries

- Connect RPCs live under the generated `BootstrapService` path from `proto/cerebro/v1/bootstrap.proto`.
- Current platform routes prefer `/platform/*` for shared platform resources.
- Legacy `/graph/*` aliases have been removed; use the `/platform/graph/*` routes or the matching Connect RPCs.
- HTTP-only surfaces are route-grouped in `internal/bootstrap/routes.go` so platform, internal, and public routes are explicit while the remaining Connect coverage gap is closed.
- Public unauthenticated routes are limited to `/health`, `/healthz`, `/livez`, `/openapi.yaml`, A2A Agent Card metadata, OAuth metadata routes, and `/.well-known/device-jwks.json` when API auth is enabled.

## Bootstrap ownership

`internal/bootstrap` is the outer composition root for the server. It owns
routing, auth, request/response mapping, and dependency wiring. New domain behavior should land behind a domain package and service interface first, with bootstrap limited to translating the HTTP or Connect boundary into that domain contract.

Production Go under `internal/bootstrap` is ratcheted by `tools/archtests` so
new routes and handlers do not quietly grow the bootstrap surface. If a PR must
increase that budget, the PR should explain why the behavior cannot move behind
a domain package yet and update this architecture note alongside the test.

The current budget includes a narrow transport-boundary exception for graph
reasoning: HTTP and MCP handlers clear the server write deadline before entering
the long-running reasoning pipeline. That deadline is owned by `net/http` and
the response writer, so the hook belongs in bootstrap instead of the graphagent
domain package.

The budget also includes the A2A gateway adapter that maps authenticated tenant
context, the platform job store, coverage context, and evidence authorizers into
`internal/a2agateway`. Durable task lifecycle behavior stays in that domain
package; bootstrap only wires the HTTP boundary into it.

The GRC report packet routes add small HTTP adapters that resolve request scope,
load findings, evidence, and graph proof, decode generated custom control-pack
requests, and hand readiness, posture calculation, scope metadata, redaction
metadata, and markdown rendering to `internal/grccontrol`. Profile resolution,
rule coverage, evidence freshness, control status behavior, custom profile
resolution, report metadata construction, and export rendering stay behind that
domain package.

The agent platform graph preflight contract lives in `internal/agentplatform`.
The bootstrap budget includes the HTTP and MCP request/response mapping needed
to force authenticated tenant context, expose preflight to agents, and attach
that preflight envelope to graph reasoning responses. Bootstrap also maps
preflight tenant-required blockers into the graph reasoning boundary's
invalid-request error shape.

The security-agent control plane also lives in `internal/agentplatform`. The
bootstrap budget includes only the HTTP route registration, auth policy, and
request/response mapping for exposing the registry, authorizing packet URNs
against the authenticated tenant, and building tenant-forced evidence packets.

Compliance control-pack generation lives in `internal/compliance`. The
bootstrap budget includes only HTTP route registration, auth policy, request
decoding, status selection, and response mapping for the control archetype,
coverage, preview, and export endpoints; reusable control archetypes,
validation, YAML generation, and rule coverage mapping stay behind the
compliance package boundary.

Inventory accountability and source-connector setup remain bootstrap-boundary
work for now. The budget includes GRC inventory request/response mapping and
tenant authorization that compose existing inventory data for review workflows;
durable inventory semantics stay behind the inventory and compliance packages.
The budget also includes connector setup metadata for source runtime config
validation, including richer OpenAI and Anthropic family/filter keys. That
metadata belongs at the connector API boundary until connector setup schemas are
extracted behind a dedicated catalog/service package.

A2A discovery, outbound event subscription metadata, and public idempotency
semantics also live in `internal/agentplatform`. The bootstrap budget includes
only public Agent Card serving and authenticated request/response mapping for
the JSON-RPC contract, event subscription contract, and idempotency contract.
Outbound webhook delivery remains a governed event contract until backed by a
source/runtime adapter and durable delivery store.

## Postgres migrations

State-store schema preparation runs at service startup and before store operations. Most migrations use additive `CREATE TABLE IF NOT EXISTS`, `CREATE INDEX IF NOT EXISTS`, or `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` patterns.

Claims projection indexes may require an `ACCESS EXCLUSIVE` lock while Postgres validates or rewrites the affected table metadata. This is expected migration-time behavior, but large deployments should run the migration during a maintenance window, verify no long-running claim reads/writes are active, and monitor Postgres lock waits until schema preparation completes.

## Auth and tenant scope

Set `CEREBRO_API_AUTH_ENABLED=true` and provide `CEREBRO_API_KEYS` to require bearer/API-key auth. API keys may bind a principal to one tenant using `key:principal:tenant`. When a request body or query includes `tenant_id`, the bootstrap layer rejects cross-tenant access before invoking service logic.

## Source CDK

Sources live under `sources/<id>` and must include:

- `catalog.yaml`
- unit/replay tests
- fixtures under `testdata/`
- no direct store writes

Arch tests and custom linters are the enforcement mechanism for keeping future
sources inside the Source CDK and preventing regressions toward the older
god-object architecture. [`SOURCE_CDK_EXTRACTION.md`](./SOURCE_CDK_EXTRACTION.md)
tracks grandfathered source LOC budgets and the extraction pressure that should
move shared behavior back into the CDK.
