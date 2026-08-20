# Runtime Profiles

Choose the smallest Cerebro profile that supports the work. Each profile adds operational duties. Do not configure a backing service until an API route, source runtime, graph operation, or client flow needs it.

The preflight receipt reports one of four `runtime_profile` values: `lightweight-api`, `durable-api`, `durable-sync`, or `graph-enabled`. Capability layers such as MCP OAuth appear in `enabled_capabilities`.

The Rust product demo is the provider-free local product path. It starts an in-memory organizational graph with synthetic data, requires no Docker services or provider credentials, and is validated with `make rust-product-demo-check`.

The Go compatibility runtime remains the live source, CLI, HTTP, Connect, MCP, append-log, findings, reports, and compatibility workflow surface until each Rust authority boundary has parity, fail-closed, rollback, and client-compatibility evidence. Durable workflows require NATS JetStream, Postgres, and Neo4j according to the profile below. Routes backed by an unconfigured durable store fail closed. No in-memory or SQLite production fallback is used for durable routes.

## Runtime Authority Map

| Surface | Current authority | Backing services | Deletion or promotion gate |
| --- | --- | --- | --- |
| Rust product demo | Rust product demo over an in-memory organizational graph | None | Browser receipt and product-shape compatibility |
| Source reads and source runtime | Go compatibility runtime | Provider config as required; durable sync additionally needs Postgres and NATS JetStream | Go/Rust protocol parity, fixture parity, durable fencing, cursor/checkpoint rollback proof |
| Public HTTP, Connect, MCP, CLI, findings, reports | Go compatibility runtime or bridged-to-Rust authority where explicitly wired | Profile-dependent; durable routes require Postgres and sometimes NATS JetStream or Neo4j | OpenAPI, proto, SDK, MCP, auth, and route inventory gates |
| Typed graph/product authority | Rust organizational platform for promoted graph routes | Neo4j or Aura for graph-enabled durable reads; Postgres and NATS JetStream for persisted projection/replay | Typed graph tests, readiness/fail-closed receipts, rollback evidence |
| Raw Cypher compatibility and migration helpers | Retained Go compatibility only where an explicit compatibility port is wired | Neo4j or Aura | Typed Rust operation replacement and raw-Cypher inventory closure |
| Slack companion | Explicit Slack authority paths, fixture-first by default | Profile-dependent durable stores | Fixture or approved-live validation with no unapproved writes |

Do not document or operate a surface as Rust-only until the matching gate has a receipt. Remaining Go compatibility is intentional migration scaffolding, not a fallback for Rust authority failure.

## Lightweight API

Use this profile for metadata routes, source catalog inspection, OpenAPI access, and provider-free source previews.

Required backing services: none.

Required config:

```bash
CEREBRO_HTTP_ADDR=:8080
CEREBRO_API_AUTH_ENABLED=true
CEREBRO_API_KEYS=<random-key>:<principal>:<tenant-id>
CEREBRO_PUBLIC_ORIGIN=https://cerebro.example.com
CEREBRO_TRUSTED_PROXY_CIDRS=10.0.0.0/8
CEREBRO_TRUSTED_PROXY_COUNT=1
```

Checks:

```bash
cerebro deploy preflight
curl -fsS https://cerebro.example.com/livez
curl -fsS https://cerebro.example.com/health
curl -fsS -H "Authorization: Bearer ${CEREBRO_API_KEY}" https://cerebro.example.com/sources
```

Not enough for: persisted source runtimes, claims, findings, reports, workflow replay, MCP OAuth, device auth, source sync, or graph operations.

## Durable API

Use this profile when Cerebro must persist runtime state, claims, findings, reports, OAuth state, or device-auth state.

Required backing services:

- Postgres with TLS, backups, restore procedure, and least-privilege credentials.

Add this config:

```bash
CEREBRO_STATE_STORE_DRIVER=postgres
CEREBRO_POSTGRES_DSN=<postgres-dsn-with-tls>
```

Checks:

```bash
cerebro deploy preflight
cerebro source-runtime list tenant_id=<tenant-id> limit=20
curl -fsS https://cerebro.example.com/health
```

Operator duties:

- Monitor connection pool wait, query failures, storage, CPU, and locks.
- Test restore before broad rollout.
- Size `CEREBRO_POSTGRES_MAX_OPEN_CONNS` against database limits and replica count.

Not enough for: append-log replay, source sync workflows, graph ingest, or graph queries.

## Durable Sync

Use this profile when source runtime sync, append-log-backed replay, or workflow replay is required.

Required backing services:

- Postgres.
- NATS JetStream with persistent storage and retention that matches replay needs.

Add the Durable API config, then add:

```bash
CEREBRO_APPEND_LOG_DRIVER=jetstream
CEREBRO_JETSTREAM_URL=<nats-jetstream-url>
CEREBRO_JETSTREAM_STREAM_NAME=CEREBRO_EVENTS
CEREBRO_JETSTREAM_SUBJECT_PREFIX=events
```

Checks:

```bash
cerebro deploy preflight
cerebro source-runtime list tenant_id=<tenant-id> limit=20
cerebro source-runtime sync <runtime-id> page_limit=1
```

Operator duties:

- Run source sync as scheduled jobs outside the API service.
- Forbid overlapping jobs for cursor-sensitive runtimes.
- Monitor stream health, storage pressure, publish errors, and consumer lag.
- Keep provider credentials and schedules in deployment records.

Not enough for: graph ingest, graph queries, graph health, or graph-agent workflows.

## Graph-Enabled

Use this profile when Cerebro needs graph projection, graph queries, graph health, graph-agent workflows, or graph-backed reports.

Required backing services:

- Postgres.
- NATS JetStream.
- Neo4j or Aura with encrypted connections where supported.

Add the Durable Sync config, then add:

```bash
CEREBRO_GRAPH_STORE_DRIVER=neo4j
CEREBRO_NEO4J_URI=<neo4j-or-aura-uri>
CEREBRO_NEO4J_USERNAME=<neo4j-user>
CEREBRO_NEO4J_PASSWORD=<neo4j-password>
```

Checks:

```bash
cerebro deploy preflight
cerebro graph health
cerebro graph counts
cerebro graph ingest-runs limit=20
```

Operator duties:

- Treat Neo4j/Aura as a projection, not the source of truth.
- Run graph ingest jobs separately from the API service.
- Use dry-run rebuilds before broad projection changes.
- Monitor ingest failures, stale-running ingest, query latency, index health, and storage growth.

## MCP/OAuth Capability Layer

Use this capability layer when MCP clients need OAuth-issued capability tokens.

Required backing services:

- Postgres.
- Public origin and trusted proxy config.
- Capability-token HMAC secrets.
- MCP OAuth client, entitlement, and upstream OAuth settings.

Add the Durable API config, then add:

```bash
CEREBRO_MCP_OAUTH_ENABLED=true
CEREBRO_CAPABILITY_TOKEN_SECRETS=<hmac-secret-1>,<hmac-secret-2>
CEREBRO_MCP_OAUTH_CLIENTS_JSON=<oauth-clients-json>
CEREBRO_MCP_OAUTH_ENTITLEMENTS_JSON=<oauth-entitlements-json>
CEREBRO_MCP_OAUTH_UPSTREAM_ISSUER=https://identity.example.com
CEREBRO_MCP_OAUTH_UPSTREAM_CLIENT_ID=<oauth-client-id>
CEREBRO_MCP_OAUTH_UPSTREAM_CLIENT_SECRET=<oauth-client-secret>
CEREBRO_MCP_OAUTH_UPSTREAM_REDIRECT_URI=https://cerebro.example.com/oauth/callback
CEREBRO_MCP_OAUTH_SECURITY_GROUPS=<group-1>,<group-2>
CEREBRO_PUBLIC_ORIGIN=https://cerebro.example.com
```

Checks:

```bash
cerebro deploy preflight
curl -fsS https://cerebro.example.com/.well-known/oauth-authorization-server
curl -fsS https://cerebro.example.com/health
```

Operator duties:

- Keep redirect URIs exact-match.
- Keep client secrets and HMAC material in the secret manager.
- Review tenant and scope entitlements before enabling new clients.
- Rotate capability token secrets with overlap.

## Profile Selection Table

| Need | Smallest profile |
| --- | --- |
| Health checks and source catalog | Lightweight API |
| Persist source runtime definitions | Durable API |
| Persist claims, findings, reports, OAuth, or device-auth state | Durable API |
| Sync source runtimes on a schedule | Durable sync |
| Replay append-log events | Durable sync |
| Run graph ingest or graph queries | Graph-enabled |
| Use graph-agent workflows | Graph-enabled |
| Issue MCP OAuth tokens | Durable API with MCP OAuth enabled |

Run `cerebro deploy preflight --format json` after changing profile config. The `runtime_profile`, `enabled_capabilities`, `required_backing_services`, and `required_secret_names` fields should match the intended profile and capability layers before traffic moves.

## Validation Commands

These commands are the repository-discoverable gates used by runtime and compatibility validators. Run the focused gate that matches the changed surface, then use `make verify` for broad PR-parity validation when scope warrants it.

```bash
make rust-fmt-check
make rust-clippy
make rust-test
make projection-parity-test
make source-fixture-check
make mcp-contract-check
make mcp-sdk-compat
make openapi-check
make openapi-lint
make sdk-test
make rust-product-demo-check
make graph-rebuild-dryrun RUNTIME_ID=<runtime-id>
make readme-check
make docs-drift-check
make verify
```

For operational preflight and health evidence, use the profile-specific checks above. Validation receipts must redact secret-bearing values such as API keys, bearer tokens, OAuth client secrets, graph shared secrets, provider tokens, Postgres DSNs, Neo4j passwords, and capability-token HMAC material. Use placeholders such as `<postgres-dsn-with-tls>`, `<neo4j-password>`, `<hmac-secret-1>`, and `<oauth-client-secret>` in shared docs and receipts.
