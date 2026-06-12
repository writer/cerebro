# Troubleshooting Cookbook

This cookbook maps common Cerebro symptoms to likely causes and first checks. It is intentionally environment-agnostic and uses placeholders for hosts, tenants, credentials, and runtime IDs.

Use it with:

- [`docs/OPERATIONS_RUNBOOK.md`](./OPERATIONS_RUNBOOK.md) for incident flow.
- [`docs/AUTH_TENANCY.md`](./AUTH_TENANCY.md) for auth and tenant checks.
- [`docs/SOURCE_RUNTIME_GUIDE.md`](./SOURCE_RUNTIME_GUIDE.md) for source runtime checks.
- [`docs/GRAPH_OPERATIONS.md`](./GRAPH_OPERATIONS.md) for graph checks.

## Quick triage

Start here:

```bash
curl -fsS http://127.0.0.1:8080/livez
curl -sS http://127.0.0.1:8080/health
```

Then identify the failing layer:

| Symptom | Likely layer |
| --- | --- |
| `/livez` fails | process, container, listener, host |
| `/livez` passes but `/health` fails | configured dependency |
| only protected routes fail | auth, tenant, scope, proxy headers |
| only source sync fails | source runtime, provider credentials, Postgres, JetStream |
| only graph routes fail | Neo4j/Aura, graph query, graph ingest |
| only MCP OAuth fails | public origin, OAuth config, Postgres, capability secrets |

## Process is not alive

Symptoms:

- `/livez` fails,
- container restarts,
- process exits on startup.

Checks:

```bash
./bin/cerebro version
CEREBRO_HTTP_ADDR=:8080 ./bin/cerebro serve
```

Look for:

- invalid environment variable values,
- unsupported driver names,
- missing required auth secrets when auth is enabled,
- dependency open or ping failures,
- port already in use,
- platform health check hitting the wrong port.

Common fixes:

- set `CEREBRO_HTTP_ADDR=:8080`,
- correct driver names,
- add required secret env vars,
- confirm backing stores are reachable,
- check that the container command is `serve`.

## Readiness is degraded

Symptoms:

- `/livez` passes,
- `/health` returns HTTP `503`,
- load balancer removes the instance.

Checks:

```bash
curl -sS http://127.0.0.1:8080/health
```

Then check configured dependencies:

| Configured dependency | Variables |
| --- | --- |
| NATS JetStream | `CEREBRO_APPEND_LOG_DRIVER`, `CEREBRO_JETSTREAM_URL` |
| Postgres | `CEREBRO_STATE_STORE_DRIVER`, `CEREBRO_POSTGRES_DSN` |
| Neo4j/Aura | `CEREBRO_GRAPH_STORE_DRIVER`, `CEREBRO_NEO4J_URI`, `CEREBRO_NEO4J_USERNAME`, `CEREBRO_NEO4J_PASSWORD` |

Common fixes:

- correct DSNs and URIs,
- restore network access,
- rotate expired credentials,
- increase dependency capacity,
- remove a driver config if that dependency is not intended for the profile.

## Auth returns 401

Symptoms:

- protected routes return `401 unauthorized`,
- public routes still work.

Checks:

```bash
curl -i \
  -H "Authorization: Bearer ${CEREBRO_API_KEY}" \
  "https://cerebro.example.com/source-runtimes?limit=1"
```

Verify:

- `CEREBRO_API_AUTH_ENABLED=true`,
- the key is present in `CEREBRO_API_KEYS` or `CEREBRO_API_CREDENTIALS_JSON`,
- the client sends `Authorization: Bearer <key>` or `X-Cerebro-API-Key: <key>`,
- the proxy preserves `Authorization`,
- capability tokens are signed with a configured secret.

## Auth returns 403

Symptoms:

- request is authenticated,
- response is `403 tenant forbidden` or `403 scope forbidden`.

Checks:

- credential `tenant_id`,
- credential `allowed_tenants`,
- request `tenant_id`,
- `X-Cerebro-Tenant`,
- tenant embedded in URNs or request bodies,
- structured credential scopes.

Common fixes:

- use a tenant-scoped key for the intended tenant,
- pass the matching `tenant_id`,
- add required scope to the credential,
- avoid mixing runtime IDs and tenant hints from different environments.

## Public origin or DPoP is wrong

Symptoms:

- OAuth or DPoP flows fail,
- generated metadata contains the wrong origin,
- requests work locally but fail through the proxy.

Checks:

```bash
echo "$CEREBRO_PUBLIC_ORIGIN"
echo "$CEREBRO_TRUSTED_PROXY_CIDRS"
echo "$CEREBRO_TRUSTED_PROXY_COUNT"
```

Verify the proxy:

- strips untrusted incoming `X-Forwarded-*`,
- sets `X-Forwarded-For`,
- sets `X-Forwarded-Host`,
- sets `X-Forwarded-Proto`,
- preserves `Authorization`,
- preserves `DPoP`.

Common fixes:

- set `CEREBRO_PUBLIC_ORIGIN=https://cerebro.example.com`,
- set trusted proxy CIDRs explicitly,
- set trusted proxy count to the actual hop count,
- correct proxy header forwarding.

## Source runtime put/list fails

Symptoms:

- `source-runtime put` fails,
- `GET /source-runtimes` fails,
- runtime state is not durable.

Checks:

```bash
echo "$CEREBRO_STATE_STORE_DRIVER"
echo "$CEREBRO_POSTGRES_DSN"
curl -sS http://127.0.0.1:8080/health
```

Common fixes:

- configure `CEREBRO_STATE_STORE_DRIVER=postgres`,
- configure `CEREBRO_POSTGRES_DSN`,
- confirm Postgres network access,
- confirm database credentials,
- check connection pool saturation.

## Source sync fails

Symptoms:

- `source-runtime sync` returns unavailable,
- sync starts but does not advance,
- provider calls fail,
- invalid events appear.

Checks:

```bash
./bin/cerebro source-runtime get <runtime-id>
./bin/cerebro source-runtime sync <runtime-id> page_limit=1
curl -fsS -H "Authorization: Bearer ${CEREBRO_API_KEY}" \
  "https://cerebro.example.com/source-runtimes/<runtime-id>/invalid-events?limit=20"
```

Verify:

- Postgres is configured,
- NATS JetStream is configured for sync,
- provider credentials are present,
- source config values are correct,
- `env:` references are allowed,
- provider rate limits are not exceeded,
- another job is not syncing the same cursor-sensitive runtime.

Common fixes:

- reduce `page_limit`,
- rotate provider credentials,
- add missing env vars to `CEREBRO_SOURCE_CONFIG_ENV_ALLOWLIST`,
- pause overlapping jobs,
- inspect invalid events and fix source config or source implementation.

## Graph routes fail

Symptoms:

- graph CLI says graph store is required,
- graph HTTP routes return unavailable,
- graph ingest runs fail.

Checks:

```bash
./bin/cerebro graph health
./bin/cerebro graph counts
./bin/cerebro graph ingest-runs limit=20
```

Verify:

- `CEREBRO_GRAPH_STORE_DRIVER=neo4j`,
- `CEREBRO_NEO4J_URI`,
- `CEREBRO_NEO4J_USERNAME`,
- `CEREBRO_NEO4J_PASSWORD`,
- optional database name,
- graph database network access,
- query timeout,
- source runtime data exists before runtime-backed ingest.

Common fixes:

- correct graph credentials,
- use encrypted Neo4j/Aura URI where required,
- set `CEREBRO_NEO4J_DATABASE` if the graph is not in the default database,
- lower graph query limits,
- inspect ingest run failures.

## Graph is stale

Symptoms:

- graph health passes but expected data is missing,
- source runtime has newer data than graph,
- impact routes return empty results.

Checks:

```bash
./bin/cerebro source-runtime get <runtime-id>
./bin/cerebro graph ingest-runs runtime_id=<runtime-id> limit=20
./bin/cerebro graph ingest-runtime <runtime-id> page_limit=1
```

Common fixes:

- run source sync first,
- run graph ingest after sync,
- investigate failed or zero-projection ingest runs,
- confirm the source emits graph-projectable event kinds,
- confirm tenant IDs match.

## MCP endpoint fails

Symptoms:

- MCP client cannot connect,
- OAuth discovery fails,
- OAuth token exchange fails,
- stateless MCP calls return unauthorized.

Checks:

```bash
curl -fsS https://cerebro.example.com/.well-known/oauth-protected-resource/api/v1/mcp
curl -fsS -H "Authorization: Bearer ${CEREBRO_API_KEY}" \
  https://cerebro.example.com/api/v1/mcp
```

Verify:

- API auth is enabled,
- `CEREBRO_PUBLIC_ORIGIN` is set,
- Postgres is configured for OAuth mode,
- `CEREBRO_CAPABILITY_TOKEN_SECRETS` is set,
- `CEREBRO_MCP_OAUTH_*` variables are correct,
- the proxy preserves request bodies and auth headers.

## Device auth fails

Symptoms:

- device enroll or token calls fail,
- DPoP verification fails,
- telemetry ingest is denied.

Checks:

- API auth is enabled,
- device-auth signing keys JSON is configured,
- current key ID exists in the key set,
- issuer and audience match clients,
- DPoP proof method and URL match the public request,
- replica count is compatible with replay protection,
- state store supports device auth.

For general OSS use, keep device auth disabled until the simpler API-key or structured-credential path works.

## HTTP status guide

| Status | Typical meaning |
| --- | --- |
| `400` | malformed request, invalid parameter, invalid JSON |
| `401` | missing or invalid authentication |
| `403` | tenant or scope forbidden |
| `404` | runtime, run, finding, or resource not found |
| `409` | conflicting operation, such as an already-running job |
| `422` | unsupported action or semantic request error |
| `503` | configured dependency or capability unavailable |

Prefer fixing the layer indicated by the status instead of restarting the process first.

## Safe debug bundle

When asking for help, collect shareable information:

- Cerebro version,
- image tag,
- relevant route path,
- HTTP status code,
- whether auth is enabled,
- selected hosting profile,
- which dependency is configured,
- redacted error message,
- redacted runtime ID shape,
- recent validation commands run.

Do not share:

- API keys,
- DSNs with credentials,
- provider tokens,
- live tenant or customer names,
- private hostnames,
- account IDs,
- secret paths,
- raw source payloads.
