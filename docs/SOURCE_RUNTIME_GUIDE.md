# Source Runtime Guide

Source runtimes are Cerebro's durable connection between a source integration and a tenant-scoped stream of events, claims, findings, and graph projections. This guide explains the public runtime model, CLI and HTTP operations, scheduling patterns, and safe configuration practices.

Use it with:

- [`docs/GETTING_STARTED.md`](./GETTING_STARTED.md) for a local SDK source walkthrough.
- [`docs/CONFIG_ENV_VARS.md`](./CONFIG_ENV_VARS.md) for source secret allowlist variables.
- [`docs/OPERATIONS_RUNBOOK.md`](./OPERATIONS_RUNBOOK.md) for sync operations.
- [`api/openapi.yaml`](../api/openapi.yaml) for the HTTP route contract.
- [`sources/*/catalog.yaml`](../sources) for source capability declarations.

## Mental model

A source runtime answers:

- which source integration to run,
- which tenant owns the data,
- what source-specific config to use,
- what cursor was last synced,
- when the runtime last advanced,
- which generated claims, findings, and graph projections can be traced back to it.

The current implementation supports:

- stateless source preview commands with no runtime persistence,
- persisted source runtimes stored in Postgres,
- source runtime sync backed by Postgres plus NATS JetStream,
- graph ingest from either direct source reads or persisted source runtimes.

## Dependency matrix

| Operation | Dependencies |
| --- | --- |
| `source list` | none |
| `source check/discover/read` | none beyond provider-specific config and credentials |
| `source-runtime put/get/list` | Postgres |
| `source-runtime sync` | Postgres plus NATS JetStream |
| source runtime claims and findings routes | Postgres |
| `graph ingest-runtime` | Postgres plus Neo4j or Aura, and often NATS for replay-oriented flows |
| source config `env:` references | environment variable plus allowlist configuration |

## Source preview

Preview source behavior before creating a persisted runtime:

```bash
./bin/cerebro source list
./bin/cerebro source check <source-id> key=value
./bin/cerebro source discover <source-id> key=value
./bin/cerebro source read <source-id> key=value page_limit=1
```

HTTP equivalents:

```bash
curl -fsS "http://127.0.0.1:8080/sources"
curl -fsS "http://127.0.0.1:8080/sources/<source-id>/check?key=value"
curl -fsS "http://127.0.0.1:8080/sources/<source-id>/discover?key=value"
curl -fsS "http://127.0.0.1:8080/sources/<source-id>/read?key=value&page_limit=1"
```

Use preview routes to validate credentials, permissions, paging, and emitted event shape before storing a runtime.

## Create a runtime

CLI:

```bash
./bin/cerebro source-runtime put <runtime-id> <source-id> \
  tenant_id=<tenant-id> \
  key=value
```

HTTP:

```bash
curl -fsS -X PUT "https://cerebro.example.com/source-runtimes/<runtime-id>" \
  -H "Authorization: Bearer ${CEREBRO_API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "runtime": {
      "id": "<runtime-id>",
      "source_id": "<source-id>",
      "tenant_id": "<tenant-id>",
      "config": {
        "key": "value"
      }
    }
  }'
```

Runtime IDs should be stable and descriptive enough for operators. Avoid embedding secrets, customer names, private hostnames, or temporary incident details in IDs.

## Read and list runtimes

```bash
./bin/cerebro source-runtime get <runtime-id>
./bin/cerebro source-runtime list tenant_id=<tenant-id> source_id=<source-id> limit=20
```

HTTP:

```bash
curl -fsS -H "Authorization: Bearer ${CEREBRO_API_KEY}" \
  "https://cerebro.example.com/source-runtimes?tenant_id=<tenant-id>&source_id=<source-id>&limit=20"

curl -fsS -H "Authorization: Bearer ${CEREBRO_API_KEY}" \
  "https://cerebro.example.com/source-runtimes/<runtime-id>"
```

Responses redact sensitive runtime config where the implementation marks config as sensitive.

## Sync a runtime

CLI:

```bash
./bin/cerebro source-runtime sync <runtime-id> page_limit=100
```

HTTP:

```bash
curl -fsS -X POST \
  -H "Authorization: Bearer ${CEREBRO_API_KEY}" \
  "https://cerebro.example.com/source-runtimes/<runtime-id>/sync?page_limit=100"
```

Operational guidance:

- Default to small page limits during onboarding.
- Use `page_limit=100` as the current practical maximum for high-throughput sync jobs.
- Avoid concurrent sync for the same runtime unless the source and persistence path are known to be concurrency-safe.
- Watch provider rate limits and partial-page errors.
- Treat cursor advancement as the sign that sync is healthy.

## Bootstrap runtimes from JSON

The CLI can load a list of runtimes from an environment variable:

```bash
export SOURCE_RUNTIMES_JSON='[
  {
    "id": "<runtime-id>",
    "source_id": "<source-id>",
    "tenant_id": "<tenant-id>",
    "config": {
      "key": "value"
    }
  }
]'

./bin/cerebro source-runtime bootstrap env=SOURCE_RUNTIMES_JSON
```

Use this for local experiments and platform-driven bootstrap flows. Do not put live provider tokens in the JSON. Use `env:` references for sensitive values.

## Secrets and `env:` references

Source config can reference environment variables with values like:

```text
env:PROVIDER_API_TOKEN
```

The environment variable must be present at runtime and allowed by configuration. Use:

```bash
CEREBRO_SOURCE_CONFIG_ENV_ALLOWLIST=PROVIDER_API_TOKEN,ANOTHER_ALLOWED_SECRET
```

If a source uses constrained cloud role assumptions, use:

```bash
CEREBRO_AWS_ASSUME_ROLE_ARNS=<role-arn-allowlist>
```

Security rules:

1. Declare secret names, not secret values, in deploy manifests.
2. Inject secret values through your platform.
3. Allow only the env vars each source needs.
4. Keep provider credentials least-privilege.
5. Rotate source credentials like any other production secret.

## Runtime health

HTTP:

```bash
curl -fsS -H "Authorization: Bearer ${CEREBRO_API_KEY}" \
  "https://cerebro.example.com/source-runtimes/health?tenant_id=<tenant-id>&limit=20"
```

Invalid event inspection:

```bash
curl -fsS -H "Authorization: Bearer ${CEREBRO_API_KEY}" \
  "https://cerebro.example.com/source-runtimes/<runtime-id>/invalid-events?limit=20"
```

Use these during onboarding and after source code changes. Invalid events usually mean a source emitted data that failed validation or projection constraints.

## Claims and findings

Runtime-scoped claim and finding routes include:

```text
GET  /source-runtimes/{runtimeID}/claims
POST /source-runtimes/{runtimeID}/claims
GET  /source-runtimes/{runtimeID}/findings
GET  /source-runtimes/{runtimeID}/finding-candidates
GET  /source-runtimes/{runtimeID}/finding-evidence
GET  /source-runtimes/{runtimeID}/finding-evaluation-runs
POST /source-runtimes/{runtimeID}/finding-candidates/evaluate
POST /source-runtimes/{runtimeID}/finding-rules/evaluate
POST /source-runtimes/{runtimeID}/findings/evaluate
```

The SDK source is useful for application-owned inventory or posture claims. See [`docs/GETTING_STARTED.md`](./GETTING_STARTED.md) for a local claim write.

## Graph ingest from runtime

When graph is enabled:

```bash
./bin/cerebro graph ingest-runtime <runtime-id> page_limit=100
```

HTTP:

```bash
curl -fsS -X POST \
  -H "Authorization: Bearer ${CEREBRO_API_KEY}" \
  "https://cerebro.example.com/source-runtimes/<runtime-id>/graph-ingest-runs?page_limit=100"
```

Inspect graph ingest runs:

```bash
./bin/cerebro graph ingest-runs runtime_id=<runtime-id> limit=20
./bin/cerebro graph ingest-run <run-id>
```

## Scheduling guidance

Use your scheduler or orchestrator to run sync jobs:

```bash
cerebro source-runtime sync <runtime-id> page_limit=100
```

Then, if graph projection is separate:

```bash
cerebro graph ingest-runtime <runtime-id> page_limit=100
```

Recommendations:

- Use one schedule per runtime and operation.
- Forbid overlapping jobs for cursor-sensitive runtimes.
- Separate API service resources from scheduled job resources.
- Start with conservative cadence and page limits.
- Monitor provider errors, cursor advancement, invalid events, and graph ingest status.

## Source manifest and release handoff

Sources may include:

- `sources/<source-id>/catalog.yaml`, which describes source capabilities,
- `sources/<source-id>/deploy.yaml`, which declares source-level secret names and canonical runtime config,
- `sources/<source-id>/source_health_receipt.json`, when a source ships a health receipt.

The deploy manifest intentionally declares what the source needs, not when or where your platform should schedule it. Deployment cadence and concrete secrets belong in your deployment system.

See [`docs/RELEASE_CONTRACT.md`](./RELEASE_CONTRACT.md) for how source manifests contribute to `cerebro-runtime-contract.json`.

## Troubleshooting quick map

| Symptom | Likely layer | First check |
| --- | --- | --- |
| `source-runtime put` fails | Postgres/config | `CEREBRO_STATE_STORE_DRIVER`, `CEREBRO_POSTGRES_DSN`, `/health` |
| sync returns unavailable | Postgres or JetStream | state store, append log, `/health` |
| sync does not advance | source/provider | credentials, rate limits, runtime config, cursor |
| invalid events appear | source validation | invalid event route, source emitted kinds, catalog |
| tenant forbidden | auth/tenant | credential tenant, request `tenant_id`, `X-Cerebro-Tenant` |
| graph ingest fails | graph dependency | Neo4j config, `graph health`, ingest run status |
