# Graph Operations

This guide covers operating Cerebro's graph projection and graph query surfaces. Graph operations require Neo4j or Aura and, for runtime-backed ingest, the configured source runtime stores.

Use it with:

- [`docs/GRAPH_ONTOLOGY_AUTOGEN.md`](./GRAPH_ONTOLOGY_AUTOGEN.md) for graph entity and relation shape.
- [`docs/GRAPH_REPORT_CONTRACTS_AUTOGEN.md`](./GRAPH_REPORT_CONTRACTS_AUTOGEN.md) for graph report contracts.
- [`docs/SOURCE_RUNTIME_GUIDE.md`](./SOURCE_RUNTIME_GUIDE.md) for source runtime sync.
- [`docs/OPERATIONS_RUNBOOK.md`](./OPERATIONS_RUNBOOK.md) for operational checks.

## Dependencies

Graph reads and writes require:

```bash
CEREBRO_GRAPH_STORE_DRIVER=neo4j
CEREBRO_NEO4J_URI=<neo4j-or-aura-uri>
CEREBRO_NEO4J_USERNAME=<username>
CEREBRO_NEO4J_PASSWORD=<password>
```

Optional:

```bash
CEREBRO_NEO4J_DATABASE=<database>
CEREBRO_NEO4J_QUERY_TIMEOUT=10s
```

Runtime-backed ingest also requires source runtime state. Most durable deployments use Postgres plus NATS JetStream with Neo4j or Aura.

## CLI overview

Inspect graph state:

```bash
./bin/cerebro graph health
./bin/cerebro graph counts
./bin/cerebro graph relation-counts
./bin/cerebro graph integrity
./bin/cerebro graph paths limit=10
./bin/cerebro graph neighborhood <root-urn> limit=10
```

Ingest from a source directly:

```bash
./bin/cerebro graph ingest <source-id> tenant_id=<tenant-id> page_limit=1 key=value
```

Ingest from a persisted runtime:

```bash
./bin/cerebro graph ingest-runtime <runtime-id> page_limit=100
```

Inspect ingest runs:

```bash
./bin/cerebro graph ingest-runs runtime_id=<runtime-id> limit=20
./bin/cerebro graph ingest-run <run-id>
```

Preview rebuild behavior:

```bash
./bin/cerebro graph rebuild <runtime-id> dry_run=true mode=replay event_limit=100 preview_limit=10
```

## HTTP routes

Graph HTTP routes live under `/platform/graph/*`. Legacy `/graph/*` aliases have been removed.

Common routes:

```text
GET /platform/graph/neighborhood?root_urn=<urn>&limit=10
GET /platform/graph/impact/vulnerability/{id}?tenant_id=<tenant-id>
GET /platform/graph/impact/package?tenant_id=<tenant-id>&package=<name-or-purl>
GET /platform/graph/impact/asset?urn=<urn>
GET /platform/graph/person-access-paths?tenant_id=<tenant-id>&person_urn=<urn>
GET /platform/graph/attack-paths?tenant_id=<tenant-id>&limit=10
GET /platform/graph/crown-jewel-rankings?tenant_id=<tenant-id>
GET /platform/graph/aws-public-endpoint-insights?tenant_id=<tenant-id>
GET /platform/graph/ingest-health
GET /platform/graph/ingest-runs
GET /platform/graph/ingest-runs/{runID}
POST /source-runtimes/{runtimeID}/graph-ingest-runs
```

When auth is enabled, include a valid credential:

```bash
curl -fsS \
  -H "Authorization: Bearer ${CEREBRO_API_KEY}" \
  "https://cerebro.example.com/platform/graph/ingest-health"
```

## Graph health

Run:

```bash
./bin/cerebro graph health
```

Use it to check:

- graph store connectivity,
- basic counts,
- topology,
- integrity checks,
- recent ingest failures,
- stale-running ingest runs,
- zero-projection ingest runs,
- missing declared runtimes when supplied.

Example with runtime expectations:

```bash
./bin/cerebro graph health declared_runtime_id=<runtime-id> ingest_limit=20
```

Treat graph health failures as projection or graph dependency incidents, not necessarily API process incidents.

## Ingest options

Direct source ingest:

```bash
./bin/cerebro graph ingest <source-id> \
  tenant_id=<tenant-id> \
  page_limit=100 \
  checkpoint=true \
  checkpoint_id=<checkpoint-id> \
  key=value
```

Runtime ingest:

```bash
./bin/cerebro graph ingest-runtime <runtime-id> \
  page_limit=100 \
  checkpoint_id=<checkpoint-id>
```

Looping runtime ingest:

```bash
./bin/cerebro graph ingest-runtime <runtime-id> \
  page_limit=100 \
  interval=30s \
  iterations=10
```

Use `iterations=forever` only under a process manager that handles restarts, logs, and termination.

Limits:

- default graph ingest page limit is `1`,
- maximum page limit is `100`,
- interval is required when iterations are greater than `1` or forever.

## Rebuilds

Use rebuilds to preview or reconstruct graph projection from runtime data.

Dry-run from append-log replay:

```bash
./bin/cerebro graph rebuild <runtime-id> \
  dry_run=true \
  mode=replay \
  event_limit=100 \
  preview_limit=10
```

Dry-run from source reads:

```bash
./bin/cerebro graph rebuild <runtime-id> \
  dry_run=true \
  mode=source \
  page_limit=10 \
  preview_limit=10
```

Operational rules:

1. Start with `dry_run=true`.
2. Keep preview limits small.
3. Confirm the target runtime and tenant.
4. Confirm source sync or append-log replay data exists.
5. Run during a low-risk window if the rebuild will write.

## Cleanup and repair commands

The CLI includes graph cleanup and repair commands for specific projection hygiene cases. They default to dry-run behavior where applicable.

Examples:

```bash
./bin/cerebro graph cleanup-projected-entities tenant_id=<tenant-id> dry_run=true
./bin/cerebro graph cleanup-endpoint-owner-id-links tenant_id=<tenant-id> dry_run=true
./bin/cerebro graph repair-open-finding-primary-links dry_run=true
```

Do not run write-mode cleanup broadly until you have reviewed dry-run output and have a rollback or rebuild plan.

## Query limits and safety

Cerebro is not a general-purpose graph database product. Graph routes and graph-agent behavior are bounded by the current API and non-goals:

- prefer platform routes over raw Cypher,
- keep traversal limits small,
- use tenant-scoped routes,
- validate URNs and tenant hints,
- monitor query latency,
- set `CEREBRO_NEO4J_QUERY_TIMEOUT` when needed.

See [`docs/NON_GOALS.md`](./NON_GOALS.md) before expanding graph storage shape, traversal depth, or public graph query surface.

## Observability

Track:

- graph health status,
- graph node and relation counts,
- failed ingest runs,
- stale-running ingest runs,
- zero-projection ingest runs,
- graph query latency,
- graph query timeouts,
- Neo4j connection errors,
- storage growth,
- index health.

Correlate graph ingest issues with source runtime sync status. If a source runtime has not advanced, graph projection may be stale even when Neo4j is healthy.

## Troubleshooting quick map

| Symptom | First check |
| --- | --- |
| graph command says store is required | `CEREBRO_GRAPH_STORE_DRIVER`, `CEREBRO_NEO4J_URI`, credentials |
| graph query times out | `CEREBRO_NEO4J_QUERY_TIMEOUT`, query limit, database load |
| no nodes after ingest | source emitted events, projection support, ingest run status |
| stale graph | source runtime sync cursor, graph ingest schedule, failed runs |
| tenant data missing | tenant parameter, credential tenant scope, runtime tenant |
| impact route returns not found | URN or vulnerability/package identifier, prerequisite projection |
| cleanup command looks too broad | stop at dry-run and add narrower filters |
