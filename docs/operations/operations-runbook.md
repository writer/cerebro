# Operations Runbook

This runbook is for operators hosting the public Cerebro bootstrap service. It is based on the current Go runtime, public CLI, public HTTP routes, and release artifacts in this repository. It intentionally avoids environment-specific hostnames, account IDs, tenant names, schedules, secret paths, and rollout processes.

Use it with:

- [`docs/operations/hosting.md`](hosting.md) for the hosting baseline.
- [`docs/operations/deployment-examples.md`](deployment-examples.md) for portable deployment patterns.
- [`docs/operations/troubleshooting.md`](troubleshooting.md) for symptom-driven debugging.
- [`docs/operations/headroom.md`](headroom.md) for capacity SLOs, saturation alerts, autoscaling signals, load-smoke gates, and capacity incident playbooks.
- [`docs/reference/config-env-vars.md`](../reference/config-env-vars.md) for current environment variables.
- [`api/openapi.yaml`](../../api/openapi.yaml) for the HTTP route contract.

## Operating model

Cerebro currently operates as one HTTP service plus optional backing stores:

| Runtime profile | Backing stores | Operational responsibility |
| --- | --- | --- |
| Lightweight API | none | keep the process alive and serve public catalog/health/API metadata routes |
| Durable API | Postgres | preserve runtime, claim, finding, report, OAuth, and device-auth state |
| Durable sync | Postgres plus NATS JetStream | preserve runtime state and replayable append-log events |
| Graph-enabled | Postgres plus NATS JetStream plus Neo4j or Aura | preserve runtime state, append-log events, and graph projection/query state |

The implementation is intentionally fail-closed for missing required dependencies. Operations that require a store should return a clear unavailable or dependency error when the store is not configured, rather than silently switching to volatile storage.

## First checks

Run these checks whenever an instance starts, restarts, or is promoted behind a load balancer:

```bash
curl -fsS http://127.0.0.1:8080/livez
curl -fsS http://127.0.0.1:8080/health
curl -fsS http://127.0.0.1:8080/openapi.yaml >/dev/null
```

If API auth is enabled, use an authenticated request for protected routes:

```bash
curl -fsS \
  -H "Authorization: Bearer ${CEREBRO_API_KEY}" \
  "https://cerebro.example.com/source-runtimes?limit=1"
```

Use `GET /livez` or `GET /healthz` for liveness. Use `GET /health` for readiness, because it is dependency-aware.

## Health and readiness

| Route | Auth | Meaning | Operator action |
| --- | --- | --- | --- |
| `GET /livez` | public | process is serving HTTP | restart only if this fails repeatedly |
| `GET /healthz` | public | liveness alias | same as `/livez` |
| `GET /health` | public | dependency-aware readiness | remove from traffic if degraded |
| `GET /metrics` | protected when auth is enabled | Prometheus-style runtime metrics | scrape only from trusted networks |
| `GET /source-runtimes/health` | protected | source runtime health summary | use for sync and source health dashboards |
| `GET /platform/graph/ingest-health` | protected | graph ingest health summary | use for graph freshness dashboards |
| `GET /platform/graph/ingest-runs` | protected | graph ingest run history | use during graph incidents |

`/health` returns HTTP `503` when the service is alive but a configured dependency is degraded. That should block readiness, but should not by itself force a process restart.

## Startup checklist

1. Confirm the image tag or binary version you intended to run.
2. Confirm `CEREBRO_HTTP_ADDR` matches the container or service port.
3. Confirm `CEREBRO_SHUTDOWN_TIMEOUT` is long enough for your platform's termination grace period.
4. Confirm `CEREBRO_API_AUTH_ENABLED=true` for shared deployments.
5. Confirm at least one auth mechanism is configured when API auth is enabled.
6. Confirm `CEREBRO_PUBLIC_ORIGIN` matches the HTTPS origin clients use.
7. Confirm trusted proxy CIDRs and hop count match the proxy topology.
8. Confirm Postgres config if durable state is expected.
9. Confirm NATS JetStream config if source sync or workflow replay is expected.
10. Confirm Neo4j or Aura config if graph operations are expected.
11. Confirm source runtime secrets are injected by the platform, not checked into files.
12. Confirm `/livez` succeeds.
13. Confirm `/health` succeeds for the selected runtime profile.
14. Confirm logs and metrics are being collected.

## Dependency checks

### Postgres

Postgres is required for durable source runtimes, claims, findings, evidence, evaluations, reports, MCP OAuth, and device-auth state.

Check:

- `CEREBRO_STATE_STORE_DRIVER=postgres`
- `CEREBRO_POSTGRES_DSN`
- TLS and network reachability from the Cerebro service
- connection pool settings if the database is connection-limited
- database storage, CPU, locks, and slow queries

Relevant variables:

- `CEREBRO_POSTGRES_MAX_OPEN_CONNS`
- `CEREBRO_POSTGRES_MAX_IDLE_CONNS`
- `CEREBRO_POSTGRES_CONN_MAX_LIFETIME`
- `CEREBRO_POSTGRES_CONN_MAX_IDLE_TIME`

### NATS JetStream

NATS JetStream is required for append-log-backed sync and replay.

Check:

- `CEREBRO_APPEND_LOG_DRIVER=jetstream`
- `CEREBRO_JETSTREAM_URL`
- `CEREBRO_JETSTREAM_STREAM_NAME`
- `CEREBRO_JETSTREAM_SUBJECT_PREFIX`
- stream storage and retention
- consumer lag
- disk pressure
- graceful drain timeout during rollout

Relevant variable:

- `CEREBRO_JETSTREAM_DRAIN_TIMEOUT`

If publish retries exhaust, check the recovery table before advancing runtime work:

```bash
./bin/cerebro append-log dead-letters stats
./bin/cerebro append-log dead-letters list status=pending limit=20
./bin/cerebro append-log dead-letters list subject=sec.findings.v1.recorded status=pending limit=20
```

After JetStream publish health is restored, replay one record:

```bash
./bin/cerebro append-log dead-letters replay <dead-letter-id>
```

Replay first claims the pending record with a two-minute ownership lease. A
concurrent operator receives `replay is already claimed`; wait for the lease
expiry reported by `list` before retrying. Failed publication releases the
claim and records the bounded `append_failed` category. A process that exits
while holding a claim leaves the record recoverable after lease expiry.

Discard a record only after confirming the event should not be replayed:

```bash
./bin/cerebro append-log dead-letters discard <dead-letter-id> reason=<reason>
```

Dead-letter IDs are deterministic for the subject, event ID, and payload. If the
same event exhausts again after an operator has replayed or discarded that
record, Cerebro preserves the terminal record and does not move it back to
`pending`.

Delete replayed or discarded records after the retention window:

```bash
./bin/cerebro append-log dead-letters cleanup terminal_before=2026-06-01T00:00:00Z actor=oncall@example.com reason=CHG-1234 limit=100
./bin/cerebro append-log dead-letters cleanup terminal_before=2026-06-01T00:00:00Z actor=oncall@example.com reason=CHG-1234 after_id=<next-after-id> limit=100
```

Each committed deletion has an audit row with the actor and reason. Cleanup
never selects pending records. Continue only when `has_more` is true, using the
returned `next_after_id` as `after_id`.

See [Append-log dead-letter data policy](append-log-dead-letter-policy.md) for
payload classification, retention, capacity limits, and emergency purge rules.

### Neo4j or Aura

Neo4j or Aura is required for graph projection, graph queries, graph health, graph ingest runs, impact queries, and graph-agent flows.

Check:

- `CEREBRO_GRAPH_STORE_DRIVER=neo4j`
- `CEREBRO_NEO4J_URI`
- `CEREBRO_NEO4J_USERNAME`
- `CEREBRO_NEO4J_PASSWORD`
- `CEREBRO_NEO4J_DATABASE`, when using a non-default database
- `CEREBRO_NEO4J_QUERY_TIMEOUT`, when graph reads need a bounded timeout

Run:

```bash
./bin/cerebro graph health
./bin/cerebro graph counts
./bin/cerebro graph ingest-runs limit=10
```

## Source runtime operations

Common runtime checks:

```bash
./bin/cerebro source list
./bin/cerebro source-runtime list tenant_id=<tenant-id> limit=20
./bin/cerebro source-runtime get <runtime-id>
curl -fsS -H "Authorization: Bearer ${CEREBRO_API_KEY}" \
  "https://cerebro.example.com/source-runtimes/health?limit=20"
```

Common sync operation:

```bash
./bin/cerebro source-runtime sync <runtime-id> page_limit=100
```

Operational guidance:

- Start new runtimes with a small `page_limit`.
- Use `page_limit=100` only after provider credentials, rate limits, and persistence are stable.
- Avoid two sync jobs for the same cursor-sensitive runtime unless the source and stores are known to handle concurrency safely.
- Treat provider rate limits and auth failures as source-specific incidents, not Cerebro process failures.
- Keep runtime IDs and schedules in your deployment system, not in public docs.

## Graph operations

Common graph checks:

```bash
./bin/cerebro graph health
./bin/cerebro graph counts
./bin/cerebro graph relation-counts
./bin/cerebro graph ingest-runs limit=20
```

Runtime-backed ingest:

```bash
./bin/cerebro graph ingest-runtime <runtime-id> page_limit=100
```

Dry-run rebuild:

```bash
./bin/cerebro graph rebuild <runtime-id> dry_run=true mode=replay event_limit=100 preview_limit=10
```

Operational guidance:

- Use `graph health` before and after enabling graph-dependent workflows.
- Use dry-run rebuilds before applying broad projection changes.
- Investigate failed, stale-running, or zero-projection ingest runs before increasing ingest cadence.
- Keep graph repair and cleanup commands in dry-run mode until you have reviewed their output.

### Cosmo hashed ID migration

Cosmo source and projection identities use collision-resistant hashed external
ID keys for `cosmo_session`, `cosmo_fact`, `cosmo_message`, and
`cosmo_survey_feedback` graph entities. This intentionally replaces the older
dash-normalized URN and event-ID suffixes that could collide when Cosmo record
IDs differed only by delimiters such as `:` and `/`.

When upgrading an environment that already ingested Cosmo data with the older
dash-normalized IDs:

1. Back up Neo4j/Aura and record current counts for tenant-scoped `cosmo_*`
   entities before rollout.
2. Deploy the new image and run one full Cosmo source sync plus graph rebuild
   for each Cosmo runtime. Keep rebuilds in dry-run mode first, then apply after
   reviewing the preview.
3. Compare the rebuilt `cosmo_*` entity counts and sample raw `record_id`,
   `key`, and `ticket_id` attributes against the pre-upgrade snapshot. These raw
   attributes are the reconciliation keys across the old and new URN shapes.
4. After the hashed entities are present and linked, run tenant-scoped graph
   cleanup for the old dash-normalized `cosmo_*` URNs. Review cleanup output in
   dry-run mode before deleting any legacy entities.
5. Do not roll back to an image that emits dash-normalized Cosmo IDs after
   legacy cleanup unless you restore the pre-cleanup graph snapshot or rebuild
   the graph from append-log history.

## Rollout

Before rollout:

1. Run local or CI validation for the release.
2. Record the image tag and config version.
3. Confirm all required secrets exist in the target runtime environment.
4. Confirm dependency migrations or schema expectations, if any, are documented for the release.
5. Confirm readiness and liveness routes are wired correctly.
6. Confirm rollback is image tag revert plus config revert, unless the release notes say otherwise.

During rollout:

1. Start with the smallest safe replica or percentage.
2. Wait for `/health` to pass.
3. Watch HTTP `5xx`, HTTP `4xx`, auth denials, dependency errors, and process restarts.
4. Watch Postgres connections, NATS stream health, and graph ingest errors.
5. Pause scheduled sync or graph jobs if dependency pressure increases.

After rollout:

1. Confirm all replicas run the expected version.
2. Confirm source runtime sync still advances.
3. Confirm graph ingest runs complete if graph is enabled.
4. Confirm dashboards and alerts receive new data.
5. Save the final image tag and config version in your deployment records.

## Rollback

Rollback should be boring:

1. Revert the image tag.
2. Revert config changes coupled to the new image.
3. Pause background jobs if they depend on the reverted behavior.
4. Wait for `/livez` and `/health`.
5. Run a representative source or graph smoke check.
6. Confirm error rates return to baseline.

If a release includes persistent storage or event-shape changes, read the release notes before rolling back. Do not assume arbitrary downgrade safety for stateful data.

## Incident triage

Use this sequence for most incidents:

1. **Scope**: process down, readiness degraded, one route failing, one tenant failing, one source failing, or graph only.
2. **Recent change**: image tag, config, secret, proxy, dependency, source provider, or schedule.
3. **Health**: `/livez`, `/health`, dependency dashboards.
4. **Auth**: `401`, `403`, tenant mismatch, scope mismatch, proxy stripped headers.
5. **State**: Postgres connectivity and connection saturation.
6. **Append log**: NATS connectivity, consumer lag, stream storage.
7. **Graph**: Neo4j connectivity, query timeout, ingest run status.
8. **Source**: provider credentials, rate limits, runtime config, cursor progress.

Escalate only after you can say which layer is failing.

For saturation or headroom incidents, immediately add:

1. Compare current replica count with configured max capacity.
2. Check CPU, memory, restart count, readiness failures, and request concurrency.
3. Check route-level 5xx, average latency from `/metrics`, and p95/p99 latency from OTEL if available.
4. Slice wide events with `main=true` by `http.route`, `service.version`, `tenant_id`, `source_id`, `runtime_id`, and bounded `error_kind`.
5. Check whether Postgres pool wait, JetStream lag, Neo4j/Aura latency, Redis/Valkey errors, source provider throttling, or LLM latency is the first saturated dependency.
6. If dependencies have room, scale Cerebro out or up. If a dependency is saturated, reduce app/background concurrency or pause the specific runtime/ingest/rebuild path before adding replicas.
7. After mitigation, run `make load-smoke` against the recovered origin and save `tmp/load-smoke.json` with the incident notes.

## Alert suggestions

Useful alerts for any shared deployment:

- process not serving `/livez`
- `/health` degraded for longer than a short rollout window
- sustained HTTP `5xx`
- sustained HTTP p95/p99 latency above the route budget
- API replicas at max capacity while CPU, memory, concurrency, or queue pressure remains high
- unusual HTTP `401` or `403` increase
- Postgres connection saturation
- Postgres query failures
- NATS JetStream unavailable
- NATS consumer lag or storage pressure
- graph ingest failure or stale-running runs
- source runtime sync failures
- repeated process restarts
- missing metrics scrape
- scheduled live load-smoke failure

Keep exact thresholds environment-specific. Use [`docs/operations/headroom.md`](headroom.md) and [`docs/operations/observability/headroom-alerts.promql`](observability/headroom-alerts.promql) as the portable baseline.
