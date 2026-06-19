# Cerebro Headroom and Capacity Guardrails

This document defines how Cerebro operators keep enough spare capacity to absorb traffic spikes, source-runtime catch-up, graph ingest bursts, dependency slowness, and deploy churn without user-visible choking. It is intentionally portable: this public repo owns the runtime contract, telemetry shape, smoke tooling, and operator checklist. Environment-specific replica counts, hostnames, account IDs, stack config, and autoscaling resources live in deployment repositories.

Use this with:

- [`docs/operations/observability.md`](observability.md) for OTEL, structured telemetry, and wide-event contracts.
- [`docs/operations/operations-runbook.md`](operations-runbook.md) for startup, readiness, dependency, rollout, rollback, and incident basics.
- [`docs/reference/config-env-vars.md`](../reference/config-env-vars.md) for runtime knobs.
- [`docs/operations/deployment-examples.md`](deployment-examples.md) for portable hosting patterns.
- [`scripts/load_smoke.py`](../../scripts/load_smoke.py) and `make load-smoke` for bounded live checks.

## Principles

1. **Headroom is a product property, not an instance property.** CPU, memory, replicas, database pools, append-log lag, graph write latency, source provider rate limits, and downstream LLM latency all count.
2. **Scale on pressure, not only CPU.** CPU can look healthy while requests queue behind Postgres, JetStream, Neo4j, Redis/Valkey, source providers, or outbound LLM calls.
3. **Page on user-visible or data-loss risk.** Warnings should create tickets or Slack noise; pages should map to degraded readiness, sustained 5xx, saturation at max replicas, data freshness risk, or unrecoverable queue growth.
4. **Every top-level unit of work needs one queryable wide event.** `main=true` and `wide_event=true` are the starting point for incident slicing.
5. **Release checks should prove margin.** A release that merely starts is not enough. It should pass bounded smoke under small concurrency and preserve latency/error budgets.
6. **Be explicit about freshness.** Source runtime and graph freshness are capacity signals. A quiet HTTP surface can still be unhealthy when sync, replay, or projection falls behind.

## Capacity SLOs

These are default budgets for a shared Cerebro deployment. Tighten them for user-facing production, loosen them for single-user development, and document environment-specific overrides in the deployment repo.

| Layer | Steady target | Warning | Critical/page | Why it matters | First action |
| --- | --- | --- | --- | --- | --- |
| HTTP availability | `99.9%` successful non-maintenance requests | 5xx rate above `0.25%` for 10m | 5xx rate above `1%` for 5m or `/health` 503 for 5m | Users and agents feel this immediately | Check recent deploy, dependency health, and per-route wide events |
| HTTP p95 latency | below `500ms` for light routes, route-specific for heavy graph/source routes | p95 above `750ms` for 10m | p95 above `1500ms` for 5m or p99 above timeout budget | Latency usually rises before errors | Slice by `http.route`, status, version, replica, and dependency counters |
| Replica CPU | below `70%` average with no single replica pinned | above `80%` for 15m | above `90%` for 5m, or CPU throttling with latency | CPU saturation elongates all work | Add replicas, raise task CPU, or reduce background concurrency |
| Replica memory | below `70%` working set | above `80%` for 15m | above `90%`, OOM kill, or restart loop | Memory pressure causes retries and cold starts | Scale out/up, inspect heap/goroutines, reduce payload/concurrency |
| Request concurrency | queueing stays flat; in-flight below `70%` of worker capacity | sustained in-flight growth | in-flight remains high while RPS is flat or falling | Queueing means capacity is gone even before errors | Scale out and find the slow route/dependency |
| Postgres pool | wait count near zero, idle connections available | wait duration rising for 10m | pool exhausted, health degraded, or write errors | Durable runtime, claims, findings, OAuth, and reports depend on it | Increase pool/DB capacity or reduce request/background concurrency |
| Redis/Valkey cache | low error rate, stable latency, hit ratio within baseline | miss spike or latency above baseline | cache unavailable plus DB/LLM pressure | Cache failures amplify expensive reads | Verify cache health, namespace, payload caps, and fallback load |
| NATS JetStream | consumer lag drains faster than it grows | lag grows for 15m or storage pressure | lag grows for 30m, append failures, stream storage critical | Replay and runtime sync durability depend on it | Pause producers, scale consumers, inspect stream limits/storage |
| Neo4j/Aura | graph reads/writes within route budgets | query latency or timeouts rising | graph health degraded, write failures, stale ingest | Graph projection/query and agent context depend on it | Identify read vs write saturation, reduce ingest, check Aura capacity |
| Source runtime freshness | runtime-specific lag below freshness expectation | lag above expectation for 1 interval | lag above expectation for 3 intervals or lease churn | Quiet sync failure silently erodes data quality | Check provider rate limits, leases, runtime errors, append-log health |
| Graph ingest freshness | ingest runs complete and freshness advances | stale-running runs or zero projections | repeated failures or stale graph-dependent workflows | Findings/impact paths can become misleading | Run ingest health, pause broad rebuilds, inspect failed runtime |
| Outbound providers/LLMs | provider errors within baseline | latency/error spike by provider/model/source | provider outage blocks core workflow | External saturation can look like app saturation | Fail closed, reduce concurrency, switch provider/model if configured |
| Deployment rollout | new version reaches readiness inside rollout window | slow readiness or one replica unhealthy | max unavailable exceeded or rollback required | Deploy churn consumes headroom | Pause rollout, compare `service.version`, rollback if needed |

## Dashboards

Every shared Cerebro environment should have a dashboard with these sections. The exact backend can be Prometheus, CloudWatch, Grafana, Datadog, Honeycomb, Sentry, or an OTEL collector pipeline, but the dimensions should stay stable.

### 1. Executive Headroom Strip

Show this at the top:

- Current availability and 5xx rate.
- HTTP p50/p95/p99 by route.
- Request rate by route and status class.
- Replica count, desired count, max count, CPU, memory, restart count.
- `/health` status and dependency readiness status.
- Source runtime freshness summary.
- Graph ingest health summary.
- Postgres pool wait and DB CPU/storage.
- JetStream lag/storage.
- Neo4j/Aura latency/error/freshness.
- Last deploy version and deploy age.

### 2. HTTP Pressure

Panels:

- `rate(cerebro_http_requests_total[5m])` by `route`, `method`, `status_code`.
- 5xx rate by `route`.
- Average latency from `/metrics` using `cerebro_http_request_duration_seconds_sum` divided by `cerebro_http_request_duration_seconds_count`.
- Tail latency from OTEL histogram `cerebro.http.server.request.duration` when exported to a backend that supports quantiles.
- Top routes by request body size and response body size from wide events.
- Top routes by `url.query.keys` and `user_agent.family` when traffic shape changes.

### 3. Dependency Pressure

Panels:

- Postgres open, idle, in-use, wait count, wait duration, query errors, slow queries, locks, storage, CPU.
- Redis/Valkey command latency, error rate, hit/miss counts, evictions, memory pressure.
- JetStream append failures, replay failures, consumer lag, stream bytes/messages, storage pressure.
- Neo4j/Aura read/write duration, timeout count, connection failures, transaction retries, graph ingest failures.
- Source provider error rate by `source_id`, `runtime_id`, upstream status class, and bounded `error_kind`.
- Graph-agent/LLM duration and error rate by provider, model, operation, and refusal/outcome.

### 4. Background Work and Freshness

Panels:

- Source runtime sync attempts, success/failure, duration, page/event counts, lease acquisition/renewal failures.
- Runtime freshness by `tenant_id`, `source_id`, and `runtime_id`.
- Graph ingest run status, age of oldest running ingest, projection counts, zero-projection runs.
- Finding evaluation run duration/error/candidate counts.
- Workflow replay request count, duration, event count, and failure kind.

### 5. Version and Rollout Correlation

Panels:

- Error rate grouped by `service.version`.
- p95 latency grouped by `service.version`.
- Request count grouped by replica/task/container ID.
- Restarts and readiness failures by version.
- Deploy age distribution.

These version panels answer "did something just go out?" without leaving the observability tool.

## Alert Policy

Default routing:

- **Page** when user-visible availability is degraded, data freshness is at risk, a durable dependency is failing, or the service is saturated at max capacity.
- **Ticket or Slack warning** when a trend will become a page if ignored, such as rising latency, rising pool wait, or source runtime lag.
- **No alert** for one-off dependency blips that recover inside the retry/backoff window and do not burn error budget.

Suggested alerts:

| Alert | Severity | Window | Condition | Triage anchor |
| --- | --- | --- | --- | --- |
| `CerebroHealthDegraded` | page | 5m | `/health` returns 503 or readiness fails | `/health`, dependency panel |
| `CerebroHigh5xxRate` | page | 5m | 5xx rate above `1%` and request volume above low-traffic floor | wide events by `http.route`, `service.version` |
| `CerebroLatencySaturation` | page | 10m | p95/p99 above route budget and RPS not dropping to zero | latency heatmap by route/version/replica |
| `CerebroAtMaxReplicas` | page | 10m | desired replicas equals max and CPU/memory/concurrency/queue pressure remains high | autoscaler and platform metrics |
| `CerebroPostgresPoolSaturated` | page | 5m | pool wait rises and request latency/errors rise | Postgres pool panel, `db.postgres.*` fields |
| `CerebroJetStreamLagGrowing` | page | 30m | consumer lag grows faster than drain rate | JetStream lag, source runtime freshness |
| `CerebroGraphIngestStale` | page | 30m | graph ingest failures or stale-running runs | graph ingest health and `graph.ingest.*` |
| `CerebroSourceFreshnessBreached` | page/ticket by source | source-specific | runtime lag exceeds freshness expectation | `source_runtime.*`, provider errors |
| `CerebroProviderErrorSpike` | ticket/page if core | 15m | source provider or LLM errors exceed baseline | `source_id`, provider/model, `error_kind` |
| `CerebroRestartsOrOOM` | page | 5m | restart loop, OOM kill, crash-loop, SIGKILL | container/task events and runtime memory |
| `CerebroLoadSmokeFailed` | page/ticket by env | one run | scheduled live load smoke fails thresholds | workflow artifact JSON/Markdown |

Use multi-window burn-rate alerts for high-traffic environments:

- Fast burn: 5xx/error budget burn over 5m and 30m.
- Slow burn: 5xx/error budget burn over 1h and 6h.
- Low-traffic floor: require enough requests to avoid paging on one request.

Example alert queries live in [`docs/operations/observability/headroom-alerts.promql`](observability/headroom-alerts.promql). Treat them as templates: adapt label names and platform metric names to the deployed collector.

## Autoscaling

Autoscaling should combine platform metrics and application pressure. CPU-only scaling misses important Cerebro failure modes.

Recommended scaling signals:

| Signal | Scale out when | Scale in when | Notes |
| --- | --- | --- | --- |
| CPU utilization | above `65-70%` for 5m | below `35%` for 30m | Keep scale-in slower than scale-out |
| Memory utilization | above `70-75%` for 10m | below `45%` for 30m | Use max memory, not only average, when replicas differ |
| Request concurrency | in-flight per replica above target for 5m | below target for 30m | Requires platform/LB/app metric |
| HTTP latency | p95 above route budget and RPS stable | below budget for 30m | Do not scale solely on latency if dependency is clearly saturated |
| JetStream lag | lag growing for 10m | lag drains and stays low for 30m | Scale consumers/background workers, not necessarily API replicas |
| Source runtime backlog | lag above freshness expectation | lag drains | Avoid stampeding provider rate limits |
| Postgres pool wait | wait duration rising | wait near zero | If DB is saturated, scale the DB or reduce app concurrency instead of adding app replicas |
| Graph ingest queue/failures | ingest age/failures rise | stable completion | Scale graph workers only if graph backend has room |

Guardrails:

- Keep at least two healthy replicas for shared deployments, unless the platform is explicitly single-user.
- Set max replicas high enough to absorb normal peaks, but low enough to protect Postgres, JetStream, Neo4j, and provider APIs.
- Use pod/task disruption budgets or equivalent so maintenance does not remove all headroom.
- Keep scale-in cooldowns long enough to avoid oscillation during source sync and graph ingest bursts.
- Pin background concurrency per replica so scaling out does not multiply provider/API pressure beyond limits.
- During incidents, prefer temporary max-replica increases only when dependencies have room.

## Load Smoke Testing

`make load-smoke` runs a bounded HTTP smoke using only Python's standard library. It is not a replacement for full load testing. It is a release and environment confidence check that answers:

- Can a live Cerebro origin serve repeated requests without immediate 5xx?
- Is p95 latency inside the configured smoke threshold?
- Do protected routes still work when a bearer token is supplied?
- Did a recent deploy or infra change remove obvious headroom?

Default local usage:

```bash
make load-smoke CEREBRO_BASE_URL=http://127.0.0.1:8080
```

Shared environment usage:

```bash
CEREBRO_LOAD_SMOKE_BEARER_TOKEN="${CEREBRO_API_KEY}" \
make load-smoke \
  CEREBRO_BASE_URL=https://cerebro.example.com \
  LOAD_SMOKE_PATHS="/health /livez" \
  LOAD_SMOKE_DURATION=60 \
  LOAD_SMOKE_RPS=3 \
  LOAD_SMOKE_CONCURRENCY=6 \
  LOAD_SMOKE_MAX_P95_MS=750 \
  LOAD_SMOKE_MAX_ERROR_RATE=0.01
```

Outputs:

- `tmp/load-smoke.json`: machine-readable summary with request counts, latency percentiles, status counts, and threshold failures.
- `tmp/load-smoke.md`: human-readable artifact for release notes, incidents, or PR comments.

The GitHub Actions workflow [`load-smoke.yml`](../../.github/workflows/load-smoke.yml) supports:

- daily scheduled execution when `CEREBRO_LOAD_SMOKE_BASE_URL` is configured as a repository secret;
- manual `workflow_dispatch` with `base_url`, duration, RPS, concurrency, and p95 threshold inputs;
- optional `CEREBRO_LOAD_SMOKE_BEARER_TOKEN` secret for protected paths;
- uploaded JSON and Markdown artifacts.

Recommended release gate:

1. Deploy canary or first production task.
2. Run `make load-smoke` against `/health` and one protected cheap route.
3. Confirm p95, error rate, 5xx rate, readiness, and dependency dashboards.
4. Continue rollout only if the smoke passes and dependency headroom remains inside target.

## CI and Test Coverage

The repo-level checks now include `make script-test`, which runs unit tests for Python utility scripts, including `scripts/load_smoke.py`.

Coverage expectations:

- **Unit tests**: scheduling, success/failure thresholds, latency threshold failure, URL safety.
- **CI**: `make script-test` on every PR and push through the `script-test` shard.
- **Scheduled smoke**: daily live smoke when secrets are present.
- **Release smoke**: manual or automated `make load-smoke` after deploy/canary.
- **Game day**: intentionally lower task CPU/memory or inject dependency latency in a non-prod stack, then verify alerts fire and runbook steps work.

Do not put live-environment smoke into required PR CI. PRs should not depend on private hostnames, credentials, or account state.

## Wide Events for Headroom

Cerebro's wide-event convention comes from the "one top-level unit of work with many queryable dimensions" pattern. Use `main=true` and `wide_event=true` to find the canonical event, then slice by route, version, source, runtime, tenant, dependency, and outcome.

Headroom-relevant fields that should be present where safe:

| Field family | Examples | Use |
| --- | --- | --- |
| Unit-of-work marker | `main`, `wide_event`, `component`, `operation` | Find the canonical event quickly |
| Service/deploy | `service.name`, `service.version`, `deployment.environment.name`, `service.build.git_hash` | Correlate incidents with deploys |
| Runtime host | `host.name`, `container.id`, `cloud.region`, `cloud.availability_zone`, `instance.cpu_count`, `instance.memory_mb` | Explain replica-specific saturation |
| HTTP shape | `http.route`, `http.request.method`, `http.response.status_code`, `duration_ms`, `http.request.body.size`, `http.response.body.size` | Identify route and payload pressure |
| Caller/client | `tenant_id`, `auth.mode`, `auth.outcome`, `user_agent.family`, `client.address_hash` | Scope to tenant/client segments without leaking secrets |
| Store counters | `db.postgres.*.count`, `cache.redis.*.count`, `db.neo4j.*.count` | Identify dependency fan-out |
| Messaging counters | `messaging.jetstream.*.count`, replay counts, append counts | Explain queue and durability pressure |
| Source runtime | `source_runtime.*`, `source_id`, `runtime_id`, event/page counts, lease outcome | Debug freshness and provider pressure |
| Graph ingest | `graph.ingest.*`, projection counts, failure counts | Debug graph staleness and write pressure |
| LLM/provider | `gen_ai.provider.name`, `gen_ai.request.model`, `gen_ai.operation.name`, bounded outcome/error kind | Separate model/provider slowness from app slowness |
| Errors | `error_kind`, `error_fingerprint`, `handled`, bounded component/operation | Group safely without raw error leakage |

Useful queries:

```sql
-- Which routes are slow right now?
SELECT P95(duration_ms), COUNT(*)
WHERE main = true AND service.name = "cerebro"
GROUP BY http.route
ORDER BY P95(duration_ms) DESC
```

```sql
-- Did the newest version introduce errors?
SELECT COUNT(*)
WHERE main = true AND service.name = "cerebro"
GROUP BY service.version, http.response.status_code
```

```sql
-- Is one dependency fan-out pattern causing tail latency?
SELECT P99(duration_ms), MAX(db.postgres.query.count), MAX(db.neo4j.write.count), MAX(messaging.jetstream.append.count)
WHERE main = true AND http.route = "/source-runtimes/{runtimeID}/sync"
GROUP BY source_id, runtime_id
ORDER BY P99(duration_ms) DESC
```

```sql
-- Which runtime/source is falling behind?
SELECT COUNT(*), P95(duration_ms)
WHERE main = true AND source_runtime.sync.outcome != "success"
GROUP BY tenant_id, source_id, runtime_id, error_kind
```

```sql
-- Is graph ingest pressure tied to zero-projection runs?
SELECT COUNT(*), P95(duration_ms)
WHERE main = true AND graph.ingest.run.count > 0
GROUP BY service.version, graph.ingest.outcome, graph.ingest.zero_projection
```

## Saturation Incident Runbook

Use this when Cerebro "feels choked": slow requests, readiness flaps, source/runtime lag, graph staleness, queue growth, or dependency pool exhaustion.

### First 5 Minutes

1. Check whether `/livez` fails, `/health` fails, or only specific routes are slow.
2. Check 5xx rate, p95/p99 latency, request rate, and current replica count.
3. Confirm whether a deploy, config change, secret rotation, dependency migration, or source schedule change just happened.
4. Slice wide events by `http.route`, `service.version`, `tenant_id`, `source_id`, `runtime_id`, and `error_kind`.
5. Check Postgres pool wait, JetStream lag, Neo4j/Aura health, Redis/Valkey health, and provider/LLM error panels.
6. If the service is at max replicas and dependencies have room, raise max replicas or task size.
7. If a dependency is saturated, avoid blindly adding app replicas; reduce background concurrency, pause broad sync/ingest/rebuild work, or scale the dependency.

### First 15 Minutes

1. Decide whether the incident is HTTP, source runtime, graph, append-log, state-store, cache, provider, or deploy-specific.
2. If deploy-specific, pause rollout and compare old/new `service.version` in wide events.
3. If source-runtime-specific, pause or lower cadence for the offending runtime and keep other runtimes running.
4. If graph-ingest-specific, pause broad rebuilds and keep read-only graph health checks running.
5. If Postgres pool waits are high, reduce app/background concurrency before increasing replicas.
6. If JetStream lag is growing, identify producers and consumers; scale consumers only if storage and downstream stores have room.
7. If Redis/Valkey is down, estimate cache miss amplification into Postgres, LLM, or graph queries.
8. If provider or LLM latency is the cause, reduce concurrency and use configured fallback/provider routing when available.

### Mitigation Choices

| Symptom | Safer mitigation | Risky mitigation |
| --- | --- | --- |
| CPU high, dependencies healthy | add replicas or task CPU | only raising timeouts |
| memory high/OOM | add memory, inspect heap/payloads, reduce concurrency | retrying failing requests aggressively |
| Postgres pool wait high | reduce app/background concurrency, tune pool/DB capacity | adding many replicas |
| JetStream lag growing | scale consumers carefully, pause noisy producers | increasing producer concurrency |
| graph writes slow | reduce ingest/rebuild concurrency, check Aura capacity | broad graph rebuild during incident |
| one source provider rate-limited | pause/lower that runtime schedule | global service restart |
| new version errors | pause/rollback deploy | scaling broken code |

### After Recovery

1. Save the dashboard time range, load-smoke artifact, and representative trace/log links.
2. Record the lowest observed headroom: max CPU/memory, max pool wait, max lag, max p95/p99, max replicas, and dependency bottleneck.
3. Add or adjust an alert if the incident was detected by humans before automation.
4. Add or adjust a wide-event field if the first useful query required guessing.
5. Update environment-specific autoscaling limits and background concurrency.
6. Run `make load-smoke` against the recovered environment and attach the artifact to the incident or release notes.

## Capacity Planning

Run this weekly for shared deployments and before major source onboarding:

1. Review p95/p99 latency by route for the last 7 and 30 days.
2. Review peak RPS, peak replica count, CPU/memory max, and scale-out time.
3. Review Postgres pool wait, slow queries, locks, storage growth, and CPU.
4. Review JetStream lag/storage and replay throughput.
5. Review Neo4j/Aura query duration, ingest duration, graph size, and failed/stale runs.
6. Review top source runtimes by duration, event count, provider errors, and freshness lag.
7. Review cache hit ratio, miss amplification, evictions, and payload rejection counts.
8. Compare actual peak load with configured max replicas and dependency limits.
9. Run a controlled non-prod load smoke or scenario test against the next planned source/runtime shape.
10. File capacity work before warnings become pages.

Planning questions:

- What is the expected peak RPS for the next 30 days?
- What is the expected source-runtime event/page volume by source?
- Which runtime has the lowest freshness margin?
- Which dependency saturates first when RPS doubles?
- Which dependency saturates first when source sync doubles?
- How long does scale-out take from alert threshold to healthy capacity?
- Are max replicas and DB/JetStream/Neo4j/provider limits aligned?
- Can we roll back without replay or graph-rebuild amplification?

## Environment Handoff

Deployment repositories should carry the concrete answers for each environment:

- min/desired/max replicas;
- task/container CPU and memory;
- autoscaling target metrics and cooldowns;
- Postgres class, storage, pool limits, and alert thresholds;
- Redis/Valkey class/memory and alert thresholds;
- JetStream storage/retention/consumer limits and alert thresholds;
- Neo4j/Aura tier and graph ingest concurrency;
- source-runtime schedule volumes and freshness expectations;
- live load-smoke target URL and token secret names;
- alert destinations and escalation policy.

Keep those values out of this public runtime repo unless they are generic examples. Link back to this document so every deployment keeps the same operating contract.
