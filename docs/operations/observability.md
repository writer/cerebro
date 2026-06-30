# Cerebro Observability

Cerebro emits three layers of operational signal:

- Prometheus-compatible counters and histograms on `GET /metrics`.
- Structured JSON telemetry lines on stderr for high-value spans and events.
- OpenTelemetry traces and metrics exported over OTLP when `CEREBRO_OTEL_*` is configured.

The structured JSON and OTEL spans share the same trace context where possible. HTTP responses include `X-Cerebro-Trace-Id` so operators can pivot from the web UI or API response to logs and traces.

For capacity SLOs, saturation dashboards, alert templates, autoscaling signals, and live load-smoke checks, use [`docs/operations/headroom.md`](headroom.md). This observability contract supplies the event and metric shape; the headroom guide defines how operators turn those signals into prevention, paging, and release gates.

## Wide Event Contract

Cerebro follows a wide-event model for request and job debugging. Each top-level
unit of work emits one canonical span/event with schema version `2026-06-18.2`
and:

- `main=true`
- `wide_event=true`
- `wide_event.schema.version`
- `telemetry.schema.version`, `telemetry.signal.kind`, `event.dataset`, `event.type`, `event.outcome`
- service, deployment, runtime, host, cloud, and container metadata
- ECS metadata when deployed on Fargate: `aws.ecs.cluster.name`, `aws.ecs.service.name`, `aws.ecs.task.family`, and `cloud.platform`
- process/headroom hints such as `process.uptime_ms`, `process.cpu.count`, `process.gomaxprocs`, `go.goroutine.count`, and Go heap/GC fields
- request/job shape
- auth/customer posture
- downstream cache, database, queue, graph, source, LLM, MCP, and domain counts
- final status, `operation.status`, `duration_ms`, `duration.bucket`, and bounded error kind

Use `main=true` as the primary query predicate when asking "what happened to
this request/job?" Child spans remain available for drill-down, but shared
service methods annotate the active main span so the first query has the full
shape.

During headroom incidents, start with `main=true`, then group by `http.route`,
`service.version`, replica/container identity, `tenant_id`, `source_id`,
`runtime_id`, `dependency.last_system`, `dependency.last_status`, `phase.last_name`,
`phase.last_status`, dependency counters, and bounded `error_kind`. That keeps the
first query broad enough to find saturation without jumping between logs,
metrics, traces, and deployment tooling.

Main spans include two generic rollup families:

- `dependency.*`: counts and last-seen status for Postgres, Neo4j, Redis, JetStream, outbound HTTP, and graph-agent LLM calls. Use this when you do not yet know which dependency is guilty.
- `phase.*`: counts and last-seen status for orchestration phases, source sync, graph ingest, GRC dashboard subtasks, and source operations. Use this when one logical job has several internal steps.

Platform jobs created through `/platform/jobs` emit a `platform.job.run` main
wide event. Treat it as the canonical envelope for async API-triggered work:
source sync, source orchestration, graph ingest, finding evaluation, reports,
and future durable job kinds. It carries the job id/kind/status, tenant,
subject, runtime/report pivots when present, queue latency, run duration,
cancel state, payload/result/ref key counts, sorted payload/result/ref key names,
bounded error kind/fingerprint, and lifecycle events such as
`platform.job.created`, `platform.job.started`, `platform.job.completed`,
`platform.job.failed`, and `platform.job.cancel_requested`. It intentionally
does not emit raw payload, result, idempotency key, or error strings.

Orchestrator wide events also carry interpreted source runtime health fields so
a single `orchestrator.run` span can explain whether work is blocked by source
sync, graph ingest, finding evaluation, or a backfill need:

- `source_runtime.family`, `source_runtime.enabled_state`, `source_runtime.freshness_state`, `source_runtime.source_sync_state`, `source_runtime.graph_ingest_state`, `source_runtime.finding_evaluation_state`
- `source_runtime.failure_class`, `source_runtime.next_action`, `source_runtime.backfill_eligible`
- `source_runtime.sync_lag_seconds`, `source_runtime.watermark_lag_seconds`, `source_runtime.graph_lag_seconds`, `source_runtime.expected_cadence_seconds`, `source_runtime.stale_after_seconds`
- `source_runtime.cursor_pending`, `source_runtime.checkpoint_cursor_present`, `source_runtime.contract_probe_state`, `source_runtime.contract_probe_status`
- `orchestrator.runtime.freshness.<state>.count`, `orchestrator.runtime.backfill_eligible.count`, and per-phase `phase.<phase>.last_duration_ms` / `phase.<phase>.max_duration_ms`

Inbound HTTP requests create a main OTEL `http.server` span. The route label is
normalized before emission. Unknown or dynamic paths are collapsed to route
families such as `/platform/jobs/{jobID}/events` or `/{unmatched}`. Query values,
authorization headers, cookies, request bodies, response bodies, DSNs, and raw
errors are not emitted.

Expected HTTP dimensions include:

- `http.request.method`, `http.route`, `http.route.family`, `http.route.healthcheck`, `url.path_depth`, `url.query.param_count`, `url.query.keys`
- `url.scheme`, `server.address`, `server.port`, `network.protocol.version`
- `http.request.body.size`, `http.request.id.present`, `http.request.id_hash`, selected safe request header values, header-presence booleans
- `user_agent.family`, `client.address_hash`
- `http.response.status_code`, `http.response.status_class`, `http.response.body.size`, selected safe response header values

Expected propagated dimensions include:

- Auth: `tenant_id`, `auth.outcome`, `auth.mode`, `auth.credential_tier`, `auth.risk_level`, `auth.denial_reason`
- MCP/OAuth: `mcp.method`, `mcp.tool`, `mcp.tool_family`, `mcp.outcome`, `oauth.operation`, `oauth.grant_type`
- GRC/LLM: `grc.ask.llm.provider`, `grc.ask.query_plan.intent`, `grc.ask.row_count`, stage timing fields
- Graph-agent LLM: `gen_ai.provider.name`, `gen_ai.operation.name`, `gen_ai.request.model`, `graphagent.*.count`, `graphagent.*.bytes`, refusal/plan/Cypher presence flags
- Stores: `cache.redis.*.count`, `db.postgres.*.count`, `db.neo4j.*.count`
- Messaging/source/graph: `messaging.jetstream.*.count`, `source_runtime.*`, `source.operation.*`, `graph.ingest.*`
- Cross-cutting rollups: `dependency.*`, `phase.*`
- Domain outcomes: `source_projection.*`, `finding_candidate.*`, `finding_evaluation.*`

Core runtime operations emit structured spans and diagnostic events:

| Span | Coverage |
| --- | --- |
| `source.http.request` | Hardened source HTTP transport, DNS safety checks, host pinning, retries, upstream status |
| `source.check`, `source.discover`, `source.read` | Source CDK operations |
| `platform.job.run` | Durable `/platform/jobs` execution envelope and lifecycle |
| `source_runtime.sync`, `source_runtime.sync_with_lease` | Runtime sync and lease lifecycle |
| `source_projection.project` | Per-event projection attempt, status, projected/deleted counts, and tenant/source/runtime drill-down fields |
| `graph_action.recorded` | Provider-backed graph action workflow linkage, provider/action identity, status, and reconciliation pivots |
| `graph.ingest_runtime` | Graph ingestion runs |
| `graphagent.http.request` | Graph-agent LLM/upstream HTTP calls |
| `graphagent.llm.draft`, `graphagent.llm.summarize`, `graphagent.llm.probe` | Graph-agent LLM operations, model/provider metadata, counts, sizes, and safe outcomes only |
| `postgres.ping`, `postgres.ensure_statements` | Postgres readiness and schema setup |
| `neo4j.read`, `neo4j.write` | Graph store transactions |
| `redis.cache.*`, `redis.ping` | Query cache operations, hits/misses, version bumps |
| `jetstream.ping`, `jetstream.append`, `jetstream.replay` | Append-log health, publish attempts/retries/acks, and replay |

Runtime contract diagnostics emit bounded events for deployment gates and
alarms:

| Event | Coverage |
| --- | --- |
| `source_runtime.contract_probe` | Contract-configured runtime probe status, with `contract_probe_status` in `success`, `failure`, `stale`, or `unknown` |
| `source_runtime.validation` | Terminal source event validation rejects, with bounded `failure_category` and `missing_canonical_field_class` |
| `runtime.evidence.link_status` | EvidenceCAS runtime evidence link rollup, with `link_status` in `linked`, `missing_resource`, `missing_case`, or `orphan` |

Outbound HTTP uses W3C `traceparent`. The source transport and graph-agent HTTP doer inject child trace context, but they do not emit full URLs, query strings, request bodies, authorization headers, or API keys. Graph-agent LLM spans also do not emit prompt text, completion text, raw Cypher, raw tool arguments, rows, or headers.

## Product OTEL Metrics

The app exports explicit low-cardinality OTEL metrics for the domain operations
that decide whether Cerebro is useful, not just reachable. These metrics are
safe to aggregate in CloudWatch, Prometheus, or a vendor backend.

| Metric | Unit | Primary dimensions | Meaning |
| --- | --- | --- | --- |
| `cerebro.http.server.requests` | `{request}` | `http.request.method`, `http.route`, `http.response.status_code` | API request rate and error-rate denominator |
| `cerebro.http.server.request.duration` | `s` | `http.request.method`, `http.route`, `http.response.status_code` | API latency distribution |
| `cerebro.source_runtime.sync.runs` | `{run}` | `source_id`, `status`, `error_kind`, `contract_configured` | Source sync success/failure rate |
| `cerebro.source_runtime.sync.duration` | `s` | `source_id`, `status`, `error_kind`, `contract_configured` | Source sync duration distribution |
| `cerebro.source_runtime.records` | `{record}` | `source_id`, `status`, `error_kind`, `contract_configured`, `record.kind` | Pages, scanned records, accepted/rejected events, appended events, and projected entities/links |
| `cerebro.source_runtime.watermark.lag` | `s` | `source_id`, `status`, `error_kind`, `contract_configured` | Observed source freshness lag when a checkpoint watermark exists |
| `cerebro.source_projection.runs` | `{projection}` | `source_id`, `event_kind`, `status` | Projection success/failure rate |
| `cerebro.source_projection.duration` | `s` | `source_id`, `event_kind`, `status` | Projection latency distribution |
| `cerebro.source_projection.records` | `{record}` | `source_id`, `event_kind`, `status`, `record.kind` | Graph/current-state records projected or deleted |
| `cerebro.graph_action.recorded` | `{action}` | `provider`, `action`, `status`, `external_status`, `dry_run` | Provider-backed graph actions successfully recorded into the workflow/event path |
| `cerebro.jetstream.publish.requests` | `{request}` | `subject`, `operation`, `status`, `error_category`, `max_attempts_exhausted` | Append-log publish success and failure counts by bounded subject and error category |
| `cerebro.jetstream.publish.retries` | `{retry}` | `subject`, `operation`, `status`, `error_category`, `max_attempts_exhausted` | Publish retry attempts by bounded subject and error category |
| `cerebro.jetstream.publish.duration` | `s` | `subject`, `operation`, `status`, `error_category`, `max_attempts_exhausted` | Publish ACK latency by bounded subject and outcome |
| `cerebro.jetstream.publish.max_attempts_exhausted` | `{request}` | `subject`, `operation`, `status`, `error_category`, `max_attempts_exhausted` | Publish requests that used every configured attempt |
| `cerebro.jetstream.replay.requests` | `{request}` | `strategy`, `status`, `error_category`, `subject_filter_present` | Append-log replay request count by scan strategy and outcome |
| `cerebro.jetstream.replay.duration` | `s` | `strategy`, `status`, `error_category`, `subject_filter_present` | Append-log replay latency by scan strategy and outcome |
| `cerebro.jetstream.replay.records` | `{record}` | `strategy`, `status`, `error_category`, `subject_filter_present`, `record.kind` | Replay records scanned, decoded, matched, missing, or returned |

Metric attributes deliberately exclude `tenant_id`, `runtime_id`, `resource_urn`,
`evidence_id`, `request_id`, and `trace_id`. Those identifiers remain available
in spans and wide events for drill-down, while metrics stay safe for aggregation
and alerting.

For source runtime, projection, and graph-action incidents, use the
low-cardinality metrics to find the failing `source_id`, `event_kind`,
`provider`, `action`, `status`, or `error_kind`, then pivot to structured
telemetry on `name="source_runtime.sync"`, `name="source_projection.project"`,
or workflow `graph_action.recorded` events. Those diagnostic events carry
`tenant_id`, `runtime_id`, finding IDs, and namespaced source/action fields for
per-tenant triage without turning tenant IDs into metric dimensions.

For JetStream append incidents, alert on `cerebro.jetstream.publish.requests`,
`cerebro.jetstream.publish.retries`, and
`cerebro.jetstream.publish.max_attempts_exhausted` grouped by `subject` and
`error_category`. Then pivot to `name="jetstream.append"` or
`name="jetstream.publish.retry_exhausted"` telemetry for `tenant_id`,
`runtime_id`, phase, retry count, and trace context. The checked-in alert
templates in [`docs/operations/observability/headroom-alerts.promql`](observability/headroom-alerts.promql)
include the dedicated `sec.findings.v1.recorded` + `no_response` page.

## Error Contract

Use `telemetry.CaptureError(ctx, name, err, attrs)` for Sentry-style handled errors. It emits:

- `name`: event name, usually `<component>.error`
- `error_kind`: bounded classification such as `context_deadline_exceeded`
- `error_fingerprint`: stable grouping hash
- `handled`: `true`
- caller-provided safe attributes such as `component`, `operation`, or `source_id`

Do not emit raw `error` fields or `err.Error()` in telemetry attributes. Driver errors often contain URLs, DSNs, or token-shaped values. The repository enforces this with `TestTelemetryFieldsDoNotUseRawErrorKey`.

## OTLP Configuration

Cerebro enables OTEL export when `CEREBRO_OTEL_ENABLED=true` or when an OTLP endpoint env var is set and `CEREBRO_OTEL_ENABLED` is unset.

| Env var | Purpose |
| --- | --- |
| `CEREBRO_OTEL_ENABLED` | Explicitly enable OTEL export |
| `CEREBRO_OTEL_SERVICE_NAME` | Overrides `service.name` |
| `CEREBRO_OTEL_EXPORTER_OTLP_PROTOCOL` | `http/protobuf` or `grpc` |
| `CEREBRO_OTEL_EXPORTER_OTLP_ENDPOINT` | Shared OTLP endpoint |
| `CEREBRO_OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` | Trace endpoint override |
| `CEREBRO_OTEL_EXPORTER_OTLP_METRICS_ENDPOINT` | Metric endpoint override |
| `CEREBRO_OTEL_EXPORTER_OTLP_HEADERS` | Comma-separated OTLP auth headers; mount from secrets only |
| `CEREBRO_OTEL_EXPORTER_OTLP_INSECURE` | Allow insecure transport only for loopback HTTP collectors, and only when a loopback OTLP endpoint is set |
| `CEREBRO_OTEL_TRACES_SAMPLE_RATE` | Float from `0` to `1` |
| `CEREBRO_OTEL_METRICS_EXPORT_INTERVAL` | Duration such as `30s` or `1m` |
| `OTEL_RESOURCE_ATTRIBUTES` | Standard resource attributes, for example `deployment.environment.name=production` |
| `CEREBRO_ENVIRONMENT` / `CEREBRO_DEPLOYMENT_ENVIRONMENT` | Environment value used by structured wide events |
| `AWS_REGION` / `AWS_DEFAULT_REGION` | AWS region used by structured wide events when running on ECS |
| `ECS_CLUSTER` / `ECS_SERVICE_NAME` / `ECS_TASK_FAMILY` / `ECS_TASK_REVISION` | Optional ECS identity used by structured wide events |

Structured wide events also read `OTEL_RESOURCE_ATTRIBUTES` so CloudWatch JSON
logs and exported OTEL spans share the same `service.namespace`,
`deployment.environment.name`, `cloud.provider`, `cloud.region`, and ECS dimensions.
The deployment-specific env vars take precedence over generic resource
attributes when both are present.

## Useful Queries

Start every incident with wide events only:

```sql
fields @timestamp, name, service.version, event.outcome, duration_ms, duration.bucket,
  http.route, runtime_id, source_id, tenant_id,
  dependency.last_system, dependency.last_status,
  phase.last_name, phase.last_status, error_kind
| filter wide_event = true and kind = "span_end"
| sort @timestamp desc
| limit 100
```

Find the dependency correlated with slow or failed work:

```sql
stats count(*) as events,
  pct(duration_ms, 95) as p95_ms,
  max(duration_ms) as max_ms
by dependency.last_system, dependency.last_status, service.version, deployment.environment.name
| sort p95_ms desc
```

Find the phase where orchestrator jobs are failing:

```sql
stats count(*) as events,
  sum(orchestrator.runtime.failed.count) as failed_runtimes,
  sum(source_runtime.invalid_event.count) as invalid_events
by phase.last_name, phase.last_status, source_id, runtime_id, error_kind
| sort events desc
```

Drill into tenant-level source runtime and projection failures:

```sql
fields @timestamp, name, trace_id, tenant_id, source_id, runtime_id, event_kind,
  status, error_kind
| filter (name = "source_runtime.sync" or name = "source_projection.project")
  and status = "failed"
| sort @timestamp desc
| limit 100
```

## Local Verification

Run focused tests for the observability surface:

```sh
go test ./internal/telemetry ./internal/observability ./internal/sourcehttp ./internal/bootstrap ./internal/querycache ./internal/statestore/postgres ./internal/graphstore/neo4j ./internal/appendlog/jetstream ./internal/sourceops ./internal/sourceruntime ./internal/sourceprojection ./internal/graphingest ./internal/findings ./cmd/cerebro
```

Run the full suite before release:

```sh
go test ./...
```

Run Python utility tests, including the load-smoke harness:

```sh
make script-test
```

Run a bounded live headroom smoke against a local or deployed service:

```sh
make load-smoke CEREBRO_BASE_URL=http://127.0.0.1:8080
```

For local OTLP export, run a collector listening on `4318` and start Cerebro with:

```sh
CEREBRO_OTEL_ENABLED=true \
CEREBRO_OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf \
CEREBRO_OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318 \
CEREBRO_OTEL_EXPORTER_OTLP_INSECURE=true \
go run ./cmd/cerebro serve
```

Remote OTLP endpoints must use `https://` without `CEREBRO_OTEL_EXPORTER_OTLP_INSECURE=true`. Plain HTTP is accepted only for loopback collector endpoints such as `http://127.0.0.1:4318`.

Then hit `/health` and one API route. Confirm:

- the response includes `X-Cerebro-Trace-Id`;
- stderr contains parseable JSON span/event lines;
- the top-level request/job span has `main=true` and `wide_event=true`;
- the collector receives `http.server` plus downstream child spans for any work performed.
