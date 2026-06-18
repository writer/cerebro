# Cerebro Observability

Cerebro emits three layers of operational signal:

- Prometheus-compatible counters and histograms on `GET /metrics`.
- Structured JSON telemetry lines on stderr for high-value spans and events.
- OpenTelemetry traces and metrics exported over OTLP when `CEREBRO_OTEL_*` is configured.

The structured JSON and OTEL spans share the same trace context where possible. HTTP responses include `X-Cerebro-Trace-Id` so operators can pivot from the web UI or API response to logs and traces.

For capacity SLOs, saturation dashboards, alert templates, autoscaling signals, and live load-smoke checks, use [`docs/HEADROOM.md`](./HEADROOM.md). This observability contract supplies the event and metric shape; the headroom guide defines how operators turn those signals into prevention, paging, and release gates.

## Wide Event Contract

Cerebro follows a wide-event model for request and job debugging. Each top-level
unit of work emits one canonical span/event with:

- `main=true`
- `wide_event=true`
- service, deployment, runtime, host, cloud, and container metadata
- request/job shape
- auth/customer posture
- downstream cache, database, queue, graph, source, LLM, MCP, and domain counts
- final status, duration, and bounded error kind

Use `main=true` as the primary query predicate when asking "what happened to
this request/job?" Child spans remain available for drill-down, but shared
service methods annotate the active main span so the first query has the full
shape.

During headroom incidents, start with `main=true`, then group by `http.route`,
`service.version`, replica/container identity, `tenant_id`, `source_id`,
`runtime_id`, dependency counters, and bounded `error_kind`. That keeps the
first query broad enough to find saturation without jumping between logs,
metrics, traces, and deployment tooling.

Inbound HTTP requests create a main OTEL `http.server` span. The route label is
normalized before emission. Unknown or dynamic paths are collapsed to route
families such as `/platform/jobs/{jobID}/events` or `/{unmatched}`. Query values,
authorization headers, cookies, request bodies, response bodies, DSNs, and raw
errors are not emitted.

Expected HTTP dimensions include:

- `http.request.method`, `http.route`, `url.path_depth`, `url.query.param_count`, `url.query.keys`
- `url.scheme`, `server.address`, `server.port`, `network.protocol.version`
- `http.request.body.size`, selected safe request header values, header-presence booleans
- `user_agent.family`, `client.address_hash`
- `http.response.status_code`, `http.response.body.size`, selected safe response header values

Expected propagated dimensions include:

- Auth: `tenant_id`, `auth.outcome`, `auth.mode`, `auth.credential_tier`, `auth.risk_level`, `auth.denial_reason`
- MCP/OAuth: `mcp.method`, `mcp.tool`, `mcp.tool_family`, `mcp.outcome`, `oauth.operation`, `oauth.grant_type`
- GRC/LLM: `grc.ask.llm.provider`, `grc.ask.query_plan.intent`, `grc.ask.row_count`, stage timing fields
- Graph-agent LLM: `gen_ai.provider.name`, `gen_ai.operation.name`, `gen_ai.request.model`, `graphagent.*.count`, `graphagent.*.bytes`, refusal/plan/Cypher presence flags
- Stores: `cache.redis.*.count`, `db.postgres.*.count`, `db.neo4j.*.count`
- Messaging/source/graph: `messaging.jetstream.*.count`, `source_runtime.*`, `source.operation.*`, `graph.ingest.*`
- Domain outcomes: `source_projection.*`, `finding_candidate.*`, `finding_evaluation.*`

Core runtime operations emit structured spans:

| Span | Coverage |
| --- | --- |
| `source.http.request` | Hardened source HTTP transport, DNS safety checks, host pinning, retries, upstream status |
| `source.check`, `source.discover`, `source.read` | Source CDK operations |
| `source_runtime.sync`, `source_runtime.sync_with_lease` | Runtime sync and lease lifecycle |
| `graph.ingest_runtime` | Graph ingestion runs |
| `graphagent.http.request` | Graph-agent LLM/upstream HTTP calls |
| `graphagent.llm.draft`, `graphagent.llm.summarize`, `graphagent.llm.probe` | Graph-agent LLM operations, model/provider metadata, counts, sizes, and safe outcomes only |
| `postgres.ping`, `postgres.ensure_statements` | Postgres readiness and schema setup |
| `neo4j.read`, `neo4j.write` | Graph store transactions |
| `redis.cache.*`, `redis.ping` | Query cache operations, hits/misses, version bumps |
| `jetstream.ping`, `jetstream.append`, `jetstream.replay` | Append-log health, publish, and replay |

Outbound HTTP uses W3C `traceparent`. The source transport and graph-agent HTTP doer inject child trace context, but they do not emit full URLs, query strings, request bodies, authorization headers, or API keys. Graph-agent LLM spans also do not emit prompt text, completion text, raw Cypher, raw tool arguments, rows, or headers.

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
| `CEREBRO_OTEL_EXPORTER_OTLP_INSECURE` | Allow insecure transport only for loopback collectors |
| `CEREBRO_OTEL_TRACES_SAMPLE_RATE` | Float from `0` to `1` |
| `CEREBRO_OTEL_METRICS_EXPORT_INTERVAL` | Duration such as `30s` or `1m` |
| `OTEL_RESOURCE_ATTRIBUTES` | Standard resource attributes, for example `deployment.environment.name=sec-dev` |
| `CEREBRO_ENVIRONMENT` / `CEREBRO_DEPLOYMENT_ENVIRONMENT` | Environment value used by structured wide events |
| `AWS_REGION` / `AWS_DEFAULT_REGION` | AWS region used by structured wide events when running on ECS |

Structured wide events also read `OTEL_RESOURCE_ATTRIBUTES` so CloudWatch JSON
logs and exported OTEL spans share the same `service.namespace`,
`deployment.environment.name`, `cloud.provider`, and `cloud.region` dimensions.
The deployment-specific env vars take precedence over generic resource
attributes when both are present.

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
