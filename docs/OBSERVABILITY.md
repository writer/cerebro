# Cerebro Observability

Cerebro emits three layers of operational signal:

- Prometheus-compatible counters and histograms on `GET /metrics`.
- Structured JSON telemetry lines on stderr for high-value spans and events.
- OpenTelemetry traces and metrics exported over OTLP when `CEREBRO_OTEL_*` is configured.

The structured JSON and OTEL spans share the same trace context where possible. HTTP responses include `X-Cerebro-Trace-Id` so operators can pivot from the web UI or API response to logs and traces.

## Trace Contract

Inbound HTTP requests create an OTEL `http.server` span with bounded attributes:

- `http.request.method`
- `http.route`
- `http.response.status_code`

The route label is normalized before emission. Unknown or dynamic paths are collapsed to route families such as `/platform/jobs/{jobID}/events` or `/{unmatched}`.

Core runtime operations emit structured spans:

| Span | Coverage |
| --- | --- |
| `source.http.request` | Hardened source HTTP transport, DNS safety checks, host pinning, retries, upstream status |
| `source.check`, `source.discover`, `source.read` | Source CDK operations |
| `source_runtime.sync`, `source_runtime.sync_with_lease` | Runtime sync and lease lifecycle |
| `graph.ingest_runtime` | Graph ingestion runs |
| `graphagent.http.request` | Graph-agent LLM/upstream HTTP calls |
| `postgres.ping`, `postgres.ensure_statements` | Postgres readiness and schema setup |
| `neo4j.read`, `neo4j.write` | Graph store transactions |
| `redis.cache.*`, `redis.ping` | Query cache operations, hits/misses, version bumps |
| `jetstream.ping`, `jetstream.append`, `jetstream.replay` | Append-log health, publish, and replay |

Outbound HTTP uses W3C `traceparent`. The source transport and graph-agent HTTP doer inject child trace context, but they do not emit full URLs, query strings, request bodies, authorization headers, or API keys.

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
| `CEREBRO_OTEL_EXPORTER_OTLP_INSECURE` | Allow insecure transport for local collectors |
| `CEREBRO_OTEL_TRACES_SAMPLE_RATE` | Float from `0` to `1` |
| `CEREBRO_OTEL_METRICS_EXPORT_INTERVAL` | Duration such as `30s` or `1m` |
| `OTEL_RESOURCE_ATTRIBUTES` | Standard resource attributes, for example `deployment.environment=sec-dev` |

## Local Verification

Run focused tests for the observability surface:

```sh
go test ./internal/telemetry ./internal/observability ./internal/sourcehttp ./internal/bootstrap ./internal/querycache ./internal/statestore/postgres ./internal/graphstore/neo4j ./internal/appendlog/jetstream
```

Run the full suite before release:

```sh
go test ./...
```

For local OTLP export, run a collector listening on `4318` and start Cerebro with:

```sh
CEREBRO_OTEL_ENABLED=true \
CEREBRO_OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf \
CEREBRO_OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318 \
CEREBRO_OTEL_EXPORTER_OTLP_INSECURE=true \
go run ./cmd/cerebro serve
```

Then hit `/health` and one API route. Confirm:

- the response includes `X-Cerebro-Trace-Id`;
- stderr contains parseable JSON span/event lines;
- the collector receives `http.server` plus downstream child spans for any work performed.
