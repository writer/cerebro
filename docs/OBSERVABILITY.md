# Cerebro Observability Deployment

Cerebro already publishes CloudWatch logs, dashboards, alarms, and `/metrics`. OTEL export is now a first-class ECS configuration surface for the API task.

## OTEL Pulumi Keys

| Pulumi key | Runtime env | Notes |
| --- | --- | --- |
| `cerebro:otelEnabled` | `CEREBRO_OTEL_ENABLED` | Set `true` only when at least one OTLP endpoint is configured |
| `cerebro:otelServiceName` | `CEREBRO_OTEL_SERVICE_NAME` | Defaults to `cerebro-api` |
| `cerebro:otelExporterOtlpProtocol` | `CEREBRO_OTEL_EXPORTER_OTLP_PROTOCOL` | `http/protobuf` or `grpc` |
| `cerebro:otelExporterOtlpEndpoint` | `CEREBRO_OTEL_EXPORTER_OTLP_ENDPOINT` | Shared traces/metrics endpoint |
| `cerebro:otelExporterOtlpTracesEndpoint` | `CEREBRO_OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` | Trace-specific override |
| `cerebro:otelExporterOtlpMetricsEndpoint` | `CEREBRO_OTEL_EXPORTER_OTLP_METRICS_ENDPOINT` | Metric-specific override |
| `cerebro:otelExporterOtlpHeadersSecretName` | `CEREBRO_OTEL_EXPORTER_OTLP_HEADERS` | Secret key only; never inline header material |
| `cerebro:otelExporterOtlpInsecure` | `CEREBRO_OTEL_EXPORTER_OTLP_INSECURE` | For private/local collectors only |
| `cerebro:otelTracesSampleRate` | `CEREBRO_OTEL_TRACES_SAMPLE_RATE` | Number from `0` to `1` |
| `cerebro:otelMetricsExportInterval` | `CEREBRO_OTEL_METRICS_EXPORT_INTERVAL` | Duration such as `30s` or `1m` |
| `cerebro:otelResourceAttributes` | `OTEL_RESOURCE_ATTRIBUTES` | Appended after `deployment.environment=<env>` |

`cerebro:otelExporterOtlpHeadersSecretName` is mounted through the existing ECS secret environment mechanism from `infisicalSecretsPrefix`/Secrets Manager as `CEREBRO_OTEL_EXPORTER_OTLP_HEADERS`. Use it for vendor tokens, for example a secret value shaped like `api-key=<token>`.

## Example

```sh
pulumi config set cerebro:otelEnabled true
pulumi config set cerebro:otelExporterOtlpProtocol http/protobuf
pulumi config set cerebro:otelExporterOtlpEndpoint https://otel-collector.example.internal
pulumi config set cerebro:otelExporterOtlpHeadersSecretName CEREBRO_OTEL_EXPORTER_OTLP_HEADERS
pulumi config set cerebro:otelTracesSampleRate 0.25
pulumi config set cerebro:otelMetricsExportInterval 30s
pulumi config set cerebro:otelResourceAttributes service.namespace=cerebro
```

Provision the referenced secret before `pulumi up`. Do not set a plaintext `otelExporterOtlpHeaders` config value; the stack validator rejects it.

## Validation

Run focused validator tests from `infra/`:

```sh
uv run python -m unittest \
  tests.test_validate_stack_config.ValidateStackConfigTest.test_otel_enabled_requires_exporter_endpoint \
  tests.test_validate_stack_config.ValidateStackConfigTest.test_otel_rejects_inline_headers_and_bad_sample_rate \
  tests.test_validate_stack_config.ValidateStackConfigTest.test_otel_accepts_endpoint_secret_and_fractional_sample_rate
```

Run the stack validator before deployment:

```sh
uv run python scripts/validate_stack_config.py aws/Pulumi.sec-dev.yaml
uv run python scripts/validate_stack_config.py aws/Pulumi.go-prod.yaml
```

After deployment, verify:

- ECS task definition contains `CEREBRO_OTEL_*` env vars and the `CEREBRO_OTEL_EXPORTER_OTLP_HEADERS` secret mount when configured.
- `/health` returns `X-Cerebro-Trace-Id`.
- CloudWatch API logs contain structured span/event JSON lines with the same `trace_id`.
- The collector receives `http.server` spans plus child spans for source HTTP, graph, cache, JetStream, and dependency operations.
