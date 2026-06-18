# Cerebro Observability Deployment

Cerebro already publishes CloudWatch logs, dashboards, alarms, and `/metrics`. OTEL export is now a first-class ECS configuration surface for the API task.

## OTEL Pulumi Keys

| Pulumi key | Runtime env | Notes |
| --- | --- | --- |
| `cerebro:otelEnabled` | `CEREBRO_OTEL_ENABLED` | Set `true` when exporting directly to an OTLP endpoint; collector mode enables it automatically |
| `cerebro:otelServiceName` | `CEREBRO_OTEL_SERVICE_NAME` | Defaults to `cerebro-api` |
| `cerebro:otelExporterOtlpProtocol` | `CEREBRO_OTEL_EXPORTER_OTLP_PROTOCOL` | `http/protobuf` or `grpc` |
| `cerebro:otelExporterOtlpEndpoint` | `CEREBRO_OTEL_EXPORTER_OTLP_ENDPOINT` | Shared traces/metrics endpoint |
| `cerebro:otelExporterOtlpTracesEndpoint` | `CEREBRO_OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` | Trace-specific override |
| `cerebro:otelExporterOtlpMetricsEndpoint` | `CEREBRO_OTEL_EXPORTER_OTLP_METRICS_ENDPOINT` | Metric-specific override |
| `cerebro:otelExporterOtlpHeadersSecretName` | `CEREBRO_OTEL_EXPORTER_OTLP_HEADERS` | Secret key only; never inline header material |
| `cerebro:otelCollectorEnabled` | `CEREBRO_OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318` | Runs an OTEL collector sidecar and routes app export through localhost |
| `cerebro:otelCollectorImage` | `otel-collector` sidecar image | Collector image that supports `AOT_CONFIG_CONTENT` |
| `cerebro:otelCollectorConfigSecretName` | `AOT_CONFIG_CONTENT` | Secret key containing collector config; put vendor endpoints/auth here |
| `cerebro:otelCollectorConfigSecretPrefix` | `AOT_CONFIG_CONTENT` source prefix | Defaults to `infisicalSecretsPrefix` |
| `cerebro:otelCollectorCpu` | `otel-collector` sidecar CPU | Defaults to `128` |
| `cerebro:otelCollectorMemory` | `otel-collector` sidecar memory reservation | Defaults to `256` MB |
| `cerebro:otelExporterOtlpInsecure` | `CEREBRO_OTEL_EXPORTER_OTLP_INSECURE` | For loopback collectors only |
| `cerebro:otelTracesSampleRate` | `CEREBRO_OTEL_TRACES_SAMPLE_RATE` | Number from `0` to `1` |
| `cerebro:otelMetricsExportInterval` | `CEREBRO_OTEL_METRICS_EXPORT_INTERVAL` | Duration such as `30s` or `1m` |
| `cerebro:otelResourceAttributes` | `OTEL_RESOURCE_ATTRIBUTES` | Appended after `deployment.environment.name=<env>` |

`cerebro:otelExporterOtlpHeadersSecretName` is mounted through the existing ECS secret environment mechanism from `infisicalSecretsPrefix`/Secrets Manager as `CEREBRO_OTEL_EXPORTER_OTLP_HEADERS`. Use it for vendor tokens, for example a secret value shaped like `api-key=<token>`.

Prefer `cerebro:otelCollectorEnabled` for production. In collector mode, the app exporter is pinned to `http://127.0.0.1:4318` with `CEREBRO_OTEL_EXPORTER_OTLP_INSECURE=true`, and backend OTLP endpoints plus auth headers belong in the collector config secret. Do not configure `cerebro:otelExporterOtlpHeadersSecretName` with collector mode.

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

Collector sidecar mode:

```sh
pulumi config set cerebro:otelCollectorEnabled true
pulumi config set cerebro:otelCollectorImage public.ecr.aws/aws-observability/aws-otel-collector:<pinned-version>
pulumi config set cerebro:otelCollectorConfigSecretName CEREBRO_OTEL_COLLECTOR_CONFIG
pulumi config set cerebro:otelTracesSampleRate 0.25
pulumi config set cerebro:otelMetricsExportInterval 30s
```

Provision the referenced secret before `pulumi up`. Do not set a plaintext `otelExporterOtlpHeaders` config value; the stack validator rejects it.

Remote OTLP endpoints must use `https://` without `cerebro:otelExporterOtlpInsecure=true`. Plain HTTP is accepted only for loopback collector endpoints such as `http://127.0.0.1:4318`.

## Validation

Run focused validator tests from `infra/`:

```sh
uv run python -m unittest \
  tests.test_validate_stack_config.ValidateStackConfigTest.test_otel_enabled_requires_exporter_endpoint \
  tests.test_validate_stack_config.ValidateStackConfigTest.test_otel_rejects_inline_headers_and_bad_sample_rate \
  tests.test_validate_stack_config.ValidateStackConfigTest.test_otel_accepts_endpoint_secret_and_fractional_sample_rate \
  tests.test_validate_stack_config.ValidateStackConfigTest.test_otel_collector_accepts_sidecar_config
```

Run the stack validator before deployment:

```sh
uv run python scripts/validate_stack_config.py aws/Pulumi.sec-dev.yaml
uv run python scripts/validate_stack_config.py aws/Pulumi.go-prod.yaml
```

After deployment, verify:

- ECS task definition contains `CEREBRO_OTEL_*` env vars and either the `CEREBRO_OTEL_EXPORTER_OTLP_HEADERS` app secret mount or the `otel-collector` sidecar with `AOT_CONFIG_CONTENT`.
- `/health` returns `X-Cerebro-Trace-Id`.
- CloudWatch API logs contain structured span/event JSON lines with the same `trace_id`.
- The collector receives `http.server` spans plus child spans for source HTTP, graph, cache, JetStream, and dependency operations.
