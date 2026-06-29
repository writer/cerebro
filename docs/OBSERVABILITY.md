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
| `cerebro:otelResourceAttributes` | `OTEL_RESOURCE_ATTRIBUTES` | Appended after stack-owned deployment/cloud/service attributes |

`cerebro:otelExporterOtlpHeadersSecretName` is mounted through the existing ECS secret environment mechanism from `infisicalSecretsPrefix`/Secrets Manager as `CEREBRO_OTEL_EXPORTER_OTLP_HEADERS`. Use it for vendor tokens, for example a secret value shaped like `api-key=<token>`.

Prefer `cerebro:otelCollectorEnabled` for production. In collector mode, the app exporter is pinned to `http://127.0.0.1:4318` with `CEREBRO_OTEL_EXPORTER_OTLP_INSECURE=true`, and backend OTLP endpoints plus auth headers belong in the collector config secret. Do not configure `cerebro:otelExporterOtlpHeadersSecretName` with collector mode.

Collector mode creates a dedicated `/ecs/<service>/otel-collector` log group, adds CloudWatch metric filters/alarms for collector errors, dropped telemetry, refused telemetry, and failed sends, and adds dashboard widgets for collector container resources, `otelcol_*` self-metrics, recent collector logs, and collector exporter errors. The ECS app container waits for the collector health check before starting.

The API dashboard also includes an OTEL product metrics band sourced from
`Cerebro/OTEL`. These are emitted by the runtime image and exported by the
collector, separate from the older CloudWatch Logs metric filters:

| Metric | Dashboard use |
| --- | --- |
| `cerebro.source_runtime.sync.runs` | Source sync success/failure rate by source and bounded error class |
| `cerebro.source_runtime.sync.duration` | Source sync latency distribution |
| `cerebro.source_runtime.records` | Pages, scanned records, accepted/rejected events, appended events, projected entities, and projected links |
| `cerebro.source_runtime.watermark.lag` | Source freshness lag when a runtime checkpoint has a watermark |
| `cerebro.source_projection.runs` | Projection success/failure rate by source, event kind, and status |
| `cerebro.source_projection.duration` | Projection latency distribution |
| `cerebro.source_projection.records` | Graph/current-state records projected or deleted |

Those OTEL metrics intentionally use low-cardinality dimensions such as
`source_id`, `status`, `error_kind`, `contract_configured`, `event_kind`, and
`record.kind`. Do not add tenant IDs, runtime IDs, resource URNs, evidence IDs,
request IDs, or trace IDs as metric dimensions; use wide events and traces for
that drill-down.

When an app log group is attached to the stack dashboard, the dashboard includes
tenant runtime drill-down widgets backed by CloudWatch Logs Insights. They query
`source_runtime.sync` and `source_projection.project` structured telemetry by
`tenant_id`, `source_id`, `runtime_id`, `event_kind`, `status`, and bounded
`error_kind`. Use the OTEL metric band to find the failing aggregate shape, then
use these log widgets to identify the affected tenant/runtime without adding
tenant-level cardinality to CloudWatch metrics.

Every ECS API task also receives stack/runtime metadata that the app copies into
wide-event attributes:

- `CEREBRO_ENVIRONMENT=<stack environment>`
- `CEREBRO_DEPLOYMENT_ENVIRONMENT=<stack environment>`
- `AWS_REGION=<provider region>`
- `AWS_DEFAULT_REGION=<provider region>`
- API task only: `ECS_SERVICE_NAME=<stack service name>`
- API and orchestrator tasks: `ECS_CLUSTER=<stack cluster name>`
- API and orchestrator tasks: `ECS_TASK_FAMILY=<task definition family>`
- `OTEL_RESOURCE_ATTRIBUTES=deployment.environment.name=<env>,deployment.environment=<env>,service.namespace=cerebro,cloud.provider=aws,cloud.region=<region>[,<cerebro:otelResourceAttributes>]`

These attributes keep CloudWatch wide events and exported spans queryable by
environment, region, service namespace, and cloud provider even when the app
image is reused across stacks. New runtime images also copy the ECS identity
environment into `aws.ecs.cluster.name`, `aws.ecs.service.name`,
`aws.ecs.task.family`, and `cloud.platform=aws_ecs` on wide events.

The live Cerebro stacks use collector mode:

| Stack | Collector config secret |
| --- | --- |
| `go-prod` | `cerebro-go-production/aws-sync/CEREBRO_OTEL_COLLECTOR_CONFIG` |
| `sec-dev` | `cerebro-sec-dev/CEREBRO_OTEL_COLLECTOR_CONFIG` |

The secret value should be an ADOT collector config that receives app OTLP on
`127.0.0.1:4318`, scrapes the collector's own `otelcol_*` internal metrics on
`127.0.0.1:8888`, exports traces to AWS X-Ray, and exports metrics to
CloudWatch EMF under `Cerebro/OTEL`. Keep backend headers, certificates, or
future vendor auth inside that secret, not in Pulumi config.

Generated AWS-native config shape:

```yaml
extensions:
  health_check:
    endpoint: 127.0.0.1:13133
receivers:
  prometheus/internal:
    config:
      scrape_configs:
        - job_name: otel-collector
          scrape_interval: 30s
          static_configs:
            - targets: [127.0.0.1:8888]
  otlp:
    protocols:
      grpc:
        endpoint: 127.0.0.1:4317
      http:
        endpoint: 127.0.0.1:4318
processors:
  memory_limiter:
    check_interval: 1s
    limit_mib: 192
    spike_limit_mib: 64
  resourcedetection:
    detectors: [env, ecs]
    timeout: 2s
    override: false
  batch/traces:
    timeout: 5s
    send_batch_size: 512
  batch/metrics:
    timeout: 30s
    send_batch_size: 512
exporters:
  awsxray: {}
  awsemf:
    namespace: Cerebro/OTEL
    log_group_name: /aws/otel/<service>/metrics
    dimension_rollup_option: NoDimensionRollup
service:
  extensions: [health_check]
  telemetry:
    logs:
      level: info
    metrics:
      level: detailed
  pipelines:
    traces:
      receivers: [otlp]
      processors: [memory_limiter, resourcedetection, batch/traces]
      exporters: [awsxray]
    metrics:
      receivers: [otlp, prometheus/internal]
      processors: [memory_limiter, resourcedetection, batch/metrics]
      exporters: [awsemf]
```

The collector config is deliberately a secret even when it only contains a
backend URL. That leaves one safe path for future auth headers, mTLS material, or
tenant routing headers without moving sensitive values into reviewed stack YAML.

## Example

```sh
pulumi config set cerebro:otelEnabled true
pulumi config set cerebro:otelExporterOtlpProtocol http/protobuf
pulumi config set cerebro:otelExporterOtlpEndpoint https://otel-collector.example.internal
pulumi config set cerebro:otelExporterOtlpHeadersSecretName CEREBRO_OTEL_EXPORTER_OTLP_HEADERS
pulumi config set cerebro:otelTracesSampleRate 0.25
pulumi config set cerebro:otelMetricsExportInterval 30s
pulumi config set cerebro:otelResourceAttributes writer.owner=security
```

Collector sidecar mode:

```sh
pulumi config set cerebro:otelCollectorEnabled true
pulumi config set cerebro:otelCollectorImage public.ecr.aws/aws-observability/aws-otel-collector:v0.48.0
pulumi config set cerebro:otelCollectorConfigSecretName CEREBRO_OTEL_COLLECTOR_CONFIG
pulumi config set cerebro:otelTracesSampleRate 0.25
pulumi config set cerebro:otelMetricsExportInterval 30s
```

Provision the referenced secret before `pulumi up`. The standard AWS-native collector config exports traces to X-Ray and metrics to CloudWatch EMF:

```sh
cd infra
uv run python scripts/provision_otel_collector_config.py \
  --stack-file aws/Pulumi.sec-dev.yaml \
  --profile cerebro-sec-dev

uv run python scripts/provision_otel_collector_config.py \
  --stack-file aws/Pulumi.go-prod.yaml \
  --profile writer-sec-prod-us1
```

Use `--dry-run` to print the rendered config hash without touching AWS. Use `--print-config` to inspect the rendered collector config. Main and manual AWS deploy workflows also run this helper before secret import verification, so stale collector config is repaired before a new ECS task definition is applied. Static infra validation boots the configured ADOT image with the rendered config in `AOT_CONFIG_CONTENT`, which catches collector schema/runtime drift before deploy. The AWS secret import guard validates the collector secret parses as a collector config with the health check extension, OTLP receivers, and trace/metric pipelines; it also rejects the legacy `service.telemetry.metrics.address` key that ADOT v0.48.0 cannot load. Do not set a plaintext `otelExporterOtlpHeaders` config value; the stack validator rejects it.

Remote OTLP endpoints must use `https://` without `cerebro:otelExporterOtlpInsecure=true`. Plain HTTP is accepted only for loopback collector endpoints such as `http://127.0.0.1:4318`.

Tenant-level runtime/projection failure drill-down:

```sql
SOURCE '/ecs/<service>/api'
| fields @timestamp, name, trace_id, tenant_id, source_id, runtime_id, event_kind, status, error_kind
| filter (name = "source_runtime.sync" or name = "source_projection.project") and status = "failed"
| sort @timestamp desc
| limit 50
```

## NATS JetStream Monitoring

The monitoring stack attaches the NATS service log group (`/ecs/<stack>/nats`)
to CloudWatch metric filters for operational symptoms that can block event
append and projection:

| Metric | Source log signal | Why it matters |
| --- | --- | --- |
| `NatsHealthcheckFailures` | `Healthcheck failed` | NATS or JetStream is unavailable to ECS health checks |
| `NatsBootstrapErrors` | `nats: error` | stream bootstrap/edit drift, timeout, or authorization failure |
| `NatsCorruptStateRecoveries` | `corrupt state file` | stream state recovered from a corrupt file during startup |
| `NatsRestoreCompletions` | `Restored ... messages for stream` | restart restore completed; use with stream size to estimate restart risk |

The `<service>-dashboard` includes a `NATS JetStream Operations` widget beside
the existing JetStream lag and stream depth widgets. Active stacks also set
`cerebro:jetstreamStreamBytesAlarmThreshold` to `85899345920` bytes (80 GiB), so
`JetStreamStreamBytes` alerts before stream restore size reaches the range that
caused long startup recovery in sec-dev. Keep the threshold below the point
where a single NATS restart would exceed the acceptable restore window, and
revisit it after restore drills or retention changes.

Active stacks keep NATS at 16 vCPU with 64 GiB memory, elastic EFS throughput,
and a Cerebro publish retry budget of at least 5 minutes. That retry window is
deliberately longer than the observed 26 GiB stream restore window, and
`cerebro:jetstreamPublishMaxInFlight` limits per-process publish fan-out during a
broker restart so source runtimes wait instead of stampeding the recovering
stream.

The app sets `CEREBRO_JETSTREAM_STREAM_NAME` from `cerebro:jetstreamStreamName`.
Publishes carry `Nats-Expected-Stream`, and readiness checks fail when that
stream is missing or does not accept the configured subject prefix. The stream
bootstrap also sets `cerebro:jetstreamDupeWindow` to `10m`, longer than the
active publish retry budget, so retried event IDs remain idempotent through a
broker restart.

The NATS bootstrap stream must bind both `events.>` and `sec.>`. Runtime events
use the configured `CEREBRO_JETSTREAM_SUBJECT_PREFIX`, while canonical security
events such as `sec.findings.v1.recorded` publish directly on the `sec.*`
taxonomy so replay and audit-log queries can preserve security-platform subject
names. If `sec.>` is missing, finding writes fail as JetStream publish
`no_response` retries even when NATS CPU, memory, EFS throughput, and consumer
lag look healthy.

## Live Rollout

Use AWS SSO profiles that match the stack accounts:

```sh
aws sso login --profile cerebro-sec-dev
aws sso login --profile writer-sec-prod-us1
```

Provision or update the collector config secrets before preview/apply:

```sh
aws secretsmanager put-secret-value \
  --profile cerebro-sec-dev \
  --region us-east-1 \
  --secret-id cerebro-sec-dev/CEREBRO_OTEL_COLLECTOR_CONFIG \
  --secret-string file://cerebro-otel-collector-config.yaml

aws secretsmanager put-secret-value \
  --profile writer-sec-prod-us1 \
  --region us-east-1 \
  --secret-id cerebro-go-production/aws-sync/CEREBRO_OTEL_COLLECTOR_CONFIG \
  --secret-string file://cerebro-otel-collector-config.yaml
```

Preview both stacks from `infra/` before merging:

```sh
AWS_PROFILE=cerebro-sec-dev AWS_SDK_LOAD_CONFIG=1 \
  uv run pulumi preview --stack sec-dev --diff --non-interactive

AWS_PROFILE=writer-sec-prod-us1 AWS_SDK_LOAD_CONFIG=1 \
  uv run pulumi preview --stack go-prod --diff --non-interactive
```

Expected ECS task-definition changes:

- app container has `CEREBRO_OTEL_ENABLED=true`
- app container exports to `http://127.0.0.1:4318` with `http/protobuf`
- app container has the runtime metadata env vars listed above
- API task definitions include `ECS_CLUSTER`, `ECS_SERVICE_NAME`, and `ECS_TASK_FAMILY`
- orchestrator task definitions include `ECS_CLUSTER` and `ECS_TASK_FAMILY`
- app container has `OTEL_RESOURCE_ATTRIBUTES` with deployment/cloud attributes
- task includes an `otel-collector` sidecar
- collector has `AOT_CONFIG_CONTENT` mounted from the stack collector secret
- collector writes logs to `/ecs/<stack>/otel-collector`
- collector error metric filters and the `OtelCollectorErrors` alarm remain wired to that collector log group

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
uv run python scripts/validate_otel_collector_config_runtime.py \
  --stack-file aws/Pulumi.sec-dev.yaml \
  --stack-file aws/Pulumi.go-prod.yaml
AWS_PROFILE=cerebro-sec-dev uv run python scripts/verify_aws_secret_imports.py --stack-file aws/Pulumi.sec-dev.yaml
AWS_PROFILE=writer-sec-prod-us1 uv run python scripts/verify_aws_secret_imports.py --stack-file aws/Pulumi.go-prod.yaml
```

After deployment, verify:

- ECS task definition contains `CEREBRO_OTEL_*` env vars and either the `CEREBRO_OTEL_EXPORTER_OTLP_HEADERS` app secret mount or the `otel-collector` sidecar with `AOT_CONFIG_CONTENT`.
- The current ECS task definition includes an `otel-collector` container, a `HEALTHY` dependency from `cerebro` to `otel-collector`, and collector logs under `/ecs/<service>/otel-collector`.
- `/health` returns `X-Cerebro-Trace-Id`.
- CloudWatch API logs contain structured span/event JSON lines with the same `trace_id`.
- The collector receives `http.server` spans plus child spans for source HTTP, graph, cache, JetStream, and dependency operations.
- The `<service>-dashboard` CloudWatch dashboard includes `OTEL Collector Container`, `OTEL Collector Errors`, `OTEL Collector Recent Logs`, and the `OTEL Product Source Runtime` / `OTEL Projection Records` widgets.

Useful read-only AWS checks:

```sh
aws ecs describe-services \
  --profile cerebro-sec-dev \
  --region us-east-1 \
  --cluster cerebro-sec-dev-cluster \
  --services cerebro-sec-dev-api \
  --query 'services[0].deployments[?status==`PRIMARY`].[taskDefinition,rolloutState,runningCount,desiredCount]'

aws ecs describe-services \
  --profile writer-sec-prod-us1 \
  --region us-east-1 \
  --cluster cerebro-go-production-cluster \
  --services cerebro-go-production-api \
  --query 'services[0].deployments[?status==`PRIMARY`].[taskDefinition,rolloutState,runningCount,desiredCount]'
```

Use the active task definition ARN from each service to inspect container env,
dependencies, logs, and secrets:

```sh
aws ecs describe-task-definition \
  --profile <profile> \
  --region us-east-1 \
  --task-definition <task-definition-arn> \
  --query 'taskDefinition.containerDefinitions[].{name:name,dependsOn:dependsOn,logs:logConfiguration.options}'

aws logs describe-log-streams \
  --profile <profile> \
  --region us-east-1 \
  --log-group-name /ecs/<stack>/otel-collector \
  --order-by LastEventTime \
  --descending \
  --max-items 5
```

Useful CloudWatch Logs Insights query for API wide events:

```sql
fields @timestamp, @logStream, name, service.version, event.outcome, duration_ms,
  http.route, runtime_id, source_id, dependency.last_system, dependency.last_status,
  phase.last_name, phase.last_status, error_kind
| filter @message like /"wide_event":true/
| sort @timestamp desc
| limit 20
```

Expected fields on fresh events:

- `wide_event.schema.version` is present
- `event.outcome`, `operation.status`, `duration_ms`, and `duration.bucket` are present
- `deployment.environment.name` is `sec-dev` or `go-production`
- `deployment.environment` matches the stack environment
- `cloud.provider` is `aws`
- `cloud.region` is `us-east-1`
- `cloud.platform` is `aws_ecs`
- `service.namespace` is `cerebro`
- `service.name` is `cerebro-api`
- `aws.ecs.cluster.name` matches the stack cluster
- API events include `aws.ecs.service.name`
- dependency-heavy work includes `dependency.*` rollups
- multi-phase work includes `phase.*` rollups

Useful dependency rollup query:

```sql
stats count(*) as events,
  pct(duration_ms, 95) as p95_ms,
  max(duration_ms) as max_ms
by dependency.last_system, dependency.last_status, service.version, deployment.environment.name
| sort p95_ms desc
```

Useful orchestrator/source-runtime phase query:

```sql
stats count(*) as events,
  sum(orchestrator.runtime.failed.count) as failed_runtimes,
  sum(source_runtime.invalid_event.count) as invalid_events
by phase.last_name, phase.last_status, source_id, runtime_id, error_kind
| sort events desc
```

Collector health is visible in `/ecs/<stack>/otel-collector`. Investigate
exporter errors there before declaring the rollout complete.
