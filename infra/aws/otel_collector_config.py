from __future__ import annotations

import hashlib
from typing import Any


def service_name(config: dict[str, Any], stack: str) -> str:
    environment = str(config.get("environment") or stack).strip()
    return f"cerebro-{environment}"


def render_collector_config(service: str) -> str:
    metrics_log_group = f"/aws/otel/{service}/metrics"
    return fr"""extensions:
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
  cumulativetodelta: {{}}
  metricstransform/cardinality:
    transforms:
      - include: '^cerebro\.source_runtime\.(sync\.(runs|duration)|records|watermark\.lag)$$'
        match_type: regexp
        action: update
        operations:
          - action: aggregate_labels
            label_set: [source_id, status, contract_configured]
            aggregation_type: sum
      - include: '^cerebro\.source_projection\.(runs|duration|records)$$'
        match_type: regexp
        action: update
        operations:
          - action: aggregate_labels
            label_set: [source_id, status]
            aggregation_type: sum
      - include: '^cerebro\.graph_rule\.(evaluations|duration|records)$$'
        match_type: regexp
        action: update
        operations:
          - action: aggregate_labels
            label_set: [source_id, status, truncated]
            aggregation_type: sum
      - include: '^cerebro\.orchestrator\.phase\.(runs|duration)$$'
        match_type: regexp
        action: update
        operations:
          - action: aggregate_labels
            label_set: [phase_key, source_id, status, timeout_exceeded]
            aggregation_type: sum
      - include: '^cerebro\.neo4j\.(operations|operation\.duration)$$'
        match_type: regexp
        action: update
        operations:
          - action: aggregate_labels
            label_set: [operation, status, database_configured]
            aggregation_type: sum
      - include: '^cerebro\.jetstream\.publish\.(requests|retries|duration)$$'
        match_type: regexp
        action: update
        operations:
          - action: aggregate_labels
            label_set: [operation, status, error_category, max_attempts_exhausted]
            aggregation_type: sum
  batch/traces:
    timeout: 5s
    send_batch_size: 512
  batch/metrics:
    timeout: 30s
    send_batch_size: 512

exporters:
  awsxray: {{}}
  awsemf:
    namespace: Cerebro/OTEL
    log_group_name: {metrics_log_group}
    dimension_rollup_option: NoDimensionRollup

service:
  extensions: [health_check]
  telemetry:
    logs:
      level: info
    metrics:
      level: basic
  pipelines:
    traces:
      receivers: [otlp]
      processors: [memory_limiter, resourcedetection, batch/traces]
      exporters: [awsxray]
    metrics:
      receivers: [otlp, prometheus/internal]
      processors: [memory_limiter, resourcedetection, cumulativetodelta, metricstransform/cardinality, batch/metrics]
      exporters: [awsemf]
"""


def collector_config_sha256(service: str) -> str:
    return hashlib.sha256(render_collector_config(service).encode("utf-8")).hexdigest()
