from __future__ import annotations

import hashlib
from typing import Any


def service_name(config: dict[str, Any], stack: str) -> str:
    environment = str(config.get("environment") or stack).strip()
    return f"cerebro-{environment}"


def render_collector_config(service: str) -> str:
    metrics_log_group = f"/aws/otel/{service}/metrics"
    return f"""extensions:
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
"""


def collector_config_sha256(service: str) -> str:
    return hashlib.sha256(render_collector_config(service).encode("utf-8")).hexdigest()
