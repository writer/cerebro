"""Lightweight rolling-window API request metrics recorder."""

from __future__ import annotations

from collections import Counter, deque
from dataclasses import dataclass
from statistics import quantiles
from threading import Lock
from time import monotonic
from typing import Deque, Dict, Iterable

from prometheus_client import Counter as PromCounter
from prometheus_client import Gauge as PromGauge
from prometheus_client import Histogram as PromHistogram

from cerebro.metrics.collection_metrics import cerebro_registry


_API_REQUEST_LATENCY_SECONDS = PromHistogram(
    "cerebro_api_request_latency_seconds",
    "Latency of API requests in seconds",
    ["method", "path_template"],
    registry=cerebro_registry,
)

_API_REQUEST_TOTAL = PromCounter(
    "cerebro_api_requests_total",
    "Total number of API requests",
    ["method", "path_template", "status_code"],
    registry=cerebro_registry,
)

_API_REQUESTS_PER_MINUTE = PromGauge(
    "cerebro_api_requests_per_minute",
    "Rolling requests-per-minute derived from in-memory window",
    registry=cerebro_registry,
)

_API_ERROR_RATE = PromGauge(
    "cerebro_api_error_rate",
    "Rolling error rate derived from in-memory window",
    registry=cerebro_registry,
)

_API_P95_LATENCY_MS = PromGauge(
    "cerebro_api_p95_latency_milliseconds",
    "P95 latency in milliseconds derived from in-memory window",
    registry=cerebro_registry,
)

_API_TOTAL_SAMPLES = PromGauge(
    "cerebro_api_request_window_samples",
    "Number of request samples currently retained in the sliding window",
    registry=cerebro_registry,
)


@dataclass
class _RequestSample:
    timestamp: float
    duration_ms: float
    status_code: int
    method: str
    path_template: str


class APIMetricsRecorder:
    """Records API request metrics over a sliding window for health reporting."""

    def __init__(self, window_seconds: int = 300) -> None:
        self._window_seconds = max(1, window_seconds)
        self._samples: Deque[_RequestSample] = deque()
        self._lock = Lock()

    def _observe_prometheus(self, sample: _RequestSample) -> None:
        labels = {
            "method": sample.method,
            "path_template": sample.path_template,
        }
        _API_REQUEST_LATENCY_SECONDS.labels(**labels).observe(
            sample.duration_ms / 1000.0
        )
        _API_REQUEST_TOTAL.labels(status_code=str(sample.status_code), **labels).inc()

    def record(
        self, *, duration_ms: float, status_code: int, method: str, path_template: str
    ) -> None:
        """Record a single API request sample."""

        sample = _RequestSample(
            timestamp=monotonic(),
            duration_ms=duration_ms,
            status_code=status_code,
            method=method,
            path_template=path_template or "unknown",
        )

        with self._lock:
            self._samples.append(sample)
            self._prune_locked(sample.timestamp)

        self._observe_prometheus(sample)

    def snapshot(self) -> Dict[str, object]:
        """Return a summary of recent API request metrics."""

        with self._lock:
            now = monotonic()
            self._prune_locked(now)

            count = len(self._samples)
            if count == 0:
                _API_REQUESTS_PER_MINUTE.set(0.0)
                _API_ERROR_RATE.set(0.0)
                _API_P95_LATENCY_MS.set(0.0)
                _API_TOTAL_SAMPLES.set(0)
                return {
                    "requests_per_minute": 0.0,
                    "error_rate": 0.0,
                    "p95_latency_ms": 0.0,
                    "total_samples": 0,
                    "top_endpoints": [],
                }

            durations = sorted(sample.duration_ms for sample in self._samples)
            p95 = self._percentile(durations, 0.95)

            error_count = sum(
                1 for sample in self._samples if sample.status_code >= 500
            )
            window_minutes = self._window_seconds / 60.0
            rpm = count / window_minutes if window_minutes else float(count)
            error_rate = error_count / count if count else 0.0

            endpoint_counts = Counter(
                (sample.method, sample.path_template) for sample in self._samples
            )
            top_endpoints = [
                {
                    "method": method,
                    "path": path,
                    "count": count,
                }
                for (method, path), count in endpoint_counts.most_common(5)
            ]

            _API_REQUESTS_PER_MINUTE.set(round(rpm, 2))
            _API_ERROR_RATE.set(round(error_rate, 4))
            _API_P95_LATENCY_MS.set(round(p95, 2))
            _API_TOTAL_SAMPLES.set(count)

            return {
                "requests_per_minute": round(rpm, 2),
                "error_rate": round(error_rate, 4),
                "p95_latency_ms": round(p95, 2),
                "total_samples": count,
                "top_endpoints": top_endpoints,
            }

    def _prune_locked(self, now: float) -> None:
        cutoff = now - self._window_seconds
        while self._samples and self._samples[0].timestamp < cutoff:
            self._samples.popleft()

    @staticmethod
    def _percentile(values: Iterable[float], percentile: float) -> float:
        data = list(values)
        if not data:
            return 0.0
        if len(data) == 1:
            return float(data[0])
        percentile = max(0.0, min(1.0, percentile))
        try:
            q = quantiles(data, n=100, method="inclusive")
            index = int(percentile * 100) - 1
            index = max(0, min(len(q) - 1, index))
            return float(q[index])
        except (ValueError, IndexError):
            # Fallback to simple selection when statistics.quantiles cannot be used.
            position = int(round(percentile * (len(data) - 1)))
            position = max(0, min(len(data) - 1, position))
            return float(data[position])


api_metrics = APIMetricsRecorder()
