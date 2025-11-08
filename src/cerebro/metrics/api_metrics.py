"""Lightweight rolling-window API request metrics recorder."""

from __future__ import annotations

from collections import Counter, deque
from dataclasses import dataclass
from statistics import quantiles
from threading import Lock
from time import monotonic
from typing import Deque, Dict, Iterable, Tuple


@dataclass(slots=True)
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

    def record(self, *, duration_ms: float, status_code: int, method: str, path_template: str) -> None:
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

    def snapshot(self) -> Dict[str, object]:
        """Return a summary of recent API request metrics."""

        with self._lock:
            now = monotonic()
            self._prune_locked(now)

            count = len(self._samples)
            if count == 0:
                return {
                    "requests_per_minute": 0.0,
                    "error_rate": 0.0,
                    "p95_latency_ms": 0.0,
                    "total_samples": 0,
                    "top_endpoints": [],
                }

            durations = sorted(sample.duration_ms for sample in self._samples)
            p95 = self._percentile(durations, 0.95)

            error_count = sum(1 for sample in self._samples if sample.status_code >= 500)
            window_minutes = self._window_seconds / 60.0
            rpm = count / window_minutes if window_minutes else float(count)

            endpoint_counts = Counter((sample.method, sample.path_template) for sample in self._samples)
            top_endpoints = [
                {
                    "method": method,
                    "path": path,
                    "count": count,
                }
                for (method, path), count in endpoint_counts.most_common(5)
            ]

            return {
                "requests_per_minute": round(rpm, 2),
                "error_rate": round(error_count / count, 4),
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
