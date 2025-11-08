import time

import pytest

from cerebro.metrics.api_metrics import APIMetricsRecorder


def test_api_metrics_snapshot_basic():
    recorder = APIMetricsRecorder(window_seconds=60)
    recorder.record(duration_ms=12.5, status_code=200, method="GET", path_template="/foo")
    recorder.record(duration_ms=25.0, status_code=500, method="POST", path_template="/bar")

    snapshot = recorder.snapshot()

    assert snapshot["total_samples"] == 2
    assert snapshot["error_rate"] == pytest.approx(0.5)
    assert snapshot["requests_per_minute"] == pytest.approx(2.0)
    assert snapshot["p95_latency_ms"] >= 24.0
    top = snapshot["top_endpoints"]
    assert any(entry["path"] == "/bar" for entry in top)


def test_api_metrics_window_prunes_old_samples():
    recorder = APIMetricsRecorder(window_seconds=1)
    recorder.record(duration_ms=10.0, status_code=200, method="GET", path_template="/foo")
    time.sleep(1.2)
    recorder.record(duration_ms=10.0, status_code=200, method="GET", path_template="/foo")

    snapshot = recorder.snapshot()

    assert snapshot["total_samples"] == 1
    assert snapshot["error_rate"] == 0.0


def test_api_metrics_empty_snapshot():
    recorder = APIMetricsRecorder(window_seconds=60)
    snapshot = recorder.snapshot()

    assert snapshot == {
        "requests_per_minute": 0.0,
        "error_rate": 0.0,
        "p95_latency_ms": 0.0,
        "total_samples": 0,
        "top_endpoints": [],
    }
