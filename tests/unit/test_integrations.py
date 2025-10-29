from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

import pytest

from cerebro.integrations.kandji import KandjiIngestion
from cerebro.integrations.sentinelone import SentinelOneConfig, SentinelOneIngestion


class _DummyClient:
    def __init__(self, config) -> None:
        self._config = config


def test_sentinelone_normalize_activity_generates_deterministic_event_id() -> None:
    config = SentinelOneConfig(
        base_url="https://example.sentinelone.net",
        api_token="token",
        organization="acme",
    )
    ingestion = SentinelOneIngestion(_DummyClient(config))

    activity = {
        "id": "12345",
        "agentId": "agent-1",
        "createdAt": "2024-05-01T12:00:00Z",
        "activityType": "ThreatDetected",
        "severity": "high",
        "data": {"computerName": "acme-mac"},
    }

    event = ingestion._normalize_activity(activity)
    assert event is not None
    assert event.host_id == "agent-1"
    assert event.hostname == "acme-mac"
    assert event.event_type == "threatdetected"
    assert event.severity == "high"
    assert event.event_id == UUID("4d8d0d29-39f3-51c8-a6c2-aaca8a83760c")


def test_kandji_build_host_telemetry_includes_serial_metadata() -> None:
    ingestion = KandjiIngestion(
        client=_DummyClient(None),
        organization="acme",
        site="sf",
    )
    device = {
        "serial_number": "C02ABC123",
        "device_family": "Mac",
        "mdm_device": {"name": "Acme-Mac", "enrollment_status": 4},
        "asset_tag": "Asset-7",
        "blueprint_id": "blue-1",
        "color": "Silver",
        "device_os_version": "14.5",
    }

    telemetry = ingestion._build_host_telemetry(device, collected_at=datetime.now(timezone.utc))
    assert telemetry is not None
    assert telemetry.host_id == "C02ABC123"
    assert telemetry.hostname == "Acme-Mac"
    assert telemetry.tags is not None and telemetry.tags["asset_tag"] == "Asset-7"
    assert telemetry.os_family == "mac"


@pytest.mark.parametrize(
    "detection,expected_uuid",
    [
        ({"device_serial_number": "C02ABC123", "cve_id": "CVE-2024-0001"}, "4e47c8b6-2c39-5a7f-b4aa-139be5220b10"),
    ],
)
def test_kandji_detection_normalization_uses_serial_and_cve(detection, expected_uuid) -> None:
    ingestion = KandjiIngestion(client=_DummyClient(None), organization="acme")
    detection.update({"latest_detection_date": "2024-05-01T00:00:00Z"})
    event = ingestion._normalize_detection(detection)
    assert event is not None
    assert event.event_id == UUID(expected_uuid)
    assert event.event_type == "cve:CVE-2024-0001"
