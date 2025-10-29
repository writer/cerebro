from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from cerebro.integrations.kandji import KandjiIngestion
from cerebro.integrations.sentinelone import SentinelOneConfig, SentinelOneIngestion
from cerebro.integrations.state import IntegrationStateRepository
from cerebro.core.models import IntegrationSyncState
from cerebro.telemetry.schemas import HostEvent


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
        "id": "device-1",
        "serial_number": "C02ABC123",
        "device_family": "Mac",
        "mdm_device": {"name": "Acme-Mac", "enrollment_status": 4},
        "asset_tag": "Asset-7",
        "blueprint_id": "blue-1",
        "color": "Silver",
        "device_os_version": "14.5",
        "compliance_status": "Compliant",
        "missing_patch_count": 0,
    }

    compliance = {"status": "Compliant", "issues": ["firewall_disabled"], "last_check_in": "2024-05-02T01:00:00Z"}
    blueprint = {"name": "Corp Managed", "owner": "fleet@acme.com"}
    smart_groups = [{"name": "Exec-Fleet"}, {"name": "High-Risk"}]
    lifecycle = {"owner_email": "user@acme.com", "department": "Security", "asset_tag": "Asset-7"}

    telemetry = ingestion._build_host_telemetry(
        device,
        collected_at=datetime.now(timezone.utc),
        compliance=compliance,
        blueprint=blueprint,
        smart_groups=smart_groups,
        lifecycle=lifecycle,
    )
    assert telemetry is not None
    assert telemetry.host_id == "C02ABC123"
    assert telemetry.hostname == "Acme-Mac"
    assert telemetry.tags is not None and telemetry.tags["asset_tag"] == "Asset-7"
    assert telemetry.os_family == "mac"
    assert telemetry.tags["compliance_status"] == "compliant"
    assert telemetry.tags["blueprint_name"] == "Corp Managed"
    assert "Exec-Fleet" in telemetry.tags["smart_groups"]
    assert telemetry.health is not None and telemetry.health.status == "healthy"


def test_kandji_installed_packages_extracted() -> None:
    ingestion = KandjiIngestion(client=_DummyClient(None), organization="acme")
    device = {
        "serial_number": "C02XYZ789",
        "mdm_device": {"name": "Acme-TST"},
        "applications": [
            {
                "name": "Safari",
                "version": "17.1",
                "installed_at": "2024-05-02T12:00:00Z",
                "source": "mac_app_store",
            }
        ],
    }

    telemetry = ingestion._build_host_telemetry(device, collected_at=datetime.now(timezone.utc))
    assert telemetry is not None
    assert telemetry.installed_packages is not None
    assert telemetry.installed_packages[0].name == "Safari"
    assert telemetry.installed_packages[0].version == "17.1"


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


def test_chunk_events_respects_batch_size() -> None:
    timestamp = datetime.now(timezone.utc)
    events = [
        HostEvent(
            event_id=None,
            host_id="host",
            hostname="host",
            category="test",
            event_type="evt",
            severity="info",
            timestamp=timestamp,
            process_id=None,
            parent_pid=None,
            user=None,
            command_line=None,
            source="unit",
            payload=None,
        )
        for _ in range(5)
    ]

    chunks = list(SentinelOneIngestion._chunk_events(events, 2))
    assert [len(chunk) for chunk in chunks] == [2, 2, 1]


def test_sentinelone_build_host_telemetry_enriches_health_and_tags() -> None:
    ingestion = SentinelOneIngestion(_DummyClient(SentinelOneConfig(
        base_url="https://example.sentinelone.net",
        api_token="token",
        organization="acme",
    )))
    agent = {
        "id": "agent-1",
        "uuid": "agent-uuid",
        "computerName": "Acme-Mac",
        "osType": "macos",
        "osVersion": "14.5",
        "siteName": "HQ",
        "groupName": "Production",
        "accountName": "Acme",
        "threatCount": 0,
        "mitigationMode": "protect",
        "networkInterfaces": [{"ipAddress": "10.0.0.1"}],
    }
    policy = {"name": "Corp Default", "policyType": "protect"}
    applications = [{"name": "Chrome", "version": "125", "publisher": "Google"}]

    telemetry = ingestion._build_host_telemetry(agent, policy, applications, datetime.now(timezone.utc))
    assert telemetry is not None
    assert telemetry.tags is not None and telemetry.tags["policy_name"] == "Corp Default"
    assert telemetry.installed_packages is not None and telemetry.installed_packages[0].name == "Chrome"
    assert telemetry.health is not None and telemetry.health.status == "healthy"


def test_kandji_normalize_audit_event() -> None:
    ingestion = KandjiIngestion(client=_DummyClient(None), organization="acme")
    record = {
        "id": "evt-1",
        "device_serial_number": "C02XYZ789",
        "event_type": "CommandRun",
        "result": "success",
        "created_at": "2024-05-03T12:00:00Z",
        "device_name": "Acme-TST",
    }
    event = ingestion._normalize_audit_event(record)
    assert event is not None
    assert event.host_id == "C02XYZ789"
    assert event.category == "kandji.audit"
    assert event.event_type == "commandrun"


def test_kandji_normalize_patch_detection() -> None:
    ingestion = KandjiIngestion(client=_DummyClient(None), organization="acme")
    detection = {
        "device_serial_number": "C02XYZ789",
        "application_name": "Chrome",
        "severity": "high",
        "detected_at": "2024-05-04T08:00:00Z",
        "device_name": "Acme-TST",
    }
    event = ingestion._normalize_patch_detection(detection)
    assert event is not None
    assert event.host_id == "C02XYZ789"
    assert event.category == "kandji.patch"
    assert event.event_type == "patch:chrome"


@pytest.mark.asyncio
async def test_integration_state_repository_roundtrip() -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(IntegrationSyncState.__table__.create)

    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    timestamp = datetime(2024, 1, 1, tzinfo=timezone.utc)

    async with session_factory() as session:
        repo = IntegrationStateRepository(session)
        await repo.upsert_state(
            integration="sentinelone.activities",
            scope="acme",
            last_timestamp=timestamp,
            metadata={"count": 10},
        )
        state = await repo.get_state("sentinelone.activities", "acme")
        assert state is not None
        state_ts = state.last_timestamp
        assert state_ts is not None
        if state_ts.tzinfo is None:
            state_ts = state_ts.replace(tzinfo=timezone.utc)
        assert state_ts == timestamp
        assert state.state_metadata == {"count": 10}

        await repo.upsert_state(
            integration="sentinelone.activities",
            scope="acme",
            last_cursor="cursor-1",
            metadata={"count": 20},
        )
        updated = await repo.get_state("sentinelone.activities", "acme")
        assert updated is not None
        assert updated.last_cursor == "cursor-1"
        assert updated.state_metadata == {"count": 20}

        states = await repo.list_states()
        assert len(states) == 1
        assert states[0].integration == "sentinelone.activities"

    await engine.dispose()
