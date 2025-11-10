from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from cerebro.core.models import ConfigSnapshot, Finding
from cerebro.telemetry.models import (
    ArtifactPack,
    ArtifactPackTarget,
    ArtifactPackTask,
    ArtifactPackTrigger,
    HostTelemetryEvent,
)
from cerebro.telemetry.schemas import (
    AgentHealth,
    ConfigurationDrift,
    HostEvent,
    HostEventBatch,
    HostTelemetry,
    ProcessSnapshot,
    SecurityEvent,
)
from cerebro.telemetry.services import TelemetryIngestionService


@pytest.mark.asyncio
async def test_process_host_creates_snapshot_and_findings(test_db):
    service = TelemetryIngestionService(test_db)

    telemetry = HostTelemetry(
        organization="Acme",
        site="HQ",
        host_id="host-123",
        hostname="acme-mbp",
        serial_number="SN-001",
        agent_version="1.0.0",
        os_family="darwin",
        os_version="14.6",
        kernel_version="23.6.0",
        architecture="arm64",
        collected_at=datetime.now(UTC),
        ip_addresses=["10.0.0.10"],
        mac_addresses=["AA:BB:CC:DD:EE:FF"],
        logged_in_users=["alice"],
        tags={"environment": "prod"},
        health=AgentHealth(status="healthy", last_heartbeat=datetime.now(UTC)),
        processes=[
            ProcessSnapshot(
                pid=1234,
                parent_pid=1,
                name="cerebro-agent",
                command="/usr/local/bin/cerebro-agent",
                binary_hash="deadbeef",
                user="alice",
                start_time=datetime.now(UTC),
            )
        ],
        security_events=[
            SecurityEvent(
                event_type="unauthorized_access",
                timestamp=datetime.now(UTC),
                severity="high",
                source_ip="10.1.1.1",
                user_id="alice",
                details={"process": "unknown"},
            )
        ],
        configuration_drift=[
            ConfigurationDrift(
                config_key="os.patch_level",
                expected_value="2025-10",
                actual_value="2025-08",
                drift_type="modified",
            )
        ],
    )

    result = await service.process_host(telemetry)

    assert result["status"] == "processed"
    assert result["host_id"] == "host-123"

    snapshots = (await test_db.execute(select(ConfigSnapshot))).scalars().all()
    assert len(snapshots) == 1
    assert snapshots[0].collector_version == "1.0.0"

    findings = (await test_db.execute(select(Finding))).scalars().all()
    assert findings, "Expected endpoint findings to be created"
    assert all(f.provider == "endpoint" for f in findings)


@pytest.mark.asyncio
async def test_process_host_deduplicates_snapshots(test_db):
    service = TelemetryIngestionService(test_db)

    base_time = datetime.now(UTC)
    telemetry = HostTelemetry(
        organization="Acme",
        host_id="host-123",
        hostname="acme-mbp",
        agent_version="1.0.0",
        os_family="darwin",
        collected_at=base_time,
        ip_addresses=["10.0.0.10"],
        processes=[],
    )

    await service.process_host(telemetry)

    # Second telemetry with same config but newer timestamp should update snapshot
    telemetry_new = telemetry.model_copy(
        update={"collected_at": base_time + timedelta(hours=1)}
    )
    await service.process_host(telemetry_new)

    snapshots = (await test_db.execute(select(ConfigSnapshot))).scalars().all()
    assert len(snapshots) == 1
    saved_at = snapshots[0].captured_at
    if saved_at.tzinfo is None:
        saved_at = saved_at.replace(tzinfo=UTC)
    assert saved_at == telemetry_new.collected_at


@pytest.mark.asyncio
async def test_process_host_events_persists_records(test_db):
    service = TelemetryIngestionService(test_db)

    now = datetime.now(UTC)
    batch = HostEventBatch(
        host_id="host-123",
        hostname="acme-mbp",
        organization="Acme",
        site="HQ",
        agent_version="1.0.0",
        collected_at=now,
        events=[
            HostEvent(
                host_id="host-123",
                hostname="acme-mbp",
                category="process",
                event_type="process_started",
                severity="info",
                timestamp=now,
                process_id=4242,
                parent_pid=1,
                user="alice",
                command_line="/bin/bash",
                source="process_watcher",
                payload={"name": "bash"},
            ),
        ],
    )

    result = await service.process_host_events(batch)

    assert result["status"] == "processed"
    assert result["events_ingested"] == 1

    events = (await test_db.execute(select(HostTelemetryEvent))).scalars().all()
    assert len(events) == 1
    stored = events[0]
    assert stored.host_id == "host-123"
    assert stored.category == "process"
    assert stored.event_type == "process_started"
    assert stored.process_id == 4242


@pytest.mark.asyncio
async def test_list_host_packs_filters_by_selectors(test_db):
    service = TelemetryIngestionService(test_db)

    context = await service._ensure_host_context_from_values(
        host_id="host-123",
        hostname="acme-mbp",
        organization="Acme",
        site="HQ",
    )

    eligible_pack = ArtifactPack(
        org_id=context.org_id,
        name="baseline",
        version="1.0.0",
        selectors={"site": ["HQ"], "tags": {"env": "prod"}},
        approval_state="approved",
        enabled=True,
    )
    eligible_pack.tasks = [
        ArtifactPackTask(
            name="snapshot",
            collector="snapshot.basic",
            interval_seconds=300,
            tags={"env": "prod"},
            discovery=["tag:env=prod"],
            parameters=[{"name": "limit", "type": "int", "default": 10}],
            parameter_values={"limit": 25},
            resources={"timeout_seconds": 60},
            tools=[{"name": "ps", "url": "https://example.com/ps"}],
        )
    ]

    excluded_pack = ArtifactPack(
        org_id=context.org_id,
        name="ops",
        version="1.0.0",
        selectors={"site": ["NYC"], "tags": {"env": "ops"}},
        approval_state="approved",
        enabled=True,
    )
    excluded_pack.tasks = [
        ArtifactPackTask(
            name="process-diff",
            collector="events.process.delta",
            interval_seconds=120,
        )
    ]

    test_db.add_all([eligible_pack, excluded_pack])
    await test_db.commit()

    packs = await service.list_host_packs(
        host_id="host-123",
        hostname="acme-mbp",
        organization="Acme",
        site="HQ",
        tags={"env": "prod"},
    )

    assert len(packs) == 1
    pack = packs[0]
    assert pack.name == "baseline"
    assert len(pack.tasks) == 1
    assert pack.tasks[0].collector == "snapshot.basic"
    assert pack.tasks[0].discovery == ["tag:env=prod"]
    assert pack.tasks[0].parameter_values == {"limit": 25}


@pytest.mark.asyncio
async def test_host_event_trigger_assigns_follow_on_pack(test_db):
    service = TelemetryIngestionService(test_db)

    context = await service._ensure_host_context_from_values(
        host_id="host-999",
        hostname="acme-dc",
        organization="Acme",
        site="HQ",
    )

    follow_on_pack = ArtifactPack(
        org_id=context.org_id,
        name="suspicious-process-response",
        version="1.0.0",
        approval_state="approved",
        enabled=True,
    )
    follow_on_pack.tasks = [
        ArtifactPackTask(
            name="collect-process-tree",
            collector="snapshot.basic",
            interval_seconds=0,
        )
    ]
    follow_on_pack.triggers = [
        ArtifactPackTrigger(
            trigger_type="event_type",
            match_value="process.suspicious",
            minimum_severity="high",
            expires_after_seconds=600,
        )
    ]

    test_db.add(follow_on_pack)
    await test_db.commit()
    await test_db.refresh(follow_on_pack)

    now = datetime.now(UTC)
    batch = HostEventBatch(
        host_id="host-999",
        hostname="acme-dc",
        organization="Acme",
        site="HQ",
        agent_version="1.2.3",
        collected_at=now,
        events=[
            HostEvent(
                host_id="host-999",
                hostname="acme-dc",
                category="process",
                event_type="process.suspicious",
                severity="critical",
                timestamp=now,
                process_id=9001,
                parent_pid=42,
                user="svc",
                command_line="/opt/cerebro/evil",
                source="process_watcher",
                payload={"reason": "rapid encryption"},
            )
        ],
    )

    await service.process_host_events(batch)

    targets = (await test_db.execute(select(ArtifactPackTarget))).scalars().all()
    assert len(targets) == 1
    target = targets[0]
    assert target.pack_id == follow_on_pack.pack_id
    assert target.fulfilled_at is None

    packs = await service.list_host_packs(
        host_id="host-999",
        hostname="acme-dc",
        organization="Acme",
        site="HQ",
        tags={},
    )

    assert packs, "Expected follow-on pack to be distributed"
    assert any(pack.name == "suspicious-process-response" for pack in packs)

    await test_db.refresh(target)
    assert target.fulfilled_at is not None
    await test_db.refresh(follow_on_pack)
    assert follow_on_pack.last_deployed_at is not None

