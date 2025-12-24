from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from cerebro.integrations.freshness import IntegrationFreshnessService
from cerebro.integrations.state import IntegrationStateRepository

UTC = UTC


@pytest.mark.asyncio()
async def test_freshness_service_marks_stale(test_db):
    repo = IntegrationStateRepository(test_db)
    now = datetime.now(UTC)
    await repo.upsert_state(
        integration="sentinelone.activities",
        scope="default",
        last_timestamp=now - timedelta(hours=2),
        metadata={"last_status": "ok"},
    )
    await test_db.commit()

    service = IntegrationFreshnessService(test_db, stale_seconds=1800)
    summaries = await service.list_freshness()
    by_integration = {record.integration: record for record in summaries}

    assert "sentinelone.activities" in by_integration
    record = by_integration["sentinelone.activities"]
    assert record.status == "stale"
    assert record.age_seconds and record.age_seconds > 1800
    assert record.confidence == "high"


@pytest.mark.asyncio()
async def test_provider_freshness_collapses_multiple_states(test_db):
    repo = IntegrationStateRepository(test_db)
    now = datetime.now(UTC)

    await repo.upsert_state(
        integration="kandji.vulnerabilities",
        scope="tenant-a",
        last_timestamp=now - timedelta(minutes=5),
        metadata={"last_status": "ok"},
    )
    await repo.upsert_state(
        integration="kandji.patch",
        scope="tenant-a",
        last_timestamp=now - timedelta(minutes=15),
        metadata={"last_status": "ok"},
    )
    await test_db.commit()

    service = IntegrationFreshnessService(test_db, stale_seconds=3600)
    provider_map = await service.provider_freshness(["kandji"])

    assert "kandji" in provider_map
    summary = provider_map["kandji"]
    assert summary.status == "fresh"
    assert summary.last_synced_at is not None
    assert "kandji.vulnerabilities" in summary.sources
    assert summary.confidence == "high"


@pytest.mark.asyncio()
async def test_freshness_confidence_overrides(test_db):
    repo = IntegrationStateRepository(test_db)
    now = datetime.now(UTC)
    await repo.upsert_state(
        integration="analytics.derived_insights",
        scope="default",
        last_timestamp=now - timedelta(minutes=10),
        metadata={"data_confidence": "medium"},
    )
    await repo.upsert_state(
        integration="user_reported.feedback",
        scope="default",
        last_timestamp=now - timedelta(minutes=5),
        metadata={"user_reported": True},
    )
    await test_db.commit()

    service = IntegrationFreshnessService(test_db, stale_seconds=3600)
    summaries = await service.list_freshness()
    confidence_map = {item.integration: item.confidence for item in summaries}

    assert confidence_map.get("analytics.derived_insights") == "medium"
    assert confidence_map.get("user_reported.feedback") == "low"
