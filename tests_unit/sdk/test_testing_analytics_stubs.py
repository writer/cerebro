from datetime import datetime, timezone, timedelta

import pytest

from cerebro_sdk.analytics import (
    IntegrationAccountSummary,
    IntegrationScopeBreakdown,
    RuntimeEventAggregate,
    RuntimeMetadataSnapshot,
)
from cerebro_sdk.testing import (
    StubIntegrationCoverageClient,
    StubRuntimeHealthClient,
    build_integration_coverage_record,
    build_runtime_health_record,
)


pytestmark = pytest.mark.asyncio


async def test_stub_runtime_health_client_returns_records():
    now = datetime.now(timezone.utc)
    record = build_runtime_health_record(
        "runtime",
        window_start=now - timedelta(hours=1),
        window_end=now,
        events={"runtime_warning": RuntimeEventAggregate(count=2, last_seen=now)},
        metadata=RuntimeMetadataSnapshot(payload={"region": "us"}, captured_at=now),
    )
    client = StubRuntimeHealthClient([record])
    results = await client.summarize()
    assert results == [record]


async def test_stub_integration_coverage_client_returns_records():
    now = datetime.now(timezone.utc)
    record = build_integration_coverage_record(
        "kandji",
        providers=["kandji"],
        status="healthy",
        scopes=IntegrationScopeBreakdown(total=2, healthy=2, warning=0, critical=0),
        accounts=IntegrationAccountSummary(total=1),
        coverage_ratio=1.0,
        last_success=now - timedelta(minutes=5),
        evaluated_at=now,
    )
    client = StubIntegrationCoverageClient([record])
    results = await client.summarize()
    assert results == [record]
