import pytest

from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock

from sqlalchemy.ext.asyncio import AsyncSession

from cerebro_sdk.analytics import (
    IntegrationCoverageClient,
    IntegrationCoverageRecord,
    IntegrationScopeBreakdown,
    IntegrationAccountSummary,
)


pytestmark = pytest.mark.asyncio


async def test_integration_coverage_client_summarize(monkeypatch):
    fake_db = AsyncMock(spec=AsyncSession)
    client = IntegrationCoverageClient(fake_db)

    evaluated_at = datetime.now(timezone.utc)
    last_success = evaluated_at - timedelta(hours=1)

    service_payload = [
        {
            "integration": "kandji",
            "providers": ["kandji"],
            "status": "healthy",
            "scopes": {
                "total": 4,
                "healthy": 4,
                "warning": 0,
                "critical": 0,
            },
            "accounts": {"total": 3},
            "coverage_ratio": 1.0,
            "last_success": last_success,
            "evaluated_at": evaluated_at,
        }
    ]

    summarize_mock = AsyncMock(return_value=service_payload)
    monkeypatch.setattr(
        "cerebro_sdk.analytics.summarize_integration_coverage",
        summarize_mock,
    )

    records = await client.summarize()

    assert records == [
        IntegrationCoverageRecord(
            integration="kandji",
            providers=["kandji"],
            status="healthy",
            scopes=IntegrationScopeBreakdown(total=4, healthy=4, warning=0, critical=0),
            accounts=IntegrationAccountSummary(total=3),
            coverage_ratio=1.0,
            last_success=last_success,
            evaluated_at=evaluated_at,
        )
    ]

    summarize_mock.assert_awaited_once_with(fake_db, provider_mapping=None, stale_seconds=None)


async def test_integration_coverage_client_skips_invalid_records(monkeypatch):
    fake_db = AsyncMock(spec=AsyncSession)
    client = IntegrationCoverageClient(fake_db)

    summarize_mock = AsyncMock(
        return_value=[
            {"integration": "missing_time"},
            {
                "integration": "partial",
                "evaluated_at": "not-a-datetime",
            },
        ]
    )
    monkeypatch.setattr(
        "cerebro_sdk.analytics.summarize_integration_coverage",
        summarize_mock,
    )

    records = await client.summarize()

    assert records == []
    summarize_mock.assert_awaited_once_with(fake_db, provider_mapping=None, stale_seconds=None)
