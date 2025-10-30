import pytest

from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock

from sqlalchemy.ext.asyncio import AsyncSession

from cerebro_sdk.analytics import (
    RuntimeHealthClient,
    RuntimeEventAggregate,
    RuntimeMetadataSnapshot,
)


pytestmark = pytest.mark.asyncio


async def test_runtime_health_client_summarize(monkeypatch):
    fake_db = AsyncMock(spec=AsyncSession)
    client = RuntimeHealthClient(fake_db)

    now = datetime.now(timezone.utc)
    window_start = now - timedelta(hours=12)

    service_payload = [
        {
            "runtime": "bedrock",
            "window_start": window_start,
            "window_end": now,
            "events": {
                "runtime_warning": {
                    "count": 3,
                    "last_seen": now - timedelta(hours=1),
                }
            },
            "warnings": {
                "model_latency": {
                    "count": 2,
                    "last_seen": now - timedelta(minutes=45),
                }
            },
            "latest_metadata": {
                "payload": {"region": "us-east-1"},
                "captured_at": now - timedelta(minutes=5),
            },
        }
    ]

    summarize_mock = AsyncMock(return_value=service_payload)
    monkeypatch.setattr(
        "cerebro_sdk.analytics.summarize_runtime_health",
        summarize_mock,
    )

    records = await client.summarize(hours=12)

    assert len(records) == 1
    record = records[0]
    assert record.runtime == "bedrock"
    assert record.window_start == window_start
    assert record.window_end == now
    assert record.events["runtime_warning"] == RuntimeEventAggregate(
        count=3,
        last_seen=service_payload[0]["events"]["runtime_warning"]["last_seen"],
    )
    assert record.warnings["model_latency"] == RuntimeEventAggregate(
        count=2,
        last_seen=service_payload[0]["warnings"]["model_latency"]["last_seen"],
    )
    assert record.latest_metadata == RuntimeMetadataSnapshot(
        payload={"region": "us-east-1"},
        captured_at=service_payload[0]["latest_metadata"]["captured_at"],
    )

    summarize_mock.assert_awaited_once_with(fake_db, hours=12)


async def test_runtime_health_client_skips_incomplete_records(monkeypatch):
    fake_db = AsyncMock(spec=AsyncSession)
    client = RuntimeHealthClient(fake_db)

    summarize_mock = AsyncMock(
        return_value=[
            {"runtime": "missing_window"},
            {
                "runtime": "partial",
                "window_start": datetime.now(timezone.utc),
                "window_end": None,
            },
        ]
    )
    monkeypatch.setattr(
        "cerebro_sdk.analytics.summarize_runtime_health",
        summarize_mock,
    )

    records = await client.summarize()

    assert records == []
    summarize_mock.assert_awaited_once_with(fake_db, hours=24)
