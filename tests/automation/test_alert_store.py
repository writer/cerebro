from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

import pytest

from cerebro.automation.alerting import (
    AlertResult,
    AlertRule,
    InMemoryCooldownStore,
    RedisCooldownStore,
    RuleComparison,
    RuleSeverity,
)


def _rule(cooldown_minutes: int = 60) -> AlertRule:
    return AlertRule(
        rule_id="test",
        metric="total_events",
        comparison=RuleComparison.GREATER_THAN,
        threshold=10,
        severity=RuleSeverity.INFO,
        description="test",
        cooldown_minutes=cooldown_minutes,
    )


def _result(rule: AlertRule) -> AlertResult:
    now = datetime.now(timezone.utc)
    return AlertResult(
        rule=rule,
        metric_value=42.0,
        triggered_at=now,
        message="",
        severity=rule.severity,
        channels=rule.channels,
    )


@pytest.mark.asyncio
async def test_redis_cooldown_store_sets_expiration() -> None:
    client = AsyncMock()
    client.exists.return_value = 0

    store = RedisCooldownStore(client)
    rule = _rule(cooldown_minutes=5)
    result = _result(rule)

    suppress = await store.should_suppress(rule, now=result.triggered_at)
    assert suppress is False

    await store.record_fire(result)

    client.set.assert_called_with(
        "telemetry-alert:test",
        result.triggered_at.isoformat(),
        ex=300,
    )


@pytest.mark.asyncio
async def test_in_memory_store_respects_expiration() -> None:
    store = InMemoryCooldownStore()
    rule = _rule(cooldown_minutes=1)
    result = _result(rule)

    suppress_initial = await store.should_suppress(rule, now=result.triggered_at)
    assert suppress_initial is False

    await store.record_fire(result)

    suppress_after = await store.should_suppress(rule, now=result.triggered_at)
    assert suppress_after is True

    future = result.triggered_at + timedelta(minutes=2)
    suppress_future = await store.should_suppress(rule, now=future)
    assert suppress_future is False
