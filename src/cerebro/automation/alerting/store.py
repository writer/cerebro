"""Cooldown storage backends for telemetry alerting."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import redis.asyncio as redis

from .evaluator import AlertCooldownStore
from .results import AlertResult
from .rules import AlertRule


class RedisCooldownStore(AlertCooldownStore):
    """Persist alert cooldowns using Redis expiration semantics."""

    def __init__(
        self,
        client: redis.Redis,
        *,
        prefix: str = "telemetry-alert",
    ) -> None:
        self._client = client
        self._prefix = prefix

    def _key(self, rule: AlertRule) -> str:
        return f"{self._prefix}:{rule.rule_id}"

    async def should_suppress(self, rule: AlertRule, *, now: datetime) -> bool:
        key = self._key(rule)
        exists = await self._client.exists(key)
        return bool(exists)

    async def record_fire(self, result: AlertResult) -> None:
        rule = result.rule
        ttl_seconds = max(0, rule.cooldown_minutes * 60)
        key = self._key(rule)
        value = result.triggered_at.isoformat()
        if ttl_seconds:
            await self._client.set(key, value, ex=ttl_seconds)
        else:
            await self._client.set(key, value)


class InMemoryCooldownStore(AlertCooldownStore):
    """Ephemeral cooldown storage for testing or local development."""

    def __init__(self) -> None:
        self._entries: dict[str, datetime] = {}

    def _key(self, rule: AlertRule) -> str:
        return rule.rule_id

    async def should_suppress(self, rule: AlertRule, *, now: datetime) -> bool:
        key = self._key(rule)
        expires_at = self._entries.get(key)
        if not expires_at:
            return False
        if expires_at <= now:
            self._entries.pop(key, None)
            return False
        return True

    async def record_fire(self, result: AlertResult) -> None:
        rule = result.rule
        if rule.cooldown_minutes <= 0:
            return
        expires_at = result.triggered_at + timedelta(minutes=rule.cooldown_minutes)
        self._entries[self._key(rule)] = expires_at
