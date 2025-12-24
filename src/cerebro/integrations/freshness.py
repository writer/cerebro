"""Helpers for computing integration data freshness indicators."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.core.config import settings
from cerebro.integrations.state import IntegrationStateRepository


def _parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


def _humanize_age(seconds: float | None) -> str | None:
    if seconds is None or seconds < 0:
        return None
    if seconds < 60:
        return f"{int(seconds)}s ago"
    minutes = seconds / 60
    if minutes < 60:
        return f"{round(minutes)}m ago"
    hours = minutes / 60
    if hours < 24:
        return f"{round(hours)}h ago"
    days = hours / 24
    return f"{round(days)}d ago"


PROVIDER_HINTS: dict[str, Sequence[str]] = {
    "aws": ("aws", "guardduty", "securityhub"),
    "okta": ("okta",),
    "github": ("github",),
    "gcp": ("gcp", "google"),
    "azure": ("azure", "microsoft"),
    "kandji": ("kandji",),
    "sentinelone": ("sentinelone",),
}


@dataclass
class IntegrationFreshness:
    integration: str
    scope: str
    last_synced_at: datetime | None
    age_seconds: float | None
    status: str
    warning: str | None
    metadata: dict[str, object]
    confidence: str

    @property
    def age_human(self) -> str | None:
        return _humanize_age(self.age_seconds)


@dataclass
class ProviderFreshness:
    provider: str
    last_synced_at: datetime | None
    age_seconds: float | None
    status: str
    warning: str | None
    sources: list[str]
    confidence: str

    @property
    def age_human(self) -> str | None:
        return _humanize_age(self.age_seconds)


class IntegrationFreshnessService:
    """Derive integration freshness summaries from sync state records."""

    def __init__(
        self, session: AsyncSession, *, stale_seconds: int | None = None
    ) -> None:
        self._session = session
        self._repo = IntegrationStateRepository(session)
        self._stale_seconds = stale_seconds or settings.integration_sync_stale_seconds

    async def list_freshness(self) -> list[IntegrationFreshness]:
        states = await self._repo.list_states()
        now = datetime.now(UTC)

        summaries: list[IntegrationFreshness] = []
        for state in states:
            metadata = dict(state.state_metadata or {})
            last_synced = self._derive_last_synced(state.last_timestamp, metadata)
            age_seconds = (now - last_synced).total_seconds() if last_synced else None
            status = self._classify_status(age_seconds, metadata)
            warning = self._build_warning(status, state.integration, age_seconds)
            confidence = self._infer_confidence(state.integration, metadata)
            summaries.append(
                IntegrationFreshness(
                    integration=state.integration,
                    scope=state.scope,
                    last_synced_at=last_synced,
                    age_seconds=age_seconds,
                    status=status,
                    warning=warning,
                    metadata=metadata,
                    confidence=confidence,
                )
            )
        return summaries

    async def provider_freshness(
        self, providers: Iterable[str]
    ) -> dict[str, ProviderFreshness]:
        integration_freshness = await self.list_freshness()
        provider_map: dict[str, ProviderFreshness] = {}

        for provider in providers:
            hints = PROVIDER_HINTS.get(provider.lower(), (provider.lower(),))
            matches = [
                item
                for item in integration_freshness
                if any(hint in item.integration.lower() for hint in hints)
            ]
            if not matches:
                provider_map[provider] = ProviderFreshness(
                    provider=provider,
                    last_synced_at=None,
                    age_seconds=None,
                    status="unknown",
                    warning=None,
                    sources=[],
                    confidence="low",
                )
                continue

            latest = max(
                matches,
                key=lambda item: item.last_synced_at
                or datetime.fromtimestamp(0, tz=UTC),
            )
            age_seconds = latest.age_seconds
            status = latest.status
            warning = latest.warning
            confidence = self._aggregate_confidence(matches)
            provider_map[provider] = ProviderFreshness(
                provider=provider,
                last_synced_at=latest.last_synced_at,
                age_seconds=age_seconds,
                status=status,
                warning=warning,
                sources=[match.integration for match in matches],
                confidence=confidence,
            )

        # Include any remaining integrations that may be relevant but not explicitly requested
        if not providers:
            for item in integration_freshness:
                provider_map[item.integration] = ProviderFreshness(
                    provider=item.integration,
                    last_synced_at=item.last_synced_at,
                    age_seconds=item.age_seconds,
                    status=item.status,
                    warning=item.warning,
                    sources=[item.integration],
                    confidence=item.confidence,
                )

        return provider_map

    def _derive_last_synced(
        self, last_timestamp: datetime | None, metadata: dict[str, object]
    ) -> datetime | None:
        candidates: list[datetime] = []
        if last_timestamp is not None:
            candidates.append(self._ensure_utc(last_timestamp))

        for key in ("last_success_at", "last_sync_at", "last_status_at"):
            value = metadata.get(key)
            if isinstance(value, str):
                parsed = _parse_datetime(value)
                if parsed is not None:
                    candidates.append(parsed)
        if "last_sync_unix" in metadata:
            try:
                unix_value = float(metadata["last_sync_unix"])  # type: ignore[arg-type]
                candidates.append(datetime.fromtimestamp(unix_value, tz=UTC))
            except (TypeError, ValueError):
                pass

        if not candidates:
            return None
        return max(candidates)

    def _classify_status(
        self, age_seconds: float | None, metadata: dict[str, object]
    ) -> str:
        status_hint = metadata.get("last_status")
        if isinstance(status_hint, str) and status_hint.lower() in {
            "error",
            "disabled",
            "skipped",
        }:
            return status_hint.lower()

        if age_seconds is None:
            return "unknown"
        if age_seconds <= self._stale_seconds:
            return "fresh"
        return "stale"

    def _build_warning(
        self, status: str, integration: str, age_seconds: float | None
    ) -> str | None:
        if status not in {"stale", "error"}:
            return None
        age_text = _humanize_age(age_seconds) if age_seconds is not None else "unknown"
        if status == "stale":
            return f"⚠️ {integration} data is {age_text} old"
        return f"🚨 {integration} sync reported errors"

    @staticmethod
    def _ensure_utc(value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)

    @staticmethod
    def _infer_confidence(integration: str, metadata: dict[str, object]) -> str:
        explicit = metadata.get("data_confidence")
        if isinstance(explicit, str):
            normalized = explicit.lower()
            if normalized in {"high", "medium", "low"}:
                return normalized

        ingestion_method = metadata.get("ingestion_method")
        if isinstance(ingestion_method, str):
            method = ingestion_method.lower()
            if method in {"api", "webhook", "stream"}:
                return "high"
            if method in {"inferred", "calculated"}:
                return "medium"
            if method in {"manual", "user_reported"}:
                return "low"

        if metadata.get("inferred", False):
            return "medium"
        if metadata.get("user_reported", False):
            return "low"

        name = integration.lower()
        if any(token in name for token in ("analytics", "derived", "correlation")):
            return "medium"
        if any(token in name for token in ("manual", "synthetic", "simulation")):
            return "low"
        return "high"

    @staticmethod
    def _aggregate_confidence(matches: list[IntegrationFreshness]) -> str:
        order = {"low": 0, "medium": 1, "high": 2}
        best = "high"
        for item in matches:
            level = order.get(item.confidence, 2)
            if level < order.get(best, 2):
                best = item.confidence
        return best
