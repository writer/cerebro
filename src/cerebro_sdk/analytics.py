"""Analytics helpers for the Cerebro SDK."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.analytics.runtime_health import summarize_runtime_health
from cerebro.integrations.coverage import summarize_integration_coverage


@dataclass
class RuntimeEventAggregate:
    """Aggregated event counts for a runtime channel."""

    count: int
    last_seen: datetime | None


@dataclass
class RuntimeMetadataSnapshot:
    """Latest metadata payload emitted by a runtime backend."""

    payload: dict[str, Any]
    captured_at: datetime


@dataclass
class RuntimeHealthRecord:
    """Summarized runtime health diagnostics for a backend."""

    runtime: str
    window_start: datetime
    window_end: datetime
    events: dict[str, RuntimeEventAggregate]
    warnings: dict[str, RuntimeEventAggregate]
    latest_metadata: RuntimeMetadataSnapshot | None


class RuntimeHealthClient:
    """Query runtime health analytics derived from agent telemetry."""

    def __init__(self, db: AsyncSession) -> None:
        self._db = db

    async def summarize(self, *, hours: int = 24) -> list[RuntimeHealthRecord]:
        """Return runtime health rollups for the requested window."""

        raw_records = await summarize_runtime_health(self._db, hours=hours)

        summary: list[RuntimeHealthRecord] = []
        for payload in raw_records:
            events = {
                name: RuntimeEventAggregate(
                    count=int(details.get("count", 0) or 0),
                    last_seen=details.get("last_seen"),
                )
                for name, details in (payload.get("events") or {}).items()
            }
            warnings = {
                name: RuntimeEventAggregate(
                    count=int(details.get("count", 0) or 0),
                    last_seen=details.get("last_seen"),
                )
                for name, details in (payload.get("warnings") or {}).items()
            }

            metadata = None
            metadata_payload = payload.get("latest_metadata")
            if metadata_payload and metadata_payload.get("captured_at") is not None:
                metadata = RuntimeMetadataSnapshot(
                    payload=dict(metadata_payload.get("payload") or {}),
                    captured_at=metadata_payload["captured_at"],
                )

            window_start = payload.get("window_start")
            window_end = payload.get("window_end")
            if not isinstance(window_start, datetime) or not isinstance(
                window_end, datetime
            ):
                continue

            summary.append(
                RuntimeHealthRecord(
                    runtime=payload.get("runtime") or "unknown",
                    window_start=window_start,
                    window_end=window_end,
                    events=events,
                    warnings=warnings,
                    latest_metadata=metadata,
                )
            )

        return summary


@dataclass
class IntegrationScopeBreakdown:
    total: int
    healthy: int
    warning: int
    critical: int


@dataclass
class IntegrationAccountSummary:
    total: int


@dataclass
class IntegrationCoverageRecord:
    integration: str
    providers: list[str]
    status: str
    scopes: IntegrationScopeBreakdown
    accounts: IntegrationAccountSummary
    coverage_ratio: float | None
    last_success: datetime | None
    evaluated_at: datetime


class IntegrationCoverageClient:
    """Summarize integration sync coverage for connected accounts."""

    def __init__(self, db: AsyncSession) -> None:
        self._db = db

    async def summarize(
        self,
        *,
        provider_mapping: Mapping[str, Iterable[str]] | None = None,
        stale_seconds: int | None = None,
    ) -> list[IntegrationCoverageRecord]:
        raw_records = await summarize_integration_coverage(
            self._db,
            provider_mapping=provider_mapping,
            stale_seconds=stale_seconds,
        )

        summary: list[IntegrationCoverageRecord] = []
        for payload in raw_records:
            scopes = payload.get("scopes") or {}
            accounts = payload.get("accounts") or {}

            breakdown = IntegrationScopeBreakdown(
                total=int(scopes.get("total", 0) or 0),
                healthy=int(scopes.get("healthy", 0) or 0),
                warning=int(scopes.get("warning", 0) or 0),
                critical=int(scopes.get("critical", 0) or 0),
            )

            account_summary = IntegrationAccountSummary(
                total=int(accounts.get("total", 0) or 0),
            )

            evaluated_at = payload.get("evaluated_at")
            if not isinstance(evaluated_at, datetime):
                continue

            summary.append(
                IntegrationCoverageRecord(
                    integration=(
                        str(payload.get("integration"))
                        if payload.get("integration")
                        else "unknown"
                    ),
                    providers=list(payload.get("providers") or []),
                    status=str(payload.get("status") or "unknown"),
                    scopes=breakdown,
                    accounts=account_summary,
                    coverage_ratio=(
                        float(payload.get("coverage_ratio") or 0)
                        if payload.get("coverage_ratio") is not None
                        else None
                    ),
                    last_success=payload.get("last_success"),
                    evaluated_at=evaluated_at,
                )
            )

        return summary


__all__ = [
    "IntegrationAccountSummary",
    "IntegrationCoverageClient",
    "IntegrationCoverageRecord",
    "IntegrationScopeBreakdown",
    "RuntimeEventAggregate",
    "RuntimeHealthClient",
    "RuntimeHealthRecord",
    "RuntimeMetadataSnapshot",
]
