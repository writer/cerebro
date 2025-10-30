"""Analytics testing harnesses for Cerebro SDK clients."""

from __future__ import annotations

from datetime import datetime
from typing import Iterable, Sequence

from cerebro_sdk.analytics import (
    IntegrationAccountSummary,
    IntegrationCoverageClient,
    IntegrationCoverageRecord,
    IntegrationScopeBreakdown,
    RuntimeEventAggregate,
    RuntimeHealthClient,
    RuntimeHealthRecord,
    RuntimeMetadataSnapshot,
)


def build_runtime_health_record(
    runtime: str,
    *,
    window_start: datetime,
    window_end: datetime,
    events: dict[str, RuntimeEventAggregate] | None = None,
    warnings: dict[str, RuntimeEventAggregate] | None = None,
    metadata: RuntimeMetadataSnapshot | None = None,
) -> RuntimeHealthRecord:
    return RuntimeHealthRecord(
        runtime=runtime,
        window_start=window_start,
        window_end=window_end,
        events=events or {},
        warnings=warnings or {},
        latest_metadata=metadata,
    )


def build_integration_coverage_record(
    integration: str,
    *,
    providers: Iterable[str],
    status: str,
    scopes: IntegrationScopeBreakdown,
    accounts: IntegrationAccountSummary,
    coverage_ratio: float | None,
    last_success: datetime | None,
    evaluated_at: datetime,
) -> IntegrationCoverageRecord:
    return IntegrationCoverageRecord(
        integration=integration,
        providers=list(providers),
        status=status,
        scopes=scopes,
        accounts=accounts,
        coverage_ratio=coverage_ratio,
        last_success=last_success,
        evaluated_at=evaluated_at,
    )


class StubRuntimeHealthClient(RuntimeHealthClient):
    """In-memory runtime health client returning pre-canned records."""

    _records: Sequence[RuntimeHealthRecord]

    def __init__(self, records: Sequence[RuntimeHealthRecord]) -> None:
        # type: ignore[call-arg] - parent expects AsyncSession but stubbing for tests
        self._records = list(records)

    async def summarize(self, *, hours: int = 24):  # type: ignore[override]
        return list(self._records)


class StubIntegrationCoverageClient(IntegrationCoverageClient):
    """In-memory integration coverage client returning static responses."""

    _records: Sequence[IntegrationCoverageRecord]

    def __init__(self, records: Sequence[IntegrationCoverageRecord]) -> None:
        # type: ignore[call-arg]
        self._records = list(records)

    async def summarize(
        self,
        *,
        provider_mapping=None,  # type: ignore[override]
        stale_seconds=None,
    ):
        return list(self._records)


__all__ = [
    "StubRuntimeHealthClient",
    "StubIntegrationCoverageClient",
    "build_runtime_health_record",
    "build_integration_coverage_record",
]
