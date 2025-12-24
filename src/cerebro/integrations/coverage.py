"""Integration coverage analytics."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import Select, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.automation.integration_sync import analyze_state
from cerebro.core.config import settings
from cerebro.core.models import Account
from cerebro.integrations.state import IntegrationStateRepository

INTEGRATION_PROVIDER_MAPPING: Mapping[str, list[str]] = {
    "kandji": ["kandji"],
    "sentinelone": ["sentinelone"],
}


async def summarize_integration_coverage(
    db: AsyncSession,
    *,
    provider_mapping: Mapping[str, Iterable[str]] | None = None,
    stale_seconds: int | None = None,
) -> list[dict[str, Any]]:
    """Summarize integration coverage against connected accounts."""

    mapping = provider_mapping or INTEGRATION_PROVIDER_MAPPING
    now = datetime.now(UTC)
    threshold = (
        stale_seconds
        if stale_seconds is not None
        else settings.integration_sync_stale_seconds
    )

    repo = IntegrationStateRepository(db)
    states = await repo.list_states()

    grouped_states: dict[str, list[Any]] = defaultdict(list)
    for state in states:
        if state.scope and state.scope.startswith("__"):
            continue
        grouped_states[state.integration].append(state)

    account_stmt: Select = select(
        Account.provider, func.count().label("account_count")
    ).group_by(Account.provider)
    account_rows = await db.execute(account_stmt)
    account_counts: dict[str, int] = {
        row.provider: int(row.account_count or 0) for row in account_rows
    }

    summaries: list[dict[str, Any]] = []
    integrations = set(grouped_states.keys()) | set(mapping.keys())

    for integration in sorted(integrations):
        integration_states = grouped_states.get(integration, [])
        total_scopes = len(integration_states)
        healthy_scopes = 0
        warning_scopes = 0
        critical_scopes = 0
        last_success: datetime | None = None

        for state in integration_states:
            if state.last_timestamp:
                state_ts = state.last_timestamp
                if state_ts.tzinfo is None:
                    state_ts = state_ts.replace(tzinfo=UTC)
                else:
                    state_ts = state_ts.astimezone(UTC)
                if last_success is None or state_ts > last_success:
                    last_success = state_ts

            issue = analyze_state(state, now, threshold)
            if issue is None:
                healthy_scopes += 1
            else:
                if issue.severity == "critical":
                    critical_scopes += 1
                else:
                    warning_scopes += 1

        providers = list(mapping.get(integration, []))
        accounts_total = sum(account_counts.get(provider, 0) for provider in providers)

        if total_scopes == 0:
            status = "not_configured" if accounts_total == 0 else "missing"
        elif critical_scopes > 0:
            status = "critical"
        elif warning_scopes > 0:
            status = "warning"
        else:
            status = "healthy"

        coverage_ratio: float | None = None
        if total_scopes > 0:
            coverage_ratio = healthy_scopes / total_scopes

        summaries.append(
            {
                "integration": integration,
                "providers": providers,
                "status": status,
                "scopes": {
                    "total": total_scopes,
                    "healthy": healthy_scopes,
                    "warning": warning_scopes,
                    "critical": critical_scopes,
                },
                "accounts": {
                    "total": accounts_total,
                },
                "coverage_ratio": coverage_ratio,
                "last_success": last_success,
                "evaluated_at": now,
            }
        )

    return summaries
