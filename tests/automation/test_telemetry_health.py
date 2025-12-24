from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from cerebro.automation.telemetry_health import (
    evaluate_health_thresholds,
    fetch_telemetry_health,
)
from cerebro.core.models import FrontendObservationEvent


@pytest.mark.asyncio
async def test_fetch_telemetry_health_counts(test_db, test_org, test_user):
    now = datetime.now(UTC)

    event = FrontendObservationEvent(
        event_id=uuid4(),
        org_id=test_org.org_id,
        user_id=test_user.user_id,
        agent_session_id=None,
        event_type="page_view",
        component="Dashboard",
        context_data={"pathname": "/dashboard"},
        event_metadata={"source": "unit-test"},
        occurred_at=now - timedelta(hours=1),
    )
    test_db.add(event)
    await test_db.commit()

    snapshot = await fetch_telemetry_health(window_days=1, db_session=test_db)

    assert snapshot.total_events == 1
    assert snapshot.unique_orgs == 1
    assert snapshot.events_by_type["page_view"] == 1
    assert snapshot.missing_metadata == 0


@pytest.mark.asyncio
async def test_evaluate_health_thresholds_flags_issue(test_db, test_org, test_user):
    now = datetime.now(UTC)

    for _ in range(10):
        event = FrontendObservationEvent(
            event_id=uuid4(),
            org_id=test_org.org_id,
            user_id=test_user.user_id,
            agent_session_id=None,
            event_type="filter_apply",
            component=None,
            context_data={},
            event_metadata=None,
            occurred_at=now - timedelta(minutes=5),
        )
        test_db.add(event)
    await test_db.commit()

    snapshot = await fetch_telemetry_health(window_days=1, db_session=test_db)

    issues = evaluate_health_thresholds(
        snapshot,
        max_missing_metadata_ratio=0.1,
        max_missing_component_ratio=0.1,
        min_total_events=1,
    )

    assert any("missing_metadata_ratio" in issue for issue in issues)
    assert any("missing_component_ratio" in issue for issue in issues)
