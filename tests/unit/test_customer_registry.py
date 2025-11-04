import pytest
from datetime import datetime, timedelta

from cerebro.customer_management.customer_registry import (
    CustomerLifecycleStage,
    CustomerRegistry,
    CustomerSegment,
)


@pytest.mark.asyncio
async def test_customer_registry_enriches_metadata():
    registry = CustomerRegistry()

    customer = await registry.register_customer(
        name="Galaxy Industries",
        account_manager="csm-jane",
        segment=CustomerSegment.ENTERPRISE,
        created_by="csm-jane",
        org_id="org-1",
        adoption_metrics={"automation": 0.8, "assurance": 0.7},
        support_tickets_open=2,
        last_engagement_at=datetime.now() - timedelta(days=10),
        metadata={"success_programs": ["design_partner"]},
    )

    metadata = customer.metadata
    assert metadata["evidence"]["category"] == "customer_profile"
    assert metadata["evidence"]["customer_id"] == customer.customer_id
    assert metadata["health"]["score"] == pytest.approx(customer.health_score)
    assert metadata["success_programs"] == ["design_partner"]
    assert any(tag.startswith("segment:") for tag in customer.tags)


@pytest.mark.asyncio
async def test_customer_health_transitions_to_at_risk():
    registry = CustomerRegistry()

    customer = await registry.register_customer(
        name="Nebula Systems",
        account_manager="csm-alex",
        segment=CustomerSegment.SMB,
        created_by="csm-alex",
        org_id="org-1",
        adoption_metrics={"automation": 0.3},
        support_tickets_open=7,
        last_engagement_at=datetime.now() - timedelta(days=75),
    )

    await registry.refresh_customer_profile(customer.customer_id, "csm-alex")

    assert customer.metadata["health"]["band"] == "at_risk"
    assert customer.lifecycle_stage == CustomerLifecycleStage.AT_RISK
