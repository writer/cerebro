"""Customer registry for tracking account health and lifecycle."""

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Any

import structlog

from ..compliance.models import create_customer_evidence, metadata_to_dict

logger = structlog.get_logger(__name__)


class CustomerSegment(Enum):
    """Standard customer segmentation buckets."""

    ENTERPRISE = "enterprise"
    COMMERCIAL = "commercial"
    SMB = "smb"
    STARTUP = "startup"
    FREE = "free"


class CustomerLifecycleStage(Enum):
    """Lifecycle stages for customer success tracking."""

    PROSPECT = "prospect"
    ONBOARDING = "onboarding"
    ACTIVE = "active"
    AT_RISK = "at_risk"
    EXPANSION = "expansion"
    CHURNED = "churned"


class CustomerHealthBand(Enum):
    """High-level view of customer health categories."""

    HEALTHY = "healthy"
    WATCHLIST = "watchlist"
    AT_RISK = "at_risk"


@dataclass
class Customer:
    """Customer entity enriched with success metrics."""

    customer_id: str
    org_id: str | None
    name: str
    primary_contact: str
    account_manager: str
    segment: CustomerSegment
    industry: str
    region: str
    seats_committed: int
    annual_recurring_revenue: float | None
    product_usage_score: float
    adoption_metrics: dict[str, float]
    support_tickets_open: int
    lifecycle_stage: CustomerLifecycleStage
    health_score: float
    churn_risk_score: float
    health_band: CustomerHealthBand
    last_engagement_at: datetime
    next_qbr_at: datetime | None
    created_at: datetime
    updated_at: datetime
    tags: list[str]
    metadata: dict[str, Any]


class CustomerRegistry:
    """Registry managing customer accounts and success telemetry."""

    def __init__(self):
        self.customers: dict[str, Customer] = {}

    async def register_customer(
        self,
        name: str,
        account_manager: str,
        segment: CustomerSegment,
        created_by: str,
        org_id: str | None = None,
        **customer_data,
    ) -> Customer:
        """Register a new customer with baseline success signals."""

        customer_id = f"customer_{name.lower().replace(' ', '_')}_{int(datetime.now().timestamp())}"
        now = datetime.now()

        lifecycle_stage = customer_data.get(
            "lifecycle_stage", CustomerLifecycleStage.ACTIVE
        )
        if isinstance(lifecycle_stage, str):
            lifecycle_stage = CustomerLifecycleStage(lifecycle_stage)

        last_engagement = customer_data.get("last_engagement_at")
        if not isinstance(last_engagement, datetime):
            last_engagement = now

        next_qbr = customer_data.get("next_qbr_at")
        if next_qbr is None:
            next_qbr = now + timedelta(days=90)

        customer = Customer(
            customer_id=customer_id,
            org_id=org_id,
            name=name,
            primary_contact=customer_data.get("primary_contact", ""),
            account_manager=account_manager,
            segment=segment,
            industry=customer_data.get("industry", ""),
            region=customer_data.get("region", ""),
            seats_committed=customer_data.get("seats_committed", 0),
            annual_recurring_revenue=customer_data.get("annual_recurring_revenue"),
            product_usage_score=customer_data.get("product_usage_score", 0.5),
            adoption_metrics=customer_data.get("adoption_metrics", {}),
            support_tickets_open=customer_data.get("support_tickets_open", 0),
            lifecycle_stage=lifecycle_stage,
            health_score=0.0,
            churn_risk_score=0.0,
            health_band=CustomerHealthBand.WATCHLIST,
            last_engagement_at=last_engagement,
            next_qbr_at=next_qbr,
            created_at=now,
            updated_at=now,
            tags=customer_data.get("tags", []),
            metadata=customer_data.get("metadata", {}),
        )

        self._score_customer_health(customer)
        self._update_customer_metadata(customer, created_by)

        self.customers[customer_id] = customer

        logger.info("Registered customer: %s (%s)", name, customer_id)
        return customer

    def _score_customer_health(self, customer: Customer):
        """Calculate health and churn risk signals from usage and support data."""

        score = customer.product_usage_score
        score -= 0.05 * min(customer.support_tickets_open, 10)

        days_since_engagement = (datetime.now() - customer.last_engagement_at).days
        if days_since_engagement > 30:
            score -= 0.1
        if days_since_engagement > 60:
            score -= 0.15

        score = max(0.0, min(1.0, score))
        customer.health_score = score

        churn_risk = 1 - score
        if customer.support_tickets_open > 5:
            churn_risk += 0.1
        churn_risk = max(0.0, min(1.0, churn_risk))
        customer.churn_risk_score = churn_risk

        if score >= 0.75:
            customer.health_band = CustomerHealthBand.HEALTHY
        elif score >= 0.45:
            customer.health_band = CustomerHealthBand.WATCHLIST
        else:
            customer.health_band = CustomerHealthBand.AT_RISK

        if score < 0.45:
            customer.lifecycle_stage = CustomerLifecycleStage.AT_RISK
        elif score > 0.85:
            customer.lifecycle_stage = CustomerLifecycleStage.EXPANSION

    def _update_customer_metadata(self, customer: Customer, created_by: str):
        """Generate structured metadata envelope for downstream analytics."""

        success_programs = customer.metadata.get("success_programs", [])

        evidence = create_customer_evidence(
            customer_id=customer.customer_id,
            customer_name=customer.name,
            created_by=created_by,
            segment=customer.segment.value,
            industry=customer.industry,
            region=customer.region,
            lifecycle_stage=customer.lifecycle_stage.value,
            health_score=customer.health_score,
            churn_risk_score=customer.churn_risk_score,
            account_manager=customer.account_manager,
            annual_recurring_revenue=customer.annual_recurring_revenue,
            seats_committed=customer.seats_committed,
            adoption_metrics=customer.adoption_metrics,
            last_engagement_at=customer.last_engagement_at,
            next_qbr_at=customer.next_qbr_at,
            support_tickets_open=customer.support_tickets_open,
            advocacy_level="champion" if customer.health_score > 0.8 else "neutral",
            success_programs=success_programs,
            tags={"org_id": customer.org_id} if customer.org_id else None,
        )

        customer.metadata = {
            "evidence": metadata_to_dict(evidence),
            "health": {
                "score": round(customer.health_score, 3),
                "band": customer.health_band.value,
                "churn_risk": round(customer.churn_risk_score, 3),
                "lifecycle_stage": customer.lifecycle_stage.value,
            },
            "adoption": {
                "product_usage_score": round(customer.product_usage_score, 3),
                "metrics": customer.adoption_metrics,
                "seats_committed": customer.seats_committed,
            },
            "engagement": {
                "last_engagement_at": customer.last_engagement_at.isoformat(),
                "next_qbr_at": (
                    customer.next_qbr_at.isoformat() if customer.next_qbr_at else None
                ),
                "open_support_tickets": customer.support_tickets_open,
            },
            "success_programs": success_programs,
            "org_id": customer.org_id,
        }

        tag_updates = {
            f"segment:{customer.segment.value}",
            f"health:{customer.health_band.value}",
            f"lifecycle:{customer.lifecycle_stage.value}",
        }
        if customer.org_id:
            tag_updates.add(f"org:{customer.org_id}")
        customer.tags = sorted({*customer.tags, *tag_updates})

    async def refresh_customer_profile(
        self, customer_id: str, updated_by: str
    ) -> Customer | None:
        """Refresh success telemetry for an existing customer."""

        customer = self.customers.get(customer_id)
        if not customer:
            return None

        self._score_customer_health(customer)
        self._update_customer_metadata(customer, updated_by)
        customer.updated_at = datetime.now()
        return customer

    def get_customers_by_segment(self, segment: CustomerSegment) -> list[Customer]:
        return [
            customer
            for customer in self.customers.values()
            if customer.segment == segment
        ]

    def get_at_risk_customers(self) -> list[Customer]:
        return [
            customer
            for customer in self.customers.values()
            if customer.health_band == CustomerHealthBand.AT_RISK
        ]

    def record_engagement(self, customer_id: str, when: datetime | None = None):
        customer = self.customers.get(customer_id)
        if not customer:
            return

        customer.last_engagement_at = when or datetime.now()
        customer.updated_at = datetime.now()
        self._score_customer_health(customer)
        self._update_customer_metadata(customer, customer.account_manager)

    def update_adoption_metrics(self, customer_id: str, metrics: dict[str, float]):
        customer = self.customers.get(customer_id)
        if not customer:
            return

        customer.adoption_metrics.update(metrics)
        if customer.adoption_metrics:
            customer.product_usage_score = sum(
                customer.adoption_metrics.values()
            ) / len(customer.adoption_metrics)
        else:
            customer.product_usage_score = 0.0
        customer.product_usage_score = max(0.0, min(1.0, customer.product_usage_score))
        self._score_customer_health(customer)
        self._update_customer_metadata(customer, customer.account_manager)


_customer_registry = CustomerRegistry()


def get_customer_registry() -> CustomerRegistry:
    """Return the global customer registry instance."""

    return _customer_registry
