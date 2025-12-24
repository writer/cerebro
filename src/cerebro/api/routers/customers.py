"""Customer management API endpoints."""

from datetime import datetime
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator

from ...api.auth import User, require_read_findings
from ...api.org_access import require_org_access
from ...core.database import get_db
from ...core.models import Organization
from ...customer_management.customer_registry import (
    CustomerLifecycleStage,
    CustomerRegistry,
    CustomerSegment,
    get_customer_registry,
)

router = APIRouter()


class CustomerCreateRequest(BaseModel):
    """Request payload for registering a customer."""

    name: str = Field(..., description="Customer name")
    account_manager: str = Field(..., description="Primary account manager email")
    primary_contact: str | None = Field(
        None, description="Primary customer contact email"
    )
    segment: str = Field(..., description="Customer segment identifier")
    industry: str | None = None
    region: str | None = None
    seats_committed: int | None = Field(None, ge=0)
    annual_recurring_revenue: float | None = Field(None, ge=0)
    adoption_metrics: dict[str, float] = Field(default_factory=dict)
    support_tickets_open: int = Field(0, ge=0)
    lifecycle_stage: str | None = Field(None, description="Lifecycle stage override")
    last_engagement_at: datetime | None = None
    next_qbr_at: datetime | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    success_programs: list[str] = Field(default_factory=list)

    @field_validator("segment")
    @classmethod
    def validate_segment(cls, value: str) -> str:
        try:
            CustomerSegment(value.lower())
        except ValueError as exc:
            raise ValueError(f"Unsupported customer segment: {value}") from exc
        return value.lower()

    @field_validator("lifecycle_stage")
    @classmethod
    def validate_lifecycle_stage(cls, value: str | None) -> str | None:
        if value is None:
            return value
        try:
            CustomerLifecycleStage(value.lower())
        except ValueError as exc:
            raise ValueError(f"Unsupported lifecycle stage: {value}") from exc
        return value.lower()


class CustomerResponse(BaseModel):
    """Serialized customer metadata envelope."""

    customerId: str
    name: str
    segment: str
    lifecycleStage: str
    healthScore: float
    churnRiskScore: float
    accountManager: str
    supportTicketsOpen: int
    metadata: dict[str, Any]


def _serialize_customer(customer) -> CustomerResponse:
    metadata = customer.metadata or {}
    evidence = metadata.get("evidence", {})
    return CustomerResponse(
        customerId=customer.customer_id,
        name=customer.name,
        segment=customer.segment.value,
        lifecycleStage=customer.lifecycle_stage.value,
        healthScore=customer.health_score,
        churnRiskScore=customer.churn_risk_score,
        accountManager=customer.account_manager,
        supportTicketsOpen=customer.support_tickets_open,
        metadata={
            **metadata,
            "evidence": evidence,
        },
    )


@router.post("/organizations/{org_id}/customers")
async def register_customer(
    org_id: UUID,
    request: CustomerCreateRequest,
    db=Depends(get_db),
    current_user: User = Depends(require_org_access(require_read_findings)),
):
    """Register a customer in the success registry."""

    organization = await db.get(Organization, org_id)
    if not organization:
        raise HTTPException(status_code=404, detail="Organization not found")

    registry: CustomerRegistry = get_customer_registry()
    segment = CustomerSegment(request.segment)
    lifecycle_stage = (
        CustomerLifecycleStage(request.lifecycle_stage)
        if request.lifecycle_stage
        else CustomerLifecycleStage.ACTIVE
    )

    customer = await registry.register_customer(
        name=request.name,
        account_manager=request.account_manager,
        segment=segment,
        created_by=current_user.username,
        org_id=str(org_id),
        primary_contact=request.primary_contact,
        industry=request.industry,
        region=request.region,
        seats_committed=request.seats_committed,
        annual_recurring_revenue=request.annual_recurring_revenue,
        adoption_metrics=request.adoption_metrics,
        support_tickets_open=request.support_tickets_open,
        lifecycle_stage=lifecycle_stage,
        last_engagement_at=request.last_engagement_at,
        next_qbr_at=request.next_qbr_at,
        metadata={**request.metadata, "created_by": current_user.username},
        success_programs=request.success_programs,
    )

    return {
        "success": True,
        "customer_id": customer.customer_id,
        "lifecycle_stage": customer.lifecycle_stage.value,
    }


@router.get("/organizations/{org_id}/customers")
async def list_customers(
    org_id: UUID,
    db=Depends(get_db),
    current_user: User = Depends(require_org_access(require_read_findings)),
):
    """List customers with health summaries."""

    organization = await db.get(Organization, org_id)
    if not organization:
        raise HTTPException(status_code=404, detail="Organization not found")

    registry: CustomerRegistry = get_customer_registry()
    customers = [
        customer
        for customer in registry.customers.values()
        if customer.org_id in {None, str(org_id)}
    ]

    return {
        "count": len(customers),
        "customers": [
            _serialize_customer(customer).model_dump() for customer in customers
        ],
    }


@router.get("/organizations/{org_id}/customers/{customer_id}")
async def get_customer(
    org_id: UUID,
    customer_id: str,
    db=Depends(get_db),
    current_user: User = Depends(require_org_access(require_read_findings)),
):
    """Retrieve a single customer record."""

    organization = await db.get(Organization, org_id)
    if not organization:
        raise HTTPException(status_code=404, detail="Organization not found")

    registry: CustomerRegistry = get_customer_registry()
    customer = registry.customers.get(customer_id)
    if not customer or (customer.org_id and customer.org_id != str(org_id)):
        raise HTTPException(status_code=404, detail="Customer not found")

    return _serialize_customer(customer).model_dump()
