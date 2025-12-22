"""Security Center integration endpoints."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from ...core.database import get_db
from ...core.models import Organization
from ...api.auth import User, require_read_findings
from ...api.org_access import require_org_access
from ...vendor_management.vendor_registry import (
    get_vendor_registry,
    Vendor,
    VendorRiskLevel,
)
from ...customer_management.customer_registry import (
    get_customer_registry,
    Customer,
    CustomerHealthBand,
)


router = APIRouter()


class DashboardMetric(BaseModel):
    label: str
    value: float | int | str
    trend: str


class RecentActivityEntry(BaseModel):
    name: str
    status: str
    timestamp: str


class UpcomingExpirationEntry(BaseModel):
    control: str
    owner: str
    due: str


class SubmissionSummary(BaseModel):
    id: str
    documentId: str
    question: str
    ownerEmail: str
    ownerTeam: str
    submittedAt: str
    status: str
    knowledgeBaseType: str
    infoSecApprover: Optional[str] = None
    dueDate: Optional[str] = None
    requiresApproval: bool = True
    autoReleaseEligible: bool = False
    kbSummary: Optional[str] = None
    requesterEmail: Optional[str] = None


class VendorInsight(BaseModel):
    vendorId: str
    name: str
    category: str
    riskLevel: str
    inherentRiskScore: float
    residualRiskScore: float
    lifecycleStage: str
    nextReviewDue: Optional[str]
    businessCriticality: str
    metadata: Dict[str, Any]


class CustomerInsight(BaseModel):
    customerId: str
    name: str
    segment: str
    healthBand: str
    healthScore: float
    churnRiskScore: float
    lifecycleStage: str
    accountManager: str
    nextQbrAt: Optional[str]
    lastEngagementAt: Optional[str]
    metadata: Dict[str, Any]


class SecurityCenterOverview(BaseModel):
    metrics: List[DashboardMetric]
    recentActivity: List[RecentActivityEntry]
    upcomingExpirations: List[UpcomingExpirationEntry]
    submissions: List[SubmissionSummary]
    vendorInsights: List[VendorInsight]
    customerInsights: List[CustomerInsight]


def _filter_vendors_by_org(
    vendors: List[Vendor], org_id: Optional[str]
) -> List[Vendor]:
    if org_id is None:
        return vendors
    return [vendor for vendor in vendors if vendor.org_id in {None, org_id}]


def _filter_customers_by_org(
    customers: List[Customer], org_id: Optional[str]
) -> List[Customer]:
    if org_id is None:
        return customers
    return [customer for customer in customers if customer.org_id in {None, org_id}]


def _format_timestamp(dt: Optional[datetime]) -> Optional[str]:
    if not dt:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def _build_metrics(
    vendors: List[Vendor], customers: List[Customer]
) -> List[DashboardMetric]:
    critically_scored = sum(
        1
        for vendor in vendors
        if vendor.risk_level in {VendorRiskLevel.HIGH, VendorRiskLevel.CRITICAL}
    )
    overdue_reviews = sum(
        1 for vendor in vendors if vendor.next_review_due < datetime.now()
    )

    at_risk_customers = sum(
        1
        for customer in customers
        if customer.health_band == CustomerHealthBand.AT_RISK
    )
    qbr_soon = sum(
        1
        for customer in customers
        if customer.next_qbr_at
        and 0 <= (customer.next_qbr_at - datetime.now()).days <= 45
    )

    watchlist_customers = sum(
        1
        for customer in customers
        if customer.health_band == CustomerHealthBand.WATCHLIST
    )

    return [
        DashboardMetric(
            label="High-risk vendors",
            value=critically_scored,
            trend=f"{overdue_reviews} overdue reviews",
        ),
        DashboardMetric(
            label="Customers at risk",
            value=at_risk_customers,
            trend=f"{qbr_soon} QBRs within 45 days",
        ),
        DashboardMetric(
            label="Customer watchlist",
            value=watchlist_customers,
            trend=f"{len(vendors)} vendors tracked",
        ),
    ]


def _build_recent_activity(
    vendors: List[Vendor], customers: List[Customer]
) -> List[RecentActivityEntry]:
    events: List[RecentActivityEntry] = []
    for vendor in sorted(vendors, key=lambda v: v.updated_at, reverse=True)[:3]:
        events.append(
            RecentActivityEntry(
                name=f"Vendor risk review · {vendor.name}",
                status=f"Risk level {vendor.risk_level.value.title()} · residual {vendor.residual_risk_score:.2f}",
                timestamp=vendor.updated_at.strftime("%b %d · %H:%M"),
            )
        )

    for customer in sorted(customers, key=lambda c: c.updated_at, reverse=True)[:3]:
        events.append(
            RecentActivityEntry(
                name=f"Customer health update · {customer.name}",
                status=f"Health {customer.health_band.value.replace('_', ' ')}",
                timestamp=customer.updated_at.strftime("%b %d · %H:%M"),
            )
        )

    return events[:6]


def _build_upcoming_expirations(
    vendors: List[Vendor], customers: List[Customer]
) -> List[UpcomingExpirationEntry]:
    upcoming: List[UpcomingExpirationEntry] = []
    now = datetime.now()
    for vendor in vendors:
        if vendor.next_review_due >= now:
            upcoming.append(
                UpcomingExpirationEntry(
                    control=f"Vendor review · {vendor.name}",
                    owner=vendor.primary_contact or vendor.created_by,
                    due=vendor.next_review_due.strftime("%b %d"),
                )
            )

    for customer in customers:
        if customer.next_qbr_at and customer.next_qbr_at >= now:
            upcoming.append(
                UpcomingExpirationEntry(
                    control=f"Customer QBR · {customer.name}",
                    owner=customer.account_manager,
                    due=customer.next_qbr_at.strftime("%b %d"),
                )
            )

    upcoming.sort(key=lambda item: datetime.strptime(item.due, "%b %d"))
    return upcoming[:6]


def _build_submissions(
    vendors: List[Vendor], customers: List[Customer]
) -> List[SubmissionSummary]:
    submissions: List[SubmissionSummary] = []
    now = datetime.now(timezone.utc)
    for vendor in vendors[:3]:
        submissions.append(
            SubmissionSummary(
                id=f"vendor_review_{vendor.vendor_id}",
                documentId=vendor.vendor_id,
                question=f"Revalidate risk assessment for {vendor.name}",
                ownerEmail=vendor.primary_contact or vendor.created_by,
                ownerTeam="security-operations",
                submittedAt=now.isoformat(),
                status="pending",
                knowledgeBaseType="known",
                infoSecApprover="infosec-duty",
                dueDate=_format_timestamp(vendor.next_review_due),
                requiresApproval=True,
                autoReleaseEligible=vendor.risk_level
                in {VendorRiskLevel.LOW, VendorRiskLevel.MEDIUM},
                kbSummary=f"Latest assessment {vendor.last_assessment_date.strftime('%Y-%m-%d')}",
                requesterEmail="security-tech@writer.com",
            )
        )

    for customer in customers[:3]:
        submissions.append(
            SubmissionSummary(
                id=f"customer_health_{customer.customer_id}",
                documentId=customer.customer_id,
                question=f"Update customer health snapshot for {customer.name}",
                ownerEmail=customer.account_manager,
                ownerTeam="customer-success",
                submittedAt=now.isoformat(),
                status=(
                    "pending"
                    if customer.health_band != CustomerHealthBand.HEALTHY
                    else "approved"
                ),
                knowledgeBaseType=(
                    "draft"
                    if customer.health_band == CustomerHealthBand.AT_RISK
                    else "known"
                ),
                infoSecApprover="trust-center",
                dueDate=_format_timestamp(customer.next_qbr_at),
                requiresApproval=customer.health_band != CustomerHealthBand.HEALTHY,
                autoReleaseEligible=customer.health_band == CustomerHealthBand.HEALTHY,
                kbSummary=(
                    "Customer flagged on watchlist"
                    if customer.health_band == CustomerHealthBand.WATCHLIST
                    else "Healthy customer automation"
                ),
                requesterEmail=customer.primary_contact
                or "customer-success@writer.com",
            )
        )

    return submissions[:6]


def _serialize_vendor(vendor: Vendor) -> VendorInsight:
    metadata = vendor.metadata or {}
    return VendorInsight(
        vendorId=vendor.vendor_id,
        name=vendor.name,
        category=vendor.category.value,
        riskLevel=vendor.risk_level.value,
        inherentRiskScore=vendor.inherent_risk_score,
        residualRiskScore=vendor.residual_risk_score,
        lifecycleStage=metadata.get("lifecycle_stage", "active"),
        nextReviewDue=_format_timestamp(vendor.next_review_due),
        businessCriticality=vendor.business_criticality,
        metadata=metadata,
    )


def _serialize_customer(customer: Customer) -> CustomerInsight:
    metadata = customer.metadata or {}
    return CustomerInsight(
        customerId=customer.customer_id,
        name=customer.name,
        segment=customer.segment.value,
        healthBand=customer.health_band.value,
        healthScore=customer.health_score,
        churnRiskScore=customer.churn_risk_score,
        lifecycleStage=customer.lifecycle_stage.value,
        accountManager=customer.account_manager,
        nextQbrAt=_format_timestamp(customer.next_qbr_at),
        lastEngagementAt=_format_timestamp(customer.last_engagement_at),
        metadata=metadata,
    )


@router.get("/organizations/{org_id}/overview")
async def get_security_center_overview(
    org_id: UUID,
    db=Depends(get_db),
    current_user: User = Depends(require_org_access(require_read_findings)),
):
    """Return aggregated dashboard data for the Writer Security Center."""

    organization = await db.get(Organization, org_id)
    if not organization:
        raise HTTPException(status_code=404, detail="Organization not found")

    vendor_registry = get_vendor_registry()
    customer_registry = get_customer_registry()

    org_key = str(org_id)
    vendors = _filter_vendors_by_org(list(vendor_registry.vendors.values()), org_key)
    customers = _filter_customers_by_org(
        list(customer_registry.customers.values()), org_key
    )

    overview = SecurityCenterOverview(
        metrics=_build_metrics(vendors, customers),
        recentActivity=_build_recent_activity(vendors, customers),
        upcomingExpirations=_build_upcoming_expirations(vendors, customers),
        submissions=_build_submissions(vendors, customers),
        vendorInsights=[_serialize_vendor(vendor) for vendor in vendors],
        customerInsights=[_serialize_customer(customer) for customer in customers],
    )

    return overview


@router.get("/organizations/{org_id}/vendors")
async def list_security_center_vendors(
    org_id: UUID,
    db=Depends(get_db),
    current_user: User = Depends(require_org_access(require_read_findings)),
):
    organization = await db.get(Organization, org_id)
    if not organization:
        raise HTTPException(status_code=404, detail="Organization not found")

    vendor_registry = get_vendor_registry()
    vendors = _filter_vendors_by_org(
        list(vendor_registry.vendors.values()), str(org_id)
    )
    return {
        "count": len(vendors),
        "vendors": [_serialize_vendor(vendor).model_dump() for vendor in vendors],
    }


@router.get("/organizations/{org_id}/customers")
async def list_security_center_customers(
    org_id: UUID,
    db=Depends(get_db),
    current_user: User = Depends(require_org_access(require_read_findings)),
):
    organization = await db.get(Organization, org_id)
    if not organization:
        raise HTTPException(status_code=404, detail="Organization not found")

    customer_registry = get_customer_registry()
    customers = _filter_customers_by_org(
        list(customer_registry.customers.values()), str(org_id)
    )
    return {
        "count": len(customers),
        "customers": [
            _serialize_customer(customer).model_dump() for customer in customers
        ],
    }
