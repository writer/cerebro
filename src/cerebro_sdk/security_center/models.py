"""Data structures describing Security Center vendor and customer insights."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

MetadataMapping = Mapping[str, Any]


@dataclass
class SecurityCenterVendorInsight:
    """Structured vendor insight used by Security Center helpers."""

    vendor_id: str
    name: str
    category: str
    risk_level: str
    inherent_risk_score: float | None = None
    residual_risk_score: float | None = None
    lifecycle_stage: str | None = None
    next_review_due: datetime | None = None
    business_criticality: str | None = None
    metadata: MetadataMapping = field(default_factory=dict)
    raw_metadata: MetadataMapping = field(default_factory=dict)


@dataclass
class SecurityCenterCustomerInsight:
    """Structured customer insight used by Security Center helpers."""

    customer_id: str
    name: str
    segment: str
    health_band: str
    health_score: float | None = None
    churn_risk_score: float | None = None
    lifecycle_stage: str | None = None
    account_manager: str | None = None
    next_qbr_at: datetime | None = None
    last_engagement_at: datetime | None = None
    metadata: MetadataMapping = field(default_factory=dict)
    raw_metadata: MetadataMapping = field(default_factory=dict)
