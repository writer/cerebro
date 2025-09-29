"""
Vendor risk assessment and scenario modeling.

Implements comprehensive risk assessment workflows, scenario analysis,
and risk quantification for vendor management.
"""

import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from uuid import UUID, uuid4

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, desc, func
from sqlalchemy.dialects.postgresql import UUID as PGUUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy import Column, String, DateTime, Boolean, Text, Float
from sqlalchemy.sql import func

from cerebro.core.database import Base
from .vendor_registry import VendorRiskLevel

logger = logging.getLogger(__name__)


class RiskDomain(Enum):
    """Risk domains for vendor assessment."""
    DATA_SECURITY = "data_security"
    ACCESS_CONTROL = "access_control"
    BUSINESS_CONTINUITY = "business_continuity"
    COMPLIANCE = "compliance"
    FINANCIAL = "financial"
    OPERATIONAL = "operational"
    REPUTATIONAL = "reputational"
    LEGAL = "legal"
    TECHNOLOGY = "technology"
    SUPPLY_CHAIN = "supply_chain"


class RiskImpact(Enum):
    """Impact levels for risk scenarios."""
    MINIMAL = "minimal"
    MINOR = "minor"
    MODERATE = "moderate"
    MAJOR = "major"
    SEVERE = "severe"
    CATASTROPHIC = "catastrophic"


class RiskLikelihood(Enum):
    """Likelihood levels for risk scenarios."""
    VERY_LOW = "very_low"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    VERY_HIGH = "very_high"
    ALMOST_CERTAIN = "almost_certain"


@dataclass
class RiskMetric:
    """Quantitative risk metric."""
    metric_name: str
    current_value: float
    target_value: float
    threshold_critical: float
    threshold_high: float
    threshold_medium: float
    unit: str
    measurement_date: datetime


@dataclass
class RiskScenario:
    """Risk scenario for vendor assessment."""
    scenario_id: str
    name: str
    description: str
    domain: RiskDomain
    impact: RiskImpact
    likelihood: RiskLikelihood
    risk_score: float
    
    # Scenario details
    threat_source: str
    vulnerability: str
    asset_at_risk: str
    business_impact: str
    
    # Mitigation
    existing_controls: List[str]
    residual_risk_score: float
    recommended_actions: List[str]
    
    # Metadata
    last_assessed: datetime
    next_assessment_due: datetime


class VendorRiskAssessment(Base):
    """Database model for vendor risk assessments."""
    __tablename__ = "vendor_risk_assessments"
    
    assessment_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    vendor_id: Mapped[str] = mapped_column(String(100), nullable=False)
    org_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    
    # Assessment metadata
    assessment_type: Mapped[str] = mapped_column(String(50), nullable=False)
    assessment_date: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=func.now())
    assessor_id: Mapped[str] = mapped_column(String(100), nullable=False)
    
    # Risk scoring
    overall_risk_score: Mapped[float] = mapped_column(Float, nullable=False)
    risk_level: Mapped[str] = mapped_column(String(20), nullable=False)
    
    # Domain-specific scores
    data_security_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    access_control_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    compliance_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    business_continuity_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    operational_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    
    # Assessment details
    methodology: Mapped[Optional[str]] = mapped_column(Text)
    scope: Mapped[Optional[str]] = mapped_column(Text)
    assumptions: Mapped[Optional[str]] = mapped_column(Text)
    limitations: Mapped[Optional[str]] = mapped_column(Text)
    
    # Results and recommendations
    key_findings: Mapped[Optional[str]] = mapped_column(Text)
    recommendations: Mapped[Optional[str]] = mapped_column(Text)
    risk_scenarios: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONB)
    mitigation_plan: Mapped[Optional[str]] = mapped_column(Text)
    
    # Timeline
    next_assessment_due: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    assessment_frequency_days: Mapped[int] = mapped_column(default=365)
    
    # Tracking
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=func.now(), onupdate=func.now())
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)


class VendorRiskManager:
    """Manager for vendor risk assessment operations."""
    
    def __init__(self, db_session: AsyncSession):
        """Initialize vendor risk manager."""
        self.db = db_session
    
    async def create_risk_assessment(
        self,
        vendor_id: str,
        org_id: UUID,
        assessor_id: str,
        assessment_type: str = "comprehensive"
    ) -> VendorRiskAssessment:
        """Create a new vendor risk assessment."""
        
        assessment = VendorRiskAssessment(
            vendor_id=vendor_id,
            org_id=org_id,
            assessor_id=assessor_id,
            assessment_type=assessment_type,
            overall_risk_score=0.0,
            risk_level=VendorRiskLevel.MEDIUM.value
        )
        
        self.db.add(assessment)
        await self.db.commit()
        await self.db.refresh(assessment)
        
        logger.info(f"Created risk assessment {assessment.assessment_id} for vendor {vendor_id}")
        return assessment
    
    async def calculate_risk_score(
        self,
        data_security: float,
        access_control: float,
        compliance: float,
        business_continuity: float,
        operational: float,
        weights: Optional[Dict[str, float]] = None
    ) -> tuple[float, str]:
        """Calculate overall risk score and level."""
        
        # Default weights if not provided
        if not weights:
            weights = {
                "data_security": 0.3,
                "access_control": 0.2,
                "compliance": 0.2,
                "business_continuity": 0.15,
                "operational": 0.15
            }
        
        # Calculate weighted score
        overall_score = (
            data_security * weights["data_security"] +
            access_control * weights["access_control"] +
            compliance * weights["compliance"] +
            business_continuity * weights["business_continuity"] +
            operational * weights["operational"]
        )
        
        # Determine risk level
        if overall_score >= 90:
            risk_level = VendorRiskLevel.LOW.value
        elif overall_score >= 75:
            risk_level = VendorRiskLevel.MEDIUM.value
        elif overall_score >= 60:
            risk_level = VendorRiskLevel.HIGH.value
        else:
            risk_level = VendorRiskLevel.CRITICAL.value
        
        return overall_score, risk_level
    
    async def update_assessment_scores(
        self,
        assessment_id: UUID,
        domain_scores: Dict[str, float]
    ) -> bool:
        """Update domain-specific scores for an assessment."""
        assessment = await self.db.get(VendorRiskAssessment, assessment_id)
        if not assessment:
            return False
        
        # Update individual domain scores
        assessment.data_security_score = domain_scores.get("data_security", 0.0)
        assessment.access_control_score = domain_scores.get("access_control", 0.0)
        assessment.compliance_score = domain_scores.get("compliance", 0.0)
        assessment.business_continuity_score = domain_scores.get("business_continuity", 0.0)
        assessment.operational_score = domain_scores.get("operational", 0.0)
        
        # Recalculate overall score
        overall_score, risk_level = await self.calculate_risk_score(
            assessment.data_security_score,
            assessment.access_control_score,
            assessment.compliance_score,
            assessment.business_continuity_score,
            assessment.operational_score
        )
        
        assessment.overall_risk_score = overall_score
        assessment.risk_level = risk_level
        
        await self.db.commit()
        
        logger.info(f"Updated assessment {assessment_id} with overall score {overall_score}")
        return True
    
    async def create_risk_scenario(
        self,
        assessment_id: UUID,
        scenario: RiskScenario
    ) -> bool:
        """Add a risk scenario to an assessment."""
        assessment = await self.db.get(VendorRiskAssessment, assessment_id)
        if not assessment:
            return False
        
        # Get existing scenarios or initialize
        scenarios = assessment.risk_scenarios or {}
        
        # Add new scenario
        scenarios[scenario.scenario_id] = {
            "name": scenario.name,
            "description": scenario.description,
            "domain": scenario.domain.value,
            "impact": scenario.impact.value,
            "likelihood": scenario.likelihood.value,
            "risk_score": scenario.risk_score,
            "threat_source": scenario.threat_source,
            "vulnerability": scenario.vulnerability,
            "asset_at_risk": scenario.asset_at_risk,
            "business_impact": scenario.business_impact,
            "existing_controls": scenario.existing_controls,
            "residual_risk_score": scenario.residual_risk_score,
            "recommended_actions": scenario.recommended_actions,
            "last_assessed": scenario.last_assessed.isoformat(),
            "next_assessment_due": scenario.next_assessment_due.isoformat()
        }
        
        assessment.risk_scenarios = scenarios
        await self.db.commit()
        
        logger.info(f"Added risk scenario {scenario.scenario_id} to assessment {assessment_id}")
        return True
    
    async def get_vendor_risk_history(
        self,
        vendor_id: str,
        org_id: UUID,
        limit: int = 12
    ) -> List[VendorRiskAssessment]:
        """Get risk assessment history for a vendor."""
        stmt = select(VendorRiskAssessment).where(
            and_(
                VendorRiskAssessment.vendor_id == vendor_id,
                VendorRiskAssessment.org_id == org_id,
                VendorRiskAssessment.is_active == True
            )
        ).order_by(desc(VendorRiskAssessment.assessment_date)).limit(limit)
        
        return list(await self.db.scalars(stmt))
    
    async def get_high_risk_vendors(self, org_id: UUID) -> List[Dict[str, Any]]:
        """Get vendors with high or critical risk levels."""
        stmt = select(VendorRiskAssessment).where(
            and_(
                VendorRiskAssessment.org_id == org_id,
                VendorRiskAssessment.risk_level.in_([
                    VendorRiskLevel.HIGH.value,
                    VendorRiskLevel.CRITICAL.value
                ]),
                VendorRiskAssessment.is_active == True
            )
        ).order_by(desc(VendorRiskAssessment.overall_risk_score))
        
        assessments = list(await self.db.scalars(stmt))
        
        return [
            {
                "vendor_id": assessment.vendor_id,
                "risk_level": assessment.risk_level,
                "overall_risk_score": assessment.overall_risk_score,
                "assessment_date": assessment.assessment_date.isoformat(),
                "key_concerns": assessment.key_findings
            }
            for assessment in assessments
        ]
    
    async def generate_risk_dashboard(self, org_id: UUID) -> Dict[str, Any]:
        """Generate risk dashboard data for an organization."""
        # Get latest assessments for each vendor
        latest_assessments_query = """
        SELECT DISTINCT ON (vendor_id) 
               vendor_id, assessment_id, overall_risk_score, risk_level, assessment_date
        FROM vendor_risk_assessments 
        WHERE org_id = :org_id AND is_active = true
        ORDER BY vendor_id, assessment_date DESC
        """
        
        result = await self.db.execute(latest_assessments_query, {"org_id": org_id})
        latest_assessments = result.fetchall()
        
        # Calculate risk distribution
        risk_distribution = {}
        total_vendors = len(latest_assessments)
        
        for assessment in latest_assessments:
            risk_level = assessment.risk_level
            risk_distribution[risk_level] = risk_distribution.get(risk_level, 0) + 1
        
        # Calculate average risk score
        if latest_assessments:
            avg_risk_score = sum(a.overall_risk_score for a in latest_assessments) / len(latest_assessments)
        else:
            avg_risk_score = 0.0
        
        return {
            "summary": {
                "total_vendors": total_vendors,
                "average_risk_score": round(avg_risk_score, 2),
                "high_risk_vendors": risk_distribution.get(VendorRiskLevel.HIGH.value, 0),
                "critical_risk_vendors": risk_distribution.get(VendorRiskLevel.CRITICAL.value, 0)
            },
            "risk_distribution": risk_distribution,
            "recent_assessments": [
                {
                    "vendor_id": a.vendor_id,
                    "risk_score": a.overall_risk_score,
                    "risk_level": a.risk_level,
                    "assessment_date": a.assessment_date.isoformat()
                }
                for a in latest_assessments[-10:]  # Last 10 assessments
            ]
        }


class RiskScenarioTemplate:
    """Template for common risk scenarios."""
    
    @staticmethod
    def get_data_breach_scenario(vendor_id: str) -> RiskScenario:
        """Create data breach risk scenario template."""
        return RiskScenario(
            scenario_id=f"data_breach_{vendor_id}",
            name="Data Breach at Vendor",
            description="Unauthorized access to sensitive data stored or processed by vendor",
            domain=RiskDomain.DATA_SECURITY,
            impact=RiskImpact.MAJOR,
            likelihood=RiskLikelihood.MEDIUM,
            risk_score=75.0,
            threat_source="External attacker, insider threat",
            vulnerability="Inadequate access controls, unpatched systems",
            asset_at_risk="Customer data, intellectual property",
            business_impact="Regulatory fines, reputational damage, customer loss",
            existing_controls=["Encryption", "Access logging", "Regular audits"],
            residual_risk_score=45.0,
            recommended_actions=[
                "Enhanced monitoring",
                "Zero-trust implementation",
                "Incident response testing"
            ],
            last_assessed=datetime.utcnow(),
            next_assessment_due=datetime.utcnow() + timedelta(days=90)
        )
    
    @staticmethod
    def get_service_disruption_scenario(vendor_id: str) -> RiskScenario:
        """Create service disruption risk scenario template."""
        return RiskScenario(
            scenario_id=f"service_disruption_{vendor_id}",
            name="Critical Service Disruption",
            description="Extended outage or service degradation affecting business operations",
            domain=RiskDomain.BUSINESS_CONTINUITY,
            impact=RiskImpact.MODERATE,
            likelihood=RiskLikelihood.LOW,
            risk_score=35.0,
            threat_source="Infrastructure failure, cyber attack, natural disaster",
            vulnerability="Single points of failure, inadequate redundancy",
            asset_at_risk="Business operations, revenue generation",
            business_impact="Operational downtime, revenue loss, SLA breaches",
            existing_controls=["SLA monitoring", "Backup systems", "Disaster recovery"],
            residual_risk_score=20.0,
            recommended_actions=[
                "Multi-region redundancy",
                "Enhanced SLA terms",
                "Regular DR testing"
            ],
            last_assessed=datetime.utcnow(),
            next_assessment_due=datetime.utcnow() + timedelta(days=180)
        )
    
    @staticmethod
    def get_compliance_violation_scenario(vendor_id: str) -> RiskScenario:
        """Create compliance violation risk scenario template."""
        return RiskScenario(
            scenario_id=f"compliance_violation_{vendor_id}",
            name="Regulatory Compliance Violation",
            description="Vendor practices result in regulatory compliance violations",
            domain=RiskDomain.COMPLIANCE,
            impact=RiskImpact.MAJOR,
            likelihood=RiskLikelihood.LOW,
            risk_score=50.0,
            threat_source="Regulatory changes, vendor non-compliance",
            vulnerability="Inadequate compliance monitoring, outdated practices",
            asset_at_risk="Regulatory standing, business licenses",
            business_impact="Regulatory fines, business restrictions, audit costs",
            existing_controls=["Compliance monitoring", "Regular attestations", "Legal review"],
            residual_risk_score=25.0,
            recommended_actions=[
                "Enhanced compliance monitoring",
                "Regular compliance audits",
                "Automated compliance reporting"
            ],
            last_assessed=datetime.utcnow(),
            next_assessment_due=datetime.utcnow() + timedelta(days=180)
        )


class VendorRiskCalculator:
    """Calculator for vendor risk metrics and scoring."""
    
    @staticmethod
    def calculate_inherent_risk(
        data_classification: str,
        business_criticality: str,
        vendor_maturity: str,
        geographic_risk: str
    ) -> float:
        """Calculate inherent risk score based on vendor characteristics."""
        
        # Risk scoring matrices
        data_risk_scores = {
            "public": 1.0,
            "internal": 2.0,
            "confidential": 3.0,
            "restricted": 4.0,
            "top_secret": 5.0
        }
        
        criticality_scores = {
            "low": 1.0,
            "medium": 2.5,
            "high": 4.0,
            "critical": 5.0
        }
        
        maturity_scores = {
            "established": 1.0,
            "growing": 2.0,
            "startup": 3.5,
            "unknown": 4.0
        }
        
        geographic_scores = {
            "domestic": 1.0,
            "allied": 1.5,
            "neutral": 2.5,
            "restricted": 4.0,
            "prohibited": 5.0
        }
        
        # Calculate weighted risk score
        data_score = data_risk_scores.get(data_classification.lower(), 3.0)
        criticality_score = criticality_scores.get(business_criticality.lower(), 3.0)
        maturity_score = maturity_scores.get(vendor_maturity.lower(), 3.0)
        geo_score = geographic_scores.get(geographic_risk.lower(), 2.0)
        
        # Weighted calculation
        inherent_risk = (
            data_score * 0.35 +
            criticality_score * 0.30 +
            maturity_score * 0.20 +
            geo_score * 0.15
        )
        
        # Normalize to 0-100 scale
        return min(100.0, (inherent_risk / 5.0) * 100)
    
    @staticmethod
    def calculate_residual_risk(
        inherent_risk: float,
        control_effectiveness: float,
        monitoring_maturity: float
    ) -> float:
        """Calculate residual risk after controls."""
        
        # Control effectiveness factor (0.0 to 1.0)
        control_factor = max(0.0, min(1.0, control_effectiveness / 100.0))
        
        # Monitoring maturity factor (0.0 to 1.0)
        monitoring_factor = max(0.0, min(1.0, monitoring_maturity / 100.0))
        
        # Combined mitigation factor
        mitigation_factor = (control_factor + monitoring_factor) / 2.0
        
        # Calculate residual risk
        residual_risk = inherent_risk * (1.0 - mitigation_factor * 0.8)  # Max 80% reduction
        
        return max(5.0, residual_risk)  # Minimum 5% residual risk
    
    @staticmethod
    def generate_default_scenarios(vendor_id: str) -> List[RiskScenario]:
        """Generate default risk scenarios for a vendor."""
        return [
            RiskScenarioTemplate.get_data_breach_scenario(vendor_id),
            RiskScenarioTemplate.get_service_disruption_scenario(vendor_id),
            RiskScenarioTemplate.get_compliance_violation_scenario(vendor_id)
        ]
