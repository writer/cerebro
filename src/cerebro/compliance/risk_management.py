"""
Integrated Risk Register and Vendor Risk Management System.

Addresses the #1 customer complaint: "We still manage risks in Excel" 
because Vanta/Drata have limited risk management capabilities.

Key features:
- Integrated risk register with customizable risk matrices
- Vendor risk assessments and questionnaires  
- Risk-to-control mapping and treatment tracking
- Third-party risk scoring and monitoring
- Risk dashboard and executive reporting
- Automated risk workflows and notifications
"""

from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from enum import Enum
from uuid import uuid4

from .evidence_data_fabric import EvidenceDataFabric


class RiskCategory(Enum):
    """Categories of organizational risks."""
    OPERATIONAL = "operational"
    FINANCIAL = "financial"
    STRATEGIC = "strategic"
    COMPLIANCE = "compliance"
    TECHNOLOGY = "technology"
    REPUTATIONAL = "reputational"
    VENDOR = "vendor"
    CYBERSECURITY = "cybersecurity"
    DATA_PRIVACY = "data_privacy"
    BUSINESS_CONTINUITY = "business_continuity"


class RiskImpactLevel(Enum):
    """Risk impact levels for risk matrix."""
    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    MINIMAL = 1


class RiskProbability(Enum):
    """Risk probability levels for risk matrix."""
    VERY_LIKELY = 5    # >80% chance
    LIKELY = 4         # 60-80% chance
    POSSIBLE = 3       # 40-60% chance  
    UNLIKELY = 2       # 20-40% chance
    RARE = 1          # <20% chance


class RiskStatus(Enum):
    """Status of risk treatment."""
    IDENTIFIED = "identified"
    ANALYZING = "analyzing"
    TREATING = "treating"
    MONITORING = "monitoring"
    ACCEPTED = "accepted"
    TRANSFERRED = "transferred"
    CLOSED = "closed"


class TreatmentType(Enum):
    """Types of risk treatments."""
    ACCEPT = "accept"        # Accept the risk
    AVOID = "avoid"          # Eliminate the risk
    MITIGATE = "mitigate"    # Reduce impact or likelihood
    TRANSFER = "transfer"    # Insurance, contracts, outsourcing


class VendorRiskTier(Enum):
    """Vendor risk tiers for assessment frequency."""
    CRITICAL = "critical"    # Monthly assessment
    HIGH = "high"           # Quarterly assessment
    MEDIUM = "medium"       # Semi-annual assessment
    LOW = "low"            # Annual assessment


@dataclass
class Risk:
    """Core risk entity in the risk register."""
    id: str
    title: str
    description: str
    category: RiskCategory
    
    # Risk assessment
    inherent_impact: RiskImpactLevel
    inherent_probability: RiskProbability
    residual_impact: RiskImpactLevel
    residual_probability: RiskProbability
    
    # Risk management
    status: RiskStatus = RiskStatus.IDENTIFIED
    owner: Optional[str] = None
    business_unit: Optional[str] = None
    
    # Treatment planning
    treatment_strategy: Optional[TreatmentType] = None
    treatment_plan: str = ""
    target_completion_date: Optional[datetime] = None
    
    # Controls and evidence
    related_controls: List[str] = field(default_factory=list)
    evidence_requirements: List[str] = field(default_factory=list)
    
    # Review and monitoring
    last_review_date: Optional[datetime] = None
    next_review_date: Optional[datetime] = None
    review_frequency_months: int = 6
    
    # Financial impact
    estimated_financial_impact: Optional[float] = None
    treatment_cost: Optional[float] = None
    
    # Metadata
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    created_by: str = ""
    tags: Dict[str, str] = field(default_factory=dict)
    
    @property
    def inherent_risk_score(self) -> float:
        """Calculate inherent risk score (impact × probability)."""
        return self.inherent_impact.value * self.inherent_probability.value
    
    @property
    def residual_risk_score(self) -> float:
        """Calculate residual risk score after controls."""
        return self.residual_impact.value * self.residual_probability.value
    
    @property
    def risk_reduction_percentage(self) -> float:
        """Calculate percentage risk reduction from controls."""
        if self.inherent_risk_score == 0:
            return 0.0
        return ((self.inherent_risk_score - self.residual_risk_score) / self.inherent_risk_score) * 100


@dataclass  
class Vendor:
    """Vendor/third-party for risk assessment."""
    id: str
    name: str
    description: str
    vendor_type: str  # technology, service, supplier, etc.
    
    # Basic information
    contact_info: Dict[str, Any] = field(default_factory=dict)
    website: Optional[str] = None
    headquarters_location: str = ""
    
    # Risk classification
    risk_tier: VendorRiskTier = VendorRiskTier.MEDIUM
    data_access_level: str = "none"  # none, limited, full
    critical_services: List[str] = field(default_factory=list)
    
    # Contract and compliance
    contract_start_date: Optional[datetime] = None
    contract_end_date: Optional[datetime] = None
    soc2_status: Optional[str] = None  # current, expired, not_applicable
    other_certifications: List[str] = field(default_factory=list)
    
    # Assessment tracking
    last_assessment_date: Optional[datetime] = None
    next_assessment_due: Optional[datetime] = None
    current_risk_score: Optional[float] = None
    
    # Metadata
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    status: str = "active"  # active, under_review, terminated


@dataclass
class VendorRiskAssessment:
    """Individual vendor risk assessment."""
    id: str
    vendor_id: str
    assessment_date: datetime
    assessor: str
    
    # Questionnaire responses
    responses: Dict[str, Any] = field(default_factory=dict)
    
    # Risk scoring
    security_score: Optional[float] = None
    privacy_score: Optional[float] = None
    operational_score: Optional[float] = None
    financial_score: Optional[float] = None
    overall_risk_score: Optional[float] = None
    
    # Assessment outcome
    risk_level: str = "medium"  # low, medium, high, critical
    approved: Optional[bool] = None
    approval_conditions: List[str] = field(default_factory=list)
    
    # Documentation
    assessment_notes: str = ""
    remediation_items: List[str] = field(default_factory=list)
    evidence_provided: List[str] = field(default_factory=list)
    
    # Follow-up
    next_review_date: Optional[datetime] = None
    created_at: datetime = field(default_factory=datetime.now)


@dataclass
class RiskTreatment:
    """Specific treatment action for a risk."""
    id: str
    risk_id: str
    treatment_type: TreatmentType
    
    # Treatment details
    title: str
    description: str
    implementation_plan: str = ""
    
    # Timeline and responsibility
    assigned_to: Optional[str] = None
    start_date: Optional[datetime] = None
    target_completion_date: Optional[datetime] = None
    actual_completion_date: Optional[datetime] = None
    
    # Progress tracking
    status: str = "planned"  # planned, in_progress, completed, on_hold
    progress_percentage: int = 0
    
    # Cost and resources
    estimated_cost: Optional[float] = None
    actual_cost: Optional[float] = None
    resource_requirements: List[str] = field(default_factory=list)
    
    # Effectiveness
    expected_risk_reduction: Optional[float] = None
    actual_risk_reduction: Optional[float] = None
    
    # Compliance mapping
    related_controls: List[str] = field(default_factory=list)
    framework_requirements: List[str] = field(default_factory=list)
    
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)


class RiskManagementSystem:
    """Integrated risk register and vendor risk management."""
    
    def __init__(self, evidence_fabric: EvidenceDataFabric):
        self.evidence_fabric = evidence_fabric
        self._risks: Dict[str, Risk] = {}
        self._vendors: Dict[str, Vendor] = {}
        self._assessments: Dict[str, VendorRiskAssessment] = {}
        self._treatments: Dict[str, RiskTreatment] = {}
        
        # Load default risk matrix and questionnaire templates
        self._risk_matrix = self._load_default_risk_matrix()
        self._vendor_questionnaire_template = self._load_vendor_questionnaire_template()
    
    def create_risk(
        self,
        title: str,
        description: str,
        category: RiskCategory,
        inherent_impact: RiskImpactLevel,
        inherent_probability: RiskProbability,
        owner: str,
        business_unit: Optional[str] = None
    ) -> Risk:
        """Create a new risk in the register."""
        
        risk_id = str(uuid4())
        
        # Set next review date based on risk score
        risk_score = inherent_impact.value * inherent_probability.value
        if risk_score >= 20:  # Critical/High risks
            review_frequency = 3  # Quarterly
        elif risk_score >= 12:  # Medium-High risks
            review_frequency = 6  # Semi-annual
        else:  # Lower risks
            review_frequency = 12  # Annual
        
        risk = Risk(
            id=risk_id,
            title=title,
            description=description,
            category=category,
            inherent_impact=inherent_impact,
            inherent_probability=inherent_probability,
            residual_impact=inherent_impact,  # Initially same as inherent
            residual_probability=inherent_probability,
            owner=owner,
            business_unit=business_unit,
            review_frequency_months=review_frequency,
            next_review_date=datetime.now() + timedelta(days=30*review_frequency)
        )
        
        self._risks[risk_id] = risk
        return risk
    
    def add_vendor(
        self,
        name: str,
        description: str,
        vendor_type: str,
        risk_tier: VendorRiskTier,
        data_access_level: str = "none"
    ) -> Vendor:
        """Add a vendor to the risk management system."""
        
        vendor_id = str(uuid4())
        
        # Set assessment schedule based on risk tier
        assessment_frequency = {
            VendorRiskTier.CRITICAL: 30,   # Monthly
            VendorRiskTier.HIGH: 90,       # Quarterly
            VendorRiskTier.MEDIUM: 180,    # Semi-annual
            VendorRiskTier.LOW: 365        # Annual
        }
        
        vendor = Vendor(
            id=vendor_id,
            name=name,
            description=description,
            vendor_type=vendor_type,
            risk_tier=risk_tier,
            data_access_level=data_access_level,
            next_assessment_due=datetime.now() + timedelta(days=assessment_frequency[risk_tier])
        )
        
        self._vendors[vendor_id] = vendor
        return vendor
    
    def conduct_vendor_assessment(
        self,
        vendor_id: str,
        assessor: str,
        questionnaire_responses: Dict[str, Any]
    ) -> VendorRiskAssessment:
        """Conduct a vendor risk assessment."""
        
        if vendor_id not in self._vendors:
            raise ValueError(f"Vendor {vendor_id} not found")
        
        assessment_id = str(uuid4())
        vendor = self._vendors[vendor_id]
        
        # Calculate risk scores based on responses
        scores = self._calculate_vendor_risk_scores(questionnaire_responses)
        
        assessment = VendorRiskAssessment(
            id=assessment_id,
            vendor_id=vendor_id,
            assessment_date=datetime.now(),
            assessor=assessor,
            responses=questionnaire_responses,
            **scores
        )
        
        # Update vendor with latest assessment info
        vendor.last_assessment_date = assessment.assessment_date
        vendor.current_risk_score = assessment.overall_risk_score
        
        # Schedule next assessment
        frequency_days = {
            VendorRiskTier.CRITICAL: 30,
            VendorRiskTier.HIGH: 90,
            VendorRiskTier.MEDIUM: 180,
            VendorRiskTier.LOW: 365
        }
        vendor.next_assessment_due = datetime.now() + timedelta(
            days=frequency_days[vendor.risk_tier]
        )
        
        self._assessments[assessment_id] = assessment
        return assessment
    
    def create_risk_treatment(
        self,
        risk_id: str,
        treatment_type: TreatmentType,
        title: str,
        description: str,
        assigned_to: str,
        target_completion_date: datetime,
        related_controls: List[str] = None
    ) -> RiskTreatment:
        """Create a risk treatment action."""
        
        if risk_id not in self._risks:
            raise ValueError(f"Risk {risk_id} not found")
        
        treatment_id = str(uuid4())
        
        treatment = RiskTreatment(
            id=treatment_id,
            risk_id=risk_id,
            treatment_type=treatment_type,
            title=title,
            description=description,
            assigned_to=assigned_to,
            target_completion_date=target_completion_date,
            related_controls=related_controls or []
        )
        
        self._treatments[treatment_id] = treatment
        return treatment
    
    def get_risk_dashboard_data(self) -> Dict[str, Any]:
        """Generate executive risk dashboard data."""
        
        total_risks = len(self._risks)
        risks_by_category = {}
        risks_by_status = {}
        high_risks = []
        overdue_treatments = []
        
        # Analyze risks
        for risk in self._risks.values():
            # Category breakdown
            category = risk.category.value
            if category not in risks_by_category:
                risks_by_category[category] = 0
            risks_by_category[category] += 1
            
            # Status breakdown
            status = risk.status.value
            if status not in risks_by_status:
                risks_by_status[status] = 0
            risks_by_status[status] += 1
            
            # High risks (residual score >= 15)
            if risk.residual_risk_score >= 15:
                high_risks.append({
                    "id": risk.id,
                    "title": risk.title,
                    "score": risk.residual_risk_score,
                    "owner": risk.owner,
                    "category": risk.category.value
                })
        
        # Analyze treatments
        treatment_effectiveness = []
        for treatment in self._treatments.values():
            risk = self._risks.get(treatment.risk_id)
            if risk and treatment.actual_risk_reduction:
                treatment_effectiveness.append({
                    "treatment_title": treatment.title,
                    "risk_title": risk.title,
                    "reduction_achieved": treatment.actual_risk_reduction,
                    "cost": treatment.actual_cost
                })
            
            # Check for overdue treatments
            if (treatment.target_completion_date and 
                treatment.target_completion_date < datetime.now() and
                treatment.status != "completed"):
                overdue_treatments.append({
                    "treatment_title": treatment.title,
                    "risk_title": risk.title if risk else "Unknown",
                    "assigned_to": treatment.assigned_to,
                    "days_overdue": (datetime.now() - treatment.target_completion_date).days
                })
        
        # Vendor risk summary
        total_vendors = len(self._vendors)
        vendors_by_tier = {}
        assessments_due = []
        
        for vendor in self._vendors.values():
            tier = vendor.risk_tier.value
            if tier not in vendors_by_tier:
                vendors_by_tier[tier] = 0
            vendors_by_tier[tier] += 1
            
            # Check for due assessments
            if (vendor.next_assessment_due and 
                vendor.next_assessment_due <= datetime.now() + timedelta(days=30)):
                assessments_due.append({
                    "vendor_name": vendor.name,
                    "risk_tier": vendor.risk_tier.value,
                    "due_date": vendor.next_assessment_due,
                    "days_until_due": (vendor.next_assessment_due - datetime.now()).days
                })
        
        return {
            "generated_at": datetime.now(),
            "risk_summary": {
                "total_risks": total_risks,
                "by_category": risks_by_category,
                "by_status": risks_by_status,
                "high_risks": sorted(high_risks, key=lambda x: x["score"], reverse=True)[:10]
            },
            "treatment_summary": {
                "total_treatments": len(self._treatments),
                "overdue_treatments": overdue_treatments,
                "treatment_effectiveness": treatment_effectiveness
            },
            "vendor_summary": {
                "total_vendors": total_vendors,
                "by_tier": vendors_by_tier,
                "assessments_due": assessments_due
            },
            "key_metrics": {
                "avg_risk_score": sum(r.residual_risk_score for r in self._risks.values()) / total_risks if total_risks > 0 else 0,
                "risks_with_treatments": len([r for r in self._risks.values() if any(t.risk_id == r.id for t in self._treatments.values())]),
                "treatment_completion_rate": len([t for t in self._treatments.values() if t.status == "completed"]) / len(self._treatments) * 100 if self._treatments else 0,
                "vendor_assessment_coverage": len([v for v in self._vendors.values() if v.last_assessment_date]) / total_vendors * 100 if total_vendors > 0 else 0
            }
        }
    
    def generate_risk_report(
        self,
        category_filter: Optional[RiskCategory] = None,
        owner_filter: Optional[str] = None,
        include_treatments: bool = True
    ) -> Dict[str, Any]:
        """Generate comprehensive risk report."""
        
        # Filter risks
        filtered_risks = []
        for risk in self._risks.values():
            if category_filter and risk.category != category_filter:
                continue
            if owner_filter and risk.owner != owner_filter:
                continue
            filtered_risks.append(risk)
        
        # Risk analysis
        risk_data = []
        for risk in filtered_risks:
            risk_info = {
                "id": risk.id,
                "title": risk.title,
                "category": risk.category.value,
                "inherent_score": risk.inherent_risk_score,
                "residual_score": risk.residual_risk_score,
                "risk_reduction": risk.risk_reduction_percentage,
                "owner": risk.owner,
                "status": risk.status.value,
                "next_review": risk.next_review_date.isoformat() if risk.next_review_date else None
            }
            
            # Add treatments if requested
            if include_treatments:
                risk_treatments = [
                    {
                        "title": t.title,
                        "type": t.treatment_type.value,
                        "status": t.status,
                        "completion_date": t.target_completion_date.isoformat() if t.target_completion_date else None
                    }
                    for t in self._treatments.values() if t.risk_id == risk.id
                ]
                risk_info["treatments"] = risk_treatments
            
            risk_data.append(risk_info)
        
        return {
            "report_generated": datetime.now().isoformat(),
            "filters": {
                "category": category_filter.value if category_filter else None,
                "owner": owner_filter
            },
            "summary": {
                "total_risks": len(filtered_risks),
                "avg_inherent_score": sum(r.inherent_risk_score for r in filtered_risks) / len(filtered_risks) if filtered_risks else 0,
                "avg_residual_score": sum(r.residual_risk_score for r in filtered_risks) / len(filtered_risks) if filtered_risks else 0,
                "avg_risk_reduction": sum(r.risk_reduction_percentage for r in filtered_risks) / len(filtered_risks) if filtered_risks else 0
            },
            "risks": sorted(risk_data, key=lambda x: x["residual_score"], reverse=True)
        }
    
    def map_risks_to_controls(self, control_framework: str) -> Dict[str, Any]:
        """Map risks to compliance controls for integrated risk-control management."""
        
        risk_control_mappings = {}
        unmapped_risks = []
        
        for risk in self._risks.values():
            if risk.related_controls:
                risk_control_mappings[risk.id] = {
                    "risk_title": risk.title,
                    "risk_score": risk.residual_risk_score,
                    "controls": risk.related_controls,
                    "control_effectiveness": self._assess_control_effectiveness(risk.related_controls)
                }
            else:
                unmapped_risks.append({
                    "risk_id": risk.id,
                    "risk_title": risk.title,
                    "risk_score": risk.residual_risk_score,
                    "suggested_controls": self._suggest_controls_for_risk(risk)
                })
        
        return {
            "framework": control_framework,
            "mapped_risks": risk_control_mappings,
            "unmapped_risks": unmapped_risks,
            "mapping_coverage": len(risk_control_mappings) / len(self._risks) * 100 if self._risks else 0
        }
    
    def _calculate_vendor_risk_scores(self, responses: Dict[str, Any]) -> Dict[str, float]:
        """Calculate vendor risk scores from questionnaire responses."""
        
        # Simplified scoring algorithm - would be more sophisticated in production
        security_questions = [q for q in responses.keys() if "security" in q.lower()]
        privacy_questions = [q for q in responses.keys() if "privacy" in q.lower()]
        operational_questions = [q for q in responses.keys() if "operational" in q.lower()]
        
        def calculate_category_score(questions: List[str]) -> float:
            if not questions:
                return 5.0  # Medium risk if no data
            
            total_score = 0
            for q in questions:
                response = responses[q]
                if isinstance(response, bool):
                    total_score += 1 if response else 10  # Good answer = 1, bad = 10
                elif isinstance(response, str):
                    total_score += 5  # Neutral for text responses
            
            return min(10, total_score / len(questions))
        
        security_score = calculate_category_score(security_questions)
        privacy_score = calculate_category_score(privacy_questions)
        operational_score = calculate_category_score(operational_questions)
        financial_score = 5.0  # Would assess financial stability
        
        overall_score = (security_score + privacy_score + operational_score + financial_score) / 4
        
        return {
            "security_score": security_score,
            "privacy_score": privacy_score,
            "operational_score": operational_score,
            "financial_score": financial_score,
            "overall_risk_score": overall_score
        }
    
    def _assess_control_effectiveness(self, control_ids: List[str]) -> Dict[str, Any]:
        """Assess effectiveness of controls mapped to a risk."""
        
        # Query evidence for these controls
        total_controls = len(control_ids)
        effective_controls = 0
        
        for control_id in control_ids:
            # Check if control has recent, passing evidence
            # This would integrate with the evidence fabric
            effective_controls += 1  # Simplified for demo
        
        return {
            "total_controls": total_controls,
            "effective_controls": effective_controls,
            "effectiveness_rate": effective_controls / total_controls * 100 if total_controls > 0 else 0
        }
    
    def _suggest_controls_for_risk(self, risk: Risk) -> List[str]:
        """Suggest relevant controls for an unmapped risk."""
        
        # Simple mapping based on risk category
        control_suggestions = {
            RiskCategory.CYBERSECURITY: ["CC6.1", "CC6.2", "CC7.1"],
            RiskCategory.DATA_PRIVACY: ["CC6.1", "CC6.7"],
            RiskCategory.VENDOR: ["CC9.1", "CC9.2"],
            RiskCategory.OPERATIONAL: ["CC7.1", "CC8.1"],
            RiskCategory.COMPLIANCE: ["CC2.1", "CC3.1"]
        }
        
        return control_suggestions.get(risk.category, ["CC1.1"])
    
    def _load_default_risk_matrix(self) -> Dict[str, Any]:
        """Load default 5x5 risk matrix configuration."""
        
        return {
            "impact_levels": [
                {"level": 1, "label": "Minimal", "description": "Minimal business impact"},
                {"level": 2, "label": "Low", "description": "Low business impact"},
                {"level": 3, "label": "Medium", "description": "Moderate business impact"},
                {"level": 4, "label": "High", "description": "High business impact"},
                {"level": 5, "label": "Critical", "description": "Critical business impact"}
            ],
            "probability_levels": [
                {"level": 1, "label": "Rare", "description": "<20% chance in next 12 months"},
                {"level": 2, "label": "Unlikely", "description": "20-40% chance in next 12 months"},
                {"level": 3, "label": "Possible", "description": "40-60% chance in next 12 months"},
                {"level": 4, "label": "Likely", "description": "60-80% chance in next 12 months"},
                {"level": 5, "label": "Very Likely", "description": ">80% chance in next 12 months"}
            ],
            "risk_levels": {
                "1-3": "Low Risk",
                "4-6": "Medium Risk", 
                "8-12": "High Risk",
                "15-25": "Critical Risk"
            }
        }
    
    def _load_vendor_questionnaire_template(self) -> Dict[str, Any]:
        """Load default vendor risk assessment questionnaire."""
        
        return {
            "sections": [
                {
                    "name": "Security Controls",
                    "questions": [
                        {
                            "id": "security_program",
                            "question": "Do you have a formal information security program?",
                            "type": "boolean",
                            "required": True
                        },
                        {
                            "id": "security_certifications",
                            "question": "What security certifications do you maintain?",
                            "type": "multiple_choice",
                            "options": ["SOC 2", "ISO 27001", "PCI DSS", "FedRAMP", "None"],
                            "required": True
                        },
                        {
                            "id": "data_encryption",
                            "question": "Do you encrypt data at rest and in transit?",
                            "type": "boolean",
                            "required": True
                        }
                    ]
                },
                {
                    "name": "Privacy & Data Protection",
                    "questions": [
                        {
                            "id": "privacy_program",
                            "question": "Do you have a formal privacy program?",
                            "type": "boolean",
                            "required": True
                        },
                        {
                            "id": "data_processing_agreement",
                            "question": "Will you sign a Data Processing Agreement (DPA)?",
                            "type": "boolean",
                            "required": True
                        }
                    ]
                }
            ]
        }


# Factory function
def create_risk_management_system(evidence_fabric: EvidenceDataFabric) -> RiskManagementSystem:
    """Create and initialize risk management system."""
    return RiskManagementSystem(evidence_fabric)
