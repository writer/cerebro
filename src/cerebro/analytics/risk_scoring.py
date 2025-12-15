"""Risk scoring engine for comprehensive organizational risk assessment."""

import logging
from typing import Dict, List, Any
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, text

from .sql_dialect import current_timestamp_expr, get_dialect_name


logger = logging.getLogger(__name__)


class RiskDimension(Enum):
    """Dimensions of organizational risk."""
    VULNERABILITY_EXPOSURE = "vulnerability_exposure"
    IDENTITY_HYGIENE = "identity_hygiene"
    ACCESS_CONTROL = "access_control"
    COMPLIANCE_POSTURE = "compliance_posture"
    OPERATIONAL_SECURITY = "operational_security"


class RiskSeverity(Enum):
    """Risk severity levels for scoring."""
    MINIMAL = "minimal"      # 0-20
    LOW = "low"              # 21-40
    MODERATE = "moderate"    # 41-60
    HIGH = "high"            # 61-80
    CRITICAL = "critical"    # 81-100


@dataclass
class RiskFactor:
    """Individual risk factor contributing to overall score."""
    factor_name: str
    category: str
    current_value: float
    baseline_value: float
    weight: float
    risk_contribution: float
    description: str
    remediation_suggestions: List[str]


@dataclass
class OrganizationRiskScore:
    """Comprehensive organizational risk score."""
    org_id: UUID
    overall_score: float
    risk_level: RiskSeverity
    calculation_date: datetime
    
    # Dimension scores
    vulnerability_score: float
    identity_score: float
    access_control_score: float
    compliance_score: float
    operational_score: float
    
    # Contributing factors
    risk_factors: List[RiskFactor]
    
    # Trends
    score_trend: str  # "improving", "declining", "stable"
    trend_confidence: float
    
    # Actionable insights
    top_risks: List[str]
    quick_wins: List[str]
    strategic_initiatives: List[str]


@dataclass
class RiskHeatmap:
    """Risk heatmap data for visualization."""
    org_id: UUID
    heatmap_data: Dict[str, Dict[str, float]]  # provider -> resource_type -> risk_score
    high_risk_areas: List[Dict[str, Any]]
    improvement_opportunities: List[Dict[str, Any]]


class RiskScoringEngine:
    """Engine for calculating comprehensive organizational risk scores."""
    
    def __init__(self, db_session: AsyncSession):
        """Initialize risk scoring engine."""
        self.db = db_session
        
        # Risk dimension weights
        self.dimension_weights = {
            RiskDimension.VULNERABILITY_EXPOSURE: 0.25,
            RiskDimension.IDENTITY_HYGIENE: 0.20,
            RiskDimension.ACCESS_CONTROL: 0.25,
            RiskDimension.COMPLIANCE_POSTURE: 0.15,
            RiskDimension.OPERATIONAL_SECURITY: 0.15
        }
    
    async def calculate_organization_risk_score(self, org_id: UUID) -> OrganizationRiskScore:
        """Calculate comprehensive organizational risk score."""
        
        logger.info(f"Calculating organization risk score for {org_id}")
        
        # Calculate dimension scores
        vulnerability_score = await self._calculate_vulnerability_score(org_id)
        identity_score = await self._calculate_identity_score(org_id)
        access_control_score = await self._calculate_access_control_score(org_id)
        compliance_score = await self._calculate_compliance_score(org_id)
        operational_score = await self._calculate_operational_score(org_id)
        
        # Calculate weighted overall score
        overall_score = (
            vulnerability_score * self.dimension_weights[RiskDimension.VULNERABILITY_EXPOSURE] +
            identity_score * self.dimension_weights[RiskDimension.IDENTITY_HYGIENE] +
            access_control_score * self.dimension_weights[RiskDimension.ACCESS_CONTROL] +
            compliance_score * self.dimension_weights[RiskDimension.COMPLIANCE_POSTURE] +
            operational_score * self.dimension_weights[RiskDimension.OPERATIONAL_SECURITY]
        )
        
        # Determine risk level
        risk_level = self._score_to_risk_level(overall_score)
        
        # Get risk factors
        risk_factors = await self._identify_risk_factors(org_id)
        
        # Analyze trends
        score_trend, trend_confidence = await self._analyze_score_trend(org_id, overall_score)
        
        # Generate actionable insights
        top_risks = await self._identify_top_risks(org_id)
        quick_wins = await self._identify_quick_wins(org_id)
        strategic_initiatives = await self._identify_strategic_initiatives(org_id)
        
        return OrganizationRiskScore(
            org_id=org_id,
            overall_score=overall_score,
            risk_level=risk_level,
            calculation_date=datetime.utcnow(),
            vulnerability_score=vulnerability_score,
            identity_score=identity_score,
            access_control_score=access_control_score,
            compliance_score=compliance_score,
            operational_score=operational_score,
            risk_factors=risk_factors,
            score_trend=score_trend,
            trend_confidence=trend_confidence,
            top_risks=top_risks,
            quick_wins=quick_wins,
            strategic_initiatives=strategic_initiatives
        )
    
    async def _calculate_vulnerability_score(self, org_id: UUID) -> float:
        """Calculate vulnerability exposure score (0-100, lower is better)."""
        
        # Get finding severity distribution
        severity_query = text("""
            SELECT severity, COUNT(*) as count
            FROM findings 
            WHERE org_id = :org_id AND status = 'open'
            GROUP BY severity
        """)
        
        result = await self.db.execute(severity_query, {"org_id": org_id})
        severity_counts = {row.severity: row.count for row in result.fetchall()}
        
        # Weight by severity (higher weight = higher risk)
        severity_weights = {
            "critical": 10.0,
            "high": 5.0,
            "medium": 2.0,
            "low": 1.0,
            "info": 0.1
        }
        
        weighted_score = 0.0
        total_findings = sum(severity_counts.values())
        
        if total_findings == 0:
            return 0.0  # No findings = no vulnerability exposure
        
        for severity, count in severity_counts.items():
            weight = severity_weights.get(severity, 1.0)
            weighted_score += count * weight
        
        # Normalize to 0-100 scale (assuming 100 findings would be maximum risk)
        normalized_score = min(100.0, (weighted_score / 100.0) * 100)
        
        return normalized_score
    
    async def _calculate_identity_score(self, org_id: UUID) -> float:
        """Calculate identity hygiene score (0-100, lower is better)."""

        dialect = get_dialect_name(self.db)
        now_expr = current_timestamp_expr(dialect=dialect)
        
        # Count various identity risks
        risk_factors = {}
        
        # Humans without MFA (high risk)
        mfa_query = text("""
            SELECT COUNT(DISTINCT p.principal_id)
            FROM principals p
            JOIN accounts a ON p.account_id = a.account_id
            WHERE a.org_id = :org_id 
                AND p.is_human = true
                AND p.principal_id NOT IN (
                    SELECT principal_id FROM findings 
                    WHERE rule_id IN (
                        SELECT rule_id FROM rules 
                        WHERE name LIKE '%MFA%' OR description LIKE '%multi-factor%'
                    )
                )
        """)
        
        result = await self.db.execute(mfa_query, {"org_id": org_id})
        no_mfa_count = result.scalar() or 0
        risk_factors["no_mfa_users"] = no_mfa_count
        
        # Stale admin accounts (high risk)
        stale_admin_query = text(f"""
            SELECT COUNT(DISTINCT ie.principal_id)
            FROM iam_edges ie
            JOIN accounts a ON ie.account_id = a.account_id
            WHERE a.org_id = :org_id
                AND ie.is_admin = true
                AND ie.effective_at < :stale_threshold
                AND (ie.expires_at IS NULL OR ie.expires_at > {now_expr})
        """)
        
        stale_threshold = datetime.utcnow() - timedelta(days=90)
        result = await self.db.execute(stale_admin_query, {
            "org_id": org_id,
            "stale_threshold": stale_threshold
        })
        stale_admin_count = result.scalar() or 0
        risk_factors["stale_admin_accounts"] = stale_admin_count
        
        # Calculate weighted identity risk score
        identity_risk = (
            no_mfa_count * 5.0 +      # High weight for MFA issues
            stale_admin_count * 3.0   # Medium-high weight for stale admins
        )
        
        # Normalize to 0-100 scale
        normalized_score = min(100.0, identity_risk * 2.0)  # Scale factor
        
        return normalized_score
    
    async def _calculate_access_control_score(self, org_id: UUID) -> float:
        """Calculate access control risk score (0-100, lower is better)."""

        dialect = get_dialect_name(self.db)
        now_expr = current_timestamp_expr(dialect=dialect)
        
        # Excessive permissions (privilege sprawl)
        privilege_sprawl_query = text(f"""
            SELECT p.principal_id, COUNT(DISTINCT ie.permission) as permission_count
            FROM principals p
            JOIN iam_edges ie ON p.principal_id = ie.principal_id
            JOIN accounts a ON p.account_id = a.account_id
            WHERE a.org_id = :org_id
                AND p.is_human = true
                AND (ie.expires_at IS NULL OR ie.expires_at > {now_expr})
            GROUP BY p.principal_id
            HAVING COUNT(DISTINCT ie.permission) > 50  -- Threshold for excessive permissions
        """)
        
        result = await self.db.execute(privilege_sprawl_query, {"org_id": org_id})
        excessive_perm_users = len(result.fetchall())
        
        # Public resources (high exposure)
        public_resources_query = text("""
            SELECT COUNT(*)
            FROM findings f
            JOIN accounts a ON f.account_id = a.account_id
            WHERE a.org_id = :org_id
                AND f.status = 'open'
                AND (f.title LIKE '%public%' OR f.title LIKE '%exposed%')
        """)
        
        result = await self.db.execute(public_resources_query, {"org_id": org_id})
        public_resource_count = result.scalar() or 0
        
        # Calculate access control risk
        access_risk = (
            excessive_perm_users * 4.0 +
            public_resource_count * 2.0
        )
        
        normalized_score = min(100.0, access_risk * 1.5)
        return normalized_score
    
    async def _calculate_compliance_score(self, org_id: UUID) -> float:
        """Calculate compliance posture score (0-100, lower is better)."""
        
        # Count policy violations
        policy_violations_query = text("""
            SELECT COUNT(*)
            FROM findings f
            JOIN rules r ON f.rule_id = r.rule_id
            JOIN accounts a ON f.account_id = a.account_id
            WHERE a.org_id = :org_id
                AND f.status = 'open'
                AND (r.cis IS NOT NULL OR r.nist_800_53 IS NOT NULL)
        """)
        
        result = await self.db.execute(policy_violations_query, {"org_id": org_id})
        policy_violations = result.scalar() or 0
        
        # Normalize to risk score
        compliance_risk = min(100.0, policy_violations * 2.0)
        return compliance_risk
    
    async def _calculate_operational_score(self, org_id: UUID) -> float:
        """Calculate operational security score (0-100, lower is better)."""
        
        # Count operational security issues
        operational_query = text("""
            SELECT COUNT(*)
            FROM findings f
            JOIN accounts a ON f.account_id = a.account_id
            WHERE a.org_id = :org_id
                AND f.status = 'open'
                AND (f.title LIKE '%logging%' OR f.title LIKE '%monitoring%' 
                     OR f.title LIKE '%backup%' OR f.title LIKE '%encryption%')
        """)
        
        result = await self.db.execute(operational_query, {"org_id": org_id})
        operational_issues = result.scalar() or 0
        
        operational_risk = min(100.0, operational_issues * 3.0)
        return operational_risk
    
    def _score_to_risk_level(self, score: float) -> RiskSeverity:
        """Convert numeric score to risk severity level."""
        if score <= 20:
            return RiskSeverity.MINIMAL
        elif score <= 40:
            return RiskSeverity.LOW
        elif score <= 60:
            return RiskSeverity.MODERATE
        elif score <= 80:
            return RiskSeverity.HIGH
        else:
            return RiskSeverity.CRITICAL
    
    async def _identify_risk_factors(self, org_id: UUID) -> List[RiskFactor]:
        """Identify specific risk factors contributing to the score."""
        
        factors = []
        
        # Critical findings factor
        critical_count_query = text("""
            SELECT COUNT(*) FROM findings f
            JOIN accounts a ON f.account_id = a.account_id
            WHERE a.org_id = :org_id AND f.severity = 'critical' AND f.status = 'open'
        """)
        result = await self.db.execute(critical_count_query, {"org_id": org_id})
        critical_count = result.scalar() or 0
        
        if critical_count > 0:
            factors.append(RiskFactor(
                factor_name="Critical Security Findings",
                category="vulnerability",
                current_value=float(critical_count),
                baseline_value=0.0,
                weight=0.3,
                risk_contribution=min(30.0, critical_count * 3.0),
                description=f"{critical_count} critical security findings require immediate attention",
                remediation_suggestions=[
                    "Prioritize critical finding remediation",
                    "Implement automated vulnerability scanning",
                    "Establish security incident response procedures"
                ]
            ))
        
        # Admin without MFA factor
        admin_no_mfa_query = text("""
            SELECT COUNT(DISTINCT ie.principal_id)
            FROM iam_edges ie
            JOIN accounts a ON ie.account_id = a.account_id
            JOIN principals p ON ie.principal_id = p.principal_id
            WHERE a.org_id = :org_id
                AND ie.is_admin = true
                AND p.is_human = true
                AND ie.principal_id NOT IN (
                    SELECT principal_id FROM findings 
                    WHERE rule_id IN (
                        SELECT rule_id FROM rules 
                        WHERE name LIKE '%MFA%'
                    )
                )
        """)
        
        result = await self.db.execute(admin_no_mfa_query, {"org_id": org_id})
        admin_no_mfa_count = result.scalar() or 0
        
        if admin_no_mfa_count > 0:
            factors.append(RiskFactor(
                factor_name="Admin Accounts Without MFA",
                category="identity",
                current_value=float(admin_no_mfa_count),
                baseline_value=0.0,
                weight=0.25,
                risk_contribution=admin_no_mfa_count * 5.0,
                description=f"{admin_no_mfa_count} admin accounts lack multi-factor authentication",
                remediation_suggestions=[
                    "Enforce MFA for all administrative accounts",
                    "Implement conditional access policies",
                    "Regular access reviews for privileged accounts"
                ]
            ))
        
        return factors
    
    async def _analyze_score_trend(self, org_id: UUID, current_score: float) -> tuple[str, float]:
        """Analyze risk score trend over time."""
        
        # Get historical risk scores (from metric snapshots)
        since_date = datetime.utcnow() - timedelta(days=30)
        
        from .time_series import SecurityMetricSnapshot
        
        stmt = select(SecurityMetricSnapshot.value).where(
            and_(
                SecurityMetricSnapshot.org_id == org_id,
                SecurityMetricSnapshot.metric_type == "overall_risk_score",
                SecurityMetricSnapshot.captured_at >= since_date
            )
        ).order_by(SecurityMetricSnapshot.captured_at)
        
        historical_scores = list(await self.db.scalars(stmt))
        
        if len(historical_scores) < 2:
            return "stable", 0.5
        
        # Calculate trend
        oldest_score = historical_scores[0]
        trend_change = current_score - oldest_score
        
        if abs(trend_change) < 5.0:  # Less than 5 point change
            trend = "stable"
        elif trend_change < 0:
            trend = "improving"  # Lower score = better security
        else:
            trend = "declining"
        
        # Confidence based on data points
        confidence = min(1.0, len(historical_scores) / 30.0)
        
        return trend, confidence
    
    async def _identify_top_risks(self, org_id: UUID) -> List[str]:
        """Identify top 5 risks for the organization."""
        
        top_risks = []
        
        # Query for top finding types
        top_findings_query = text("""
            SELECT r.name, COUNT(*) as count, r.severity
            FROM findings f
            JOIN rules r ON f.rule_id = r.rule_id
            JOIN accounts a ON f.account_id = a.account_id
            WHERE a.org_id = :org_id AND f.status = 'open'
            GROUP BY r.name, r.severity
            ORDER BY 
                CASE r.severity 
                    WHEN 'critical' THEN 4
                    WHEN 'high' THEN 3  
                    WHEN 'medium' THEN 2
                    WHEN 'low' THEN 1
                    ELSE 0
                END DESC,
                count DESC
            LIMIT 5
        """)
        
        result = await self.db.execute(top_findings_query, {"org_id": org_id})
        
        for row in result.fetchall():
            top_risks.append(f"{row.count} {row.severity} - {row.name}")
        
        return top_risks
    
    async def _identify_quick_wins(self, org_id: UUID) -> List[str]:
        """Identify quick wins for risk reduction."""
        
        quick_wins = []
        
        # Look for common, easy-to-fix issues
        quick_win_patterns = [
            ("Public S3 buckets", "s3.*public"),
            ("Unencrypted resources", ".*unencrypted.*"),
            ("Default passwords", ".*default.*password"),
            ("Missing MFA", ".*mfa.*disabled"),
            ("Excessive permissions", ".*overprivileged")
        ]
        
        for pattern_name, pattern in quick_win_patterns:
            count_query = text("""
                SELECT COUNT(*)
                FROM findings f
                JOIN rules r ON f.rule_id = r.rule_id
                JOIN accounts a ON f.account_id = a.account_id
                WHERE a.org_id = :org_id 
                    AND f.status = 'open'
                    AND (r.name ~* :pattern OR r.description ~* :pattern)
            """)
            
            result = await self.db.execute(count_query, {
                "org_id": org_id,
                "pattern": pattern
            })
            count = result.scalar() or 0
            
            if count > 0:
                quick_wins.append(f"Fix {count} {pattern_name.lower()}")
        
        return quick_wins[:3]  # Top 3 quick wins
    
    async def _identify_strategic_initiatives(self, org_id: UUID) -> List[str]:
        """Identify strategic security initiatives."""
        
        initiatives = []
        
        # Analyze patterns for strategic recommendations
        provider_coverage_query = text("""
            SELECT r.provider, COUNT(DISTINCT r.resource_id) as resource_count
            FROM resources r
            JOIN accounts a ON r.account_id = a.account_id
            WHERE a.org_id = :org_id
            GROUP BY r.provider
            ORDER BY resource_count DESC
        """)
        
        result = await self.db.execute(provider_coverage_query, {"org_id": org_id})
        providers = result.fetchall()
        
        if len(providers) > 3:
            initiatives.append("Implement unified cloud security posture management")
        
        # Check for identity sprawl
        identity_count_query = text("""
            SELECT COUNT(DISTINCT p.principal_id)
            FROM principals p
            JOIN accounts a ON p.account_id = a.account_id
            WHERE a.org_id = :org_id AND p.is_human = true
        """)
        
        result = await self.db.execute(identity_count_query, {"org_id": org_id})
        identity_count = result.scalar() or 0
        
        if identity_count > 100:
            initiatives.append("Deploy identity governance and lifecycle management")
        
        return initiatives
    
    async def generate_risk_heatmap(self, org_id: UUID) -> RiskHeatmap:
        """Generate risk heatmap by provider and resource type."""
        
        heatmap_query = text("""
            SELECT 
                r.provider,
                r.resource_type,
                COUNT(f.finding_id) as finding_count,
                AVG(CASE f.severity 
                    WHEN 'critical' THEN 4
                    WHEN 'high' THEN 3
                    WHEN 'medium' THEN 2
                    WHEN 'low' THEN 1
                    ELSE 0
                END) as avg_severity_score
            FROM resources r
            JOIN accounts a ON r.account_id = a.account_id
            LEFT JOIN findings f ON r.resource_id = f.resource_id AND f.status = 'open'
            WHERE a.org_id = :org_id
            GROUP BY r.provider, r.resource_type
            ORDER BY avg_severity_score DESC, finding_count DESC
        """)
        
        result = await self.db.execute(heatmap_query, {"org_id": org_id})
        
        heatmap_data = {}
        high_risk_areas = []
        
        for row in result.fetchall():
            provider = row.provider
            resource_type = row.resource_type
            risk_score = (row.avg_severity_score or 0) * 25  # Scale to 0-100
            
            if provider not in heatmap_data:
                heatmap_data[provider] = {}
            
            heatmap_data[provider][resource_type] = risk_score
            
            # Identify high-risk areas
            if risk_score > 60:  # High risk threshold
                high_risk_areas.append({
                    "provider": provider,
                    "resource_type": resource_type,
                    "risk_score": risk_score,
                    "finding_count": row.finding_count
                })
        
        # Identify improvement opportunities
        improvement_opportunities = []
        for area in high_risk_areas[:3]:  # Top 3 opportunities
            current_risk = float(area["risk_score"])
            improvement_opportunities.append({
                "area": f"{area['provider']} {area['resource_type']}",
                "current_risk": current_risk,
                "potential_reduction": current_risk * 0.7,  # Estimate 70% reduction potential
                "impact": "high" if current_risk > 80 else "medium"
            })
        
        return RiskHeatmap(
            org_id=org_id,
            heatmap_data=heatmap_data,
            high_risk_areas=high_risk_areas,
            improvement_opportunities=improvement_opportunities
        )
