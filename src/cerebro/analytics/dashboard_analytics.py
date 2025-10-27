"""Dashboard analytics for executive and operational security insights."""

import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from uuid import UUID
from time import perf_counter

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, desc, func, text

from .time_series import TimeSeriesCollector, TrendAnalyzer, MetricType
from .risk_scoring import RiskScoringEngine
from .identity_analytics import IdentityAnalyzer, PrivilegeSprawlDetector
from .dashboard_repository import DashboardRepository
from prometheus_client import Histogram

logger = logging.getLogger(__name__)


dashboard_component_duration = Histogram(
    "cerebro_dashboard_component_duration_seconds",
    "Time spent generating executive dashboard components",
    labelnames=("component",),
)


@dataclass
class SecurityMetrics:
    """Core security metrics for dashboard."""
    # Finding metrics
    total_findings: int
    critical_findings: int
    high_findings: int
    open_findings: int
    
    # Trends (sparkline data)
    findings_trend: List[float]
    critical_trend: List[float]
    
    # SLA and MTTR
    sla_breaches: int
    mean_time_to_remediation: float
    
    # Recent activity
    new_findings_24h: int
    resolved_findings_24h: int


@dataclass
class ExecutiveSummary:
    """Executive-level security summary."""
    org_id: UUID
    report_date: datetime
    
    # Overall posture
    overall_risk_score: float
    risk_level: str
    risk_trend: str  # "improving", "declining", "stable"
    dimension_scores: Dict[str, float]
    
    # Key metrics
    total_assets: int
    total_identities: int
    active_findings: int
    compliance_score: float
    
    # Top risks (board-friendly)
    top_5_risks: List[str]
    
    # Progress indicators
    findings_burned_down_30d: int
    new_controls_implemented: int
    risk_score_change_30d: float
    
    # Investment priorities
    recommended_investments: List[Dict[str, Any]]


class DashboardAnalytics:
    """Comprehensive analytics for security dashboard."""
    
    def __init__(self, db_session: AsyncSession):
        """Initialize dashboard analytics."""
        self.db = db_session
        self.time_series = TimeSeriesCollector(db_session)
        self.trend_analyzer = TrendAnalyzer(db_session)
        self.risk_engine = RiskScoringEngine(db_session)
        self.identity_analyzer = IdentityAnalyzer(db_session)
        self.repository = DashboardRepository(db_session)
        self._last_generation_timings: Dict[str, float] = {}

    @property
    def last_generation_timings(self) -> Dict[str, float]:
        """Expose timings from the last dashboard generation cycle."""

        return dict(self._last_generation_timings)

    async def _track_component(self, component: str, coroutine):
        start = perf_counter()
        try:
            return await coroutine
        finally:
            duration = perf_counter() - start
            self._last_generation_timings[component] = duration
            try:
                dashboard_component_duration.labels(component=component).observe(duration)
            except Exception:  # pragma: no cover - metrics registration edge cases
                logger.debug(
                    "Failed to record dashboard timing metric",
                    exc_info=True,
                )
    
    async def generate_security_metrics(self, org_id: UUID) -> SecurityMetrics:
        """Generate core security metrics for dashboard KPIs."""
        
        # Current finding counts
        total_findings = await self.repository.get_finding_count(org_id)
        critical_findings = await self.repository.get_finding_count_by_severity(org_id, "critical")
        high_findings = await self.repository.get_finding_count_by_severity(org_id, "high")
        open_findings = await self.repository.get_finding_count_by_status(org_id, "open")
        
        # Generate sparkline data (last 7 days)
        findings_trend = await self.trend_analyzer.generate_sparkline_data(
            org_id, MetricType.FINDING_COUNT, days_back=7
        )
        
        # Generate critical findings trend
        critical_trend_query = text("""
            SELECT DATE(captured_at) as date, value
            FROM security_metric_snapshots
            WHERE org_id = :org_id 
                AND metric_type = 'critical_finding_count'
                AND captured_at >= :since_date
            ORDER BY captured_at
        """)
        
        since_date = datetime.utcnow() - timedelta(days=7)
        result = await self.db.execute(critical_trend_query, {
            "org_id": org_id,
            "since_date": since_date
        })
        
        critical_trend = [row.value for row in result.fetchall()]
        
        # Calculate SLA breaches
        sla_breaches = await self.repository.count_sla_breaches(org_id)

        # Calculate MTTR
        mttr = await self.repository.calculate_mttr(org_id)

        # Recent activity (24 hours)
        new_findings_24h = await self.repository.count_new_findings(org_id)
        resolved_findings_24h = await self.repository.count_resolved_findings(org_id)
        
        return SecurityMetrics(
            total_findings=total_findings,
            critical_findings=critical_findings,
            high_findings=high_findings,
            open_findings=open_findings,
            findings_trend=findings_trend[-7:] if len(findings_trend) >= 7 else findings_trend,
            critical_trend=critical_trend[-7:] if len(critical_trend) >= 7 else critical_trend,
            sla_breaches=sla_breaches,
            mean_time_to_remediation=mttr,
            new_findings_24h=new_findings_24h,
            resolved_findings_24h=resolved_findings_24h
        )
    
    async def generate_executive_summary(self, org_id: UUID) -> ExecutiveSummary:
        """Generate executive-level security summary."""
        
        logger.info(f"Generating executive summary for org {org_id}")
        
        # Calculate overall risk score
        risk_score = await self.risk_engine.calculate_organization_risk_score(org_id)
        dimension_scores = {
            "vulnerability_exposure": risk_score.vulnerability_score,
            "identity_hygiene": risk_score.identity_score,
            "access_control": risk_score.access_control_score,
            "compliance_posture": risk_score.compliance_score,
            "operational_security": risk_score.operational_score,
        }
        
        # Get asset and identity counts
        total_assets = await self.repository.count_total_assets(org_id)
        total_identities = await self.repository.count_total_identities(org_id)
        active_findings = await self.repository.get_finding_count_by_status(org_id, "open")

        # Calculate compliance score (simplified)
        compliance_score = await self.repository.calculate_compliance_score(org_id)
        
        # Generate top 5 risks (board-friendly format)
        top_5_risks = await self._generate_top_5_risks(org_id)
        
        # Calculate progress indicators
        findings_burned_30d = await self._calculate_findings_burned_down(org_id, 30)
        new_controls = await self._count_new_controls_implemented(org_id, 30)
        risk_change_30d = await self._calculate_risk_score_change(org_id, 30)
        
        # Generate investment recommendations
        investment_recommendations = await self._generate_investment_recommendations(org_id)
        
        return ExecutiveSummary(
            org_id=org_id,
            report_date=datetime.utcnow(),
            overall_risk_score=risk_score.overall_score,
            risk_level=risk_score.risk_level.value,
            risk_trend=risk_score.score_trend,
            dimension_scores=dimension_scores,
            total_assets=total_assets,
            total_identities=total_identities,
            active_findings=active_findings,
            compliance_score=compliance_score,
            top_5_risks=top_5_risks,
            findings_burned_down_30d=findings_burned_30d,
            new_controls_implemented=new_controls,
            risk_score_change_30d=risk_change_30d,
            recommended_investments=investment_recommendations
        )
    
        result = await self.db.execute(total_compliance_query)
        total_compliance_rules = result.scalar() or 1
        
        # Get compliant rules (no open findings)
        compliant_query = text("""
            SELECT COUNT(DISTINCT r.rule_id)
            FROM rules r
            WHERE (r.cis IS NOT NULL OR r.nist_800_53 IS NOT NULL)
                AND r.rule_id NOT IN (
                    SELECT DISTINCT f.rule_id
                    FROM findings f
                    JOIN accounts a ON f.account_id = a.account_id
                    WHERE a.org_id = :org_id AND f.status = 'open'
                )
        """)
        
        result = await self.db.execute(compliant_query, {"org_id": org_id})
        compliant_rules = result.scalar() or 0
        
        compliance_score = (compliant_rules / total_compliance_rules) * 100
        return compliance_score
    
    async def _generate_top_5_risks(self, org_id: UUID) -> List[str]:
        """Generate top 5 risks in board-friendly language."""
        
        risks_query = text("""
            WITH risk_analysis AS (
                SELECT 
                    CASE 
                        WHEN r.name ILIKE '%public%' OR r.name ILIKE '%exposed%' THEN 'Data Exposure'
                        WHEN r.name ILIKE '%admin%' OR r.name ILIKE '%privilege%' THEN 'Privilege Escalation'
                        WHEN r.name ILIKE '%mfa%' OR r.name ILIKE '%authentication%' THEN 'Authentication Weaknesses'
                        WHEN r.name ILIKE '%encryption%' OR r.name ILIKE '%unencrypted%' THEN 'Data Protection'
                        WHEN r.name ILIKE '%logging%' OR r.name ILIKE '%monitoring%' THEN 'Visibility Gaps'
                        ELSE 'Other Security Issues'
                    END as risk_category,
                    COUNT(*) as finding_count,
                    AVG(CASE f.severity 
                        WHEN 'critical' THEN 4
                        WHEN 'high' THEN 3
                        WHEN 'medium' THEN 2
                        WHEN 'low' THEN 1
                        ELSE 0
                    END) as avg_severity
                FROM findings f
                JOIN rules r ON f.rule_id = r.rule_id
                JOIN accounts a ON f.account_id = a.account_id
                WHERE a.org_id = :org_id AND f.status = 'open'
                GROUP BY risk_category
            )
            SELECT 
                risk_category,
                finding_count,
                avg_severity,
                (finding_count * avg_severity) as risk_impact
            FROM risk_analysis
            ORDER BY risk_impact DESC
            LIMIT 5
        """)
        
        result = await self.db.execute(risks_query, {"org_id": org_id})
        
        top_risks = []
        for row in result.fetchall():
            severity_text = "critical" if row.avg_severity >= 3.5 else "high" if row.avg_severity >= 2.5 else "medium"
            top_risks.append(f"#{len(top_risks)+1} {row.risk_category}: {row.finding_count} {severity_text} issues")
        
        return top_risks
    
    async def _calculate_findings_burned_down(self, org_id: UUID, days: int) -> int:
        """Calculate how many findings were resolved in the last N days."""
        since_date = datetime.utcnow() - timedelta(days=days)
        
        query = text("""
            SELECT COUNT(*)
            FROM findings f
            JOIN accounts a ON f.account_id = a.account_id
            WHERE a.org_id = :org_id
                AND f.status IN ('fixed', 'accepted_risk')
                AND f.last_seen >= :since_date
        """)
        
        result = await self.db.execute(query, {"org_id": org_id, "since_date": since_date})
        return result.scalar() or 0
    
    async def _count_new_controls_implemented(self, org_id: UUID, days: int) -> int:
        """Count new security controls (rules) implemented in last N days."""
        since_date = datetime.utcnow() - timedelta(days=days)
        
        query = text("""
            SELECT COUNT(*)
            FROM rules r
            JOIN policies p ON r.policy_id = p.policy_id
            WHERE p.org_id = :org_id
                AND r.created_at >= :since_date
                AND r.is_active = true
        """)
        
        result = await self.db.execute(query, {"org_id": org_id, "since_date": since_date})
        return result.scalar() or 0
    
    async def _calculate_risk_score_change(self, org_id: UUID, days: int) -> float:
        """Calculate risk score change over last N days."""
        since_date = datetime.utcnow() - timedelta(days=days)
        
        # Get oldest and newest risk scores
        score_query = text("""
            SELECT value, captured_at
            FROM security_metric_snapshots
            WHERE org_id = :org_id 
                AND metric_type = 'overall_risk_score'
                AND captured_at >= :since_date
            ORDER BY captured_at
        """)
        
        result = await self.db.execute(score_query, {
            "org_id": org_id,
            "since_date": since_date
        })
        
        scores = result.fetchall()
        
        if len(scores) < 2:
            return 0.0
        
        oldest_score = scores[0].value
        newest_score = scores[-1].value
        
        return newest_score - oldest_score
    
    async def _generate_investment_recommendations(self, org_id: UUID) -> List[Dict[str, Any]]:
        """Generate investment recommendations based on risk analysis."""
        
        recommendations = []
        
        # Analyze finding patterns for investment priorities
        investment_analysis_query = text("""
            WITH provider_risk AS (
                SELECT 
                    a.provider,
                    COUNT(*) as finding_count,
                    COUNT(CASE WHEN f.severity IN ('critical', 'high') THEN 1 END) as high_risk_count
                FROM findings f
                JOIN accounts a ON f.account_id = a.account_id
                WHERE a.org_id = :org_id AND f.status = 'open'
                GROUP BY a.provider
            )
            SELECT 
                provider,
                finding_count,
                high_risk_count,
                (high_risk_count::float / finding_count * 100) as risk_percentage
            FROM provider_risk
            WHERE finding_count > 5
            ORDER BY risk_percentage DESC, finding_count DESC
        """)
        
        result = await self.db.execute(investment_analysis_query, {"org_id": org_id})
        
        for row in result.fetchall():
            if row.risk_percentage > 50:  # High-risk provider
                recommendations.append({
                    "priority": "high",
                    "category": "Provider Security",
                    "recommendation": f"Invest in {row.provider} security tooling",
                    "rationale": f"{row.high_risk_count} high-risk findings out of {row.finding_count} total",
                    "estimated_impact": "30-50% risk reduction",
                    "investment_level": "medium"
                })
        
        # Identity management investment
        identity_sprawl = await self.identity_analyzer.analyze_risky_identities(org_id, limit=5)
        if len(identity_sprawl) > 3:
            recommendations.append({
                "priority": "medium",
                "category": "Identity Governance",
                "recommendation": "Implement automated identity lifecycle management",
                "rationale": f"{len(identity_sprawl)} high-risk identities identified",
                "estimated_impact": "20-40% identity risk reduction",
                "investment_level": "high"
            })
        
        return recommendations
    
    async def generate_comprehensive_dashboard(self, org_id: UUID) -> Dict[str, Any]:
        """Generate comprehensive dashboard data combining all analytics."""
        
        logger.info(f"Generating comprehensive dashboard for org {org_id}")

        self._last_generation_timings = {}
        total_start = perf_counter()
        
        # Collect all analytics
        security_metrics = await self._track_component(
            "security_metrics",
            self.generate_security_metrics(org_id),
        )
        executive_summary = await self._track_component(
            "executive_summary",
            self.generate_executive_summary(org_id),
        )
        
        # Identity analytics
        identity_data = await self._track_component(
            "identity_analytics",
            self.identity_analyzer.generate_identity_dashboard_data(org_id),
        )
        
        # Risk heatmap
        risk_heatmap = await self._track_component(
            "risk_heatmap",
            self.risk_engine.generate_risk_heatmap(org_id),
        )
        
        # Compliance status
        compliance_status = await self._track_component(
            "compliance_status",
            self._get_compliance_status_by_framework(org_id),
        )

        total_duration = perf_counter() - total_start
        self._last_generation_timings["total"] = total_duration
        try:
            dashboard_component_duration.labels(component="total").observe(total_duration)
        except Exception:  # pragma: no cover - metrics registration edge cases
            logger.debug("Failed to record total dashboard timing", exc_info=True)

        logger.debug(
            "Dashboard generation timings",
            extra={"org_id": str(org_id), "timings": self._last_generation_timings},
        )
        
        return {
            "executive_summary": {
                "org_id": str(executive_summary.org_id),
                "report_date": executive_summary.report_date.isoformat(),
                "overall_risk_score": executive_summary.overall_risk_score,
                "risk_level": executive_summary.risk_level,
                "risk_trend": executive_summary.risk_trend,
                "dimension_scores": executive_summary.dimension_scores,
                "total_assets": executive_summary.total_assets,
                "total_identities": executive_summary.total_identities,
                "active_findings": executive_summary.active_findings,
                "compliance_score": executive_summary.compliance_score,
                "top_5_risks": executive_summary.top_5_risks,
                "progress_indicators": {
                    "findings_burned_down_30d": executive_summary.findings_burned_down_30d,
                    "new_controls_implemented": executive_summary.new_controls_implemented,
                    "risk_score_change_30d": executive_summary.risk_score_change_30d,
                },
            },
            "security_metrics": {
                "findings": {
                    "total": security_metrics.total_findings,
                    "critical": security_metrics.critical_findings,
                    "high": security_metrics.high_findings,
                    "open": security_metrics.open_findings,
                    "trend_7d": security_metrics.findings_trend,
                    "critical_trend_7d": security_metrics.critical_trend
                },
                "sla_performance": {
                    "breaches": security_metrics.sla_breaches,
                    "mttr_hours": round(security_metrics.mean_time_to_remediation, 1),
                    "new_24h": security_metrics.new_findings_24h,
                    "resolved_24h": security_metrics.resolved_findings_24h
                }
            },
            "identity_analytics": identity_data,
            "risk_heatmap": {
                "heatmap_data": risk_heatmap.heatmap_data,
                "high_risk_areas": risk_heatmap.high_risk_areas,
                "improvement_opportunities": risk_heatmap.improvement_opportunities
            },
            "compliance_status": compliance_status,
            "investment_recommendations": executive_summary.recommended_investments
        }
    
    async def _get_compliance_status_by_framework(self, org_id: UUID) -> Dict[str, Any]:
        """Get compliance status breakdown by framework."""
        
        frameworks_query = text("""
            SELECT 
                UNNEST(r.cis) as framework_control,
                COUNT(*) as total_controls,
                COUNT(CASE WHEN f.finding_id IS NULL THEN 1 END) as compliant_controls
            FROM rules r
            LEFT JOIN findings f ON r.rule_id = f.rule_id 
                AND f.status = 'open'
                AND f.account_id IN (
                    SELECT account_id FROM accounts WHERE org_id = :org_id
                )
            WHERE r.cis IS NOT NULL
            GROUP BY UNNEST(r.cis)
            
            UNION ALL
            
            SELECT 
                UNNEST(r.nist_800_53) as framework_control,
                COUNT(*) as total_controls,
                COUNT(CASE WHEN f.finding_id IS NULL THEN 1 END) as compliant_controls
            FROM rules r
            LEFT JOIN findings f ON r.rule_id = f.rule_id 
                AND f.status = 'open'
                AND f.account_id IN (
                    SELECT account_id FROM accounts WHERE org_id = :org_id
                )
            WHERE r.nist_800_53 IS NOT NULL
            GROUP BY UNNEST(r.nist_800_53)
        """)
        
        result = await self.db.execute(frameworks_query, {"org_id": org_id})
        
        framework_compliance = {}
        for row in result.fetchall():
            framework = row.framework_control.split('.')[0] if '.' in row.framework_control else 'Unknown'
            
            if framework not in framework_compliance:
                framework_compliance[framework] = {
                    "total_controls": 0,
                    "compliant_controls": 0
                }
            
            framework_compliance[framework]["total_controls"] += row.total_controls
            framework_compliance[framework]["compliant_controls"] += row.compliant_controls
        
        # Calculate compliance percentages
        for framework, data in framework_compliance.items():
            total = data["total_controls"]
            compliant = data["compliant_controls"]
            percentage = (compliant / total * 100) if total > 0 else 0
            data["compliance_percentage"] = round(percentage, 1)
            data["status"] = "compliant" if percentage >= 90 else "partial" if percentage >= 70 else "non_compliant"
        
        return framework_compliance
