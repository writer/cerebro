"""Advanced analysis endpoints."""

from typing import List, Optional
from uuid import UUID
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, Query
import logging
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel

from cerebro.core.database import get_db
from cerebro.core.models import Organization, Principal
from cerebro.api.auth import User, require_read_findings
from cerebro.api.org_access import require_org_access
from cerebro.analysis.blast_radius import BlastRadiusAnalyzer
from cerebro.analysis.forensic_replay import ForensicReplayEngine
from cerebro.analysis.change_replay import ChangeReplayEngine

try:
    from cerebro.analysis.identity_anomaly import IdentityAnomalyDetector, AnomalyResult

    IDENTITY_ANOMALY_AVAILABLE = True
except ImportError:
    IdentityAnomalyDetector = None  # type: ignore[misc, assignment]
    AnomalyResult = None  # type: ignore[misc, assignment]
    IDENTITY_ANOMALY_AVAILABLE = False
from cerebro.compliance.generator import ComplianceEvidenceGenerator
from cerebro.compliance.frameworks import list_frameworks, get_framework
from cerebro.compliance.framework_registry import AutomationLevel
from cerebro.rules.engine import rule_engine

router = APIRouter()
logger = logging.getLogger(__name__)


class BlastRadiusRequest(BaseModel):
    principal_id: UUID
    scenario_type: str = "credential_theft"
    at_time: Optional[datetime] = None


class ForensicReplayRequest(BaseModel):
    target_time: datetime
    scope: Optional[dict] = None


class ChangeReplayRequest(BaseModel):
    rule_expression: str
    start_time: datetime
    end_time: datetime
    providers: Optional[List[str]] = None


class IdentityAnomalyRequest(BaseModel):
    org_id: UUID
    principal_id: Optional[UUID] = None
    lookback_days: int = 30


@router.post("/organizations/{org_id}/blast-radius")
async def analyze_blast_radius(
    org_id: UUID,
    request: BlastRadiusRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_org_access(require_read_findings)),
):
    """Analyze blast radius for principal compromise."""
    # Verify organization exists
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    # Verify principal exists and belongs to organization
    principal = await db.get(Principal, request.principal_id)
    if not principal or principal.account.org_id != org_id:
        raise HTTPException(status_code=404, detail="Principal not found")

    try:
        analyzer = BlastRadiusAnalyzer(db)
        assessment = await analyzer.analyze_principal_compromise(
            request.principal_id, request.scenario_type, request.at_time
        )

        return {
            "scenario": {
                "principal_name": assessment.scenario.principal_name,
                "principal_type": assessment.scenario.principal_type,
                "provider": assessment.scenario.provider,
                "scenario_type": assessment.scenario.scenario_type,
                "compromise_time": assessment.scenario.compromise_time.isoformat(),
            },
            "impact": {
                "total_resources_at_risk": assessment.total_resources_at_risk,
                "max_sensitivity_score": assessment.max_sensitivity_score,
                "business_impact_score": assessment.business_impact_score,
                "escalation_paths_count": len(assessment.escalation_paths),
            },
            "directly_accessible": [
                {
                    "resource_external_id": r.resource_external_id,
                    "resource_type": r.resource_type,
                    "provider": r.provider,
                    "access_level": r.access_level,
                    "sensitivity_score": r.sensitivity_score,
                    "potential_actions": r.potential_actions,
                }
                for r in assessment.directly_accessible[:20]  # Limit for API response
            ],
            "mitigation_recommendations": assessment.mitigation_recommendations,
            "analysis_metadata": {
                "total_escalation_paths": len(assessment.escalation_paths),
                "cross_provider_resources": len(assessment.cross_provider_impact),
            },
        }

    except Exception:
        logger.exception("Blast radius analysis failed", extra={"org_id": str(org_id)})
        raise HTTPException(status_code=500, detail="Analysis failed")


@router.get("/organizations/{org_id}/blast-radius/report")
async def generate_blast_radius_report(
    org_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_org_access(require_read_findings)),
):
    """Generate organization-wide blast radius report."""
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    try:
        analyzer = BlastRadiusAnalyzer(db)
        report = await analyzer.generate_blast_radius_report(org_id)
        return report

    except Exception:
        logger.exception(
            "Blast radius report generation failed", extra={"org_id": str(org_id)}
        )
        raise HTTPException(status_code=500, detail="Report generation failed")


@router.post("/organizations/{org_id}/forensic-replay")
async def forensic_replay(
    org_id: UUID,
    request: ForensicReplayRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_org_access(require_read_findings)),
):
    """Reconstruct system state at a historical point in time."""
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    try:
        replay_engine = ForensicReplayEngine(db)
        historical_state = await replay_engine.reconstruct_state_at_time(
            org_id, request.target_time, request.scope
        )

        return {
            "timestamp": historical_state.timestamp.isoformat(),
            "organization": historical_state.organization,
            "summary": historical_state.security_summary,
            "principals": [
                {
                    "external_id": p.external_id,
                    "display_name": p.display_name,
                    "principal_type": p.principal_type,
                    "provider": p.provider,
                    "was_active": p.was_active,
                    "permission_count": len(p.permissions),
                    "admin_permissions": len(
                        [perm for perm in p.permissions if perm["is_admin"]]
                    ),
                }
                for p in historical_state.principals[:50]  # Limit for API
            ],
            "resources": [
                {
                    "external_id": r.external_id,
                    "resource_type": r.resource_type,
                    "provider": r.provider,
                    "security_score": r.security_posture["overall_score"],
                    "access_count": len(r.who_had_access),
                    "issues": r.security_posture.get("issues", []),
                }
                for r in historical_state.resources[:50]  # Limit for API
            ],
            "active_findings": historical_state.active_findings[:50],
        }

    except Exception:
        logger.exception("Forensic replay failed", extra={"org_id": str(org_id)})
        raise HTTPException(status_code=500, detail="Forensic replay failed")


@router.post("/organizations/{org_id}/change-replay")
async def change_replay(
    org_id: UUID,
    request: ChangeReplayRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_org_access(require_read_findings)),
):
    """Replay rule changes against historical data."""
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    try:
        replay_engine = ChangeReplayEngine(db, rule_engine)

        # Create temporary rule ID for analysis
        temp_rule_id = UUID("00000000-0000-0000-0000-000000000001")

        # Evaluate rule against historical data
        result = await replay_engine.replay_rule_historically(
            temp_rule_id,
            org_id,
            request.start_time,
            request.end_time,
            request.providers,
        )

        return {
            "rule_expression": request.rule_expression,
            "time_period": result.time_period,
            "evaluation_results": {
                "total_evaluations": result.total_evaluations,
                "matches_found": result.matches_found,
                "match_rate_percentage": (
                    result.matches_found / max(result.total_evaluations, 1)
                )
                * 100,
                "new_findings_count": result.new_findings_count,
            },
            "coverage_analysis": result.coverage_analysis,
            "performance_metrics": result.performance_metrics,
            "sample_findings": result.findings_that_would_exist[:10],
        }

    except Exception:
        logger.exception("Change replay failed", extra={"org_id": str(org_id)})
        raise HTTPException(status_code=500, detail="Change replay failed")


@router.get("/organizations/{org_id}/rule-effectiveness")
async def get_rule_effectiveness(
    org_id: UUID,
    lookback_days: int = Query(default=90, description="Days to look back"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_org_access(require_read_findings)),
):
    """Get rule effectiveness analysis."""
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    try:
        replay_engine = ChangeReplayEngine(db, rule_engine)
        report = await replay_engine.generate_rule_effectiveness_report(
            org_id, lookback_days
        )
        return report

    except Exception:
        logger.exception(
            "Rule effectiveness analysis failed", extra={"org_id": str(org_id)}
        )
        raise HTTPException(status_code=500, detail="Analysis failed")


@router.post("/organizations/{org_id}/what-if-rule")
async def what_if_rule_analysis(
    org_id: UUID,
    rule_expression: str,
    providers: List[str],
    time_period_days: int = Query(default=30, description="Days to analyze"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_org_access(require_read_findings)),
):
    """Analyze what would happen if a rule had been active."""
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    try:
        replay_engine = ChangeReplayEngine(db, rule_engine)
        result = await replay_engine.what_if_rule_analysis(
            rule_expression, org_id, providers, time_period_days
        )
        return result

    except Exception:
        logger.exception("What-if rule analysis failed", extra={"org_id": str(org_id)})
        raise HTTPException(status_code=500, detail="Analysis failed")


@router.get("/organizations/{org_id}/identity/anomalies")
async def get_identity_anomalies(
    org_id: UUID,
    principal_id: Optional[UUID] = Query(
        None, description="Specific principal to analyze"
    ),
    lookback_days: int = Query(
        default=30, description="Days to look back for baseline"
    ),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_org_access(require_read_findings)),
):
    """Detect identity anomalies using machine learning."""
    if not IDENTITY_ANOMALY_AVAILABLE:
        raise HTTPException(
            status_code=501, detail="Identity anomaly detection requires sklearn"
        )

    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    try:
        detector = IdentityAnomalyDetector(lookback_days=lookback_days)
        anomalies = await detector.analyze_identity_anomalies(
            str(org_id), str(principal_id) if principal_id else None
        )

        return {
            "org_id": str(org_id),
            "analysis_period": {
                "lookback_days": lookback_days,
                "analyzed_at": datetime.now().isoformat(),
            },
            "total_anomalies": len(anomalies),
            "anomalies": [
                {
                    "principal_id": anomaly.principal_id,
                    "anomaly_type": anomaly.anomaly_type.value,
                    "risk_level": anomaly.risk_level.value,
                    "score": anomaly.score,
                    "confidence": anomaly.confidence,
                    "description": anomaly.description,
                    "details": anomaly.details,
                    "detected_at": anomaly.detected_at.isoformat(),
                    "recommended_actions": anomaly.recommended_actions,
                }
                for anomaly in anomalies
            ],
        }

    except Exception:
        logger.exception(
            "Identity anomaly detection failed", extra={"org_id": str(org_id)}
        )
        raise HTTPException(status_code=500, detail="Anomaly detection failed")


@router.get("/organizations/{org_id}/identity/anomalies/summary")
async def get_identity_anomaly_summary(
    org_id: UUID,
    lookback_days: int = Query(
        default=30, description="Days to look back for baseline"
    ),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_org_access(require_read_findings)),
):
    """Get summary of identity anomalies for organization."""
    if not IDENTITY_ANOMALY_AVAILABLE:
        raise HTTPException(
            status_code=501, detail="Identity anomaly detection requires sklearn"
        )

    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    try:
        detector = IdentityAnomalyDetector(lookback_days=lookback_days)
        summary = await detector.get_anomaly_summary(str(org_id))

        return {
            "org_id": str(org_id),
            "analysis_period": {
                "lookback_days": lookback_days,
                "period_start": summary["summary_period"][0].isoformat(),
                "period_end": summary["summary_period"][1].isoformat(),
            },
            "summary": {
                "total_anomalies": summary["total_anomalies"],
                "by_risk_level": summary["by_risk_level"],
                "by_type": summary["by_type"],
                "top_principals": summary["top_principals"],
            },
        }

    except Exception:
        logger.exception(
            "Identity anomaly summary failed", extra={"org_id": str(org_id)}
        )
        raise HTTPException(status_code=500, detail="Summary generation failed")


@router.post("/organizations/{org_id}/identity/anomalies/analyze")
async def analyze_identity_anomalies_post(
    org_id: UUID,
    request: IdentityAnomalyRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_org_access(require_read_findings)),
):
    """Run identity anomaly analysis with custom parameters."""
    if not IDENTITY_ANOMALY_AVAILABLE:
        raise HTTPException(
            status_code=501, detail="Identity anomaly detection requires sklearn"
        )

    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    try:
        detector = IdentityAnomalyDetector(lookback_days=request.lookback_days)
        anomalies = await detector.analyze_identity_anomalies(
            str(org_id), str(request.principal_id) if request.principal_id else None
        )

        return {
            "request": {
                "org_id": str(org_id),
                "principal_id": (
                    str(request.principal_id) if request.principal_id else None
                ),
                "lookback_days": request.lookback_days,
            },
            "results": {
                "total_anomalies": len(anomalies),
                "high_risk_count": len(
                    [a for a in anomalies if a.risk_level.value in ["high", "critical"]]
                ),
                "anomalies": [
                    {
                        "principal_id": anomaly.principal_id,
                        "anomaly_type": anomaly.anomaly_type.value,
                        "risk_level": anomaly.risk_level.value,
                        "score": anomaly.score,
                        "confidence": anomaly.confidence,
                        "description": anomaly.description,
                        "details": anomaly.details,
                        "detected_at": anomaly.detected_at.isoformat(),
                        "baseline_period": [
                            anomaly.baseline_period[0].isoformat(),
                            anomaly.baseline_period[1].isoformat(),
                        ],
                        "recommended_actions": anomaly.recommended_actions,
                    }
                    for anomaly in anomalies[:50]  # Limit results
                ],
            },
        }

    except Exception:
        logger.exception(
            "Identity anomaly analysis failed", extra={"org_id": str(org_id)}
        )
        raise HTTPException(status_code=500, detail="Analysis failed")


# Compliance Evidence Generation Endpoints
@router.get("/compliance/frameworks")
async def list_compliance_frameworks(
    current_user: User = Depends(require_read_findings),
):
    """List all available compliance frameworks."""
    frameworks = list_frameworks()
    framework_details = []

    for framework_name in frameworks:
        framework = get_framework(framework_name)
        if framework:
            automated_controls = len(
                [c for c in framework.controls if c.automation_level == AutomationLevel.AUTOMATED]
            )

            framework_details.append(
                {
                    "name": framework.name,
                    "key": framework_name,
                    "version": framework.version,
                    "description": framework.description,
                    "total_controls": len(framework.controls),
                    "automated_controls": automated_controls,
                    "automation_percentage": round(
                        (automated_controls / len(framework.controls)) * 100, 1
                    ),
                }
            )

    return {"frameworks": framework_details, "total_frameworks": len(framework_details)}


@router.get("/compliance/frameworks/{framework_name}")
async def get_compliance_framework(
    framework_name: str,
    current_user: User = Depends(require_read_findings),
):
    """Get detailed information about a specific compliance framework."""
    framework = get_framework(framework_name)
    if not framework:
        raise HTTPException(
            status_code=404, detail=f"Framework '{framework_name}' not found"
        )

    controls_by_category: dict[str, list[dict[str, object]]] = {}
    for control in framework.controls:
        if control.category not in controls_by_category:
            controls_by_category[control.category] = []

        controls_by_category[control.category].append(
            {
                "control_id": control.control_id,
                "title": control.title,
                "description": control.description,
                "control_type": control.control_type.value,
                "automation_level": control.automation_level,
                "frequency": getattr(control, "frequency", None),  # type: ignore[attr-defined]
                "required_evidence": [e.value for e in getattr(control, "required_evidence", [])],  # type: ignore[attr-defined]
                "sql_queries_count": len(getattr(control, "sql_queries", [])),  # type: ignore[attr-defined]
            }
        )

    return {
        "framework": {
            "name": framework.name,
            "key": framework_name,
            "version": framework.version,
            "description": framework.description,
        },
        "summary": {
            "total_controls": len(framework.controls),
            "categories": len(controls_by_category),
            "automated_controls": len(
                [c for c in framework.controls if c.automation_level == AutomationLevel.AUTOMATED]
            ),
            "semi_automated_controls": len(
                [
                    c
                    for c in framework.controls
                    if c.automation_level == AutomationLevel.SEMI_AUTOMATED
                ]
            ),
            "manual_controls": len(
                [c for c in framework.controls if c.automation_level == AutomationLevel.MANUAL]
            ),
        },
        "controls_by_category": controls_by_category,
    }


@router.post("/organizations/{org_id}/compliance/{framework_name}/evidence")
async def generate_compliance_evidence(
    org_id: UUID,
    framework_name: str,
    period_start: Optional[str] = Query(
        None, description="Evidence period start (ISO format)"
    ),
    period_end: Optional[str] = Query(
        None, description="Evidence period end (ISO format)"
    ),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_org_access(require_read_findings)),
):
    """Generate compliance evidence report for an organization."""
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    framework = get_framework(framework_name)
    if not framework:
        raise HTTPException(
            status_code=404, detail=f"Framework '{framework_name}' not found"
        )

    # Parse dates
    from dateutil.parser import parse

    try:
        start_date = (
            parse(period_start) if period_start else datetime.now() - timedelta(days=90)
        )
        end_date = parse(period_end) if period_end else datetime.now()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid date format: {e}")

    try:
        generator = ComplianceEvidenceGenerator()
        report = await generator.generate_compliance_report(
            framework_name, str(org_id), start_date, end_date
        )

        return {
            "organization_id": str(org_id),
            "framework": framework_name,
            "report": report,
            "generated_at": datetime.now().isoformat(),
        }

    except Exception:
        logger.exception(
            "Compliance evidence generation failed", extra={"org_id": str(org_id)}
        )
        raise HTTPException(status_code=500, detail="Evidence generation failed")


@router.get("/organizations/{org_id}/compliance/{framework_name}/status")
async def get_compliance_status(
    org_id: UUID,
    framework_name: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_org_access(require_read_findings)),
):
    """Get current compliance status for an organization and framework."""
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    framework = get_framework(framework_name)
    if not framework:
        raise HTTPException(
            status_code=404, detail=f"Framework '{framework_name}' not found"
        )

    try:
        generator = ComplianceEvidenceGenerator()

        # Generate quick status check
        current_time = datetime.now()
        status_report = await generator.generate_compliance_report(
            framework_name,
            str(org_id),
            current_time - timedelta(days=30),  # Last 30 days
            current_time,
        )

        return {
            "organization_id": str(org_id),
            "framework": {
                "name": framework.name,
                "key": framework_name,
                "version": framework.version,
            },
            "status": status_report["summary"],
            "last_assessed": current_time.isoformat(),
            "assessment_period_days": 30,
        }

    except Exception:
        logger.exception(
            "Compliance status check failed", extra={"org_id": str(org_id)}
        )
        raise HTTPException(status_code=500, detail="Status check failed")
