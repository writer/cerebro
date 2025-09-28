"""Advanced analysis endpoints."""

from typing import List, Optional
from uuid import UUID
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel

from cerebro.core.database import get_db
from cerebro.core.models import Organization, Principal
from cerebro.api.auth import require_read_findings
from cerebro.analysis.blast_radius import BlastRadiusAnalyzer
from cerebro.analysis.forensic_replay import ForensicReplayEngine
from cerebro.analysis.change_replay import ChangeReplayEngine
from cerebro.rules.engine import rule_engine

router = APIRouter()


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


@router.post("/organizations/{org_id}/blast-radius")
async def analyze_blast_radius(
    org_id: UUID,
    request: BlastRadiusRequest,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(require_read_findings)
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
            request.principal_id,
            request.scenario_type,
            request.at_time
        )
        
        return {
            "scenario": {
                "principal_name": assessment.scenario.principal_name,
                "principal_type": assessment.scenario.principal_type,
                "provider": assessment.scenario.provider,
                "scenario_type": assessment.scenario.scenario_type,
                "compromise_time": assessment.scenario.compromise_time.isoformat()
            },
            "impact": {
                "total_resources_at_risk": assessment.total_resources_at_risk,
                "max_sensitivity_score": assessment.max_sensitivity_score,
                "business_impact_score": assessment.business_impact_score,
                "escalation_paths_count": len(assessment.escalation_paths)
            },
            "directly_accessible": [
                {
                    "resource_external_id": r.resource_external_id,
                    "resource_type": r.resource_type,
                    "provider": r.provider,
                    "access_level": r.access_level,
                    "sensitivity_score": r.sensitivity_score,
                    "potential_actions": r.potential_actions
                }
                for r in assessment.directly_accessible[:20]  # Limit for API response
            ],
            "mitigation_recommendations": assessment.mitigation_recommendations,
            "analysis_metadata": {
                "total_escalation_paths": len(assessment.escalation_paths),
                "cross_provider_resources": len(assessment.cross_provider_impact)
            }
        }
        
    except Exception as e:
        logger.error(f"Blast radius analysis failed: {e}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@router.get("/organizations/{org_id}/blast-radius/report")
async def generate_blast_radius_report(
    org_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(require_read_findings)
):
    """Generate organization-wide blast radius report."""
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    try:
        analyzer = BlastRadiusAnalyzer(db)
        report = await analyzer.generate_blast_radius_report(org_id)
        return report
        
    except Exception as e:
        logger.error(f"Blast radius report generation failed: {e}")
        raise HTTPException(status_code=500, detail=f"Report generation failed: {str(e)}")


@router.post("/organizations/{org_id}/forensic-replay")
async def forensic_replay(
    org_id: UUID,
    request: ForensicReplayRequest,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(require_read_findings)
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
                    "admin_permissions": len([perm for perm in p.permissions if perm["is_admin"]])
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
                    "issues": r.security_posture.get("issues", [])
                }
                for r in historical_state.resources[:50]  # Limit for API
            ],
            "active_findings": historical_state.active_findings[:50]
        }
        
    except Exception as e:
        logger.error(f"Forensic replay failed: {e}")
        raise HTTPException(status_code=500, detail=f"Forensic replay failed: {str(e)}")


@router.post("/organizations/{org_id}/change-replay")
async def change_replay(
    org_id: UUID,
    request: ChangeReplayRequest,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(require_read_findings)
):
    """Replay rule changes against historical data."""
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    try:
        replay_engine = ChangeReplayEngine(db, rule_engine)
        
        # Create temporary rule ID for analysis
        temp_rule_id = UUID('00000000-0000-0000-0000-000000000001')
        
        # Evaluate rule against historical data
        result = await replay_engine.replay_rule_historically(
            temp_rule_id, org_id, request.start_time, request.end_time, request.providers
        )
        
        return {
            "rule_expression": request.rule_expression,
            "time_period": result.time_period,
            "evaluation_results": {
                "total_evaluations": result.total_evaluations,
                "matches_found": result.matches_found,
                "match_rate_percentage": (result.matches_found / max(result.total_evaluations, 1)) * 100,
                "new_findings_count": result.new_findings_count
            },
            "coverage_analysis": result.coverage_analysis,
            "performance_metrics": result.performance_metrics,
            "sample_findings": result.findings_that_would_exist[:10]
        }
        
    except Exception as e:
        logger.error(f"Change replay failed: {e}")
        raise HTTPException(status_code=500, detail=f"Change replay failed: {str(e)}")


@router.get("/organizations/{org_id}/rule-effectiveness")
async def get_rule_effectiveness(
    org_id: UUID,
    lookback_days: int = Query(default=90, description="Days to look back"),
    db: AsyncSession = Depends(get_db),
    current_user = Depends(require_read_findings)
):
    """Get rule effectiveness analysis."""
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    try:
        replay_engine = ChangeReplayEngine(db, rule_engine)
        report = await replay_engine.generate_rule_effectiveness_report(org_id, lookback_days)
        return report
        
    except Exception as e:
        logger.error(f"Rule effectiveness analysis failed: {e}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@router.post("/organizations/{org_id}/what-if-rule")
async def what_if_rule_analysis(
    org_id: UUID,
    rule_expression: str,
    providers: List[str],
    time_period_days: int = Query(default=30, description="Days to analyze"),
    db: AsyncSession = Depends(get_db),
    current_user = Depends(require_read_findings)
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
        
    except Exception as e:
        logger.error(f"What-if rule analysis failed: {e}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")
