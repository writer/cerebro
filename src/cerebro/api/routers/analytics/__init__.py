"""
Analytics API module - organized by domain.

This module splits the large analytics router into focused sub-routers:
- dashboard: High-level dashboard and executive summaries
- risk_analytics: Risk scores, heatmaps, identity risk, privilege sprawl
- metrics: Time-series trends, sparklines, metric analysis
- monitoring: SLA breaches, Celery worker health
- compliance_analytics: Compliance evidence, severity breakdowns
"""

from fastapi import APIRouter
from . import dashboard, risk_analytics, metrics, monitoring, compliance_analytics

# Create main analytics router
router = APIRouter()

# Include sub-routers
router.include_router(dashboard.router, tags=["analytics:dashboard"])
router.include_router(risk_analytics.router, tags=["analytics:risk"])
router.include_router(metrics.router, tags=["analytics:metrics"])
router.include_router(monitoring.router, tags=["analytics:monitoring"])
router.include_router(compliance_analytics.router, tags=["analytics:compliance"])

__all__ = ["router"]
