"""
Main compliance evidence generator.

DEPRECATED: This module is deprecated in favor of the unified evidence system.
Use EvidenceService from evidence_service.py for new implementations.
"""

import asyncio
from typing import Dict, List, Any, Optional
from datetime import datetime

from .frameworks import get_framework
from .evidence_service import EvidenceService
from .reporting import ComplianceReporter


class ComplianceEvidenceGenerator:
    """Main class for generating compliance evidence.

    DEPRECATED: Use EvidenceService from evidence_service.py instead.
    This class now uses dependency injection to avoid architectural violations.
    """

    def __init__(self, query_engine=None, db_session=None):
        """Initialize with dependency injection using unified evidence service.

        Args:
            query_engine: Query engine instance for evidence collection
            db_session: Database session for unified evidence service (required)
        """
        if not db_session:
            raise ValueError("Database session is required - deprecated evidence collector has been removed")

        self.evidence_service = EvidenceService(
            db_session=db_session,
            query_service=query_engine
        )
        self.reporter = ComplianceReporter()
    
    async def generate_compliance_report(
        self, 
        framework_name: str, 
        org_id: str,
        period_start: datetime,
        period_end: datetime
    ) -> Dict[str, Any]:
        """Generate complete compliance report."""
        framework = get_framework(framework_name)
        if not framework:
            raise ValueError(f"Unknown framework: {framework_name}")
        
        # Collect evidence for all controls
        all_evidence = {}
        for control in framework.controls:
            if control.automation_level in ["automated", "semi-automated"]:
                evidence = await self.evidence_collector.collect_evidence(
                    control.control_id, 
                    control.sql_queries
                )
                all_evidence[control.control_id] = evidence
        
        # Generate report
        return await self.reporter.generate_report(
            framework, all_evidence, org_id, period_start, period_end
        )
