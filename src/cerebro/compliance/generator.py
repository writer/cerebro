"""
Main compliance evidence generator.
"""

import asyncio
from typing import Dict, List, Any
from datetime import datetime

from .frameworks import get_framework
from .evidence import EvidenceCollector
from .reporting import ComplianceReporter


class ComplianceEvidenceGenerator:
    """Main class for generating compliance evidence."""
    
    def __init__(self):
        self.evidence_collector = EvidenceCollector()
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
