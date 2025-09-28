"""
Compliance reporting functionality.
"""

from typing import Dict, List, Any
from datetime import datetime
from .frameworks import ComplianceFramework
from .evidence import EvidenceItem


class ComplianceReporter:
    """Generates compliance reports."""
    
    async def generate_report(
        self,
        framework: ComplianceFramework,
        evidence: Dict[str, List[EvidenceItem]], 
        org_id: str,
        period_start: datetime,
        period_end: datetime
    ) -> Dict[str, Any]:
        """Generate compliance report."""
        
        # Calculate compliance status
        control_status = {}
        for control in framework.controls:
            control_evidence = evidence.get(control.control_id, [])
            
            # Simple compliance calculation based on evidence
            has_evidence = len([e for e in control_evidence if e.evidence_type != "query_error"]) > 0
            control_status[control.control_id] = {
                "status": "compliant" if has_evidence else "non-compliant",
                "evidence_count": len(control_evidence),
                "last_assessed": datetime.now().isoformat()
            }
        
        compliant_controls = len([s for s in control_status.values() if s["status"] == "compliant"])
        total_controls = len(framework.controls)
        
        return {
            "framework": {
                "name": framework.name,
                "version": framework.version,
                "description": framework.description
            },
            "organization_id": org_id,
            "assessment_period": {
                "start": period_start.isoformat(),
                "end": period_end.isoformat()
            },
            "generated_at": datetime.now().isoformat(),
            "summary": {
                "total_controls": total_controls,
                "compliant_controls": compliant_controls,
                "compliance_percentage": round((compliant_controls / total_controls) * 100, 1),
                "status": "compliant" if compliant_controls == total_controls else "non-compliant"
            },
            "control_results": control_status,
            "evidence_summary": {
                control_id: {
                    "evidence_items": len(items),
                    "successful_queries": len([e for e in items if e.evidence_type != "query_error"])
                }
                for control_id, items in evidence.items()
            }
        }
