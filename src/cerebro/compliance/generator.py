"""High-level compliance evidence generation utilities."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional

from .frameworks import ComplianceControl, ComplianceFramework, get_framework, list_frameworks
from .evidence import EvidenceCollector, EvidenceItem


@dataclass
class ControlEvaluation:
    """Summary of a single control's evaluation."""

    control: ComplianceControl
    evidence: List[EvidenceItem]

    @property
    def successful_queries(self) -> int:
        return sum(1 for item in self.evidence if item.evidence_type == "sql_query_result")

    @property
    def failed_queries(self) -> int:
        return sum(1 for item in self.evidence if item.evidence_type == "query_error")

    def to_dict(self) -> Dict[str, object]:
        return {
            "control_id": self.control.control_id,
            "title": self.control.title,
            "category": self.control.category,
            "automation_level": self.control.automation_level,
            "required_evidence": [etype.value for etype in self.control.required_evidence],
            "successful_queries": self.successful_queries,
            "failed_queries": self.failed_queries,
        }


class ComplianceEvidenceGenerator:
    """Generate structured compliance reports for supported frameworks."""

    def __init__(self, collector: Optional[EvidenceCollector] = None):
        self.evidence_collector = collector or EvidenceCollector()

    async def generate_compliance_report(
        self,
        framework_name: str,
        organization_id: str,
        period_start: datetime,
        period_end: datetime,
        org_query_scope: Optional[str] = None,
    ) -> Dict[str, object]:
        framework = self._load_framework(framework_name)

        evaluations: List[ControlEvaluation] = []
        for control in framework.controls:
            evidence = await self.evidence_collector.collect_evidence(
                control.control_id,
                control.sql_queries,
                org_id=org_query_scope or organization_id,
            )
            evaluations.append(ControlEvaluation(control=control, evidence=evidence))

        report = {
            "framework": {
                "id": framework_name.lower(),
                "name": framework.name,
                "version": framework.version,
                "description": framework.description,
            },
            "organization_id": organization_id,
            "generated_at": datetime.utcnow().isoformat(),
            "period": {
                "start": period_start.isoformat(),
                "end": period_end.isoformat(),
                "days": max((period_end - period_start).days, 0),
            },
        }

        report["control_results"] = [evaluation.to_dict() for evaluation in evaluations]
        report["summary"] = self._build_summary(framework, evaluations)
        report["evidence_summary"] = self._build_evidence_summary(evaluations)

        return report

    @staticmethod
    def available_frameworks() -> List[str]:
        return list_frameworks()

    def _load_framework(self, framework_name: str) -> ComplianceFramework:
        framework = get_framework(framework_name)
        if framework is None:
            raise ValueError(f"Unknown framework: {framework_name}")
        return framework

    @staticmethod
    def _build_summary(
        framework: ComplianceFramework,
        evaluations: List[ControlEvaluation],
    ) -> Dict[str, object]:
        total_controls = len(framework.controls)
        successful_controls = sum(1 for evaluation in evaluations if evaluation.successful_queries > 0)
        automated_controls = len(framework.get_automated_controls())

        compliance_percentage = 0.0
        if total_controls:
            compliance_percentage = round((successful_controls / total_controls) * 100, 2)

        return {
            "total_controls": total_controls,
            "automated_controls": automated_controls,
            "successful_controls": successful_controls,
            "compliance_percentage": compliance_percentage,
        }

    @staticmethod
    def _build_evidence_summary(
        evaluations: List[ControlEvaluation],
    ) -> Dict[str, Dict[str, int]]:
        summary: Dict[str, Dict[str, int]] = {}
        for evaluation in evaluations:
            summary[evaluation.control.control_id] = {
                "evidence_items": len(evaluation.evidence),
                "successful_queries": evaluation.successful_queries,
                "failed_queries": evaluation.failed_queries,
            }
        return summary
