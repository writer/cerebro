"""Utility classes for collecting structured compliance evidence."""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional


@dataclass
class EvidenceItem:
    """Represents a single piece of collected evidence for a control."""

    control_id: str
    evidence_type: str
    data: Dict[str, Any]
    collected_at: _dt.datetime = field(default_factory=lambda: _dt.datetime.utcnow())
    metadata: Dict[str, Any] = field(default_factory=dict)


class EvidenceCollector:
    """Collects evidence for compliance controls using a query engine."""

    def __init__(self, query_engine: Optional[Any] = None):
        self.query_engine = query_engine

    async def collect_evidence(
        self,
        control_id: str,
        sql_queries: Iterable[str],
        org_id: Optional[str] = None,
    ) -> List[EvidenceItem]:
        """Run the supplied SQL queries and capture results as evidence items."""

        if self.query_engine is None:
            raise ValueError(
                "EvidenceCollector requires a query_engine before collecting evidence"
            )

        evidence: List[EvidenceItem] = []

        for query in sql_queries:
            try:
                result = await self.query_engine.execute_query(sql=query, org_id=org_id)

                rows = getattr(result, "rows", [])
                total_rows = getattr(result, "total_rows", len(rows))
                columns = getattr(result, "columns", [])
                errors = getattr(result, "errors", [])

                evidence.append(
                    EvidenceItem(
                        control_id=control_id,
                        evidence_type="sql_query_result",
                        data={
                            "query": query,
                            "columns": columns,
                            "rows": rows,
                            "total_rows": total_rows,
                            "errors": errors,
                        },
                    )
                )
            except Exception as exc:  # pragma: no cover - guarded in tests
                evidence.append(
                    EvidenceItem(
                        control_id=control_id,
                        evidence_type="query_error",
                        data={"query": query, "error": str(exc)},
                    )
                )

        return evidence
