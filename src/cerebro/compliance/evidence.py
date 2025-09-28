"""
Evidence collection for compliance frameworks.
"""

import asyncio
from typing import Dict, List, Any
from dataclasses import dataclass
from datetime import datetime

from ..query.engine import QueryEngine
from ..providers.tables import register_all_provider_tables


@dataclass
class EvidenceItem:
    """Single piece of compliance evidence."""
    control_id: str
    evidence_type: str
    data: Dict[str, Any]
    collected_at: datetime
    query_used: str


class EvidenceCollector:
    """Collects evidence for compliance controls."""
    
    def __init__(self):
        self.query_engine = QueryEngine()
        register_all_provider_tables()
    
    async def collect_evidence(self, control_id: str, sql_queries: List[str]) -> List[EvidenceItem]:
        """Collect evidence for a specific control."""
        evidence = []
        
        for query in sql_queries:
            try:
                result = await self.query_engine.execute_query(query)
                
                evidence.append(EvidenceItem(
                    control_id=control_id,
                    evidence_type="sql_query_result", 
                    data={
                        "query": query,
                        "rows": result.rows,
                        "total_rows": result.total_rows,
                        "columns": result.columns
                    },
                    collected_at=datetime.now(),
                    query_used=query
                ))
                
            except Exception as e:
                # Log error but continue with other queries
                evidence.append(EvidenceItem(
                    control_id=control_id,
                    evidence_type="query_error",
                    data={"error": str(e), "query": query},
                    collected_at=datetime.now(), 
                    query_used=query
                ))
        
        return evidence
