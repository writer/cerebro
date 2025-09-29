"""
Evidence collection for compliance frameworks.

DEPRECATED: This module is deprecated in favor of the unified evidence system
in evidence_service.py and models.py. Use those for new implementations.
"""

import asyncio
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from datetime import datetime


@dataclass
class EvidenceItem:
    """Single piece of compliance evidence.

    DEPRECATED: Use ComplianceEvidenceMetadata from models.py instead.
    """
    control_id: str
    evidence_type: str
    data: Dict[str, Any]
    collected_at: datetime
    query_used: str


class EvidenceCollector:
    """Collects evidence for compliance controls.

    DEPRECATED: Use EvidenceService from evidence_service.py instead.
    This class now uses dependency injection to avoid architectural violations.
    """

    def __init__(self, query_engine=None, provider_registry=None):
        """Initialize with dependency injection to avoid direct imports.

        Args:
            query_engine: Optional query engine instance
            provider_registry: Optional provider registry for table registration
        """
        self._query_engine = query_engine
        self._provider_registry = provider_registry

        # Only import and setup if dependencies are not provided (legacy compatibility)
        if self._query_engine is None:
            try:
                from ..query.engine import QueryEngine
                self._query_engine = QueryEngine()
            except ImportError:
                pass  # Fail gracefully if query engine not available

        if self._provider_registry is None:
            try:
                from ..providers.tables import register_all_provider_tables
                register_all_provider_tables()
            except ImportError:
                pass  # Fail gracefully if providers not available
    
    async def collect_evidence(self, control_id: str, sql_queries: List[str]) -> List[EvidenceItem]:
        """Collect evidence for a specific control."""
        evidence = []

        if not self._query_engine:
            # Return error evidence if no query engine available
            for query in sql_queries:
                evidence.append(EvidenceItem(
                    control_id=control_id,
                    evidence_type="configuration_error",
                    data={"error": "Query engine not available", "query": query},
                    collected_at=datetime.now(),
                    query_used=query
                ))
            return evidence

        for query in sql_queries:
            try:
                result = await self._query_engine.execute_query(query)
                
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
