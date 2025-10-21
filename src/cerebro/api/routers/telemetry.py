"""Telemetry ingestion API endpoints."""

from typing import Any, Optional

from fastapi import APIRouter, Depends, Header, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.api.auth import require_scopes
from cerebro.core.database import get_db
from cerebro.telemetry.schemas import (
    ComplianceEvidence,
    DependencyGraph,
    RepositoryTelemetry,
    RuntimeTelemetry,
)
from cerebro.telemetry.services import TelemetryIngestionService, TelemetryProcessingError


router = APIRouter(prefix="/telemetry", tags=["Telemetry", "Intelligence"])


# ============================================================================
# ============================================================================
# API Endpoints
# ============================================================================

@router.post("/repository", status_code=200)
async def receive_repository_telemetry(
    telemetry: RepositoryTelemetry,
    db: AsyncSession = Depends(get_db),
    _: Any = Depends(require_scopes("ingest:telemetry")),
    _authorization: Optional[str] = Header(None)
):
    """Receive telemetry from repository CI/CD workflows."""

    try:
        return await TelemetryIngestionService(db).process_repository(telemetry)
    except TelemetryProcessingError as exc:  # pragma: no cover
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/runtime", status_code=200)
async def receive_runtime_telemetry(
    telemetry: RuntimeTelemetry,
    db: AsyncSession = Depends(get_db),
    _: Any = Depends(require_scopes("ingest:telemetry")),
    _authorization: Optional[str] = Header(None)
):
    """Receive runtime telemetry from running applications."""

    try:
        return await TelemetryIngestionService(db).process_runtime(telemetry)
    except TelemetryProcessingError as exc:  # pragma: no cover
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/compliance/evidence", status_code=200)
async def receive_compliance_evidence(
    evidence: ComplianceEvidence,
    db: AsyncSession = Depends(get_db),
    _: Any = Depends(require_scopes("ingest:telemetry")),
    _authorization: Optional[str] = Header(None)
):
    """Receive compliance evidence collected from repositories."""

    try:
        return await TelemetryIngestionService(db).process_compliance_evidence(evidence)
    except TelemetryProcessingError as exc:  # pragma: no cover
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/supply-chain/dependency-graph", status_code=200)
async def receive_dependency_graph(
    graph: DependencyGraph,
    db: AsyncSession = Depends(get_db),
    _: Any = Depends(require_scopes("ingest:telemetry")),
    _authorization: Optional[str] = Header(None)
):
    """Receive complete dependency graph including transitive dependencies."""

    try:
        return await TelemetryIngestionService(db).process_dependency_graph(graph)
    except TelemetryProcessingError as exc:  # pragma: no cover
        raise HTTPException(status_code=500, detail=str(exc)) from exc




