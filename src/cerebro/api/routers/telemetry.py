"""Telemetry ingestion API endpoints."""

from typing import Any, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.api.auth import User, get_current_user, require_scopes
from cerebro.core.database import get_db
from cerebro.telemetry.schemas import (
    ComplianceEvidence,
    DependencyGraph,
    FrontendObservationTelemetry,
    ArtifactPackDefinition,
    HostEventBatch,
    HostTelemetry,
    RepositoryTelemetry,
    RuntimeTelemetry,
)
from cerebro.telemetry.services import (
    TelemetryIngestionService,
    TelemetryProcessingError,
)


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
    _authorization: Optional[str] = Header(None),
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
    _authorization: Optional[str] = Header(None),
):
    """Receive runtime telemetry from running applications."""

    try:
        return await TelemetryIngestionService(db).process_runtime(telemetry)
    except TelemetryProcessingError as exc:  # pragma: no cover
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/host", status_code=200)
async def receive_host_telemetry(
    telemetry: HostTelemetry,
    db: AsyncSession = Depends(get_db),
    _: Any = Depends(require_scopes("ingest:telemetry")),
    _authorization: Optional[str] = Header(None),
):
    """Receive endpoint telemetry from the Cerebro desktop agent."""

    try:
        return await TelemetryIngestionService(db).process_host(telemetry)
    except TelemetryProcessingError as exc:  # pragma: no cover
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/host/packs", response_model=list[ArtifactPackDefinition])
async def list_host_packs(
    host_id: str = Query(..., description="Stable host identifier"),
    hostname: Optional[str] = Query(None, description="Hostname override"),
    organization: Optional[str] = Query(None, description="Organization name"),
    site: Optional[str] = Query(None, description="Site or location tag"),
    tags: Optional[list[str]] = Query(
        None, alias="tag", description="Tag filters in key=value form"
    ),
    db: AsyncSession = Depends(get_db),
    _: Any = Depends(require_scopes("ingest:telemetry")),
):
    """Return artifact packs applicable to the requesting host."""

    tag_map: dict[str, str] = {}
    if tags:
        for entry in tags:
            if not entry:
                continue
            if "=" not in entry:
                tag_map[entry] = "true"
                continue
            key, value = entry.split("=", 1)
            tag_map[key] = value

    service = TelemetryIngestionService(db)
    try:
        return await service.list_host_packs(
            host_id=host_id,
            hostname=hostname,
            organization=organization,
            site=site,
            tags=tag_map,
        )
    except TelemetryProcessingError as exc:  # pragma: no cover
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/host/events", status_code=200)
async def receive_host_event_batch(
    batch: HostEventBatch,
    db: AsyncSession = Depends(get_db),
    _: Any = Depends(require_scopes("ingest:telemetry")),
    _authorization: Optional[str] = Header(None),
):
    """Receive host event batches from the desktop agent."""

    try:
        return await TelemetryIngestionService(db).process_host_events(batch)
    except TelemetryProcessingError as exc:  # pragma: no cover
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/compliance/evidence", status_code=200)
async def receive_compliance_evidence(
    evidence: ComplianceEvidence,
    db: AsyncSession = Depends(get_db),
    _: Any = Depends(require_scopes("ingest:telemetry")),
    _authorization: Optional[str] = Header(None),
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
    _authorization: Optional[str] = Header(None),
):
    """Receive complete dependency graph including transitive dependencies."""

    try:
        return await TelemetryIngestionService(db).process_dependency_graph(graph)
    except TelemetryProcessingError as exc:  # pragma: no cover
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/frontend/observe", status_code=200)
async def receive_frontend_observation(
    observation: FrontendObservationTelemetry,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Record a frontend analyst observation for reinforcement learning pipelines."""

    if current_user.org_id is None:
        raise HTTPException(
            status_code=400, detail="User is not associated with an organization"
        )

    try:
        return await TelemetryIngestionService(db).process_frontend_observation(
            current_user.org_id,
            current_user.user_id,
            observation,
        )
    except TelemetryProcessingError as exc:  # pragma: no cover
        raise HTTPException(status_code=500, detail=str(exc)) from exc
