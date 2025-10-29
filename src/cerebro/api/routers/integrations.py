"""API endpoints exposing integration synchronization status."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.api.auth import require_scopes
from cerebro.core.database import get_db
from cerebro.integrations.state import IntegrationIssueEventRepository, IntegrationStateRepository
from cerebro.automation.integration_sync import analyze_state
from cerebro.core.config import settings
from cerebro.tasks.integration_tasks import sync_kandji, sync_sentinelone
from cerebro.tasks.celery_app import celery_app


class IntegrationStatus(BaseModel):
    integration: str = Field(..., description="Integration identifier")
    scope: str = Field(..., description="Integration scope such as organization or tenant")
    last_timestamp: Optional[datetime] = Field(None, description="Timestamp of the most recent sync")
    last_cursor: Optional[str] = Field(None, description="Opaque cursor returned by the upstream API")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Additional sync metadata")


class IntegrationIssueResponse(BaseModel):
    integration: str = Field(..., description="Integration identifier")
    scope: str = Field(..., description="Integration scope such as organization or tenant")
    status: str = Field(..., description="Last recorded status for the integration scope")
    issue_type: str = Field(..., description="Type of issue detected (error, stale, missing, skipped)")
    severity: str = Field(..., description="Severity classification of the issue")
    message: str = Field(..., description="Human-readable summary of the issue")
    observed_at: datetime = Field(..., description="Timestamp when the issue was evaluated")
    last_timestamp: Optional[datetime] = Field(None, description="Timestamp of the last successful sync if available")
    age_seconds: Optional[float] = Field(None, description="Seconds elapsed since last successful sync")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Raw metadata associated with the scope")


class IntegrationIssueHistoryEvent(BaseModel):
    integration: str
    scope: str
    issue_type: str
    severity: str
    message: str
    observed_at: datetime
    last_timestamp: Optional[datetime]
    age_seconds: Optional[float]
    metadata: Dict[str, Any] = Field(default_factory=dict)


class IntegrationIssueTrendBucket(BaseModel):
    bucket_start: datetime
    bucket_end: datetime
    counts: Dict[str, int] = Field(default_factory=dict)


class IntegrationIssueHistoryResponse(BaseModel):
    events: List[IntegrationIssueHistoryEvent] = Field(default_factory=list)
    buckets: List[IntegrationIssueTrendBucket] = Field(default_factory=list)


class IntegrationSyncRequest(BaseModel):
    integration: Literal["kandji", "sentinelone"] = Field(..., description="Integration to synchronize")
    lookback_minutes: Optional[int] = Field(
        None,
        ge=1,
        le=1440,
        description="Optional SentinelOne lookback window in minutes",
    )


class IntegrationSyncJobResponse(BaseModel):
    task_id: str = Field(..., description="Celery task identifier")
    integration: str = Field(..., description="Integration that was queued")
    scope: str = Field(..., description="Scope associated with the integration")
    queued_at: datetime = Field(..., description="Timestamp when the task was enqueued")


class IntegrationSyncStatusResponse(BaseModel):
    task_id: str = Field(..., description="Celery task identifier")
    status: str = Field(..., description="Celery task status value")
    finished: bool = Field(..., description="True when the task has reached a terminal state")
    date_done: Optional[datetime] = Field(None, description="Completion timestamp if available")
    result: Optional[Any] = Field(None, description="Serialized task result when available")


router = APIRouter(prefix="/integrations", tags=["integrations"])


@router.get("/status", response_model=List[IntegrationStatus])
async def list_integration_status(
    integration: Optional[str] = Query(None, description="Filter by integration identifier"),
    db: AsyncSession = Depends(get_db),
    _: Any = Depends(require_scopes("view:integrations")),
) -> List[IntegrationStatus]:
    repo = IntegrationStateRepository(db)
    states = await repo.list_states(integration=integration)
    return [
        IntegrationStatus(
            integration=state.integration,
            scope=state.scope,
            last_timestamp=state.last_timestamp,
            last_cursor=state.last_cursor,
            metadata=state.state_metadata or {},
        )
        for state in states
    ]


@router.post("/sync", response_model=IntegrationSyncJobResponse, status_code=202)
async def trigger_integration_sync(
    request: IntegrationSyncRequest,
    _: Any = Depends(require_scopes("collect:data")),
) -> IntegrationSyncJobResponse:
    queued_at = datetime.now(timezone.utc)

    if request.integration == "kandji":
        if not settings.kandji_enabled:
            raise HTTPException(status_code=400, detail="Kandji integration is disabled")
        if request.lookback_minutes is not None:
            raise HTTPException(status_code=422, detail="lookback_minutes is not supported for Kandji")
        result = sync_kandji.apply_async()
        scope = settings.kandji_org_name or "kandji"
    else:
        if not settings.sentinelone_enabled:
            raise HTTPException(status_code=400, detail="SentinelOne integration is disabled")
        kwargs: dict[str, Any] = {}
        if request.lookback_minutes is not None:
            kwargs["lookback_minutes"] = request.lookback_minutes
        result = sync_sentinelone.apply_async(kwargs=kwargs)
        scope = settings.sentinelone_org_name or "sentinelone"

    return IntegrationSyncJobResponse(
        task_id=result.id,
        integration=request.integration,
        scope=scope,
        queued_at=queued_at,
    )


@router.get("/sync/{task_id}", response_model=IntegrationSyncStatusResponse)
async def get_integration_sync_status(
    task_id: str,
    _: Any = Depends(require_scopes("view:integrations")),
) -> IntegrationSyncStatusResponse:
    result = celery_app.AsyncResult(task_id)
    finished = result.ready()
    status = result.status
    date_done = result.date_done

    payload: Optional[Any] = None
    if finished:
        value = result.result
        if isinstance(value, (str, int, float, bool)) or value is None:
            payload = value
        elif isinstance(value, dict):
            payload = value
        elif isinstance(value, list):
            payload = value
        else:
            payload = str(value)

    return IntegrationSyncStatusResponse(
        task_id=task_id,
        status=status,
        finished=finished,
        date_done=date_done,
        result=payload,
    )


@router.get("/status/issues", response_model=List[IntegrationIssueResponse])
async def list_integration_issues(
    integration: Optional[str] = Query(None, description="Filter by integration identifier"),
    scope: Optional[str] = Query(None, description="Filter by scope"),
    stale_seconds: Optional[int] = Query(
        None,
        description="Override default staleness threshold in seconds",
        ge=0,
    ),
    db: AsyncSession = Depends(get_db),
    _: Any = Depends(require_scopes("view:integrations")),
) -> List[IntegrationIssueResponse]:
    repo = IntegrationStateRepository(db)
    states = await repo.list_states(integration=integration)

    now = datetime.now(timezone.utc)
    issues: List[IntegrationIssueResponse] = []
    threshold = stale_seconds if stale_seconds is not None else settings.integration_sync_stale_seconds

    for state in states:
        if scope and state.scope != scope:
            continue
        issue = analyze_state(state, now, threshold)
        if issue is None:
            continue
        issues.append(
            IntegrationIssueResponse(
                integration=issue.integration,
                scope=issue.scope,
                status=issue.status,
                issue_type=issue.issue_type,
                severity=issue.severity,
                message=issue.message,
                observed_at=issue.observed_at,
                last_timestamp=issue.last_timestamp,
                age_seconds=issue.age_seconds,
                metadata=issue.metadata,
            )
        )

    return issues


@router.get("/status/issues/history", response_model=IntegrationIssueHistoryResponse)
async def list_integration_issue_history(
    integration: Optional[str] = Query(None, description="Filter by integration identifier"),
    scope: Optional[str] = Query(None, description="Filter by scope"),
    hours: int = Query(24, ge=1, le=168, description="Lookback window in hours"),
    bucket_minutes: int = Query(60, ge=5, le=720, description="Aggregation bucket size in minutes"),
    limit: int = Query(100, ge=1, le=500, description="Maximum number of recent events to return"),
    db: AsyncSession = Depends(get_db),
    _: Any = Depends(require_scopes("view:integrations")),
) -> IntegrationIssueHistoryResponse:
    issue_repo = IntegrationIssueEventRepository(db)
    now = datetime.now(timezone.utc)
    window = timedelta(hours=hours)
    since = now - window

    events = await issue_repo.list_events(
        integration=integration,
        scope=scope,
        since=since,
        limit=limit,
    )

    bucket = timedelta(minutes=bucket_minutes)
    buckets = await issue_repo.summarize_events(
        integration=integration,
        scope=scope,
        window=window,
        bucket=bucket,
    )

    history_events = [
        IntegrationIssueHistoryEvent(
            integration=event.integration,
            scope=event.scope,
            issue_type=event.issue_type,
            severity=event.severity,
            message=event.message,
            observed_at=event.observed_at,
            last_timestamp=event.last_timestamp,
            age_seconds=event.age_seconds,
            metadata=dict(event.issue_metadata or {}),
        )
        for event in reversed(events)
    ]

    history_buckets = [
        IntegrationIssueTrendBucket(
            bucket_start=item["bucket_start"],
            bucket_end=item["bucket_end"],
            counts=item["counts"],
        )
        for item in buckets
    ]

    return IntegrationIssueHistoryResponse(events=history_events, buckets=history_buckets)


@router.get("/status/{integration}", response_model=List[IntegrationStatus])
async def get_integration_status(
    integration: str,
    db: AsyncSession = Depends(get_db),
    _: Any = Depends(require_scopes("view:integrations")),
) -> List[IntegrationStatus]:
    repo = IntegrationStateRepository(db)
    states = await repo.list_states(integration=integration)
    if not states:
        raise HTTPException(status_code=404, detail="Integration not found")
    return [
        IntegrationStatus(
            integration=state.integration,
            scope=state.scope,
            last_timestamp=state.last_timestamp,
            last_cursor=state.last_cursor,
            metadata=state.state_metadata or {},
        )
        for state in states
    ]
