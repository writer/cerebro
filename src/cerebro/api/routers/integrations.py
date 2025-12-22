"""API endpoints exposing integration synchronization status."""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.api.auth import require_scopes
from cerebro.core.database import get_db
from cerebro.integrations.coverage import summarize_integration_coverage
from cerebro.integrations.state import (
    IntegrationIssueEventRepository,
    IntegrationStateRepository,
)
from cerebro.automation.integration_sync import analyze_state
from cerebro.core.config import settings
from cerebro.tasks.integration_tasks import sync_kandji, sync_sentinelone
from cerebro.tasks.celery_app import celery_app
from cerebro.integrations.freshness import IntegrationFreshnessService


class IntegrationStatus(BaseModel):
    integration: str = Field(..., description="Integration identifier")
    scope: str = Field(
        ..., description="Integration scope such as organization or tenant"
    )
    last_timestamp: Optional[datetime] = Field(
        None, description="Timestamp of the most recent sync"
    )
    last_cursor: Optional[str] = Field(
        None, description="Opaque cursor returned by the upstream API"
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict, description="Additional sync metadata"
    )


class IntegrationIssueResponse(BaseModel):
    integration: str = Field(..., description="Integration identifier")
    scope: str = Field(
        ..., description="Integration scope such as organization or tenant"
    )
    status: str = Field(
        ..., description="Last recorded status for the integration scope"
    )
    issue_type: str = Field(
        ..., description="Type of issue detected (error, stale, missing, skipped)"
    )
    severity: str = Field(..., description="Severity classification of the issue")
    message: str = Field(..., description="Human-readable summary of the issue")
    observed_at: datetime = Field(
        ..., description="Timestamp when the issue was evaluated"
    )
    last_timestamp: Optional[datetime] = Field(
        None, description="Timestamp of the last successful sync if available"
    )
    age_seconds: Optional[float] = Field(
        None, description="Seconds elapsed since last successful sync"
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict, description="Raw metadata associated with the scope"
    )


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
    integration: Literal["kandji", "sentinelone"] = Field(
        ..., description="Integration to synchronize"
    )
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
    finished: bool = Field(
        ..., description="True when the task has reached a terminal state"
    )
    date_done: Optional[datetime] = Field(
        None, description="Completion timestamp if available"
    )
    result: Optional[Any] = Field(
        None, description="Serialized task result when available"
    )


class IntegrationCoverageScopes(BaseModel):
    total: int
    healthy: int
    warning: int
    critical: int


class IntegrationCoverageAccounts(BaseModel):
    total: int


class IntegrationCoverageSummary(BaseModel):
    integration: str
    providers: List[str]
    status: str
    scopes: IntegrationCoverageScopes
    accounts: IntegrationCoverageAccounts
    coverage_ratio: Optional[float]
    last_success: Optional[datetime]
    evaluated_at: datetime


class IntegrationAdminOverview(BaseModel):
    integration: str
    scope: str
    status: str
    last_synced_at: Optional[datetime]
    age_seconds: Optional[float]
    age_human: Optional[str]
    warning: Optional[str]
    next_scheduled_sync_at: Optional[datetime]
    duration_average_seconds: Optional[float]
    duration_samples: List[float] = Field(default_factory=list)
    recent_errors: List[Dict[str, Any]] = Field(default_factory=list)
    confidence: str = Field("unknown")
    metadata: Dict[str, Any] = Field(default_factory=dict)
    stale_threshold_hours: Optional[int] = Field(
        None, description="Stale alert threshold in hours"
    )


router = APIRouter(prefix="/integrations", tags=["integrations"])


@router.get("/status", response_model=List[IntegrationStatus])
async def list_integration_status(
    integration: Optional[str] = Query(
        None, description="Filter by integration identifier"
    ),
    db: AsyncSession = Depends(get_db),
    _: Any = Depends(require_scopes("read:findings")),
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


@router.get("/coverage", response_model=List[IntegrationCoverageSummary])
async def get_integration_coverage(
    stale_seconds: Optional[int] = Query(
        None, description="Override default staleness threshold in seconds"
    ),
    db: AsyncSession = Depends(get_db),
    _: Any = Depends(require_scopes("view:integrations")),
) -> List[IntegrationCoverageSummary]:
    summaries = await summarize_integration_coverage(
        db,
        stale_seconds=stale_seconds,
    )

    return [
        IntegrationCoverageSummary(
            integration=item["integration"],
            providers=item["providers"],
            status=item["status"],
            scopes=IntegrationCoverageScopes(**item["scopes"]),
            accounts=IntegrationCoverageAccounts(**item["accounts"]),
            coverage_ratio=item["coverage_ratio"],
            last_success=item["last_success"],
            evaluated_at=item["evaluated_at"],
        )
        for item in summaries
    ]


@router.post("/sync", response_model=IntegrationSyncJobResponse, status_code=202)
async def trigger_integration_sync(
    request: IntegrationSyncRequest,
    _: Any = Depends(require_scopes("collect:data")),
) -> IntegrationSyncJobResponse:
    queued_at = datetime.now(timezone.utc)

    if request.integration == "kandji":
        if not settings.kandji_enabled:
            raise HTTPException(
                status_code=400, detail="Kandji integration is disabled"
            )
        if request.lookback_minutes is not None:
            raise HTTPException(
                status_code=422, detail="lookback_minutes is not supported for Kandji"
            )
        result = sync_kandji.apply_async()
        scope = settings.kandji_org_name or "kandji"
    else:
        if not settings.sentinelone_enabled:
            raise HTTPException(
                status_code=400, detail="SentinelOne integration is disabled"
            )
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


@router.get("/admin/overview", response_model=List[IntegrationAdminOverview])
async def list_integration_admin_overview(
    db: AsyncSession = Depends(get_db),
    _: Any = Depends(require_scopes("view:integrations")),
) -> List[IntegrationAdminOverview]:
    freshness_service = IntegrationFreshnessService(db)
    freshness_records = await freshness_service.list_freshness()

    repo = IntegrationIssueEventRepository(db)
    since = datetime.now(timezone.utc) - timedelta(hours=24)
    recent_events = await repo.list_events(since=since)

    event_counts: Dict[tuple[str, str], Counter[str]] = defaultdict(Counter)
    for event in recent_events:
        key = (event.integration, event.scope)
        event_counts[key][event.severity] += 1

    schedule_index = _build_schedule_index()
    overviews: List[IntegrationAdminOverview] = []

    for record in freshness_records:
        metadata = dict(record.metadata or {})
        events = event_counts.get((record.integration, record.scope), Counter())
        duration_samples = _coerce_float_list(metadata.get("duration_samples", []))
        duration_average = (
            sum(duration_samples) / len(duration_samples)
            if duration_samples
            else metadata.get("last_duration_seconds")
        )
        confidence = getattr(record, "confidence", None) or _derive_confidence(
            record.status
        )
        next_sync = _compute_next_scheduled(record.integration, schedule_index)
        recent_errors = metadata.get("recent_errors", [])
        if isinstance(recent_errors, list):
            filtered_errors = [err for err in recent_errors if isinstance(err, dict)]
        else:
            filtered_errors = []

        metadata["issues_last_24h"] = dict(events)
        error_count = sum(
            count
            for severity, count in events.items()
            if str(severity).lower() in {"error", "critical"}
        )
        metadata["error_count_24h"] = error_count
        metadata["stale_threshold_hours"] = _integration_stale_threshold(
            record.integration
        )
        metadata["status_confidence"] = _derive_confidence(record.status)

        overviews.append(
            IntegrationAdminOverview(
                integration=record.integration,
                scope=record.scope,
                status=record.status,
                last_synced_at=record.last_synced_at,
                age_seconds=record.age_seconds,
                age_human=record.age_human,
                warning=record.warning,
                next_scheduled_sync_at=next_sync,
                duration_average_seconds=duration_average,
                duration_samples=duration_samples,
                recent_errors=filtered_errors,
                confidence=confidence,
                metadata=metadata,
                stale_threshold_hours=metadata.get("stale_threshold_hours"),
            )
        )

    return overviews


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
    integration: Optional[str] = Query(
        None, description="Filter by integration identifier"
    ),
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
    threshold = (
        stale_seconds
        if stale_seconds is not None
        else settings.integration_sync_stale_seconds
    )

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
    integration: Optional[str] = Query(
        None, description="Filter by integration identifier"
    ),
    scope: Optional[str] = Query(None, description="Filter by scope"),
    hours: int = Query(24, ge=1, le=168, description="Lookback window in hours"),
    bucket_minutes: int = Query(
        60, ge=5, le=720, description="Aggregation bucket size in minutes"
    ),
    limit: int = Query(
        100, ge=1, le=500, description="Maximum number of recent events to return"
    ),
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

    return IntegrationIssueHistoryResponse(
        events=history_events, buckets=history_buckets
    )


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


def _coerce_float_list(value: Any) -> List[float]:
    samples: List[float] = []
    if isinstance(value, list):
        for item in value:
            try:
                samples.append(float(item))
            except (TypeError, ValueError):
                continue
    return samples[-10:]


def _derive_confidence(status: str) -> str:
    normalized = status.lower()
    if normalized == "fresh":
        return "high"
    if normalized == "stale":
        return "medium"
    if normalized in {"error", "disabled"}:
        return "low"
    return "unknown"


def _integration_stale_threshold(integration: str) -> int:
    overrides = settings.operational_integration_stale_overrides or {}
    normalized = integration.lower()
    for key, value in overrides.items():
        if not isinstance(key, str):
            continue
        try:
            threshold = int(value)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            continue
        if key.lower() in normalized:
            return max(1, threshold)
    return max(1, settings.operational_integration_stale_hours)


def _build_schedule_index() -> Dict[str, Any]:
    schedule_conf = getattr(celery_app.conf, "beat_schedule", {}) or {}
    return {
        details.get("task"): details.get("schedule")
        for details in schedule_conf.values()
        if isinstance(details, dict) and details.get("task")
    }


def _compute_next_scheduled(
    integration: str, schedule_index: Dict[str, Any]
) -> Optional[datetime]:
    task_name = _resolve_task_for_integration(integration, schedule_index.keys())
    if not task_name:
        return None
    schedule_obj = schedule_index.get(task_name)
    if schedule_obj is None:
        return None

    now = datetime.now(timezone.utc)
    delta: Optional[timedelta] = None
    if isinstance(schedule_obj, (int, float)):
        delta = timedelta(seconds=float(schedule_obj))
    elif isinstance(schedule_obj, timedelta):
        delta = schedule_obj
    elif hasattr(schedule_obj, "remaining_estimate"):
        try:
            remaining = schedule_obj.remaining_estimate(datetime.utcnow())
            if isinstance(remaining, timedelta):
                delta = remaining
        except Exception:
            delta = None
    elif hasattr(schedule_obj, "run_every") and isinstance(
        schedule_obj.run_every, timedelta
    ):
        delta = schedule_obj.run_every

    if delta is None:
        return None
    return now + delta


def _resolve_task_for_integration(
    integration: str, tasks: Iterable[str]
) -> Optional[str]:
    integration_key = integration.split(".")[0].lower()
    for task in tasks:
        if not isinstance(task, str):
            continue
        if integration_key in task.lower():
            return task
    explicit_map = {
        "sentinelone.activities": "cerebro.tasks.integration.sync_sentinelone",
        "kandji.vulnerabilities": "cerebro.tasks.integration.sync_kandji",
    }
    return explicit_map.get(integration)
