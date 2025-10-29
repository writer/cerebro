"""SentinelOne activity ingestion pipeline."""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass
import asyncio
import random
from datetime import datetime, timedelta, timezone
from typing import Any, AsyncIterator, Dict, Iterable, List, Optional
from uuid import UUID, uuid5

import httpx
from dateutil import parser as date_parser
from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.telemetry.schemas import HostEvent, HostEventBatch
from cerebro.telemetry.services import TelemetryIngestionService
from cerebro.integrations.state import IntegrationStateRepository

logger = logging.getLogger(__name__)

_S1_NAMESPACE = UUID("0cbd0ef1-7d3b-4d46-b3f8-7934b85ad16f")
_EVENT_BATCH_SIZE = 200
_MAX_RETRIES = 5
_RETRY_BASE_SECONDS = 1.0
_STATE_DRIFT = timedelta(minutes=1)


def _isoformat(dt: datetime) -> str:
    """Render datetimes in the canonical format expected by SentinelOne filters."""

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


class SentinelOneError(RuntimeError):
    """Raised when SentinelOne API responses are invalid."""


@dataclass(slots=True)
class SentinelOneConfig:
    base_url: str
    api_token: str
    organization: str
    site: Optional[str] = None
    agent_version: str = "sentinelone-sync/1.0"
    verify: bool = True
    page_size: int = 200


class SentinelOneClient:
    """Thin async wrapper around the SentinelOne REST API."""

    def __init__(self, config: SentinelOneConfig, timeout: float = 30.0) -> None:
        headers = {
            "Authorization": f"ApiToken {config.api_token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        self._client = httpx.AsyncClient(
            base_url=config.base_url.rstrip("/"),
            timeout=timeout,
            headers=headers,
            verify=config.verify,
        )
        self._config = config

    async def __aenter__(self) -> "SentinelOneClient":
        await self._client.__aenter__()
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self._client.__aexit__(*exc)

    async def iter_activities(
        self,
        *,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
    ) -> AsyncIterator[Dict[str, Any]]:
        """Yield activity records using cursor pagination.

        SentinelOne exposes its timeline via a cursor-based API where every response
        may include a ``pagination.nextCursor`` token.  We keep a stable set of
        base filters (date bounds with ISO8601 formatting and page size) and
        re-issue requests while a cursor is provided.  The generator structure
        keeps memory usage low even when large backfills are requested.
        """

        base_params: Dict[str, Any] = {"limit": self._config.page_size}
        if since:
            base_params["createdAt__gte"] = _isoformat(since)
        if until:
            base_params["createdAt__lte"] = _isoformat(until)

        params = dict(base_params)
        cursor: Optional[str] = None

        while True:
            if cursor:
                params = dict(base_params)
                params["cursor"] = cursor

            # The activities endpoint returns a heterogeneous payload depending on
            # account tier.  We rely on helper extractors to normalize the shape
            # before yielding individual rows to callers.
            payload = await self._request_json("/web/api/v2.1/activities", params=params)

            records = self._extract_records(payload)
            for record in records:
                yield record

            cursor = self._extract_cursor(payload)
            if not cursor:
                break

    @staticmethod
    def _extract_records(payload: Dict[str, Any]) -> Iterable[Dict[str, Any]]:
        """Return the list of activity records irrespective of platform version."""

        if not isinstance(payload, dict):
            raise SentinelOneError("Unexpected SentinelOne response payload")

        for key in ("data", "activities", "items"):
            value = payload.get(key)
            if isinstance(value, list):
                return value

        return []

    @staticmethod
    def _extract_cursor(payload: Dict[str, Any]) -> Optional[str]:
        """Read the continuation cursor from different response layouts."""

        pagination = payload.get("pagination")
        if isinstance(pagination, dict):
            for key in ("nextCursor", "next", "next_cursor"):
                value = pagination.get(key)
                if isinstance(value, str) and value:
                    return value
        next_cursor = payload.get("nextCursor")
        if isinstance(next_cursor, str) and next_cursor:
            return next_cursor
        return None

    async def _request_json(self, url: str, *, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Execute a GET request with retry/backoff semantics."""

        attempt = 0
        backoff = _RETRY_BASE_SECONDS
        while True:
            attempt += 1
            try:
                response = await self._client.get(url, params=params)
            except httpx.TransportError:
                if attempt >= _MAX_RETRIES:
                    raise
            else:
                if response.status_code in {429, 500, 502, 503, 504}:
                    if attempt >= _MAX_RETRIES:
                        response.raise_for_status()
                else:
                    response.raise_for_status()
                    return response.json()

                retry_after = response.headers.get("Retry-After")
                if retry_after and retry_after.isdigit():
                    backoff = max(float(retry_after), backoff)
            jitter = random.uniform(0.0, 0.25 * backoff)
            await asyncio.sleep(backoff + jitter)
            backoff = min(backoff * 2, 30.0)


class SentinelOneIngestion:
    """Normalizes SentinelOne activities into Cerebro host events."""

    def __init__(self, client: SentinelOneClient) -> None:
        self._client = client
        self._config = client._config

    async def ingest(
        self,
        db: AsyncSession,
        *,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """Load activities, normalize them, and persist via the telemetry service."""

        service = TelemetryIngestionService(db)
        state_repo = IntegrationStateRepository(db)
        state = await state_repo.get_state("sentinelone.activities", self._config.organization)

        effective_since = since
        if state and state.last_timestamp:
            candidate = state.last_timestamp - _STATE_DRIFT
            if effective_since is None or candidate > effective_since:
                effective_since = candidate

        grouped: Dict[str, List[HostEvent]] = defaultdict(list)
        now = datetime.now(timezone.utc)
        latest_timestamp: Optional[datetime] = None

        async for activity in self._client.iter_activities(since=effective_since, until=until):
            event = self._normalize_activity(activity)
            if event is None:
                continue
            grouped[event.host_id].append(event)
            if latest_timestamp is None or event.timestamp > latest_timestamp:
                latest_timestamp = event.timestamp

        ingested = 0
        for host_id, events in grouped.items():
            for chunk in self._chunk_events(events, _EVENT_BATCH_SIZE):
                batch = HostEventBatch(
                    host_id=host_id,
                    hostname=chunk[0].hostname,
                    organization=self._config.organization,
                    site=self._config.site,
                    agent_version=self._config.agent_version,
                    collected_at=now,
                    events=chunk,
                )
                await service.process_host_events(batch)
                ingested += len(chunk)

        if latest_timestamp:
            await state_repo.upsert_state(
                integration="sentinelone.activities",
                scope=self._config.organization,
                last_timestamp=latest_timestamp,
                metadata={"last_ingested_count": ingested},
            )

        return {"events_ingested": ingested, "hosts": len(grouped)}

    def _normalize_activity(self, activity: Dict[str, Any]) -> Optional[HostEvent]:
        """Translate raw SentinelOne activity JSON into a ``HostEvent`` model.

        The activity schema differs across environments and product tiers.  We
        defensively look for identifiers under both top-level and nested ``data``
        payloads.  When essential fields are missing (no activity ID or agent)
        we drop the event to avoid inserting ambiguous host records.
        """

        if not isinstance(activity, dict):
            return None

        activity_id = str(activity.get("id") or activity.get("activityUuid") or "").strip()
        if not activity_id:
            return None

        data = activity.get("data") if isinstance(activity.get("data"), dict) else {}
        agent_id = (
            activity.get("agentId")
            or data.get("agentId")
            or data.get("agentUuid")
            or data.get("agent_id")
        )
        if not agent_id:
            return None

        hostname = (
            activity.get("computerName")
            or data.get("computerName")
            or data.get("machineName")
            or data.get("agentHostname")
        )

        created_at = activity.get("createdAt") or activity.get("created_at")
        if not isinstance(created_at, str):
            created_at = data.get("createdAt")
        if isinstance(created_at, str):
            timestamp = date_parser.isoparse(created_at)
        else:
            timestamp = datetime.now(timezone.utc)

        severity = self._map_severity(
            activity.get("severity")
            or data.get("severity")
            or activity.get("threatLevel")
        )

        event_uuid = uuid5(_S1_NAMESPACE, f"activity:{activity_id}")
        event_raw = activity.get("activityType") or activity.get("activity_name") or "activity"
        event_type = str(event_raw).lower()
        category = "sentinelone.activity"
        # Persist the raw record for analysts while keeping the schema stable.
        payload = {k: v for k, v in activity.items() if k not in {"data"}}
        payload["data"] = data

        return HostEvent(
            event_id=event_uuid,
            host_id=str(agent_id),
            hostname=str(hostname) if hostname else None,
            category=category,
            event_type=event_type or "activity",
            severity=severity,
            timestamp=timestamp,
            user=data.get("loginsUsername") or activity.get("userName"),
            source="sentinelone.activities",
            payload=payload,
        )

    @staticmethod
    def _map_severity(severity: Any) -> Optional[str]:
        """Normalize SentinelOne severity levels into Cerebro's label set."""

        if severity is None:
            return None
        if isinstance(severity, (int, float)):
            if severity >= 8:
                return "critical"
            if severity >= 5:
                return "high"
            if severity >= 3:
                return "medium"
            return "low"
        level = str(severity).lower()
        mapping = {
            "informational": "info",
            "information": "info",
            "low": "low",
            "medium": "medium",
            "high": "high",
            "critical": "critical",
        }
        return mapping.get(level, "info")

    @staticmethod
    def _chunk_events(events: List[HostEvent], size: int) -> Iterable[List[HostEvent]]:
        for idx in range(0, len(events), size):
            yield events[idx : idx + size]
