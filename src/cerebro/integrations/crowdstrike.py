"""CrowdStrike Falcon integration for EDR findings and threat detection.

This module provides integration with CrowdStrike Falcon platform to ingest:
- Detection events (malware, suspicious behavior, etc.)
- Host/endpoint information
- Vulnerability findings
- IOC (Indicator of Compromise) data
"""

from __future__ import annotations

import asyncio
from collections import defaultdict
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import httpx
import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.integrations.state import IntegrationStateRepository
from cerebro.metrics.integration_metrics import record_integration_sync
from cerebro.telemetry.schemas import (
    EndpointThreat,
    HostEvent,
    HostEventBatch,
    HostTelemetry,
)
from cerebro.telemetry.services import TelemetryIngestionService

logger = structlog.get_logger(__name__)

_CS_NAMESPACE = UUID("f47ac10b-58cc-4372-a567-0e02b2c3d479")
_EVENT_BATCH_SIZE = 200
_MAX_RETRIES = 5
_RETRY_BASE_SECONDS = 1.0
_STATE_DRIFT = timedelta(minutes=1)


class CrowdStrikeError(RuntimeError):
    """Raised when CrowdStrike API responses are invalid."""


@dataclass
class CrowdStrikeConfig:
    """Configuration for CrowdStrike Falcon API connection."""

    base_url: str  # e.g., https://api.crowdstrike.com
    client_id: str
    client_secret: str
    organization: str
    site: str | None = None
    agent_version: str = "crowdstrike-sync/1.0"
    verify: bool = True
    page_size: int = 100


@dataclass
class CrowdStrikeDetection:
    """Normalized CrowdStrike detection."""

    detection_id: str
    host_id: str
    hostname: str | None
    severity: str
    status: str
    behavior_id: str | None
    tactic: str | None
    technique: str | None
    description: str | None
    timestamp: datetime
    filename: str | None
    filepath: str | None
    sha256: str | None
    cmdline: str | None
    user: str | None
    parent_process: str | None
    raw: dict[str, Any]


class CrowdStrikeClient:
    """Async client for CrowdStrike Falcon API.

    Implements OAuth2 client credentials flow for authentication.
    """

    def __init__(self, config: CrowdStrikeConfig, timeout: float = 30.0) -> None:
        self._config = config
        self._timeout = timeout
        self._client: httpx.AsyncClient | None = None
        self._access_token: str | None = None
        self._token_expires_at: datetime | None = None

    async def __aenter__(self) -> CrowdStrikeClient:
        self._client = httpx.AsyncClient(
            base_url=self._config.base_url.rstrip("/"),
            timeout=self._timeout,
            verify=self._config.verify,
        )
        return self

    async def __aexit__(self, *exc: Any) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    async def _ensure_authenticated(self) -> None:
        """Ensure we have a valid access token, refreshing if needed."""
        if self._access_token and self._token_expires_at:
            if datetime.now(UTC) < self._token_expires_at - timedelta(minutes=5):
                return

        if not self._client:
            raise CrowdStrikeError("Client not initialized")

        response = await self._client.post(
            "/oauth2/token",
            data={
                "client_id": self._config.client_id,
                "client_secret": self._config.client_secret,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        response.raise_for_status()

        data = response.json()
        self._access_token = data["access_token"]
        expires_in = data.get("expires_in", 1800)
        self._token_expires_at = datetime.now(UTC) + timedelta(seconds=expires_in)

        logger.info("CrowdStrike authentication successful")

    def _get_headers(self) -> dict[str, str]:
        """Get headers with current access token."""
        if not self._access_token:
            raise CrowdStrikeError("Not authenticated")
        return {
            "Authorization": f"Bearer {self._access_token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    async def _request_json(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        json_data: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Execute an API request with retry/backoff semantics."""
        await self._ensure_authenticated()

        if not self._client:
            raise CrowdStrikeError("Client not initialized")

        attempt = 0
        backoff = _RETRY_BASE_SECONDS

        while True:
            attempt += 1
            try:
                response = await self._client.request(
                    method,
                    url,
                    params=params,
                    json=json_data,
                    headers=self._get_headers(),
                )
            except httpx.TransportError:
                if attempt >= _MAX_RETRIES:
                    raise
            else:
                if response.status_code == 401:
                    self._access_token = None
                    await self._ensure_authenticated()
                    continue

                if response.status_code in {429, 500, 502, 503, 504}:
                    if attempt >= _MAX_RETRIES:
                        response.raise_for_status()
                else:
                    response.raise_for_status()
                    return response.json()

                retry_after = response.headers.get("X-RateLimit-RetryAfter")
                if retry_after and retry_after.isdigit():
                    backoff = max(float(retry_after), backoff)

            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 30.0)

        raise CrowdStrikeError("Max retries exceeded")

    async def iter_detections(
        self,
        *,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = 100,
    ) -> AsyncIterator[dict[str, Any]]:
        """Iterate over detection events.

        Uses the /detects/queries/detects/v1 and /detects/entities/summaries/GET/v1
        endpoints to fetch detection data.
        """
        params: dict[str, Any] = {"limit": limit}

        # Build filter query
        filters = []
        if since:
            filters.append(f"created_timestamp:>='{since.isoformat()}'")
        if until:
            filters.append(f"created_timestamp:<='{until.isoformat()}'")

        if filters:
            params["filter"] = "+".join(filters)

        offset: str | None = None

        while True:
            if offset:
                params["offset"] = offset

            # First, get detection IDs
            ids_response = await self._request_json(
                "GET", "/detects/queries/detects/v1", params=params
            )

            resources = ids_response.get("resources", [])
            if not resources:
                break

            # Then fetch full detection details
            details_response = await self._request_json(
                "POST",
                "/detects/entities/summaries/GET/v1",
                json_data={"ids": resources},
            )

            for detection in details_response.get("resources", []):
                yield detection

            # Handle pagination
            meta = ids_response.get("meta", {})
            pagination = meta.get("pagination", {})
            offset = pagination.get("offset")

            if not offset or len(resources) < limit:
                break

    async def iter_hosts(self, *, limit: int = 100) -> AsyncIterator[dict[str, Any]]:
        """Iterate over managed hosts/endpoints."""
        params: dict[str, Any] = {"limit": limit}
        offset: str | None = None

        while True:
            if offset:
                params["offset"] = offset

            # Get host IDs
            ids_response = await self._request_json(
                "GET", "/devices/queries/devices/v1", params=params
            )

            resources = ids_response.get("resources", [])
            if not resources:
                break

            # Fetch host details
            details_response = await self._request_json(
                "POST",
                "/devices/entities/devices/v2",
                json_data={"ids": resources},
            )

            for host in details_response.get("resources", []):
                yield host

            meta = ids_response.get("meta", {})
            pagination = meta.get("pagination", {})
            offset = pagination.get("offset")

            if not offset or len(resources) < limit:
                break

    async def iter_vulnerabilities(
        self,
        *,
        since: datetime | None = None,
        limit: int = 100,
    ) -> AsyncIterator[dict[str, Any]]:
        """Iterate over vulnerability findings from Spotlight."""
        params: dict[str, Any] = {"limit": limit}

        filters = []
        if since:
            filters.append(f"created_timestamp:>='{since.isoformat()}'")

        if filters:
            params["filter"] = "+".join(filters)

        offset: str | None = None

        while True:
            if offset:
                params["after"] = offset

            response = await self._request_json(
                "GET", "/spotlight/combined/vulnerabilities/v1", params=params
            )

            for vuln in response.get("resources", []):
                yield vuln

            meta = response.get("meta", {})
            pagination = meta.get("pagination", {})
            offset = pagination.get("after")

            if not offset:
                break

    async def get_iocs(
        self,
        *,
        ioc_type: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Get custom IOC indicators."""
        params: dict[str, Any] = {"limit": limit}

        if ioc_type:
            params["filter"] = f"type:'{ioc_type}'"

        response = await self._request_json(
            "GET", "/iocs/combined/indicator/v1", params=params
        )

        return response.get("resources", [])


class CrowdStrikeIngestion:
    """Normalizes CrowdStrike data into Cerebro events and findings."""

    def __init__(self, client: CrowdStrikeClient) -> None:
        self._client = client
        self._config = client._config

    def _normalize_detection(
        self, detection: dict[str, Any]
    ) -> CrowdStrikeDetection | None:
        """Normalize a CrowdStrike detection to internal format."""
        try:
            device = detection.get("device", {})
            behaviors = detection.get("behaviors", [])
            first_behavior = behaviors[0] if behaviors else {}

            # Parse timestamp
            timestamp_str = detection.get("created_timestamp") or detection.get(
                "first_behavior"
            )
            if timestamp_str:
                timestamp = datetime.fromisoformat(
                    timestamp_str.replace("Z", "+00:00")
                )
            else:
                timestamp = datetime.now(UTC)

            # Map severity
            severity_map = {
                "Critical": "critical",
                "High": "high",
                "Medium": "medium",
                "Low": "low",
                "Informational": "info",
            }
            raw_severity = detection.get("max_severity_displayname", "Medium")
            severity = severity_map.get(raw_severity, "medium")

            return CrowdStrikeDetection(
                detection_id=detection.get("detection_id", ""),
                host_id=device.get("device_id", ""),
                hostname=device.get("hostname"),
                severity=severity,
                status=detection.get("status", "new"),
                behavior_id=first_behavior.get("behavior_id"),
                tactic=first_behavior.get("tactic"),
                technique=first_behavior.get("technique"),
                description=first_behavior.get("description"),
                timestamp=timestamp,
                filename=first_behavior.get("filename"),
                filepath=first_behavior.get("filepath"),
                sha256=first_behavior.get("sha256"),
                cmdline=first_behavior.get("cmdline"),
                user=first_behavior.get("user_name"),
                parent_process=first_behavior.get("parent_details", {}).get(
                    "parent_process_graph_id"
                ),
                raw=detection,
            )
        except Exception as e:
            logger.warning(f"Failed to normalize detection: {e}")
            return None

    def _detection_to_host_event(
        self, detection: CrowdStrikeDetection
    ) -> HostEvent:
        """Convert a detection to a HostEvent."""
        return HostEvent(
            host_id=detection.host_id,
            hostname=detection.hostname,
            category="detection",
            event_type=f"crowdstrike.{detection.tactic or 'unknown'}",
            severity=detection.severity,
            timestamp=detection.timestamp,
            user=detection.user,
            command_line=detection.cmdline,
            source="crowdstrike",
            payload={
                "detection_id": detection.detection_id,
                "behavior_id": detection.behavior_id,
                "technique": detection.technique,
                "description": detection.description,
                "filename": detection.filename,
                "filepath": detection.filepath,
                "sha256": detection.sha256,
                "status": detection.status,
            },
        )

    def _detection_to_threat(
        self, detection: CrowdStrikeDetection
    ) -> EndpointThreat:
        """Convert a detection to an EndpointThreat."""
        return EndpointThreat(
            threat_id=detection.detection_id,
            name=detection.description or f"CrowdStrike Detection: {detection.tactic}",
            classification=detection.technique,
            severity=detection.severity,
            status=detection.status,
            file_path=detection.filepath,
            sha256=detection.sha256,
            detected_at=detection.timestamp,
            mitre_tactics=[detection.tactic] if detection.tactic else None,
            mitre_techniques=[detection.technique] if detection.technique else None,
        )

    async def ingest_detections(
        self,
        db: AsyncSession,
        *,
        since: datetime | None = None,
        until: datetime | None = None,
    ) -> dict[str, Any]:
        """Ingest detection events from CrowdStrike."""
        service = TelemetryIngestionService(db)
        state_repo = IntegrationStateRepository(db)
        state = await state_repo.get_state(
            "crowdstrike.detections", self._config.organization
        )

        effective_since = since
        if state and state.last_timestamp:
            candidate = state.last_timestamp - _STATE_DRIFT
            if effective_since is None or candidate > effective_since:
                effective_since = candidate

        grouped: dict[str, list[HostEvent]] = defaultdict(list)
        threats_by_host: dict[str, list[EndpointThreat]] = defaultdict(list)
        now = datetime.now(UTC)
        latest_timestamp: datetime | None = None
        detection_count = 0

        async for raw_detection in self._client.iter_detections(
            since=effective_since, until=until
        ):
            detection = self._normalize_detection(raw_detection)
            if detection is None:
                continue

            detection_count += 1
            event = self._detection_to_host_event(detection)
            grouped[detection.host_id].append(event)
            threats_by_host[detection.host_id].append(
                self._detection_to_threat(detection)
            )

            if latest_timestamp is None or detection.timestamp > latest_timestamp:
                latest_timestamp = detection.timestamp

        ingested = 0
        for host_id, events in grouped.items():
            for i in range(0, len(events), _EVENT_BATCH_SIZE):
                chunk = events[i : i + _EVENT_BATCH_SIZE]
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
            ts = (
                latest_timestamp
                if latest_timestamp.tzinfo
                else latest_timestamp.replace(tzinfo=UTC)
            )
            await state_repo.set_state(
                "crowdstrike.detections",
                self._config.organization,
                last_timestamp=ts,
            )

        record_integration_sync(
            "crowdstrike",
            self._config.organization,
            success=True,
            records=detection_count,
        )

        logger.info(
            "CrowdStrike detection ingestion complete",
            detections=detection_count,
            events_ingested=ingested,
            since=effective_since.isoformat() if effective_since else None,
        )

        return {
            "status": "success",
            "detections_processed": detection_count,
            "events_ingested": ingested,
            "latest_timestamp": latest_timestamp.isoformat() if latest_timestamp else None,
        }

    async def ingest_hosts(self, db: AsyncSession) -> dict[str, Any]:
        """Ingest host/endpoint inventory from CrowdStrike."""
        service = TelemetryIngestionService(db)
        now = datetime.now(UTC)
        host_count = 0

        async for raw_host in self._client.iter_hosts():
            host_count += 1
            telemetry = HostTelemetry(
                organization=self._config.organization,
                site=self._config.site,
                host_id=raw_host.get("device_id", ""),
                hostname=raw_host.get("hostname", "unknown"),
                serial_number=raw_host.get("serial_number"),
                agent_version=raw_host.get("agent_version", ""),
                os_family=raw_host.get("platform_name", "").lower(),
                os_version=raw_host.get("os_version"),
                kernel_version=raw_host.get("kernel_version"),
                collected_at=now,
                ip_addresses=[
                    ip
                    for ip in [
                        raw_host.get("local_ip"),
                        raw_host.get("external_ip"),
                    ]
                    if ip
                ],
                mac_addresses=[raw_host.get("mac_address")]
                if raw_host.get("mac_address")
                else None,
                tags={
                    "crowdstrike_cid": raw_host.get("cid", ""),
                    "last_seen": raw_host.get("last_seen", ""),
                    "first_seen": raw_host.get("first_seen", ""),
                    "system_manufacturer": raw_host.get("system_manufacturer", ""),
                    "system_product_name": raw_host.get("system_product_name", ""),
                },
            )
            await service.process_host_telemetry(telemetry)

        logger.info(
            "CrowdStrike host ingestion complete",
            hosts=host_count,
        )

        return {
            "status": "success",
            "hosts_processed": host_count,
        }


async def sync_crowdstrike(
    db: AsyncSession,
    config: CrowdStrikeConfig,
    *,
    since: datetime | None = None,
    until: datetime | None = None,
    include_hosts: bool = True,
    include_detections: bool = True,
) -> dict[str, Any]:
    """Main entry point for CrowdStrike synchronization.

    Args:
        db: Database session
        config: CrowdStrike configuration
        since: Start time for incremental sync
        until: End time for sync window
        include_hosts: Whether to sync host inventory
        include_detections: Whether to sync detection events

    Returns:
        Summary of sync results
    """
    results: dict[str, Any] = {"organization": config.organization}

    async with CrowdStrikeClient(config) as client:
        ingestion = CrowdStrikeIngestion(client)

        if include_hosts:
            results["hosts"] = await ingestion.ingest_hosts(db)

        if include_detections:
            results["detections"] = await ingestion.ingest_detections(
                db, since=since, until=until
            )

    return results
