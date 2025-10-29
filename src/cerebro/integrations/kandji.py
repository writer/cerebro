"""Kandji device and vulnerability ingestion."""

from __future__ import annotations

import logging
import asyncio
import random
from datetime import datetime, timedelta, timezone
from typing import Any, AsyncIterator, Dict, Iterable, List, Optional
from uuid import UUID, uuid5

import httpx
from dateutil import parser as date_parser
from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.telemetry.schemas import HostEvent, HostEventBatch, HostTelemetry
from cerebro.telemetry.services import TelemetryIngestionService
from cerebro.integrations.state import IntegrationStateRepository

logger = logging.getLogger(__name__)

_KANDJI_EVENT_NAMESPACE = UUID("c7070277-9e5c-431d-9487-59ac266c3a54")
_DETECTIONS_SCOPE = "kandji.vulnerabilities"
_DETECTIONS_DRIFT = timedelta(minutes=5)
_EVENT_BATCH_SIZE = 200
_MAX_RETRIES = 5
_RETRY_BASE_SECONDS = 1.0


class KandjiError(RuntimeError):
    """Raised when Kandji API responses are invalid."""


class KandjiClient:
    """Async wrapper around Kandji's REST API."""

    def __init__(
        self,
        base_url: str,
        api_token: str,
        *,
        verify: bool = True,
        timeout: float = 30.0,
    ) -> None:
        headers = {
            "Authorization": f"Bearer {api_token}",
            "Accept": "application/json",
        }
        self._client = httpx.AsyncClient(
            base_url=base_url.rstrip("/"),
            timeout=timeout,
            headers=headers,
            verify=verify,
        )

    async def __aenter__(self) -> "KandjiClient":
        await self._client.__aenter__()
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self._client.__aexit__(*exc)

    async def iter_devices(self, *, page_size: int = 300) -> AsyncIterator[Dict[str, Any]]:
        """Stream device inventory using Kandji's cursor-based pagination."""

        url = "/api/v1/devices"
        params: Optional[Dict[str, Any]] = {"limit": page_size}

        while url:
            payload = await self._request_json(url, params=params)
            results = payload.get("results") if isinstance(payload, dict) else None
            if isinstance(results, list):
                for item in results:
                    if isinstance(item, dict):
                        yield item
            url = payload.get("next") if isinstance(payload, dict) else None
            params = None

    async def iter_vulnerability_detections(
        self,
        *,
        page_size: int = 300,
    ) -> AsyncIterator[Dict[str, Any]]:
        """Yield vulnerability detections with pagination awareness."""

        url = "/api/v1/vulnerability-management/detections"
        params: Optional[Dict[str, Any]] = {"size": page_size}

        while url:
            payload = await self._request_json(url, params=params)
            results = payload.get("results") if isinstance(payload, dict) else None
            if isinstance(results, list):
                for item in results:
                    if isinstance(item, dict):
                        yield item
            url = payload.get("next") if isinstance(payload, dict) else None
            params = None

    async def _request_json(self, url: str, *, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Execute Kandji API calls with retry/backoff handling."""

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


class KandjiIngestion:
    """Transforms Kandji data into Cerebro telemetry objects."""

    def __init__(
        self,
        client: KandjiClient,
        *,
        organization: str,
        site: Optional[str] = None,
        agent_version: str = "kandji-sync/1.0",
    ) -> None:
        self._client = client
        self._organization = organization
        self._site = site
        self._agent_version = agent_version

    async def ingest(self, db: AsyncSession) -> Dict[str, Any]:
        """Ingest devices and vulnerability detections.

        Device snapshots are processed first to guarantee that we have an
        up-to-date ``Resource`` row for every host.  Vulnerability detections are
        then batched by serial number and shipped through the existing host event
        ingestion pipeline.  Returning simple counters keeps the Celery task
        result compact while still providing operational visibility.
        """

        service = TelemetryIngestionService(db)
        state_repo = IntegrationStateRepository(db)
        state = await state_repo.get_state(_DETECTIONS_SCOPE, self._organization)
        detection_cutoff: Optional[datetime] = None
        if state and state.last_timestamp:
            detection_cutoff = state.last_timestamp - _DETECTIONS_DRIFT

        now = datetime.now(timezone.utc)

        device_count = 0
        async for device in self._client.iter_devices():
            telemetry = self._build_host_telemetry(device, collected_at=now)
            if telemetry is None:
                continue
            await service.process_host(telemetry)
            device_count += 1

        grouped_events: Dict[str, List[HostEvent]] = {}
        latest_detection: Optional[datetime] = None
        async for detection in self._client.iter_vulnerability_detections():
            event = self._normalize_detection(detection)
            if event is None:
                continue
            if detection_cutoff and event.timestamp <= detection_cutoff:
                continue
            if latest_detection is None or event.timestamp > latest_detection:
                latest_detection = event.timestamp
            grouped_events.setdefault(event.host_id, []).append(event)

        total_events = 0
        for host_id, events in grouped_events.items():
            hostname = next((e.hostname for e in events if e.hostname), None)
            for chunk in self._chunk_events(events, _EVENT_BATCH_SIZE):
                chunk_hostname = next((e.hostname for e in chunk if e.hostname), hostname)
                batch = HostEventBatch(
                    host_id=host_id,
                    hostname=chunk_hostname,
                    organization=self._organization,
                    site=self._site,
                    agent_version=self._agent_version,
                    collected_at=now,
                    events=chunk,
                )
                await service.process_host_events(batch)
                total_events += len(chunk)

        if latest_detection:
            await state_repo.upsert_state(
                integration=_DETECTIONS_SCOPE,
                scope=self._organization,
                last_timestamp=latest_detection,
                metadata={"last_event_count": total_events},
            )

        return {"devices": device_count, "events_ingested": total_events, "hosts": len(grouped_events)}

    def _build_host_telemetry(
        self,
        device: Dict[str, Any],
        *,
        collected_at: datetime,
    ) -> Optional[HostTelemetry]:
        """Construct ``HostTelemetry`` snapshots from Kandji device payloads."""

        if not isinstance(device, dict):
            return None

        serial = str(device.get("serial_number") or device.get("id") or "").strip()
        if not serial:
            return None

        mdm_device = device.get("mdm_device") if isinstance(device.get("mdm_device"), dict) else {}
        hostname = (
            mdm_device.get("name")
            or device.get("device_name")
            or device.get("description")
            or serial
        )

        os_family = (device.get("os") or device.get("device_family") or "unknown").lower()
        blueprint = str(device.get("blueprint_id") or device.get("blueprint") or "")
        tags: Dict[str, str] = {}
        if blueprint:
            tags["blueprint_id"] = blueprint
        if mdm_device.get("enrollment_status") is not None:
            tags["enrollment_status"] = str(mdm_device["enrollment_status"])
        if device.get("asset_tag"):
            tags["asset_tag"] = str(device["asset_tag"])
        if device.get("color"):
            tags["hardware_color"] = str(device["color"])

        return HostTelemetry(
            organization=self._organization,
            site=self._site or self._derive_site(device),
            host_id=serial,
            hostname=str(hostname),
            serial_number=serial,
            agent_version=self._agent_version,
            os_family=os_family,
            os_version=device.get("device_os_version") or device.get("model"),
            kernel_version=None,
            architecture=None,
            collected_at=collected_at,
            ip_addresses=[],
            mac_addresses=None,
            logged_in_users=None,
            tags=tags or None,
        )

    def _normalize_detection(self, detection: Dict[str, Any]) -> Optional[HostEvent]:
        """Represent Kandji vulnerability detections as host events."""

        if not isinstance(detection, dict):
            return None

        serial = str(detection.get("device_serial_number") or detection.get("device_id") or "").strip()
        if not serial:
            return None

        cve = str(detection.get("cve_id") or detection.get("name") or "").strip()
        if not cve:
            return None

        timestamp_raw = detection.get("latest_detection_date") or detection.get("first_detection_date")
        if isinstance(timestamp_raw, str):
            timestamp = date_parser.isoparse(timestamp_raw)
        else:
            timestamp = datetime.now(timezone.utc)

        event_uuid = uuid5(_KANDJI_EVENT_NAMESPACE, f"vuln:{serial}:{cve}")
        severity = str(detection.get("cvss_severity") or detection.get("severity") or "").lower() or None

        # Preserve Kandji's raw detection data so analysts can cross-reference
        # affected software, remediation state, and ticket links.
        payload = {k: v for k, v in detection.items()}

        return HostEvent(
            event_id=event_uuid,
            host_id=serial,
            hostname=detection.get("device_name"),
            category="kandji.vulnerability",
            event_type=f"cve:{cve}",
            severity=severity,
            timestamp=timestamp,
            source="kandji.vulnerability",
            payload=payload,
        )

    def _derive_site(self, device: Dict[str, Any]) -> Optional[str]:
        """Fallback to Kandji DEP server name when no site override is provided."""

        dep = device.get("dep_account")
        if isinstance(dep, dict):
            name = dep.get("server_name")
            if isinstance(name, str) and name:
                return name
        return self._site

    @staticmethod
    def _chunk_events(events: List[HostEvent], size: int) -> Iterable[List[HostEvent]]:
        for idx in range(0, len(events), size):
            yield events[idx : idx + size]
