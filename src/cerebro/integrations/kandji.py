"""Kandji device and vulnerability ingestion."""

from __future__ import annotations

import asyncio
import random
from collections.abc import AsyncIterator, Iterable
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid5

import httpx
import structlog
from dateutil import parser as date_parser
from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.integrations.state import IntegrationStateRepository
from cerebro.metrics.integration_metrics import record_integration_sync
from cerebro.telemetry.schemas import (
    AgentHealth,
    HostEvent,
    HostEventBatch,
    HostTelemetry,
    SoftwarePackage,
)
from cerebro.telemetry.services import TelemetryIngestionService

logger = structlog.get_logger(__name__)

_KANDJI_EVENT_NAMESPACE = UUID("c7070277-9e5c-431d-9487-59ac266c3a54")
_DETECTIONS_SCOPE = "kandji.vulnerabilities"
_AUDIT_SCOPE = "kandji.audit"
_PATCH_SCOPE = "kandji.patch"
_DETECTIONS_DRIFT = timedelta(minutes=5)
_AUDIT_DRIFT = timedelta(minutes=5)
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

    async def __aenter__(self) -> KandjiClient:
        await self._client.__aenter__()
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self._client.__aexit__(*exc)

    async def iter_devices(
        self, *, page_size: int = 300
    ) -> AsyncIterator[dict[str, Any]]:
        """Stream device inventory using Kandji's cursor-based pagination."""

        url = "/api/v1/devices"
        params: dict[str, Any] | None = {"limit": page_size}

        while url:
            payload = await self._request_json(url, params=params)
            results = payload.get("results") if isinstance(payload, dict) else None
            if isinstance(results, list):
                for item in results:
                    if isinstance(item, dict):
                        yield item
            next_url = payload.get("next") if isinstance(payload, dict) else None
            url = str(next_url) if next_url else None  # type: ignore[assignment]
            params = None

    async def iter_vulnerability_detections(
        self,
        *,
        page_size: int = 300,
    ) -> AsyncIterator[dict[str, Any]]:
        """Yield vulnerability detections with pagination awareness."""

        url = "/api/v1/vulnerability-management/detections"
        params: dict[str, Any] | None = {"size": page_size}

        while url:
            payload = await self._request_json(url, params=params)
            results = payload.get("results") if isinstance(payload, dict) else None
            if isinstance(results, list):
                for item in results:
                    if isinstance(item, dict):
                        yield item
            next_url = payload.get("next") if isinstance(payload, dict) else None
            url = str(next_url) if next_url else None  # type: ignore[assignment]
            params = None

    async def get_device_details(self, device_id: str) -> dict[str, Any] | None:
        try:
            return await self._request_json(f"/api/v1/devices/{device_id}")
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                return None
            raise

    async def get_device_compliance(self, device_id: str) -> dict[str, Any] | None:
        try:
            return await self._request_json(f"/api/v1/devices/{device_id}/compliance")
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code in {404, 403}:
                return None
            raise

    async def get_device_smart_groups(
        self, device_id: str
    ) -> list[dict[str, Any]] | None:
        try:
            payload = await self._request_json(
                f"/api/v1/devices/{device_id}/smart-groups"
            )
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code in {404, 403}:
                return None
            raise
        if isinstance(payload, dict):
            groups = payload.get("results")
            if isinstance(groups, list):
                return [g for g in groups if isinstance(g, dict)]
        return None

    async def get_blueprint(self, blueprint_id: str) -> dict[str, Any] | None:
        if not blueprint_id:
            return None
        try:
            return await self._request_json(f"/api/v1/blueprints/{blueprint_id}")
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                return None
            raise

    async def iter_audit_events(
        self,
        *,
        since: datetime | None = None,
        page_size: int = 300,
    ) -> AsyncIterator[dict[str, Any]]:
        url = "/api/v1/audit/events"
        params: dict[str, Any] = {"page_size": page_size}
        if since:
            params["occurred_after"] = self._isoformat(since)

        while url:
            payload = await self._request_json(url, params=params)
            events = payload.get("results") if isinstance(payload, dict) else None
            if isinstance(events, list):
                for item in events:
                    if isinstance(item, dict):
                        yield item
            next_url = payload.get("next") if isinstance(payload, dict) else None
            url = str(next_url) if next_url else None  # type: ignore[assignment]
            params = {}

    async def iter_patch_updates(
        self,
        *,
        page_size: int = 300,
    ) -> AsyncIterator[dict[str, Any]]:
        url = "/api/v1/patch-management/available-updates"
        params: dict[str, Any] | None = {"size": page_size}

        while url:
            payload = await self._request_json(url, params=params)
            detections = payload.get("results") if isinstance(payload, dict) else None
            if isinstance(detections, list):
                for item in detections:
                    if isinstance(item, dict):
                        yield item
            next_url = payload.get("next") if isinstance(payload, dict) else None
            url = str(next_url) if next_url else None  # type: ignore[assignment]
            params = None

    async def _request_json(
        self, url: str, *, params: dict[str, Any] | None = None
    ) -> dict[str, Any]:
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

    @staticmethod
    def _isoformat(dt: datetime) -> str:
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt.astimezone(UTC).isoformat().replace("+00:00", "Z")


class KandjiIngestion:
    """Transforms Kandji data into Cerebro telemetry objects."""

    def __init__(
        self,
        client: KandjiClient,
        *,
        organization: str,
        site: str | None = None,
        agent_version: str = "kandji-sync/1.0",
    ) -> None:
        self._client = client
        self._organization = organization
        self._site = site
        self._agent_version = agent_version
        self._blueprint_cache: dict[str, dict[str, Any]] = {}

    async def ingest(self, db: AsyncSession) -> dict[str, Any]:
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
        detection_cutoff: datetime | None = None
        if state and state.last_timestamp:
            detection_cutoff = state.last_timestamp - _DETECTIONS_DRIFT

        now = datetime.now(UTC)

        device_count = 0
        async for device in self._client.iter_devices():
            compliance, blueprint, smart_groups, lifecycle = (
                await self._collect_device_enrichment(device)
            )
            telemetry = self._build_host_telemetry(
                device,
                collected_at=now,
                compliance=compliance,
                blueprint=blueprint,
                smart_groups=smart_groups,
                lifecycle=lifecycle,
            )
            if telemetry is None:
                continue
            await service.process_host(telemetry)
            device_count += 1

        grouped_events: dict[str, list[HostEvent]] = {}
        latest_detection: datetime | None = None
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
                chunk_hostname = next(
                    (e.hostname for e in chunk if e.hostname), hostname
                )
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
            ts = (
                latest_detection
                if latest_detection.tzinfo
                else latest_detection.replace(tzinfo=UTC)
            )
            await state_repo.upsert_state(
                integration=_DETECTIONS_SCOPE,
                scope=self._organization,
                last_timestamp=ts,
                metadata={"last_event_count": total_events},
            )
            record_integration_sync(
                integration=_DETECTIONS_SCOPE,
                scope=self._organization,
                last_sync_unix=ts.timestamp(),
                events_ingested=total_events,
            )

        audit_events, audit_count = await self._ingest_audit_events(service, state_repo)
        patch_events, patch_count = await self._ingest_patch_events(service, state_repo)

        return {
            "devices": device_count,
            "events_ingested": total_events + audit_count + patch_count,
            "hosts": len(grouped_events) + len(audit_events) + len(patch_events),
        }

    async def _ingest_audit_events(
        self,
        service: TelemetryIngestionService,
        state_repo: IntegrationStateRepository,
    ) -> tuple[dict[str, list[HostEvent]], int]:
        state = await state_repo.get_state(_AUDIT_SCOPE, self._organization)
        cutoff = (
            state.last_timestamp - _AUDIT_DRIFT
            if state and state.last_timestamp
            else None
        )
        grouped: dict[str, list[HostEvent]] = {}
        latest: datetime | None = None
        async for record in self._client.iter_audit_events(since=cutoff):
            event = self._normalize_audit_event(record)
            if event is None:
                continue
            if cutoff and event.timestamp <= cutoff:
                continue
            grouped.setdefault(event.host_id, []).append(event)
            if latest is None or event.timestamp > latest:
                latest = event.timestamp

        count = 0
        now = datetime.now(UTC)
        for host_id, events in grouped.items():
            hostname = next((e.hostname for e in events if e.hostname), None)
            for chunk in self._chunk_events(events, _EVENT_BATCH_SIZE):
                batch = HostEventBatch(
                    host_id=host_id,
                    hostname=hostname,
                    organization=self._organization,
                    site=self._site,
                    agent_version=self._agent_version,
                    collected_at=now,
                    events=chunk,
                )
                await service.process_host_events(batch)
                count += len(chunk)

        if latest:
            ts = latest if latest.tzinfo else latest.replace(tzinfo=UTC)
            await state_repo.upsert_state(
                integration=_AUDIT_SCOPE,
                scope=self._organization,
                last_timestamp=ts,
                metadata={"last_event_count": count},
            )
            record_integration_sync(
                integration=_AUDIT_SCOPE,
                scope=self._organization,
                last_sync_unix=ts.timestamp(),
                events_ingested=count,
            )

        return grouped, count

    async def _ingest_patch_events(
        self,
        service: TelemetryIngestionService,
        state_repo: IntegrationStateRepository,
    ) -> tuple[dict[str, list[HostEvent]], int]:
        state = await state_repo.get_state(_PATCH_SCOPE, self._organization)
        cutoff = (
            state.last_timestamp - _DETECTIONS_DRIFT
            if state and state.last_timestamp
            else None
        )
        grouped: dict[str, list[HostEvent]] = {}
        latest: datetime | None = None
        async for detection in self._client.iter_patch_updates():
            event = self._normalize_patch_detection(detection)
            if event is None:
                continue
            if cutoff and event.timestamp <= cutoff:
                continue
            grouped.setdefault(event.host_id, []).append(event)
            if latest is None or event.timestamp > latest:
                latest = event.timestamp

        count = 0
        now = datetime.now(UTC)
        for host_id, events in grouped.items():
            hostname = next((e.hostname for e in events if e.hostname), None)
            for chunk in self._chunk_events(events, _EVENT_BATCH_SIZE):
                batch = HostEventBatch(
                    host_id=host_id,
                    hostname=hostname,
                    organization=self._organization,
                    site=self._site,
                    agent_version=self._agent_version,
                    collected_at=now,
                    events=chunk,
                )
                await service.process_host_events(batch)
                count += len(chunk)

        if latest:
            ts = latest if latest.tzinfo else latest.replace(tzinfo=UTC)
            await state_repo.upsert_state(
                integration=_PATCH_SCOPE,
                scope=self._organization,
                last_timestamp=ts,
                metadata={"last_event_count": count},
            )
            record_integration_sync(
                integration=_PATCH_SCOPE,
                scope=self._organization,
                last_sync_unix=ts.timestamp(),
                events_ingested=count,
            )

        return grouped, count

    async def _collect_device_enrichment(
        self,
        device: dict[str, Any],
    ) -> tuple[
        dict[str, Any] | None,
        dict[str, Any] | None,
        list[dict[str, Any]] | None,
        dict[str, Any],
    ]:
        device_id = str(device.get("id") or "")
        compliance: dict[str, Any] | None = None
        smart_groups: list[dict[str, Any]] | None = None
        blueprint_info: dict[str, Any] | None = None
        lifecycle: dict[str, Any] = {}

        if device_id:
            compliance = await self._client.get_device_compliance(device_id)
            smart_groups = await self._client.get_device_smart_groups(device_id)
            details = await self._client.get_device_details(device_id)
            if isinstance(details, dict):
                lifecycle = {
                    "owner_email": (
                        details.get("owner", {}).get("email")
                        if isinstance(details.get("owner"), dict)
                        else None
                    ),
                    "department": details.get("department"),
                    "asset_tag": details.get("asset_tag"),
                    "enrollment": details.get("enrollment_status"),
                    "last_check_in": details.get("last_check_in")
                    or details.get("last_check_in_date"),
                }

        blueprint_id = str(device.get("blueprint_id") or device.get("blueprint") or "")
        if blueprint_id:
            if blueprint_id not in self._blueprint_cache:
                blueprint = await self._client.get_blueprint(blueprint_id)
                if blueprint is not None:
                    self._blueprint_cache[blueprint_id] = blueprint
            blueprint_info = self._blueprint_cache.get(blueprint_id)

        return compliance, blueprint_info, smart_groups, lifecycle

    def _build_host_telemetry(
        self,
        device: dict[str, Any],
        *,
        collected_at: datetime,
        compliance: dict[str, Any] | None = None,
        blueprint: dict[str, Any] | None = None,
        smart_groups: list[dict[str, Any]] | None = None,
        lifecycle: dict[str, Any] | None = None,
    ) -> HostTelemetry | None:
        """Construct ``HostTelemetry`` snapshots from Kandji device payloads."""

        if not isinstance(device, dict):
            return None

        serial = str(device.get("serial_number") or device.get("id") or "").strip()
        if not serial:
            return None

        mdm_raw = device.get("mdm_device")  # type: ignore[union-attr]
        mdm_device: dict[str, Any] = mdm_raw if isinstance(mdm_raw, dict) else {}
        hostname = (
            mdm_device.get("name")
            or device.get("device_name")
            or device.get("description")
            or serial
        )

        os_family = (
            device.get("os") or device.get("device_family") or "unknown"
        ).lower()
        blueprint_id = str(device.get("blueprint_id") or device.get("blueprint") or "")
        tags: dict[str, str] = {}
        if blueprint_id:
            tags["blueprint_id"] = blueprint_id
        if mdm_device.get("enrollment_status") is not None:
            tags["enrollment_status"] = str(mdm_device["enrollment_status"])
        if device.get("asset_tag"):
            tags["asset_tag"] = str(device["asset_tag"])
        if device.get("color"):
            tags["hardware_color"] = str(device["color"])

        compliance_tags = self._extract_compliance_tags(device)
        if compliance_tags:
            tags.update(compliance_tags)

        if lifecycle:
            owner_email = lifecycle.get("owner_email")
            if owner_email:
                tags["owner_email"] = owner_email
            if lifecycle.get("department"):
                tags["department"] = str(lifecycle["department"])
            if lifecycle.get("asset_tag"):
                tags.setdefault("asset_tag", str(lifecycle["asset_tag"]))
            if lifecycle.get("enrollment") is not None:
                tags["enrollment_status"] = str(lifecycle["enrollment"])

        if blueprint:
            name = blueprint.get("name")
            if name:
                tags["blueprint_name"] = str(name)
            owner = blueprint.get("owner")
            if owner:
                tags["blueprint_owner"] = str(owner)

        if smart_groups:
            names = [
                str(group.get("name")) for group in smart_groups if group.get("name")
            ]
            if names:
                tags["smart_groups"] = ",".join(sorted(names))

        health = self._build_health(compliance, collected_at)
        installed_packages = self._extract_installed_packages(device)

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
            installed_packages=installed_packages,
            health=health,
        )

    def _normalize_detection(self, detection: dict[str, Any]) -> HostEvent | None:
        """Represent Kandji vulnerability detections as host events."""

        if not isinstance(detection, dict):
            return None

        serial = str(
            detection.get("device_serial_number") or detection.get("device_id") or ""
        ).strip()
        if not serial:
            return None

        cve = str(detection.get("cve_id") or detection.get("name") or "").strip()
        if not cve:
            return None

        timestamp_raw = detection.get("latest_detection_date") or detection.get(
            "first_detection_date"
        )
        if isinstance(timestamp_raw, str):
            timestamp = date_parser.isoparse(timestamp_raw)
        else:
            timestamp = datetime.now(UTC)

        event_uuid = uuid5(_KANDJI_EVENT_NAMESPACE, f"vuln:{serial}:{cve}")
        severity = (
            str(
                detection.get("cvss_severity") or detection.get("severity") or ""
            ).lower()
            or None
        )

        # Preserve Kandji's raw detection data so analysts can cross-reference
        # affected software, remediation state, and ticket links.
        payload = dict(detection.items())

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

    def _derive_site(self, device: dict[str, Any]) -> str | None:
        """Fallback to Kandji DEP server name when no site override is provided."""

        dep = device.get("dep_account")
        if isinstance(dep, dict):
            name = dep.get("server_name")
            if isinstance(name, str) and name:
                return name
        return self._site

    @staticmethod
    def _chunk_events(events: list[HostEvent], size: int) -> Iterable[list[HostEvent]]:
        for idx in range(0, len(events), size):
            yield events[idx : idx + size]

    @staticmethod
    def _parse_datetime(value: Any) -> datetime | None:
        if isinstance(value, str):
            try:
                parsed = date_parser.isoparse(value)
            except (ValueError, TypeError):
                return None
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=UTC)
            return parsed
        return None

    def _extract_compliance_tags(self, device: dict[str, Any]) -> dict[str, str]:
        tags: dict[str, str] = {}
        compliance_status = device.get("compliance_status") or device.get(
            "device_status"
        )
        if compliance_status not in (None, ""):
            tags["compliance_status"] = str(compliance_status).lower()

        compliance_score = device.get("compliance_score")
        if compliance_score not in (None, ""):
            tags["compliance_score"] = str(compliance_score)

        missing_patches = device.get("missing_patch_count") or device.get(
            "pending_updates"
        )
        if missing_patches not in (None, ""):
            tags["missing_patch_count"] = str(missing_patches)

        return tags

    def _build_health(
        self, compliance: dict[str, Any] | None, collected_at: datetime
    ) -> AgentHealth | None:
        if not compliance:
            return None

        status = str(
            compliance.get("status") or compliance.get("state") or "unknown"
        ).lower()
        issues_field = compliance.get("issues") or compliance.get("failures")
        if isinstance(issues_field, list):
            issues = [str(item) for item in issues_field if item]
        elif isinstance(issues_field, dict):
            issues = [f"{k}:{v}" for k, v in issues_field.items()]
        else:
            issues = []

        last_check = compliance.get("last_check_in") or compliance.get(
            "last_evaluated_at"
        )
        parsed = self._parse_datetime(last_check)
        heartbeat = parsed or collected_at

        normalized_status = {
            "compliant": "healthy",
            "healthy": "healthy",
            "noncompliant": "degraded",
            "not_compliant": "degraded",
        }.get(status, status or "unknown")

        return AgentHealth(
            status=normalized_status, last_heartbeat=heartbeat, issues=issues or None
        )

    def _extract_installed_packages(
        self, device: dict[str, Any]
    ) -> list[SoftwarePackage] | None:
        candidates = [
            device.get("applications"),
            device.get("installed_applications"),
            device.get("apps"),
        ]
        packages: list[SoftwarePackage] = []
        for apps in candidates:
            if not isinstance(apps, list):
                continue
            for entry in apps:
                if not isinstance(entry, dict):
                    continue
                name = (
                    entry.get("name")
                    or entry.get("app_name")
                    or entry.get("bundle_name")
                )
                if not name:
                    continue
                version = (
                    entry.get("version")
                    or entry.get("app_version")
                    or entry.get("bundle_version")
                )
                package = SoftwarePackage(
                    name=str(name),
                    version=str(version) if version else "unknown",
                    source=entry.get("source") or entry.get("bundle_id"),
                    install_time=self._parse_datetime(
                        entry.get("installed_at") or entry.get("install_date")
                    ),
                    vendor=entry.get("vendor") or entry.get("developer"),
                    signature=entry.get("signature"),
                )
                packages.append(package)
        return packages or None

    def _normalize_audit_event(self, record: dict[str, Any]) -> HostEvent | None:
        if not isinstance(record, dict):
            return None

        serial = str(
            record.get("device_serial_number") or record.get("serial_number") or ""
        ).strip()
        if not serial:
            return None

        event_type = str(
            record.get("event_type") or record.get("type") or "audit"
        ).lower()
        status = str(record.get("result") or record.get("status") or "info").lower()
        timestamp = self._parse_datetime(
            record.get("created_at") or record.get("timestamp")
        )
        if timestamp is None:
            timestamp = datetime.now(UTC)

        payload = dict(record.items())

        event_uuid = uuid5(
            _KANDJI_EVENT_NAMESPACE,
            f"audit:{serial}:{payload.get('id') or timestamp.isoformat()}:{event_type}",
        )

        return HostEvent(
            event_id=event_uuid,
            host_id=serial,
            hostname=record.get("device_name"),
            category="kandji.audit",
            event_type=event_type,
            severity=status,
            timestamp=timestamp,
            source="kandji.audit",
            payload=payload,
        )

    def _normalize_patch_detection(
        self, detection: dict[str, Any]
    ) -> HostEvent | None:
        if not isinstance(detection, dict):
            return None

        serial = str(
            detection.get("device_serial_number") or detection.get("device_id") or ""
        ).strip()
        if not serial:
            return None

        app_name = (
            detection.get("application_name")
            or detection.get("name")
            or detection.get("title")
        )
        cve = detection.get("cve") or detection.get("cve_id")
        event_key = app_name or cve or "patch"
        event_type = f"patch:{event_key}".lower()
        severity = str(
            detection.get("severity") or detection.get("priority") or "info"
        ).lower()
        timestamp = self._parse_datetime(
            detection.get("detected_at") or detection.get("updated_at")
        )
        if timestamp is None:
            timestamp = datetime.now(UTC)

        payload = dict(detection.items())

        event_uuid = uuid5(
            _KANDJI_EVENT_NAMESPACE,
            f"patch:{serial}:{event_key}:{timestamp.isoformat()}",
        )

        return HostEvent(
            event_id=event_uuid,
            host_id=serial,
            hostname=detection.get("device_name"),
            category="kandji.patch",
            event_type=event_type,
            severity=severity,
            timestamp=timestamp,
            source="kandji.patch",
            payload=payload,
        )
