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

from cerebro.telemetry.schemas import (
    AgentHealth,
    EndpointThreat,
    HostEvent,
    HostEventBatch,
    HostTelemetry,
    SoftwarePackage,
)
from cerebro.telemetry.services import TelemetryIngestionService
from cerebro.integrations.state import IntegrationStateRepository
from cerebro.metrics.integration_metrics import record_integration_sync

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


@dataclass
class SentinelOneConfig:
    base_url: str
    api_token: str
    organization: str
    site: Optional[str] = None
    agent_version: str = "sentinelone-sync/1.0"
    verify: bool = True
    page_size: int = 200


@dataclass
class _NormalizedThreat:
    host_id: str
    hostname: Optional[str]
    os_family: Optional[str]
    os_version: Optional[str]
    agent_version: Optional[str]
    ip_addresses: List[str]
    threat: EndpointThreat


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
            payload = await self._request_json(
                "/web/api/v2.1/activities", params=params
            )

            records = self._extract_records(payload)
            for record in records:
                yield record

            cursor = self._extract_cursor(payload)
            if not cursor:
                break

    async def iter_threats(
        self,
        *,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
        limit: Optional[int] = None,
    ) -> AsyncIterator[Dict[str, Any]]:
        """Yield threat records using cursor pagination.

        Mirrors :meth:`iter_activities` but targets the ``/threats`` endpoint
        so callers can backfill and incrementally load SentinelOne detections.
        """

        page_size = limit or self._config.page_size
        base_params: Dict[str, Any] = {"limit": page_size}
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

            payload = await self._request_json("/web/api/v2.1/threats", params=params)

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

    async def iter_agents(self, *, limit: int = 200) -> AsyncIterator[Dict[str, Any]]:
        params: Dict[str, Any] = {"limit": limit}
        cursor: Optional[str] = None

        while True:
            if cursor:
                params = {"limit": limit, "cursor": cursor}
            payload = await self._request_json("/web/api/v2.1/agents", params=params)
            agents = payload.get("data") if isinstance(payload, dict) else None
            if isinstance(agents, list):
                for agent in agents:
                    if isinstance(agent, dict):
                        yield agent
            pagination = (
                payload.get("pagination") if isinstance(payload, dict) else None
            )
            cursor = (
                pagination.get("nextCursor") if isinstance(pagination, dict) else None
            )
            if not cursor:
                break

    async def get_policy(self, policy_id: Optional[str]) -> Optional[Dict[str, Any]]:
        if not policy_id:
            return None
        try:
            return await self._request_json(f"/web/api/v2.1/policies/{policy_id}")
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                return None
            raise

    async def get_agent_applications(
        self, agent_id: Optional[str]
    ) -> Optional[List[Dict[str, Any]]]:
        if not agent_id:
            return None
        try:
            payload = await self._request_json(
                f"/web/api/v2.1/agents/{agent_id}/applications"
            )
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code in {403, 404}:
                return None
            raise
        apps = payload.get("data") if isinstance(payload, dict) else None
        if isinstance(apps, list):
            return [app for app in apps if isinstance(app, dict)]
        return None

    async def _request_json(
        self, url: str, *, params: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
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
        self._policy_cache: Dict[str, Dict[str, Any]] = {}

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
        state = await state_repo.get_state(
            "sentinelone.activities", self._config.organization
        )

        effective_since = since
        if state and state.last_timestamp:
            candidate = state.last_timestamp - _STATE_DRIFT
            if effective_since is None or candidate > effective_since:
                effective_since = candidate

        grouped: Dict[str, List[HostEvent]] = defaultdict(list)
        now = datetime.now(timezone.utc)
        latest_timestamp: Optional[datetime] = None

        async for activity in self._client.iter_activities(
            since=effective_since, until=until
        ):
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
            ts = (
                latest_timestamp
                if latest_timestamp.tzinfo
                else latest_timestamp.replace(tzinfo=timezone.utc)
            )
            await state_repo.upsert_state(
                integration="sentinelone.activities",
                scope=self._config.organization,
                last_timestamp=ts,
                metadata={"last_ingested_count": ingested},
            )
            record_integration_sync(
                integration="sentinelone.activities",
                scope=self._config.organization,
                last_sync_unix=ts.timestamp(),
                events_ingested=ingested,
            )
        agent_count = await self._ingest_agents(service)

        threat_summary = await self._ingest_threats(
            service=service,
            state_repo=state_repo,
            since=since,
            until=until,
        )

        return {
            "events_ingested": ingested,
            "hosts": agent_count,
            "event_hosts": len(grouped),
            "threats_ingested": threat_summary.get("threats_ingested", 0),
            "threat_hosts": threat_summary.get("threat_hosts", 0),
        }

    async def _ingest_agents(self, service: TelemetryIngestionService) -> int:
        collected_at = datetime.now(timezone.utc)
        count = 0
        async for agent in self._client.iter_agents():
            policy = await self._get_policy(agent.get("policyId"))
            applications = await self._client.get_agent_applications(agent.get("id"))
            telemetry = self._build_host_telemetry(
                agent, policy, applications, collected_at
            )
            if telemetry is None:
                continue
            await service.process_host(telemetry)
            count += 1
        return count

    async def _ingest_threats(
        self,
        *,
        service: TelemetryIngestionService,
        state_repo: IntegrationStateRepository,
        since: Optional[datetime],
        until: Optional[datetime],
    ) -> Dict[str, Any]:
        state = await state_repo.get_state(
            "sentinelone.threats", self._config.organization
        )
        effective_since = since
        if state and state.last_timestamp:
            candidate = state.last_timestamp - _STATE_DRIFT
            if effective_since is None or candidate > effective_since:
                effective_since = candidate

        grouped: Dict[str, Dict[str, Any]] = {}
        latest_timestamp: Optional[datetime] = None
        processed_records = 0
        active_records = 0

        async for raw in self._client.iter_threats(since=effective_since, until=until):
            normalized = self._normalize_threat(raw)
            if normalized is None:
                continue

            processed_records += 1

            threat_ts = normalized.threat.detected_at
            if latest_timestamp is None or threat_ts > latest_timestamp:
                latest_timestamp = threat_ts

            if not self._is_active_threat(normalized.threat):
                continue

            entry = grouped.setdefault(
                normalized.host_id,
                {
                    "hostname": normalized.hostname,
                    "os_family": normalized.os_family,
                    "os_version": normalized.os_version,
                    "agent_version": normalized.agent_version,
                    "ip_addresses": set(normalized.ip_addresses),
                    "threats": [],
                },
            )

            if normalized.hostname and not entry.get("hostname"):
                entry["hostname"] = normalized.hostname
            if normalized.os_family and not entry.get("os_family"):
                entry["os_family"] = normalized.os_family
            if normalized.os_version and not entry.get("os_version"):
                entry["os_version"] = normalized.os_version
            if normalized.agent_version and not entry.get("agent_version"):
                entry["agent_version"] = normalized.agent_version
            entry["ip_addresses"].update(normalized.ip_addresses)
            entry["threats"].append(normalized.threat)
            active_records += 1

        hosts_processed = 0
        for host_id, entry in grouped.items():
            threats: List[EndpointThreat] = entry.get("threats", [])
            if not threats:
                continue

            collected_at = max(
                (threat.detected_at for threat in threats),
                default=datetime.now(timezone.utc),
            )
            if collected_at.tzinfo is None:
                collected_at = collected_at.replace(tzinfo=timezone.utc)

            ip_addresses = sorted(entry.get("ip_addresses", set()))

            telemetry = HostTelemetry(
                organization=self._config.organization,
                site=self._config.site,
                host_id=host_id,
                hostname=entry.get("hostname") or host_id,
                serial_number=host_id,
                agent_version=entry.get("agent_version") or self._config.agent_version,
                os_family=(entry.get("os_family") or "unknown"),
                os_version=entry.get("os_version"),
                kernel_version=None,
                architecture=None,
                collected_at=collected_at,
                ip_addresses=ip_addresses,
                mac_addresses=None,
                logged_in_users=None,
                tags=None,
                health=None,
                processes=[],
                network_connections=None,
                installed_packages=None,
                security_events=None,
                configuration_drift=None,
                threats=threats,
            )

            await service.process_host(telemetry)
            hosts_processed += 1

        if latest_timestamp:
            ts = (
                latest_timestamp
                if latest_timestamp.tzinfo
                else latest_timestamp.replace(tzinfo=timezone.utc)
            )
            await state_repo.upsert_state(
                integration="sentinelone.threats",
                scope=self._config.organization,
                last_timestamp=ts,
                metadata={
                    "last_ingested_count": processed_records,
                    "active_count": active_records,
                },
            )
            record_integration_sync(
                integration="sentinelone.threats",
                scope=self._config.organization,
                last_sync_unix=ts.timestamp(),
                events_ingested=processed_records,
            )

        return {
            "threats_ingested": active_records,
            "threat_hosts": hosts_processed,
        }

    def _normalize_threat(self, threat: Dict[str, Any]) -> Optional[_NormalizedThreat]:
        if not isinstance(threat, dict):
            return None

        threat_info = threat.get("threatInfo")
        info: Dict[str, Any] = threat_info if isinstance(threat_info, dict) else {}

        agent_detection = threat.get("agentDetectionInfo")
        detection: Dict[str, Any] = agent_detection if isinstance(agent_detection, dict) else {}

        agent_realtime = threat.get("agentRealtimeInfo")
        realtime: Dict[str, Any] = agent_realtime if isinstance(agent_realtime, dict) else {}

        mitigation_status = threat.get("mitigationStatus")
        mitigation: Dict[str, Any] = mitigation_status if isinstance(mitigation_status, dict) else {}

        threat_id = info.get("threatId") or threat.get("id") or threat.get("threatId")
        if not threat_id:
            return None
        threat_id = str(threat_id)

        host_id = (
            detection.get("agentUuid")
            or detection.get("agentId")
            or threat.get("agentId")
            or realtime.get("agentUuid")
            or realtime.get("agentId")
            or info.get("agentId")
            or detection.get("deviceId")
            or threat.get("deviceId")
        )
        if not host_id:
            return None
        host_id = str(host_id)

        hostname = (
            detection.get("agentComputerName")
            or detection.get("agentHostname")
            or detection.get("computerName")
            or realtime.get("agentComputerName")
            or realtime.get("computerName")
            or info.get("agentComputerName")
            or info.get("computerName")
        )
        if hostname is not None:
            hostname = str(hostname)

        os_family = (
            realtime.get("agentOsName")
            or realtime.get("agentOsType")
            or detection.get("agentOsName")
            or detection.get("agentOsType")
        )
        if os_family is not None:
            os_family = str(os_family).lower()

        os_version = (
            realtime.get("agentOsRevision")
            or detection.get("agentOsRevision")
            or detection.get("agentVersion")
        )
        if os_version is not None:
            os_version = str(os_version)

        agent_version = detection.get("agentVersion") or realtime.get("agentVersion")
        if agent_version is not None:
            agent_version = str(agent_version)

        ip_addresses: set[str] = set()
        for key in ("agentIpV4", "agentIpv4", "agentIpV6", "agentIpv6", "externalIp"):
            value = detection.get(key)
            if value:
                ip_addresses.update(self._ensure_list(value))
        for key in ("externalIp", "lastExternalIp"):
            value = realtime.get(key)
            if value:
                ip_addresses.update(self._ensure_list(value))

        interfaces = realtime.get("networkInterfaces")
        if isinstance(interfaces, list):
            for iface in interfaces:
                if not isinstance(iface, dict):
                    continue
                for key in ("inet", "inet6", "ip", "addresses"):
                    value = iface.get(key)
                    if value:
                        ip_addresses.update(self._ensure_list(value))

        detected_at = (
            self._parse_datetime(info.get("identifiedAt"))
            or self._parse_datetime(info.get("createdAt"))
            or self._parse_datetime(threat.get("createdAt"))
            or datetime.now(timezone.utc)
        )
        updated_at = self._parse_datetime(
            info.get("updatedAt") or threat.get("updatedAt")
        )
        resolved_at = self._parse_datetime(mitigation.get("mitigationEndedAt"))

        categories, tactics, techniques, indicator_text, c2_domains, source_ips = (
            self._extract_indicator_details(threat)
        )

        classification = info.get("classification")
        confidence = info.get("confidenceLevel")
        severity = self._map_threat_severity(classification, confidence, categories)

        status = (
            info.get("incidentStatus") or info.get("status") or threat.get("status")
        )
        mitigation_status = (
            mitigation.get("status")
            or info.get("mitigationStatus")
            or info.get("mitigationStatusDescription")
        )

        endpoint_threat = EndpointThreat(
            threat_id=threat_id,
            name=str(info.get("threatName") or info.get("displayName") or threat_id),
            classification=str(classification) if classification is not None else None,
            confidence=str(confidence) if confidence is not None else None,
            severity=severity,
            status=str(status) if status is not None else None,
            mitigation_status=(
                str(mitigation_status) if mitigation_status is not None else None
            ),
            analyst_verdict=(
                str(info.get("analystVerdict")) if info.get("analystVerdict") else None
            ),
            initiated_by=(
                str(info.get("initiatedBy")) if info.get("initiatedBy") else None
            ),
            initiating_user=(
                str(info.get("initiatingUsername") or info.get("initiatingUserId"))
                if (info.get("initiatingUsername") or info.get("initiatingUserId"))
                else None
            ),
            process_user=(
                str(info.get("processUser")) if info.get("processUser") else None
            ),
            file_path=str(info.get("filePath")) if info.get("filePath") else None,
            md5=str(info.get("md5")) if info.get("md5") else None,
            sha1=str(info.get("sha1")) if info.get("sha1") else None,
            sha256=str(info.get("sha256")) if info.get("sha256") else None,
            storyline=str(info.get("storyline")) if info.get("storyline") else None,
            detected_at=detected_at,
            updated_at=updated_at,
            resolved_at=resolved_at,
            reboot_required=(
                bool(info.get("rebootRequired"))
                if info.get("rebootRequired") is not None
                else None
            ),
            categories=sorted(categories) or None,
            mitre_tactics=sorted(tactics) or None,
            mitre_techniques=sorted(techniques) or None,
            indicators=sorted(indicator_text) or None,
            c2_domains=sorted(c2_domains) or None,
            source_ips=sorted(source_ips) or None,
            quarantine_status=(
                str(mitigation.get("action")) if mitigation.get("action") else None
            ),
        )

        return _NormalizedThreat(
            host_id=host_id,
            hostname=hostname,
            os_family=os_family,
            os_version=os_version,
            agent_version=agent_version,
            ip_addresses=list(ip_addresses),
            threat=endpoint_threat,
        )

    @staticmethod
    def _parse_datetime(value: Any) -> Optional[datetime]:
        if isinstance(value, datetime):
            return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        if isinstance(value, str):
            try:
                parsed = date_parser.isoparse(value)
            except (ValueError, TypeError):
                return None
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        return None

    @staticmethod
    def _ensure_list(value: Any) -> List[str]:
        if value is None:
            return []
        if isinstance(value, (list, tuple, set)):
            list_result: List[str] = []
            for item in value:
                list_result.extend(SentinelOneIngestion._ensure_list(item))
            return list_result
        if isinstance(value, dict):
            dict_result: List[str] = []
            for item in value.values():
                dict_result.extend(SentinelOneIngestion._ensure_list(item))
            return dict_result
        return [str(value)] if value not in ("",) else []

    def _extract_indicator_details(
        self,
        threat: Dict[str, Any],
    ) -> tuple[set[str], set[str], set[str], set[str], set[str], set[str]]:
        categories: set[str] = set()
        tactics: set[str] = set()
        techniques: set[str] = set()
        indicator_text: set[str] = set()
        c2_domains: set[str] = set()
        source_ips: set[str] = set()

        _threat_info = threat.get("threatInfo")
        threat_info: Dict[str, Any] = _threat_info if isinstance(_threat_info, dict) else {}
        indicators = threat.get("indicators")
        if isinstance(indicators, dict):
            categories.update(
                self._ensure_list(
                    indicators.get("category") or indicators.get("categories")
                )
            )
            indicator_text.update(
                self._ensure_list(
                    indicators.get("description") or indicators.get("descriptions")
                )
            )
            self._extend_tactics(indicators.get("tactics"), tactics, techniques)
        elif isinstance(indicators, list):
            for item in indicators:
                if not isinstance(item, dict):
                    continue
                categories.update(self._ensure_list(item.get("category")))
                indicator_text.update(
                    self._ensure_list(item.get("description") or item.get("title"))
                )
                self._extend_tactics(item.get("tactics"), tactics, techniques)

        detection_engines = threat.get("detectionEngines")
        if detection_engines is None and isinstance(threat_info, dict):
            detection_engines = threat_info.get("detectionEngines")
        if isinstance(detection_engines, dict):
            indicator_text.update(self._ensure_list(detection_engines.get("title")))
        elif isinstance(detection_engines, list):
            for engine in detection_engines:
                if isinstance(engine, dict):
                    indicator_text.update(self._ensure_list(engine.get("title")))

        for key in ("sourceIp", "sourceIP"):
            value = threat_info.get(key)
            if value:
                source_ips.update(self._ensure_list(value))

        network_indicators = threat.get("networkIndicators")
        if isinstance(network_indicators, list):
            for item in network_indicators:
                if not isinstance(item, dict):
                    continue
                for key in (
                    "domain",
                    "url",
                    "address",
                    "destination",
                    "c2Domain",
                    "commandAndControlDomain",
                ):
                    value = item.get(key)
                    if value:
                        c2_domains.update(self._ensure_list(value))
                for key in ("sourceIp", "srcIp", "ip"):
                    value = item.get(key)
                    if value:
                        source_ips.update(self._ensure_list(value))

        connection = threat.get("connectionInfo")
        if isinstance(connection, dict):
            for key in ("sourceIp", "srcIp"):
                value = connection.get(key)
                if value:
                    source_ips.update(self._ensure_list(value))

        return categories, tactics, techniques, indicator_text, c2_domains, source_ips

    def _extend_tactics(
        self,
        value: Any,
        tactics: set[str],
        techniques: set[str],
    ) -> None:
        if value is None:
            return
        if isinstance(value, dict):
            tactics.update(self._ensure_list(value.get("name") or value.get("names")))
            self._extend_tactics(value.get("techniques"), tactics, techniques)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    tactics.update(
                        self._ensure_list(item.get("name") or item.get("names"))
                    )
                    techniques.update(self._ensure_list(item.get("id")))
                    self._extend_tactics(item.get("techniques"), tactics, techniques)
                else:
                    tactics.update(self._ensure_list(item))
        else:
            tactics.update(self._ensure_list(value))

        # Techniques may be provided as list/dict nested within value
        if isinstance(value, dict):
            techniques.update(
                self._ensure_list(
                    value.get("name") if value.get("type") == "technique" else None
                )
            )

    def _map_threat_severity(
        self,
        classification: Optional[str],
        confidence: Optional[str],
        categories: Iterable[str],
    ) -> str:
        severity = "medium"

        classification_text = (classification or "").lower()
        category_tokens = {token.lower() for token in categories if token}

        critical_indicators = {"ransom", "ransomware", "wiper", "bootkit", "rootkit"}
        high_indicators = {"malware", "trojan", "worm", "backdoor", "botnet", "exploit"}

        if any(token in classification_text for token in critical_indicators):
            severity = "critical"
        elif any(token in classification_text for token in high_indicators):
            severity = "high"
        elif category_tokens & {
            "command and control",
            "c2",
            "exfiltration",
            "lateral movement",
        }:
            severity = "high"
        elif (
            "pua" in classification_text
            or "grayware" in classification_text
            or "adware" in classification_text
        ):
            severity = "medium"
        elif classification_text:
            severity = "medium"

        if confidence:
            confidence_level = confidence.lower()
            if confidence_level == "low" and severity in {"medium", "low"}:
                severity = "low"
            elif confidence_level == "medium" and severity == "low":
                severity = "medium"
            elif confidence_level == "high" and severity == "medium":
                severity = "high"

        return severity

    @staticmethod
    def _is_active_threat(threat: EndpointThreat) -> bool:
        status = (threat.status or "").lower()
        mitigation = (threat.mitigation_status or "").lower()
        verdict = (threat.analyst_verdict or "").lower()

        resolved_tokens = {
            "resolved",
            "mitigated",
            "dismissed",
            "benign",
            "suspicious",
            "false_positive",
        }

        if threat.resolved_at is not None:
            return False
        if any(token in status for token in resolved_tokens if token):
            return False
        if any(token in mitigation for token in resolved_tokens if token):
            return False
        if verdict in {"benign", "false_positive", "expected_behavior"}:
            return False
        return True

    async def _get_policy(self, policy_id: Optional[str]) -> Optional[Dict[str, Any]]:
        if not policy_id:
            return None
        cached = self._policy_cache.get(policy_id)
        if cached is not None:
            return cached
        policy = await self._client.get_policy(policy_id)
        if policy is not None:
            self._policy_cache[policy_id] = policy
        return policy

    def _build_host_telemetry(
        self,
        agent: Dict[str, Any],
        policy: Optional[Dict[str, Any]],
        applications: Optional[List[Dict[str, Any]]],
        collected_at: datetime,
    ) -> Optional[HostTelemetry]:
        agent_id = str(agent.get("id") or agent.get("agentId") or "").strip()
        if not agent_id:
            return None

        uuid = str(agent.get("uuid") or agent_id).strip()
        hostname = (
            agent.get("computerName")
            or agent.get("machineName")
            or agent.get("agentName")
            or uuid
        )
        os_family = (
            agent.get("osType") or agent.get("operatingSystem") or "unknown"
        ).lower()

        tags: Dict[str, str] = {}
        if agent.get("siteName"):
            tags["site"] = str(agent["siteName"])
        if agent.get("groupName"):
            tags["group"] = str(agent["groupName"])
        if agent.get("accountName"):
            tags["account"] = str(agent["accountName"])
        if agent.get("isEligibleForMitigation") is not None:
            tags["eligible_for_mitigation"] = str(
                agent.get("isEligibleForMitigation")
            ).lower()
        if policy:
            if policy.get("name"):
                tags["policy_name"] = str(policy["name"])
            if policy.get("policyType"):
                tags["policy_type"] = str(policy["policyType"])

        installed_packages = self._build_packages(applications)
        health = self._build_health(agent, collected_at)

        return HostTelemetry(
            organization=self._config.organization,
            site=self._config.site,
            host_id=uuid,
            hostname=str(hostname),
            serial_number=uuid,
            agent_version=self._config.agent_version,
            os_family=os_family,
            os_version=agent.get("osVersion") or agent.get("agentVersion"),
            kernel_version=None,
            architecture=agent.get("cpuType"),
            collected_at=collected_at,
            ip_addresses=self._collect_ips(agent),
            mac_addresses=None,
            logged_in_users=None,
            tags=tags or None,
            installed_packages=installed_packages,
            health=health,
        )

    @staticmethod
    def _collect_ips(agent: Dict[str, Any]) -> List[str]:
        ips: List[str] = []
        interfaces = agent.get("networkInterfaces")
        if isinstance(interfaces, list):
            for iface in interfaces:
                if isinstance(iface, dict):
                    for key in ("ipAddress", "ipV4", "ipV6"):
                        value = iface.get(key)
                        if value:
                            ips.append(str(value))
        else:
            for key in ("externalIp", "lastExternalIp"):
                if agent.get(key):
                    ips.append(str(agent[key]))
        return ips

    @staticmethod
    def _build_packages(
        applications: Optional[List[Dict[str, Any]]],
    ) -> Optional[List[SoftwarePackage]]:
        if not applications:
            return None
        packages: List[SoftwarePackage] = []
        for app in applications:
            name = app.get("name") or app.get("productName")
            if not name:
                continue
            packages.append(
                SoftwarePackage(
                    name=str(name),
                    version=str(
                        app.get("version") or app.get("productVersion") or "unknown"
                    ),
                    source=app.get("publisher"),
                    install_time=None,
                    vendor=app.get("publisher"),
                    signature=None,
                )
            )
        return packages or None

    @staticmethod
    def _build_health(agent: Dict[str, Any], collected_at: datetime) -> AgentHealth:
        threat_count = int(agent.get("threatCount") or agent.get("activeThreats") or 0)
        mitigation_mode = str(agent.get("mitigationMode", "")).lower()
        status = "healthy"
        issues: List[str] = []
        if threat_count > 0:
            status = "degraded"
            issues.append(f"active_threats:{threat_count}")
        if mitigation_mode not in {"protect", "detect"}:
            issues.append("mitigation_inactive")
            status = "degraded"
        last_seen = agent.get("lastActiveDate") or agent.get("lastSeen")
        parsed = None
        if isinstance(last_seen, str):
            try:
                parsed = date_parser.isoparse(last_seen)
            except (ValueError, TypeError):
                parsed = None
        if parsed is None:
            parsed = collected_at
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return AgentHealth(status=status, last_heartbeat=parsed, issues=issues or None)

    def _normalize_activity(self, activity: Dict[str, Any]) -> Optional[HostEvent]:
        """Translate raw SentinelOne activity JSON into a ``HostEvent`` model.

        The activity schema differs across environments and product tiers.  We
        defensively look for identifiers under both top-level and nested ``data``
        payloads.  When essential fields are missing (no activity ID or agent)
        we drop the event to avoid inserting ambiguous host records.
        """

        if not isinstance(activity, dict):
            return None

        activity_id = str(
            activity.get("id") or activity.get("activityUuid") or ""
        ).strip()
        if not activity_id:
            return None

        _data = activity.get("data")
        data: Dict[str, Any] = _data if isinstance(_data, dict) else {}
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
        event_raw = (
            activity.get("activityType") or activity.get("activity_name") or "activity"
        )
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
