"""Service layer for telemetry ingestion flows."""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Optional, List
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from cerebro.core.models import (
    Account,
    ConfigSnapshot,
    Finding,
    FrontendObservationEvent,
    Organization,
    Resource,
    Rule,
)
from cerebro.telemetry.models import (
    ArtifactPack,
    ArtifactPackTask,
    HostContext,
    HostTelemetryEvent,
    RepositoryContext,
    RuntimeContext,
    TelemetryResult,
)
from cerebro.telemetry.schemas import (
    ArtifactPackDefinition,
    ArtifactTaskDefinition,
    ComplianceEvidence,
    DependencyGraph,
    DependencyScan,
    DependencyVulnerability,
    FrontendObservationTelemetry,
    HostEventBatch,
    RepositoryTelemetry,
    RuntimeTelemetry,
    SecretsScanResult,
    SecurityEvent,
    ConfigurationDrift,
    HostTelemetry,
)

logger = logging.getLogger(__name__)


class TelemetryProcessingError(RuntimeError):
    """Raised when telemetry ingestion fails."""


class TelemetryIngestionService:
    """Orchestrates telemetry ingestion and finding generation."""

    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    # ---------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def process_repository(self, payload: RepositoryTelemetry) -> Dict[str, Any]:
        """Ingest repository telemetry and create findings."""

        logger.info("Received repository telemetry", repository=payload.repository)

        try:
            context = await self._ensure_repository_context(payload.repository)
            findings = []

            if payload.secrets_scan:
                for secret in payload.secrets_scan:
                    finding = await self._create_secret_finding(secret, payload, context)
                    if finding:
                        findings.append(finding)

            if payload.dependencies:
                vulnerabilities = self._extract_vulnerabilities(payload.dependencies)
                for vuln in vulnerabilities:
                    finding = await self._create_dependency_finding(vuln, payload, context)
                    if finding:
                        findings.append(finding)

            if payload.sbom:
                await self._store_sbom(context.resource_id, payload.sbom)

            await self.db.commit()

            logger.info(
                "Processed repository telemetry",
                repository=payload.repository,
                findings_created=len(findings),
            )

            return {
                "status": "processed",
                "repository": payload.repository,
                "findings_created": len(findings),
                "finding_ids": [str(fid) for fid in findings],
            }
        except Exception as exc:  # pragma: no cover - rewrap unexpected errors
            await self.db.rollback()
            logger.exception("Repository telemetry processing failed", exc_info=exc)
            raise TelemetryProcessingError(str(exc)) from exc

    async def process_runtime(self, payload: RuntimeTelemetry) -> Dict[str, Any]:
        """Ingest runtime telemetry and create findings."""

        logger.info(
            "Received runtime telemetry", service=payload.service, environment=payload.environment
        )

        try:
            context = await self._ensure_runtime_context(payload)
            findings: list[UUID] = []

            if payload.security_events:
                for event in payload.security_events:
                    if not self._is_suspicious_event(event):
                        continue
                    finding = await self._create_runtime_event_finding(event, payload, context)
                    if finding:
                        findings.append(finding)

            if payload.configuration_drift:
                for drift in payload.configuration_drift:
                    finding = await self._create_config_drift_finding(drift, payload, context)
                    if finding:
                        findings.append(finding)

            await self.db.commit()

            logger.info(
                "Processed runtime telemetry",
                service=payload.service,
                environment=payload.environment,
                findings_created=len(findings),
            )

            return {
                "status": "processed",
                "service": payload.service,
                "environment": payload.environment,
                "findings_created": len(findings),
            }
        except Exception as exc:  # pragma: no cover
            await self.db.rollback()
            logger.exception("Runtime telemetry processing failed", exc_info=exc)
            raise TelemetryProcessingError(str(exc)) from exc

    async def process_frontend_observation(
        self,
        org_id: UUID,
        user_id: Optional[UUID],
        payload: FrontendObservationTelemetry,
    ) -> Dict[str, Any]:
        """Persist a frontend observation emitted by an analyst workflow."""

        if org_id is None:
            raise TelemetryProcessingError("Frontend observation missing organization context")

        occurred_at = payload.occurred_at
        if occurred_at is None:
            occurred_at = datetime.now(timezone.utc)
        elif occurred_at.tzinfo is None:
            occurred_at = occurred_at.replace(tzinfo=timezone.utc)

        event = FrontendObservationEvent(
            org_id=org_id,
            user_id=user_id,
            agent_session_id=payload.agent_session_id,
            event_type=payload.event_type,
            component=payload.component,
            context_data=payload.context or {},
            event_metadata=payload.metadata or {},
            occurred_at=occurred_at,
        )

        self.db.add(event)

        try:
            await self.db.commit()
        except Exception as exc:  # pragma: no cover
            await self.db.rollback()
            logger.exception("Frontend observation ingestion failed", exc_info=exc)
            raise TelemetryProcessingError(str(exc)) from exc

        return {
            "status": "recorded",
            "event_id": str(event.event_id),
        }

    async def process_host(self, payload: HostTelemetry) -> Dict[str, Any]:
        """Ingest endpoint telemetry emitted by the desktop agent."""

        logger.info(
            "Received host telemetry",
            extra={
                "host_id": payload.host_id,
                "hostname": payload.hostname,
                "org": payload.organization,
            },
        )

        collected_at = payload.collected_at
        if collected_at.tzinfo is None:
            collected_at = collected_at.replace(tzinfo=timezone.utc)

        try:
            context = await self._ensure_host_context(payload)
            snapshot_id = await self._persist_host_snapshot(context, payload, collected_at)
            findings: list[UUID] = []

            if payload.security_events:
                for event in payload.security_events:
                    if not self._is_suspicious_event(event):
                        continue
                    finding = await self._create_host_security_event_finding(
                        event,
                        payload,
                        context,
                    )
                    if finding:
                        findings.append(finding)

            if payload.configuration_drift:
                for drift in payload.configuration_drift:
                    finding = await self._create_host_drift_finding(
                        drift,
                        payload,
                        context,
                    )
                    if finding:
                        findings.append(finding)

            await self.db.commit()

            return {
                "status": "processed",
                "host_id": payload.host_id,
                "hostname": payload.hostname,
                "snapshot_id": str(snapshot_id) if snapshot_id else None,
                "findings_created": len(findings),
            }
        except Exception as exc:  # pragma: no cover
            await self.db.rollback()
            logger.exception("Host telemetry processing failed", exc_info=exc)
            raise TelemetryProcessingError(str(exc)) from exc

    async def process_host_events(self, payload: HostEventBatch) -> Dict[str, Any]:
        """Ingest incremental host events emitted by the desktop agent."""

        logger.info(
            "Received host events",
            extra={
                "host_id": payload.host_id,
                "hostname": payload.hostname,
                "org": payload.organization,
                "count": len(payload.events),
            },
        )

        if not payload.events:
            return {
                "status": "processed",
                "host_id": payload.host_id,
                "events_ingested": 0,
            }

        try:
            context = await self._ensure_host_context_from_values(
                host_id=payload.host_id,
                hostname=payload.hostname,
                organization=payload.organization,
                site=payload.site,
            )

            ingested = 0

            for event in payload.events:
                observed_at = event.timestamp
                if observed_at.tzinfo is None:
                    observed_at = observed_at.replace(tzinfo=timezone.utc)

                record = HostTelemetryEvent(
                    org_id=context.org_id,
                    account_id=context.account_id,
                    resource_id=context.resource_id,
                    host_id=context.host_id,
                    hostname=event.hostname or context.hostname,
                    category=event.category,
                    event_type=event.event_type,
                    severity=event.severity,
                    process_id=event.process_id,
                    parent_pid=event.parent_pid,
                    user=event.user,
                    command_line=event.command_line,
                    source=event.source,
                    agent_version=payload.agent_version,
                    payload=event.payload,
                    observed_at=observed_at,
                )

                if event.event_id:
                    record.event_id = event.event_id

                self.db.add(record)
                ingested += 1

            await self.db.commit()

            return {
                "status": "processed",
                "host_id": payload.host_id,
                "events_ingested": ingested,
            }
        except Exception as exc:  # pragma: no cover
            await self.db.rollback()
            logger.exception("Host events processing failed", exc_info=exc)
            raise TelemetryProcessingError(str(exc)) from exc

    async def list_host_packs(
        self,
        *,
        host_id: str,
        hostname: Optional[str],
        organization: Optional[str],
        site: Optional[str],
        tags: Dict[str, str],
    ) -> List[ArtifactPackDefinition]:
        """Return artifact packs applicable to the specified host."""

        logger.info(
            "Listing host packs",
            extra={
                "host_id": host_id,
                "hostname": hostname,
                "organization": organization,
                "site": site,
            },
        )

        context = await self._ensure_host_context_from_values(
            host_id=host_id,
            hostname=hostname,
            organization=organization,
            site=site,
        )

        stmt = (
            select(ArtifactPack)
            .where(ArtifactPack.org_id == context.org_id)
            .options(selectinload(ArtifactPack.tasks))
        )

        result = await self.db.execute(stmt)
        packs = result.scalars().unique().all()

        eligible: List[ArtifactPackDefinition] = []
        for pack in packs:
            if not self._pack_matches(pack, context, tags):
                continue
            eligible.append(self._serialize_pack(pack))

        return eligible

    async def process_compliance_evidence(self, payload: ComplianceEvidence) -> Dict[str, Any]:
        """Persist compliance evidence metadata."""

        logger.info(
            "Received compliance evidence",
            repository=payload.repository,
            framework=payload.framework,
        )

        try:
            context = await self._ensure_repository_context(payload.repository)

            # TODO: persist evidence payload once data model is available.
            logger.info(
                "Compliance evidence recorded",
                framework=payload.framework,
                controls=list(payload.evidence.keys()),
            )

            await self.db.commit()

            return {
                "status": "processed",
                "repository": payload.repository,
                "framework": payload.framework,
                "controls_evidenced": len(payload.evidence),
            }
        except Exception as exc:  # pragma: no cover
            await self.db.rollback()
            logger.exception("Compliance evidence ingestion failed", exc_info=exc)
            raise TelemetryProcessingError(str(exc)) from exc

    async def process_dependency_graph(self, payload: DependencyGraph) -> Dict[str, Any]:
        """Ingest dependency graph telemetry."""

        logger.info("Received dependency graph", repository=payload.repository)

        try:
            context = await self._ensure_repository_context(payload.repository)
            findings: list[UUID] = []

            for vuln in payload.vulnerabilities:
                finding = await self._create_dependency_finding(
                    vuln,
                    {
                        "repository": payload.repository,
                        "timestamp": payload.timestamp,
                    },
                    context,
                )
                if finding:
                    findings.append(finding)

            # TODO: persist dependency graph, malicious package detections, license checks.

            await self.db.commit()

            logger.info(
                "Processed dependency graph",
                repository=payload.repository,
                findings_created=len(findings),
            )

            return {
                "status": "processed",
                "repository": payload.repository,
                "vulnerabilities_found": len(payload.vulnerabilities),
                "findings_created": len(findings),
            }
        except Exception as exc:  # pragma: no cover
            await self.db.rollback()
            logger.exception("Dependency graph ingestion failed", exc_info=exc)
            raise TelemetryProcessingError(str(exc)) from exc

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _ensure_repository_context(self, repository: str) -> RepositoryContext:
        org_name = repository.split("/")[0]
        org = await self._get_or_create_org(org_name)
        account = await self._get_or_create_account(org.org_id, "github", org_name)
        resource = await self._get_or_create_resource(
            account.account_id,
            "github.repository",
            repository,
            repository,
        )

        return RepositoryContext(
            org_id=org.org_id,
            org_name=org.name,
            account_id=account.account_id,
            account_provider=account.provider,
            resource_id=resource.resource_id,
            resource_type=resource.resource_type,
            resource_external_id=resource.external_id,
            resource_name=resource.name,
            received_at=datetime.utcnow(),
            metadata={},
        )

    async def _ensure_runtime_context(self, payload: RuntimeTelemetry) -> RuntimeContext:
        org = await self._get_or_create_org("runtime-services")
        account = await self._get_or_create_account(org.org_id, "runtime", "runtime-services")
        identifier = f"{payload.service}-{payload.environment}"
        resource = await self._get_or_create_resource(
            account.account_id,
            "service.runtime",
            identifier,
            payload.service,
        )

        return RuntimeContext(
            org_id=org.org_id,
            account_id=account.account_id,
            resource_id=resource.resource_id,
            service_name=payload.service,
            environment=payload.environment,
            received_at=datetime.utcnow(),
            metadata={},
        )

    async def _ensure_host_context(self, payload: HostTelemetry) -> HostContext:
        context = await self._ensure_host_context_from_values(
            host_id=payload.host_id,
            hostname=payload.hostname,
            organization=payload.organization,
            site=payload.site,
        )
        return context

    async def _ensure_host_context_from_values(
        self,
        *,
        host_id: str,
        hostname: Optional[str],
        organization: Optional[str],
        site: Optional[str],
    ) -> HostContext:
        org_name = organization or "endpoint-devices"
        org = await self._get_or_create_org(org_name)
        account = await self._get_or_create_account(org.org_id, "endpoint", org_name)
        resource = await self._get_or_create_resource(
            account.account_id,
            "endpoint.device",
            host_id,
            hostname or host_id,
        )

        metadata: Dict[str, Any] = {}
        if site:
            metadata["site"] = site

        return HostContext(
            org_id=org.org_id,
            account_id=account.account_id,
            resource_id=resource.resource_id,
            host_id=host_id,
            hostname=hostname or host_id,
            received_at=datetime.utcnow(),
            metadata=metadata,
        )

    def _pack_matches(
        self,
        pack: ArtifactPack,
        context: HostContext,
        tags: Dict[str, str],
    ) -> bool:
        selectors = pack.selectors or {}

        if not selectors:
            return True

        site_selector = selectors.get("site")
        if site_selector:
            host_site = context.metadata.get("site")
            if isinstance(site_selector, (list, tuple, set)):
                if host_site not in site_selector:
                    return False
            elif host_site != site_selector:
                return False

        tag_selector = selectors.get("tags")
        if isinstance(tag_selector, dict):
            for key, expected in tag_selector.items():
                if tags.get(key) != expected:
                    return False

        return True

    def _serialize_pack(self, pack: ArtifactPack) -> ArtifactPackDefinition:
        tasks = []
        for task in sorted(pack.tasks, key=lambda item: item.name):
            tasks.append(
                ArtifactTaskDefinition(
                    task_id=task.task_id,
                    name=task.name,
                    collector=task.collector,
                    interval_seconds=task.interval_seconds,
                    tags=task.tags or None,
                    config=task.config or None,
                    discovery=task.discovery or None,
                    parameters=task.parameters or None,
                    parameter_values=task.parameter_values or None,
                    resources=task.resources or None,
                    tools=task.tools or None,
                )
            )

        selectors = pack.selectors or None

        return ArtifactPackDefinition(
            pack_id=pack.pack_id,
            name=pack.name,
            version=pack.version,
            description=pack.description,
            selectors=selectors,
            tasks=tasks,
        )

    async def _get_or_create_org(self, name: str) -> Organization:
        stmt = select(Organization).where(Organization.name == name)
        org = await self.db.scalar(stmt)
        if org is None:
            org = Organization(name=name)
            self.db.add(org)
            await self.db.flush()
            logger.info("Created organization %s", name)
        return org

    async def _get_or_create_account(
        self,
        org_id: UUID,
        provider: str,
        external_id: str,
    ) -> Account:
        stmt = select(Account).where(
            Account.org_id == org_id,
            Account.provider == provider,
            Account.external_id == external_id,
        )
        account = await self.db.scalar(stmt)
        if account is None:
            account = Account(
                org_id=org_id,
                provider=provider,
                external_id=external_id,
                display_name=external_id,
            )
            self.db.add(account)
            await self.db.flush()
            logger.info(
                "Created account provider=%s external_id=%s",
                provider,
                external_id,
            )
        return account

    async def _get_or_create_resource(
        self,
        account_id: UUID,
        resource_type: str,
        external_id: str,
        name: str,
    ) -> Resource:
        stmt = select(Resource).where(
            Resource.account_id == account_id,
            Resource.external_id == external_id,
        )
        resource = await self.db.scalar(stmt)
        if resource is None:
            resource = Resource(
                account_id=account_id,
                provider=resource_type.split(".")[0],
                resource_type=resource_type,
                external_id=external_id,
                name=name,
            )
            self.db.add(resource)
            await self.db.flush()
            logger.info(
                "Created resource type=%s external_id=%s",
                resource_type,
                external_id,
            )
        return resource

    async def _persist_host_snapshot(
        self,
        context: HostContext,
        payload: HostTelemetry,
        collected_at: datetime,
    ) -> Optional[UUID]:
        normalized_config = self._build_host_snapshot(payload, collected_at)

        config_json = json.dumps(
            normalized_config,
            sort_keys=True,
            default=self._snapshot_default,
        )
        config_sha = hashlib.sha256(config_json.encode("utf-8")).digest()

        stmt = select(ConfigSnapshot).where(
            ConfigSnapshot.resource_id == context.resource_id,
            ConfigSnapshot.config_sha == config_sha,
        )
        snapshot = await self.db.scalar(stmt)
        if snapshot:
            snapshot.captured_at = collected_at
            snapshot.normalized_config = normalized_config
            snapshot.collector_version = payload.agent_version
            await self.db.flush()
            return snapshot.snapshot_id

        snapshot = ConfigSnapshot(
            resource_id=context.resource_id,
            captured_at=collected_at,
            config_sha=config_sha,
            normalized_config=normalized_config,
            collector_version=payload.agent_version,
        )
        self.db.add(snapshot)
        await self.db.flush()
        return snapshot.snapshot_id

    def _build_host_snapshot(
        self,
        payload: HostTelemetry,
        collected_at: datetime,
    ) -> Dict[str, Any]:
        host_info = {
            "host_id": payload.host_id,
            "hostname": payload.hostname,
            "serial_number": payload.serial_number,
            "os_family": payload.os_family,
            "os_version": payload.os_version,
            "kernel_version": payload.kernel_version,
            "architecture": payload.architecture,
            "ip_addresses": payload.ip_addresses,
            "mac_addresses": payload.mac_addresses,
            "logged_in_users": payload.logged_in_users,
            "tags": payload.tags,
            "agent_version": payload.agent_version,
        }

        snapshot: Dict[str, Any] = {
            "host": {k: v for k, v in host_info.items() if v is not None},
            "health": payload.health.model_dump(exclude_none=True) if payload.health else None,
            "processes": [proc.model_dump(exclude_none=True) for proc in payload.processes],
            "network_connections": [
                conn.model_dump(exclude_none=True) for conn in (payload.network_connections or [])
            ],
            "installed_packages": [
                pkg.model_dump(exclude_none=True) for pkg in (payload.installed_packages or [])
            ],
        }

        # Drop empty collections to keep snapshot concise
        compact = {k: v for k, v in snapshot.items() if v not in (None, [], {})}
        return self._normalize_datetimes(compact)

    async def _get_or_create_rule(
        self,
        *,
        name: str,
        description: str,
        severity: str,
        provider: str,
    ) -> Rule:
        stmt = select(Rule).where(Rule.name == name)
        rule = await self.db.scalar(stmt)
        if rule is None:
            rule = Rule(
                name=name,
                description=description,
                provider=[provider],
                resource_types=["github.repository", "service.runtime"],
                expression_lang="cel",
                expression="true",
                severity=severity,
                cis=["5.1.1"],
                nist_800_53=["SI-4"],
            )
            self.db.add(rule)
            await self.db.flush()
        return rule

    async def _create_secret_finding(
        self,
        secret: SecretsScanResult,
        telemetry: RepositoryTelemetry,
        context: RepositoryContext,
    ) -> Optional[UUID]:
        rule = await self._get_or_create_rule(
            name="Secret Detected in Code",
            description="Sensitive secret or credential detected in repository code",
            severity="critical",
            provider="telemetry",
        )

        fingerprint = self._fingerprint(
            "telemetry-secret",
            telemetry.repository,
            secret.file_path,
            secret.secret_type,
        )

        finding = await self._get_existing_finding(context.org_id, fingerprint)
        if finding:
            finding.last_seen = telemetry.timestamp
            return finding.finding_id

        finding = Finding(
            org_id=context.org_id,
            account_id=context.account_id,
            provider="github",
            rule_id=rule.rule_id,
            rule_version=rule.version,
            resource_id=context.resource_id,
            first_seen=telemetry.timestamp,
            last_seen=telemetry.timestamp,
            status="open",
            severity="critical",
            fingerprint=fingerprint,
            title=f"Secret detected: {secret.secret_type} in {secret.file_path}",
            summary=(
                f"Secret of type '{secret.secret_type}' detected in {telemetry.repository} "
                f"at {secret.file_path}. This secret should be removed and rotated."
            ),
            evidence={
                "source": "telemetry",
                "detector": secret.detector_name,
                "file_path": secret.file_path,
                "line_number": secret.line_number,
                "secret_type": secret.secret_type,
                "verified": secret.verified,
                "commit_sha": telemetry.sha,
                "detected_at": telemetry.timestamp.isoformat(),
            },
        )
        self.db.add(finding)
        await self.db.flush()
        return finding.finding_id

    async def _create_dependency_finding(
        self,
        vuln: DependencyVulnerability,
        telemetry: RepositoryTelemetry | Dict[str, Any],
        context: RepositoryContext,
    ) -> Optional[UUID]:
        severity_map = {
            "CRITICAL": "critical",
            "HIGH": "high",
            "MODERATE": "medium",
            "MEDIUM": "medium",
            "LOW": "low",
        }
        severity = severity_map.get(vuln.severity.upper(), "medium")

        rule = await self._get_or_create_rule(
            name="Vulnerable Dependency",
            description="Application depends on package with known vulnerability",
            severity=severity,
            provider="telemetry",
        )

        repo = telemetry["repository"] if isinstance(telemetry, dict) else telemetry.repository
        timestamp = telemetry["timestamp"] if isinstance(telemetry, dict) else telemetry.timestamp

        fingerprint = self._fingerprint(
            "telemetry-vuln",
            repo,
            vuln.package_name,
            vuln.vulnerability_id,
        )

        finding = await self._get_existing_finding(context.org_id, fingerprint)
        if finding:
            finding.last_seen = timestamp
            return finding.finding_id

        finding = Finding(
            org_id=context.org_id,
            account_id=context.account_id,
            provider="github",
            rule_id=rule.rule_id,
            rule_version=rule.version,
            resource_id=context.resource_id,
            first_seen=timestamp,
            last_seen=timestamp,
            status="open",
            severity=severity,
            fingerprint=fingerprint,
            title=f"Vulnerability {vuln.vulnerability_id}: {vuln.package_name}@{vuln.package_version}",
            summary=(
                f"Package {vuln.package_name} version {vuln.package_version} has known vulnerability "
                f"{vuln.vulnerability_id}. "
                + (
                    f"Fixed in version {vuln.fixed_version}."
                    if vuln.fixed_version
                    else "No fix available yet."
                )
            ),
            evidence={
                "source": "telemetry",
                "package_name": vuln.package_name,
                "package_version": vuln.package_version,
                "vulnerability_id": vuln.vulnerability_id,
                "severity": vuln.severity,
                "description": vuln.description,
                "fixed_version": vuln.fixed_version,
                "cwe": vuln.cwe,
                "detected_at": timestamp.isoformat() if timestamp else None,
            },
        )
        self.db.add(finding)
        await self.db.flush()
        return finding.finding_id

    async def _create_runtime_event_finding(
        self,
        event: SecurityEvent,
        telemetry: RuntimeTelemetry,
        context: RuntimeContext,
    ) -> Optional[UUID]:
        severity = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
        }.get(event.severity.lower(), "medium")

        rule = await self._get_or_create_rule(
            name=f"Runtime Security Event: {event.event_type}",
            description=f"Security event detected in running application: {event.event_type}",
            severity=severity,
            provider="telemetry",
        )

        fingerprint = self._fingerprint(
            "telemetry-runtime",
            telemetry.service,
            event.event_type,
            event.timestamp.isoformat(),
        )

        finding = Finding(
            org_id=context.org_id,
            account_id=context.account_id,
            provider="runtime",
            rule_id=rule.rule_id,
            rule_version=rule.version,
            resource_id=context.resource_id,
            first_seen=event.timestamp,
            last_seen=event.timestamp,
            status="open",
            severity=severity,
            fingerprint=fingerprint,
            title=f"Runtime security event: {event.event_type}",
            summary=(
                f"Security event '{event.event_type}' detected in {telemetry.service} "
                f"({telemetry.environment})."
            ),
            evidence={
                "source": "telemetry",
                "service": telemetry.service,
                "environment": telemetry.environment,
                "instance_id": telemetry.instance_id,
                "event_type": event.event_type,
                "source_ip": event.source_ip,
                "user_id": event.user_id,
                "details": event.details,
                "detected_at": event.timestamp.isoformat(),
            },
        )
        self.db.add(finding)
        await self.db.flush()
        return finding.finding_id

    async def _create_config_drift_finding(
        self,
        drift: ConfigurationDrift,
        telemetry: RuntimeTelemetry,
        context: RuntimeContext,
    ) -> Optional[UUID]:
        rule = await self._get_or_create_rule(
            name="Configuration Drift Detected",
            description="Application configuration has drifted from expected baseline",
            severity="high",
            provider="telemetry",
        )

        fingerprint = self._fingerprint(
            "telemetry-drift",
            telemetry.service,
            drift.config_key,
        )

        finding = await self._get_existing_finding(context.org_id, fingerprint)
        if finding:
            finding.last_seen = telemetry.timestamp
            if finding.evidence:
                finding.evidence["actual_value"] = drift.actual_value
                finding.evidence["last_detected"] = telemetry.timestamp.isoformat()
            return finding.finding_id

        finding = Finding(
            org_id=context.org_id,
            account_id=context.account_id,
            provider="runtime",
            rule_id=rule.rule_id,
            rule_version=rule.version,
            resource_id=context.resource_id,
            first_seen=telemetry.timestamp,
            last_seen=telemetry.timestamp,
            status="open",
            severity="high",
            fingerprint=fingerprint,
            title=f"Configuration drift: {drift.config_key}",
            summary=(
                f"Configuration '{drift.config_key}' in {telemetry.service} drifted from baseline. "
                f"Expected: {drift.expected_value}, Actual: {drift.actual_value}."
            ),
            evidence={
                "source": "telemetry",
                "service": telemetry.service,
                "environment": telemetry.environment,
                "config_key": drift.config_key,
                "expected_value": drift.expected_value,
                "actual_value": drift.actual_value,
                "drift_type": drift.drift_type,
                "detected_at": telemetry.timestamp.isoformat(),
            },
        )
        self.db.add(finding)
        await self.db.flush()
        return finding.finding_id

    async def _create_host_security_event_finding(
        self,
        event: SecurityEvent,
        telemetry: HostTelemetry,
        context: HostContext,
    ) -> Optional[UUID]:
        severity = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
        }.get(event.severity.lower(), "medium")

        rule = await self._get_or_create_rule(
            name=f"Endpoint Security Event: {event.event_type}",
            description=f"Security event detected on endpoint: {event.event_type}",
            severity=severity,
            provider="telemetry",
        )

        event_ts = event.timestamp
        if event_ts.tzinfo is None:
            event_ts = event_ts.replace(tzinfo=timezone.utc)

        fingerprint = self._fingerprint(
            "telemetry-host-event",
            context.host_id,
            event.event_type,
            event_ts.isoformat(),
        )

        finding = Finding(
            org_id=context.org_id,
            account_id=context.account_id,
            provider="endpoint",
            rule_id=rule.rule_id,
            rule_version=rule.version,
            resource_id=context.resource_id,
            first_seen=event_ts,
            last_seen=event_ts,
            status="open",
            severity=severity,
            fingerprint=fingerprint,
            title=f"Endpoint security event: {event.event_type}",
            summary=(
                f"Security event '{event.event_type}' detected on host {telemetry.hostname}"
            ),
            evidence={
                "source": "telemetry",
                "host_id": telemetry.host_id,
                "hostname": telemetry.hostname,
                "event_type": event.event_type,
                "details": event.details,
                "severity": event.severity,
                "detected_at": event_ts.isoformat(),
                "ip_addresses": telemetry.ip_addresses,
                "users": telemetry.logged_in_users,
            },
        )
        self.db.add(finding)
        await self.db.flush()
        return finding.finding_id

    async def _create_host_drift_finding(
        self,
        drift: ConfigurationDrift,
        telemetry: HostTelemetry,
        context: HostContext,
    ) -> Optional[UUID]:
        rule = await self._get_or_create_rule(
            name="Endpoint Configuration Drift Detected",
            description="Endpoint configuration has drifted from expected baseline",
            severity="high",
            provider="telemetry",
        )

        fingerprint = self._fingerprint(
            "telemetry-host-drift",
            context.host_id,
            drift.config_key,
        )

        existing = await self._get_existing_finding(context.org_id, fingerprint)
        collected_at = telemetry.collected_at
        if collected_at.tzinfo is None:
            collected_at = collected_at.replace(tzinfo=timezone.utc)

        if existing:
            existing.last_seen = collected_at
            if existing.evidence:
                existing.evidence["actual_value"] = drift.actual_value
                existing.evidence["last_detected"] = collected_at.isoformat()
            return existing.finding_id

        finding = Finding(
            org_id=context.org_id,
            account_id=context.account_id,
            provider="endpoint",
            rule_id=rule.rule_id,
            rule_version=rule.version,
            resource_id=context.resource_id,
            first_seen=collected_at,
            last_seen=collected_at,
            status="open",
            severity="high",
            fingerprint=fingerprint,
            title=f"Endpoint configuration drift: {drift.config_key}",
            summary=(
                f"Configuration '{drift.config_key}' on host {telemetry.hostname} drifted."
                f" Expected: {drift.expected_value}, Actual: {drift.actual_value}."
            ),
            evidence={
                "source": "telemetry",
                "host_id": telemetry.host_id,
                "hostname": telemetry.hostname,
                "config_key": drift.config_key,
                "expected_value": drift.expected_value,
                "actual_value": drift.actual_value,
                "drift_type": drift.drift_type,
                "detected_at": collected_at.isoformat(),
            },
        )
        self.db.add(finding)
        await self.db.flush()
        return finding.finding_id

    def _extract_vulnerabilities(
        self, scan: DependencyScan
    ) -> Iterable[DependencyVulnerability]:
        if scan.npm and isinstance(scan.npm, dict):
            npm_vulns = scan.npm.get("vulnerabilities", {})
            for pkg_name, vuln_data in npm_vulns.items():
                if not isinstance(vuln_data, dict):
                    continue
                yield DependencyVulnerability(
                    package_name=pkg_name,
                    package_version=vuln_data.get("version", "unknown"),
                    vulnerability_id=
                    (
                        vuln_data.get("via", [{}])[0].get("url", "CVE-UNKNOWN")
                        if isinstance(vuln_data.get("via"), list)
                        else "CVE-UNKNOWN"
                    ),
                    severity=vuln_data.get("severity", "medium").upper(),
                    description=(
                        vuln_data.get("via", [{}])[0].get("title")
                        if isinstance(vuln_data.get("via"), list)
                        else None
                    ),
                    fixed_version=(
                        vuln_data.get("fixAvailable", {}).get("version")
                        if isinstance(vuln_data.get("fixAvailable"), dict)
                        else None
                    ),
                )

        # TODO: Parse pip-audit, go, maven vulnerability formats.

    async def _get_existing_finding(self, org_id: UUID, fingerprint: str) -> Optional[Finding]:
        stmt = select(Finding).where(
            Finding.org_id == org_id,
            Finding.fingerprint == fingerprint,
        )
        return await self.db.scalar(stmt)

    async def _store_sbom(self, resource_id: UUID, sbom: Dict[str, Any]) -> None:
        # TODO: implement persistence once schema is available
        logger.info("SBOM stored", resource_id=str(resource_id))

    def _fingerprint(self, prefix: str, *parts: str) -> str:
        data = "-".join(parts)
        digest = hashlib.sha256(data.encode()).hexdigest()[:32]
        return f"{prefix}-{digest}"

    def _is_suspicious_event(self, event: SecurityEvent) -> bool:
        suspicious_types = {
            "failed_auth",
            "privilege_escalation",
            "unauthorized_access",
            "data_exfiltration",
            "malicious_payload",
        }
        return event.event_type in suspicious_types or event.severity.lower() in {"high", "critical"}

    @staticmethod
    def _snapshot_default(value: Any) -> Any:
        if isinstance(value, datetime):
            if value.tzinfo is None:
                value = value.replace(tzinfo=timezone.utc)
            return value.isoformat()
        return value

    def _normalize_datetimes(self, value: Any) -> Any:
        if isinstance(value, datetime):
            if value.tzinfo is None:
                value = value.replace(tzinfo=timezone.utc)
            return value.isoformat()
        if isinstance(value, list):
            return [self._normalize_datetimes(item) for item in value]
        if isinstance(value, dict):
            return {key: self._normalize_datetimes(item) for key, item in value.items()}
        return value
