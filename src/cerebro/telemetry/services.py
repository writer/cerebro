"""Service layer for telemetry ingestion flows."""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Optional
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.core.models import (
    Account,
    Finding,
    FrontendObservationEvent,
    Organization,
    Resource,
    Rule,
)
from cerebro.telemetry.models import RepositoryContext, RuntimeContext, TelemetryResult
from cerebro.telemetry.schemas import (
    ComplianceEvidence,
    DependencyGraph,
    DependencyScan,
    DependencyVulnerability,
    FrontendObservationTelemetry,
    RepositoryTelemetry,
    RuntimeTelemetry,
    SecretsScanResult,
    SecurityEvent,
    ConfigurationDrift,
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

    async def _get_or_create_org(self, name: str) -> Organization:
        stmt = select(Organization).where(Organization.name == name)
        org = await self.db.scalar(stmt)
        if org is None:
            org = Organization(name=name)
            self.db.add(org)
            await self.db.flush()
            logger.info("Created organization", name=name)
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
            logger.info("Created account", provider=provider, external_id=external_id)
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
            logger.info("Created resource", resource_type=resource_type, external_id=external_id)
        return resource

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
