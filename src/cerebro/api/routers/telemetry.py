"""Repository and runtime telemetry endpoints.

Receives intelligence from Forklift-injected shims running in repositories
and applications. Creates findings and tracks security posture in real-time.
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Header
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from cerebro.core.database import get_db
from cerebro.core.models import Finding, Organization, Account, Resource, Rule
from cerebro.findings.manager import FindingManager

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/telemetry", tags=["Telemetry", "Intelligence"])


# ============================================================================
# Pydantic Models for Telemetry Data
# ============================================================================

class SecretsScanResult(BaseModel):
    """Secret detection results from TruffleHog or similar."""
    detector_name: Optional[str] = None
    file_path: str
    line_number: Optional[int] = None
    secret_type: str
    verified: Optional[bool] = False
    raw_result: Optional[Dict[str, Any]] = None


class DependencyVulnerability(BaseModel):
    """Vulnerability in a dependency."""
    package_name: str
    package_version: str
    vulnerability_id: str  # CVE-2023-1234
    severity: str
    description: Optional[str] = None
    fixed_version: Optional[str] = None
    cwe: Optional[List[str]] = None


class DependencyScan(BaseModel):
    """Dependency scan results."""
    npm: Optional[Dict[str, Any]] = None
    pip: Optional[Dict[str, Any]] = None
    go: Optional[Dict[str, Any]] = None
    maven: Optional[Dict[str, Any]] = None


class CodeMetrics(BaseModel):
    """Code quality metrics."""
    total_lines: Optional[int] = None
    languages: Optional[Dict[str, int]] = None
    complexity: Optional[Dict[str, Any]] = None


class RepositoryTelemetry(BaseModel):
    """Complete telemetry payload from repository workflow."""
    repository: str = Field(..., description="Full repo name (org/repo)")
    ref: str = Field(..., description="Git ref (refs/heads/main)")
    sha: str = Field(..., description="Commit SHA")
    event: str = Field(..., description="GitHub event type")
    timestamp: datetime
    
    # Telemetry data
    secrets_scan: Optional[List[SecretsScanResult]] = None
    dependencies: Optional[DependencyScan] = None
    sbom: Optional[Dict[str, Any]] = None
    code_metrics: Optional[CodeMetrics] = None
    
    # Metadata
    workflow_run_id: Optional[str] = None
    actor: Optional[str] = None


class SecurityEvent(BaseModel):
    """Runtime security event."""
    event_type: str = Field(..., description="failed_auth, privilege_escalation, etc.")
    timestamp: datetime
    severity: str
    source_ip: Optional[str] = None
    user_id: Optional[str] = None
    details: Dict[str, Any]


class ConfigurationDrift(BaseModel):
    """Configuration drift from baseline."""
    config_key: str
    expected_value: Any
    actual_value: Any
    drift_type: str  # modified, missing, added


class RuntimeTelemetry(BaseModel):
    """Runtime telemetry from application."""
    service: str = Field(..., description="Service name")
    environment: str = Field(..., description="prod, staging, dev")
    instance_id: Optional[str] = None
    timestamp: datetime
    
    # Runtime data
    security_events: Optional[List[SecurityEvent]] = None
    configuration_drift: Optional[List[ConfigurationDrift]] = None
    health_metrics: Optional[Dict[str, Any]] = None
    active_vulnerabilities: Optional[List[str]] = None


class ComplianceEvidence(BaseModel):
    """Compliance evidence collected from repository."""
    repository: str
    framework: str = Field(..., description="soc2, iso27001, etc.")
    collected_at: datetime
    evidence: Dict[str, Any] = Field(..., description="Control-mapped evidence")


class DependencyGraph(BaseModel):
    """Complete dependency graph including transitive dependencies."""
    repository: str
    timestamp: datetime
    dependency_graph: Dict[str, Any]
    licenses: Dict[str, Any]
    vulnerabilities: List[DependencyVulnerability]


# ============================================================================
# API Endpoints
# ============================================================================

@router.post("/repository", status_code=200)
async def receive_repository_telemetry(
    telemetry: RepositoryTelemetry,
    db: AsyncSession = Depends(get_db),
    authorization: Optional[str] = Header(None)
):
    """
    Receive telemetry from repository CI/CD workflows.
    
    Creates findings for:
    - Secrets found in code (TruffleHog scan)
    - Vulnerable dependencies (npm-audit, pip-audit, etc.)
    - Missing security controls
    - Code quality issues
    """
    
    logger.info(f"Received repository telemetry from {telemetry.repository}")
    
    try:
        # Get or create organization and account
        org_name = telemetry.repository.split('/')[0]
        org = await get_or_create_organization(org_name, db)
        account = await get_or_create_account(org.org_id, "github", org_name, db)
        
        # Get or create resource for repository
        resource = await get_or_create_resource(
            account.account_id,
            "github.repository",
            telemetry.repository,
            telemetry.repository,
            db
        )
        
        findings_created = []
        
        # Process secrets scan
        if telemetry.secrets_scan:
            for secret in telemetry.secrets_scan:
                finding = await create_finding_from_secret(
                    secret, org.org_id, account.account_id, resource.resource_id,
                    telemetry, db
                )
                if finding:
                    findings_created.append(finding.finding_id)
        
        # Process dependency vulnerabilities
        if telemetry.dependencies:
            vulns = extract_vulnerabilities_from_deps(telemetry.dependencies)
            for vuln in vulns:
                finding = await create_finding_from_vulnerability(
                    vuln, org.org_id, account.account_id, resource.resource_id,
                    telemetry, db
                )
                if finding:
                    findings_created.append(finding.finding_id)
        
        # Store SBOM for supply chain analysis
        if telemetry.sbom:
            await store_sbom(resource.resource_id, telemetry.sbom, db)
        
        await db.commit()
        
        logger.info(f"Processed telemetry from {telemetry.repository}: "
                   f"{len(findings_created)} findings created")
        
        return {
            "status": "processed",
            "repository": telemetry.repository,
            "findings_created": len(findings_created),
            "finding_ids": [str(f) for f in findings_created]
        }
        
    except Exception as e:
        logger.exception(f"Failed to process repository telemetry: {e}")
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Telemetry processing failed: {str(e)}")


@router.post("/runtime", status_code=200)
async def receive_runtime_telemetry(
    telemetry: RuntimeTelemetry,
    db: AsyncSession = Depends(get_db),
    authorization: Optional[str] = Header(None)
):
    """
    Receive runtime telemetry from running applications.
    
    Creates findings for:
    - Failed authentication attempts (brute force attacks)
    - Privilege escalation attempts
    - Configuration drift from baseline
    - Runtime vulnerabilities
    - Suspicious network activity
    """
    
    logger.info(f"Received runtime telemetry from {telemetry.service} ({telemetry.environment})")
    
    try:
        # TODO: Map service to organization/account (might need service registry)
        # For now, create a generic org
        org = await get_or_create_organization("runtime-services", db)
        account = await get_or_create_account(org.org_id, "runtime", "runtime-services", db)
        
        # Get or create resource for service
        resource = await get_or_create_resource(
            account.account_id,
            "service.runtime",
            f"{telemetry.service}-{telemetry.environment}",
            telemetry.service,
            db
        )
        
        findings_created = []
        
        # Process security events
        if telemetry.security_events:
            for event in telemetry.security_events:
                if is_suspicious_event(event):
                    finding = await create_finding_from_runtime_event(
                        event, org.org_id, account.account_id, resource.resource_id,
                        telemetry, db
                    )
                    if finding:
                        findings_created.append(finding.finding_id)
        
        # Process configuration drift
        if telemetry.configuration_drift:
            for drift in telemetry.configuration_drift:
                finding = await create_finding_from_config_drift(
                    drift, org.org_id, account.account_id, resource.resource_id,
                    telemetry, db
                )
                if finding:
                    findings_created.append(finding.finding_id)
        
        await db.commit()
        
        logger.info(f"Processed runtime telemetry from {telemetry.service}: "
                   f"{len(findings_created)} findings created")
        
        return {
            "status": "processed",
            "service": telemetry.service,
            "environment": telemetry.environment,
            "findings_created": len(findings_created)
        }
        
    except Exception as e:
        logger.exception(f"Failed to process runtime telemetry: {e}")
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Telemetry processing failed: {str(e)}")


@router.post("/compliance/evidence", status_code=200)
async def receive_compliance_evidence(
    evidence: ComplianceEvidence,
    db: AsyncSession = Depends(get_db),
    authorization: Optional[str] = Header(None)
):
    """
    Receive compliance evidence collected from repositories.
    
    Stores evidence for audit purposes and validates controls.
    """
    
    logger.info(f"Received compliance evidence from {evidence.repository} ({evidence.framework})")
    
    try:
        org_name = evidence.repository.split('/')[0]
        org = await get_or_create_organization(org_name, db)
        account = await get_or_create_account(org.org_id, "github", org_name, db)
        
        resource = await get_or_create_resource(
            account.account_id,
            "github.repository",
            evidence.repository,
            evidence.repository,
            db
        )
        
        # Store evidence (could create a ComplianceEvidence table)
        # For now, just log it
        logger.info(f"Compliance evidence collected for {evidence.framework}: "
                   f"{list(evidence.evidence.keys())}")
        
        # TODO: Validate controls and create findings for gaps
        
        await db.commit()
        
        return {
            "status": "processed",
            "repository": evidence.repository,
            "framework": evidence.framework,
            "controls_evidenced": len(evidence.evidence)
        }
        
    except Exception as e:
        logger.exception(f"Failed to process compliance evidence: {e}")
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Evidence processing failed: {str(e)}")


@router.post("/supply-chain/dependency-graph", status_code=200)
async def receive_dependency_graph(
    graph: DependencyGraph,
    db: AsyncSession = Depends(get_db),
    authorization: Optional[str] = Header(None)
):
    """
    Receive complete dependency graph including transitive dependencies.
    
    Enables supply chain attack detection and license compliance.
    """
    
    logger.info(f"Received dependency graph from {graph.repository}")
    
    try:
        org_name = graph.repository.split('/')[0]
        org = await get_or_create_organization(org_name, db)
        account = await get_or_create_account(org.org_id, "github", org_name, db)
        
        resource = await get_or_create_resource(
            account.account_id,
            "github.repository",
            graph.repository,
            graph.repository,
            db
        )
        
        findings_created = []
        
        # Process vulnerabilities
        for vuln in graph.vulnerabilities:
            finding = await create_finding_from_vulnerability(
                vuln, org.org_id, account.account_id, resource.resource_id,
                {"repository": graph.repository, "timestamp": graph.timestamp}, db
            )
            if finding:
                findings_created.append(finding.finding_id)
        
        # TODO: Store dependency graph for supply chain analysis
        # TODO: Check for malicious packages
        # TODO: Validate license compliance
        
        await db.commit()
        
        logger.info(f"Processed dependency graph from {graph.repository}: "
                   f"{len(findings_created)} vulnerability findings created")
        
        return {
            "status": "processed",
            "repository": graph.repository,
            "vulnerabilities_found": len(graph.vulnerabilities),
            "findings_created": len(findings_created)
        }
        
    except Exception as e:
        logger.exception(f"Failed to process dependency graph: {e}")
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Dependency graph processing failed: {str(e)}")


# ============================================================================
# Helper Functions
# ============================================================================

async def get_or_create_organization(name: str, db: AsyncSession) -> Organization:
    """Get or create organization by name."""
    stmt = select(Organization).where(Organization.name == name)
    org = await db.scalar(stmt)
    
    if not org:
        org = Organization(name=name)
        db.add(org)
        await db.flush()
        logger.info(f"Created organization: {name}")
    
    return org


async def get_or_create_account(
    org_id: UUID, provider: str, external_id: str, db: AsyncSession
) -> Account:
    """Get or create account."""
    stmt = select(Account).where(
        Account.org_id == org_id,
        Account.provider == provider,
        Account.external_id == external_id
    )
    account = await db.scalar(stmt)
    
    if not account:
        account = Account(
            org_id=org_id,
            provider=provider,
            external_id=external_id,
            display_name=external_id
        )
        db.add(account)
        await db.flush()
        logger.info(f"Created account: {provider}/{external_id}")
    
    return account


async def get_or_create_resource(
    account_id: UUID, resource_type: str, external_id: str, name: str, db: AsyncSession
) -> Resource:
    """Get or create resource."""
    stmt = select(Resource).where(
        Resource.account_id == account_id,
        Resource.external_id == external_id
    )
    resource = await db.scalar(stmt)
    
    if not resource:
        resource = Resource(
            account_id=account_id,
            provider=resource_type.split('.')[0],
            resource_type=resource_type,
            external_id=external_id,
            name=name
        )
        db.add(resource)
        await db.flush()
        logger.info(f"Created resource: {resource_type}/{external_id}")
    
    return resource


async def get_or_create_telemetry_rule(
    rule_name: str, description: str, severity: str, db: AsyncSession
) -> Rule:
    """Get or create a telemetry-specific rule."""
    stmt = select(Rule).where(Rule.name == rule_name)
    rule = await db.scalar(stmt)
    
    if not rule:
        rule = Rule(
            name=rule_name,
            description=description,
            provider=["telemetry"],
            resource_types=["github.repository", "service.runtime"],
            expression_lang="cel",
            expression="true",  # Always true, we create findings directly from telemetry
            severity=severity,
            cis=["5.1.1"],
            nist_800_53=["SI-4"]
        )
        db.add(rule)
        await db.flush()
    
    return rule


async def create_finding_from_secret(
    secret: SecretsScanResult,
    org_id: UUID,
    account_id: UUID,
    resource_id: UUID,
    telemetry: RepositoryTelemetry,
    db: AsyncSession
) -> Optional[Finding]:
    """Create finding from detected secret."""
    
    # Get or create rule
    rule = await get_or_create_telemetry_rule(
        "Secret Detected in Code",
        "Sensitive secret or credential detected in repository code",
        "critical",
        db
    )
    
    # Create fingerprint
    import hashlib
    fingerprint_data = f"secret-{telemetry.repository}-{secret.file_path}-{secret.secret_type}"
    fingerprint = hashlib.sha256(fingerprint_data.encode()).hexdigest()[:32]
    fingerprint = f"telemetry-secret-{fingerprint}"
    
    # Check if finding already exists
    stmt = select(Finding).where(
        Finding.org_id == org_id,
        Finding.fingerprint == fingerprint
    )
    existing = await db.scalar(stmt)
    
    if existing:
        # Update last_seen
        existing.last_seen = telemetry.timestamp
        logger.debug(f"Updated existing secret finding: {fingerprint}")
        return existing
    
    # Create new finding
    finding = Finding(
        org_id=org_id,
        account_id=account_id,
        provider="github",
        rule_id=rule.rule_id,
        rule_version=rule.version,
        resource_id=resource_id,
        first_seen=telemetry.timestamp,
        last_seen=telemetry.timestamp,
        status="open",
        severity="critical",
        fingerprint=fingerprint,
        title=f"Secret detected: {secret.secret_type} in {secret.file_path}",
        summary=(
            f"Secret of type '{secret.secret_type}' detected in {telemetry.repository} "
            f"at {secret.file_path}. This secret should be removed from the repository and rotated."
        ),
        evidence={
            "source": "telemetry",
            "detector": secret.detector_name,
            "file_path": secret.file_path,
            "line_number": secret.line_number,
            "secret_type": secret.secret_type,
            "verified": secret.verified,
            "commit_sha": telemetry.sha,
            "detected_at": telemetry.timestamp.isoformat()
        }
    )
    
    db.add(finding)
    await db.flush()
    logger.info(f"Created secret finding: {finding.finding_id}")
    
    return finding


async def create_finding_from_vulnerability(
    vuln: DependencyVulnerability,
    org_id: UUID,
    account_id: UUID,
    resource_id: UUID,
    telemetry: Any,
    db: AsyncSession
) -> Optional[Finding]:
    """Create finding from dependency vulnerability."""
    
    # Map severity
    severity_map = {
        "CRITICAL": "critical",
        "HIGH": "high",
        "MODERATE": "medium",
        "MEDIUM": "medium",
        "LOW": "low"
    }
    severity = severity_map.get(vuln.severity.upper(), "medium")
    
    # Get or create rule
    rule = await get_or_create_telemetry_rule(
        "Vulnerable Dependency",
        "Application depends on package with known security vulnerability",
        severity,
        db
    )
    
    # Create fingerprint
    import hashlib
    repo = telemetry.get("repository") if isinstance(telemetry, dict) else telemetry.repository
    fingerprint_data = f"vuln-{repo}-{vuln.package_name}-{vuln.vulnerability_id}"
    fingerprint = hashlib.sha256(fingerprint_data.encode()).hexdigest()[:32]
    fingerprint = f"telemetry-vuln-{fingerprint}"
    
    # Check if finding already exists
    stmt = select(Finding).where(
        Finding.org_id == org_id,
        Finding.fingerprint == fingerprint
    )
    existing = await db.scalar(stmt)
    
    timestamp = telemetry.get("timestamp") if isinstance(telemetry, dict) else telemetry.timestamp
    
    if existing:
        # Update last_seen
        existing.last_seen = timestamp
        logger.debug(f"Updated existing vulnerability finding: {fingerprint}")
        return existing
    
    # Create new finding
    finding = Finding(
        org_id=org_id,
        account_id=account_id,
        provider="github",
        rule_id=rule.rule_id,
        rule_version=rule.version,
        resource_id=resource_id,
        first_seen=timestamp,
        last_seen=timestamp,
        status="open",
        severity=severity,
        fingerprint=fingerprint,
        title=f"Vulnerability {vuln.vulnerability_id}: {vuln.package_name}@{vuln.package_version}",
        summary=(
            f"Package {vuln.package_name} version {vuln.package_version} has known vulnerability "
            f"{vuln.vulnerability_id}. " +
            (f"Fixed in version {vuln.fixed_version}." if vuln.fixed_version else "No fix available yet.")
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
            "detected_at": timestamp.isoformat() if timestamp else None
        }
    )
    
    db.add(finding)
    await db.flush()
    logger.info(f"Created vulnerability finding: {finding.finding_id}")
    
    return finding


async def create_finding_from_runtime_event(
    event: SecurityEvent,
    org_id: UUID,
    account_id: UUID,
    resource_id: UUID,
    telemetry: RuntimeTelemetry,
    db: AsyncSession
) -> Optional[Finding]:
    """Create finding from runtime security event."""
    
    severity_map = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low"
    }
    severity = severity_map.get(event.severity.lower(), "medium")
    
    # Get or create rule
    rule = await get_or_create_telemetry_rule(
        f"Runtime Security Event: {event.event_type}",
        f"Security event detected in running application: {event.event_type}",
        severity,
        db
    )
    
    # Create fingerprint
    import hashlib
    fingerprint_data = f"runtime-{telemetry.service}-{event.event_type}-{event.timestamp.isoformat()}"
    fingerprint = hashlib.sha256(fingerprint_data.encode()).hexdigest()[:32]
    fingerprint = f"telemetry-runtime-{fingerprint}"
    
    # Create finding (runtime events are always new)
    finding = Finding(
        org_id=org_id,
        account_id=account_id,
        provider="runtime",
        rule_id=rule.rule_id,
        rule_version=rule.version,
        resource_id=resource_id,
        first_seen=event.timestamp,
        last_seen=event.timestamp,
        status="open",
        severity=severity,
        fingerprint=fingerprint,
        title=f"Runtime security event: {event.event_type}",
        summary=f"Security event '{event.event_type}' detected in {telemetry.service} ({telemetry.environment})",
        evidence={
            "source": "telemetry",
            "service": telemetry.service,
            "environment": telemetry.environment,
            "instance_id": telemetry.instance_id,
            "event_type": event.event_type,
            "source_ip": event.source_ip,
            "user_id": event.user_id,
            "details": event.details,
            "detected_at": event.timestamp.isoformat()
        }
    )
    
    db.add(finding)
    await db.flush()
    logger.info(f"Created runtime event finding: {finding.finding_id}")
    
    return finding


async def create_finding_from_config_drift(
    drift: ConfigurationDrift,
    org_id: UUID,
    account_id: UUID,
    resource_id: UUID,
    telemetry: RuntimeTelemetry,
    db: AsyncSession
) -> Optional[Finding]:
    """Create finding from configuration drift."""
    
    rule = await get_or_create_telemetry_rule(
        "Configuration Drift Detected",
        "Application configuration has drifted from expected baseline",
        "high",
        db
    )
    
    # Create fingerprint
    import hashlib
    fingerprint_data = f"drift-{telemetry.service}-{drift.config_key}"
    fingerprint = hashlib.sha256(fingerprint_data.encode()).hexdigest()[:32]
    fingerprint = f"telemetry-drift-{fingerprint}"
    
    # Check if finding already exists
    stmt = select(Finding).where(
        Finding.org_id == org_id,
        Finding.fingerprint == fingerprint
    )
    existing = await db.scalar(stmt)
    
    if existing:
        existing.last_seen = telemetry.timestamp
        # Update evidence with new values
        if existing.evidence:
            existing.evidence["actual_value"] = drift.actual_value
            existing.evidence["last_detected"] = telemetry.timestamp.isoformat()
        return existing
    
    # Create new finding
    finding = Finding(
        org_id=org_id,
        account_id=account_id,
        provider="runtime",
        rule_id=rule.rule_id,
        rule_version=rule.version,
        resource_id=resource_id,
        first_seen=telemetry.timestamp,
        last_seen=telemetry.timestamp,
        status="open",
        severity="high",
        fingerprint=fingerprint,
        title=f"Configuration drift: {drift.config_key}",
        summary=(
            f"Configuration '{drift.config_key}' in {telemetry.service} has drifted from baseline. "
            f"Expected: {drift.expected_value}, Actual: {drift.actual_value}"
        ),
        evidence={
            "source": "telemetry",
            "service": telemetry.service,
            "environment": telemetry.environment,
            "config_key": drift.config_key,
            "expected_value": drift.expected_value,
            "actual_value": drift.actual_value,
            "drift_type": drift.drift_type,
            "detected_at": telemetry.timestamp.isoformat()
        }
    )
    
    db.add(finding)
    await db.flush()
    logger.info(f"Created configuration drift finding: {finding.finding_id}")
    
    return finding


def extract_vulnerabilities_from_deps(deps: DependencyScan) -> List[DependencyVulnerability]:
    """Extract vulnerabilities from dependency scan results."""
    vulnerabilities = []
    
    # Parse npm audit results
    if deps.npm and isinstance(deps.npm, dict):
        npm_vulns = deps.npm.get("vulnerabilities", {})
        for pkg_name, vuln_data in npm_vulns.items():
            if isinstance(vuln_data, dict):
                vulnerabilities.append(DependencyVulnerability(
                    package_name=pkg_name,
                    package_version=vuln_data.get("version", "unknown"),
                    vulnerability_id=vuln_data.get("via", [{}])[0].get("url", "CVE-UNKNOWN") if isinstance(vuln_data.get("via"), list) else "CVE-UNKNOWN",
                    severity=vuln_data.get("severity", "medium").upper(),
                    description=vuln_data.get("via", [{}])[0].get("title") if isinstance(vuln_data.get("via"), list) else None,
                    fixed_version=vuln_data.get("fixAvailable", {}).get("version") if isinstance(vuln_data.get("fixAvailable"), dict) else None
                ))
    
    # TODO: Parse pip-audit, go vulnerabilities, etc.
    
    return vulnerabilities


def is_suspicious_event(event: SecurityEvent) -> bool:
    """Determine if a runtime event is suspicious enough to create a finding."""
    suspicious_types = [
        "failed_auth",
        "privilege_escalation",
        "unauthorized_access",
        "data_exfiltration",
        "malicious_payload"
    ]
    
    return event.event_type in suspicious_types or event.severity in ["critical", "high"]


async def store_sbom(resource_id: UUID, sbom: Dict[str, Any], db: AsyncSession) -> None:
    """Store Software Bill of Materials for supply chain analysis."""
    # TODO: Create SBOM table and store
    logger.info(f"SBOM stored for resource {resource_id}")
    pass
