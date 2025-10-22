"""Pydantic models for telemetry ingestion payloads."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, Field


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
    vulnerability_id: str  # e.g., CVE-2023-1234
    severity: str
    description: Optional[str] = None
    fixed_version: Optional[str] = None
    cwe: Optional[List[str]] = None


class DependencyScan(BaseModel):
    """Dependency scan results grouped by ecosystem."""

    npm: Optional[Dict[str, Any]] = None
    pip: Optional[Dict[str, Any]] = None
    go: Optional[Dict[str, Any]] = None
    maven: Optional[Dict[str, Any]] = None


class CodeMetrics(BaseModel):
    """Code quality metrics captured during telemetry runs."""

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

    secrets_scan: Optional[List[SecretsScanResult]] = None
    dependencies: Optional[DependencyScan] = None
    sbom: Optional[Dict[str, Any]] = None
    code_metrics: Optional[CodeMetrics] = None

    workflow_run_id: Optional[str] = None
    actor: Optional[str] = None


class SecurityEvent(BaseModel):
    """Runtime security event."""

    event_type: str = Field(..., description="Event classifier, e.g., failed_auth")
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
    environment: str = Field(..., description="Environment (prod, staging, dev)")
    instance_id: Optional[str] = None
    timestamp: datetime

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


class FrontendObservationTelemetry(BaseModel):
    """Telemetry emitted from the Cerebro frontend during analyst workflows."""

    event_type: str = Field(..., description="Classifier for the user interaction")
    component: Optional[str] = Field(None, description="UI component emitting the telemetry")
    agent_session_id: Optional[UUID] = Field(
        None,
        description="Optional agent session identifier tied to the observation",
    )
    context: Optional[Dict[str, Any]] = Field(
        None,
        description="Lightweight context describing the analyst state (filters, scopes)",
    )
    metadata: Optional[Dict[str, Any]] = Field(
        None,
        description="Arbitrary metadata payload relevant to the event",
    )
    occurred_at: Optional[datetime] = Field(
        None,
        description="Timestamp when the observation took place (defaults to request time)",
    )

