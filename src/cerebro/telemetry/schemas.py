"""Pydantic models for telemetry ingestion payloads."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field


class SecretsScanResult(BaseModel):
    """Secret detection results from TruffleHog or similar."""

    detector_name: str | None = None
    file_path: str
    line_number: int | None = None
    secret_type: str
    verified: bool | None = False
    raw_result: dict[str, Any] | None = None


class DependencyVulnerability(BaseModel):
    """Vulnerability in a dependency."""

    package_name: str
    package_version: str
    vulnerability_id: str  # e.g., CVE-2023-1234
    severity: str
    description: str | None = None
    fixed_version: str | None = None
    cwe: list[str] | None = None


class DependencyScan(BaseModel):
    """Dependency scan results grouped by ecosystem."""

    npm: dict[str, Any] | None = None
    pip: dict[str, Any] | None = None
    go: dict[str, Any] | None = None
    maven: dict[str, Any] | None = None


class CodeMetrics(BaseModel):
    """Code quality metrics captured during telemetry runs."""

    total_lines: int | None = None
    languages: dict[str, int] | None = None
    complexity: dict[str, Any] | None = None


class RepositoryTelemetry(BaseModel):
    """Complete telemetry payload from repository workflow."""

    repository: str = Field(..., description="Full repo name (org/repo)")
    ref: str = Field(..., description="Git ref (refs/heads/main)")
    sha: str = Field(..., description="Commit SHA")
    event: str = Field(..., description="GitHub event type")
    timestamp: datetime

    secrets_scan: list[SecretsScanResult] | None = None
    dependencies: DependencyScan | None = None
    sbom: dict[str, Any] | None = None
    code_metrics: CodeMetrics | None = None

    workflow_run_id: str | None = None
    actor: str | None = None


class SecurityEvent(BaseModel):
    """Runtime security event."""

    event_type: str = Field(..., description="Event classifier, e.g., failed_auth")
    timestamp: datetime
    severity: str
    source_ip: str | None = None
    user_id: str | None = None
    details: dict[str, Any]


class EndpointThreat(BaseModel):
    """Threat detected on an endpoint by an external sensor."""

    threat_id: str = Field(..., description="Unique SentinelOne threat identifier")
    name: str | None = Field(None, description="Human readable threat name")
    classification: str | None = Field(
        None, description="Threat classification label"
    )
    confidence: str | None = Field(None, description="Detection confidence level")
    severity: str | None = Field(None, description="Mapped severity level")
    status: str | None = Field(None, description="Threat incident status")
    mitigation_status: str | None = Field(
        None, description="Current mitigation status"
    )
    analyst_verdict: str | None = Field(
        None, description="Analyst verdict when available"
    )
    initiated_by: str | None = Field(
        None, description="Process or sensor initiating mitigation"
    )
    initiating_user: str | None = Field(
        None, description="User associated with initiation"
    )
    process_user: str | None = Field(
        None, description="User owning the malicious process"
    )
    file_path: str | None = Field(
        None, description="Filesystem path associated with the threat"
    )
    md5: str | None = Field(None, description="MD5 hash of malicious artifact")
    sha1: str | None = Field(None, description="SHA1 hash of malicious artifact")
    sha256: str | None = Field(None, description="SHA256 hash of malicious artifact")
    storyline: str | None = Field(
        None, description="SentinelOne storyline identifier"
    )
    detected_at: datetime = Field(
        ..., description="Timestamp when the threat was identified"
    )
    updated_at: datetime | None = Field(None, description="Timestamp of last update")
    resolved_at: datetime | None = Field(
        None, description="Timestamp when mitigation completed"
    )
    reboot_required: bool | None = Field(
        None, description="Whether mitigation requires reboot"
    )
    categories: list[str] | None = Field(
        None, description="Indicator categories associated with threat"
    )
    mitre_tactics: list[str] | None = Field(
        None, description="MITRE ATT&CK tactics mapped to threat"
    )
    mitre_techniques: list[str] | None = Field(
        None, description="MITRE ATT&CK techniques mapped to threat"
    )
    indicators: list[str] | None = Field(
        None, description="Descriptive indicators linked to the threat"
    )
    c2_domains: list[str] | None = Field(
        None, description="Command-and-control domains or endpoints"
    )
    source_ips: list[str] | None = Field(
        None, description="Source IP addresses involved in the threat"
    )
    quarantine_status: str | None = Field(
        None, description="Current quarantine status of the asset"
    )


class ConfigurationDrift(BaseModel):
    """Configuration drift from baseline."""

    config_key: str
    expected_value: Any
    actual_value: Any
    drift_type: str  # modified, missing, added


class ProcessSnapshot(BaseModel):
    """Process state captured on the endpoint."""

    pid: int = Field(..., description="Process identifier")
    parent_pid: int | None = Field(None, description="Parent process identifier")
    name: str = Field(..., description="Executable name")
    command: str | None = Field(None, description="Full command line")
    binary_hash: str | None = Field(
        None,
        description="SHA256 hash of the executable binary",
    )
    user: str | None = Field(None, description="Owning user account")
    start_time: datetime | None = Field(None, description="Process start time")
    integrity_level: str | None = Field(
        None, description="Integrity level or sandbox tier"
    )
    network_ports: list[int] | None = Field(
        None,
        description="Local ports opened by this process",
    )


class NetworkConnection(BaseModel):
    """Network connection snapshot."""

    protocol: str = Field(..., description="Protocol (tcp, udp, unix)")
    local_address: str = Field(..., description="Local IP or path")
    local_port: int = Field(..., description="Local port or 0 for unix sockets")
    remote_address: str | None = Field(None, description="Remote IP if applicable")
    remote_port: int | None = Field(None, description="Remote port")
    status: str | None = Field(
        None, description="Connection state (LISTEN, ESTABLISHED, etc.)"
    )
    process_id: int | None = Field(None, description="Owning process identifier")


class SoftwarePackage(BaseModel):
    """Installed software inventory entry."""

    name: str
    version: str
    source: str | None = Field(None, description="Package manager or installer")
    install_time: datetime | None = Field(None, description="Installation timestamp")
    vendor: str | None = Field(None, description="Software vendor if known")
    signature: dict[str, Any] | None = Field(
        None,
        description="Digital signature metadata (subject, issuer, status)",
    )


class AgentHealth(BaseModel):
    """Agent self-reported health information."""

    status: str = Field(
        ..., description="Status indicator: healthy, degraded, or error"
    )
    last_heartbeat: datetime = Field(
        ..., description="Timestamp of last successful heartbeat"
    )
    issues: list[str] | None = Field(None, description="Outstanding health issues")


class HostTelemetry(BaseModel):
    """Endpoint telemetry emitted by the Cerebro desktop agent."""

    organization: str | None = Field(
        None,
        description="Owning organization name; defaults to endpoint-devices if omitted",
    )
    site: str | None = Field(None, description="Location or business unit tag")
    host_id: str = Field(..., description="Stable host identifier (UUID, device ID)")
    hostname: str = Field(..., description="System hostname")
    serial_number: str | None = Field(None, description="Hardware serial number")
    agent_version: str = Field(..., description="Desktop agent version")
    os_family: str = Field(
        ..., description="Operating system family (windows, darwin, linux)"
    )
    os_version: str | None = Field(None, description="Operating system version")
    kernel_version: str | None = Field(None, description="Kernel or build version")
    architecture: str | None = Field(None, description="CPU architecture")
    collected_at: datetime = Field(..., description="Collection timestamp")

    ip_addresses: list[str] = Field(
        default_factory=list, description="Observed IP addresses"
    )
    mac_addresses: list[str] | None = Field(None, description="MAC addresses")
    logged_in_users: list[str] | None = Field(
        None, description="Interactive users at collection time"
    )
    tags: dict[str, str] | None = Field(
        None, description="Arbitrary device metadata tags"
    )

    health: AgentHealth | None = Field(None, description="Agent health snapshot")
    processes: list[ProcessSnapshot] = Field(
        default_factory=list, description="Active process inventory"
    )
    network_connections: list[NetworkConnection] | None = Field(
        None,
        description="Active network connections",
    )
    installed_packages: list[SoftwarePackage] | None = Field(
        None,
        description="Installed software inventory",
    )
    security_events: list[SecurityEvent] | None = Field(
        None,
        description="Security-relevant events observed on the host",
    )
    configuration_drift: list[ConfigurationDrift] | None = Field(
        None,
        description="Detected configuration drift items",
    )
    threats: list[EndpointThreat] | None = Field(
        None,
        description="Active or recently observed threats reported by security sensors",
    )


class HostEvent(BaseModel):
    """Discrete host event emitted by the desktop agent."""

    event_id: UUID | None = Field(
        None, description="Unique identifier for the event"
    )
    host_id: str = Field(..., description="Host identifier associated with the event")
    hostname: str | None = Field(
        None, description="Host name associated with the event"
    )
    category: str = Field(
        ..., description="Logical category for the event (process, network, etc.)"
    )
    event_type: str = Field(..., description="Specific event type name")
    severity: str | None = Field(
        None, description="Severity label (info, high, etc.)"
    )
    timestamp: datetime = Field(..., description="Timestamp recorded by the agent")
    process_id: int | None = Field(
        None, description="Process identifier if relevant"
    )
    parent_pid: int | None = Field(None, description="Parent process identifier")
    user: str | None = Field(None, description="User associated with the event")
    command_line: str | None = Field(
        None, description="Command line for process events"
    )
    source: str = Field(..., description="Collector source that produced the event")
    payload: dict[str, Any] | None = Field(
        None, description="Arbitrary event metadata"
    )


class HostEventBatch(BaseModel):
    """Batch transport envelope for host events."""

    host_id: str = Field(..., description="Host identifier")
    hostname: str | None = Field(None, description="Host name")
    organization: str | None = Field(None, description="Organization identifier")
    site: str | None = Field(None, description="Optional site/location tag")
    agent_version: str = Field(..., description="Agent version transmitting the batch")
    collected_at: datetime = Field(..., description="Batch collection timestamp")
    events: list[HostEvent] = Field(
        ..., description="List of events included in the batch"
    )


class ArtifactTaskDefinition(BaseModel):
    """Task specification delivered to an endpoint agent via artifact packs."""

    task_id: UUID = Field(..., description="Unique identifier for the artifact task")
    name: str = Field(..., description="Human readable task name")
    collector: str = Field(
        ..., description="Registered collector name the agent should execute"
    )
    interval_seconds: int | None = Field(
        None,
        description="Execution interval expressed in seconds; falls back to agent defaults when omitted",
    )
    tags: dict[str, str] | None = Field(
        None,
        description="Additional telemetry tags to annotate results emitted by this task",
    )
    config: dict[str, Any] | None = Field(
        None,
        description="Collector-specific configuration payload",
    )
    discovery: list[str] | None = Field(
        None,
        description="Discovery predicates evaluated by the agent before executing the task",
    )
    parameters: list[ArtifactTaskParameter] | None = Field(
        None,
        description="Parameter definitions expected by the collector",
    )
    parameter_values: dict[str, Any] | None = Field(
        None,
        description="Resolved parameter values provided by the control plane",
    )
    resources: ArtifactTaskResources | None = Field(
        None,
        description="Resource hints including timeouts and thresholds",
    )
    tools: list[ArtifactTool] | None = Field(
        None,
        description="Tool bundle metadata required by this task",
    )


class ArtifactTaskParameter(BaseModel):
    """Parameter metadata describing allowed values and defaults."""

    name: str = Field(..., description="Parameter name")
    type: str | None = Field(None, description="Parameter type hint")
    description: str | None = Field(None, description="Description of the parameter")
    default: Any | None = Field(
        None, description="Default value applied when not supplied"
    )
    required: bool | None = Field(
        None, description="Whether the parameter is required"
    )
    choices: list[str] | None = Field(
        None, description="Enumerated set of allowed values"
    )


class ArtifactTaskResources(BaseModel):
    """Resource limits and execution hints for a pack task."""

    timeout_seconds: int | None = Field(
        None, description="Max execution time for the task"
    )
    max_rows: int | None = Field(
        None, description="Maximum rows to collect before truncation"
    )
    max_upload_bytes: int | None = Field(None, description="Maximum bytes to upload")
    ops_per_second: int | None = Field(
        None, description="Suggested ops/second throttle"
    )


class ArtifactTool(BaseModel):
    """External tool dependency required by a pack task."""

    name: str = Field(..., description="Tool identifier")
    url: str | None = Field(None, description="Download URL for the tool")
    expected_hash: str | None = Field(
        None, description="Expected SHA256 hash of the tool"
    )
    serve_url: str | None = Field(
        None, description="Server-hosted URL when distributed centrally"
    )
    version: str | None = Field(None, description="Tool version identifier")


class ArtifactPackTrigger(BaseModel):
    trigger_id: UUID
    trigger_type: str
    match_value: str
    minimum_severity: str | None = None
    expires_after_seconds: int | None = None


class ArtifactPackTriggerCreate(BaseModel):
    trigger_type: str
    match_value: str
    minimum_severity: str | None = None
    expires_after_seconds: int | None = None


class ArtifactPackTaskCreate(BaseModel):
    name: str
    collector: str
    interval_seconds: int | None = None
    tags: dict[str, str] | None = None
    config: dict[str, Any] | None = None
    discovery: list[str] | None = None
    parameters: list[ArtifactTaskParameter] | None = None
    parameter_values: dict[str, Any] | None = None
    resources: ArtifactTaskResources | None = None
    tools: list[ArtifactTool] | None = None


class ArtifactPackCreate(BaseModel):
    name: str
    version: str | None = None
    description: str | None = None
    selectors: dict[str, Any] | None = None
    enabled: bool = True
    approval_state: str | None = None
    approval_notes: str | None = None
    schedule_interval_seconds: int | None = None
    tasks: list[ArtifactPackTaskCreate]
    triggers: list[ArtifactPackTriggerCreate] | None = None


class ArtifactPackUpdate(BaseModel):
    name: str | None = None
    version: str | None = None
    description: str | None = None
    selectors: dict[str, Any] | None = None
    enabled: bool | None = None
    approval_state: str | None = None
    approval_notes: str | None = None
    schedule_interval_seconds: int | None = None
    tasks: list[ArtifactPackTaskCreate] | None = None
    triggers: list[ArtifactPackTriggerCreate] | None = None


class ArtifactPackDefinition(BaseModel):
    """Pack definition returned to agents based on eligibility selectors."""

    pack_id: UUID = Field(..., description="Identifier for the artifact pack")
    name: str = Field(..., description="Pack name")
    version: str | None = Field(
        None, description="Semantic version of the pack contents"
    )
    description: str | None = Field(
        None, description="Short description of the pack purpose"
    )
    selectors: dict[str, Any] | None = Field(
        None,
        description="Selector criteria (tags, sites, OS families) used to target eligible agents",
    )
    tasks: list[ArtifactTaskDefinition] = Field(
        ..., description="Task definitions included in the pack"
    )
    enabled: bool = Field(
        True, description="Whether the pack is active for distribution"
    )
    approval_state: str = Field(
        "draft", description="Approval workflow state for the pack"
    )
    approval_notes: str | None = Field(
        None, description="Reviewer notes attached to the pack"
    )
    schedule_interval_seconds: int | None = Field(
        None, description="Optional recurring schedule for the pack"
    )
    last_deployed_at: datetime | None = Field(
        None, description="Timestamp of the most recent deployment"
    )
    triggers: list[ArtifactPackTrigger] | None = Field(
        None, description="Automation triggers associated with the pack"
    )


class RuntimeTelemetry(BaseModel):
    """Runtime telemetry from application."""

    service: str = Field(..., description="Service name")
    environment: str = Field(..., description="Environment (prod, staging, dev)")
    instance_id: str | None = None
    timestamp: datetime

    security_events: list[SecurityEvent] | None = None
    configuration_drift: list[ConfigurationDrift] | None = None
    health_metrics: dict[str, Any] | None = None
    active_vulnerabilities: list[str] | None = None


class ComplianceEvidence(BaseModel):
    """Compliance evidence collected from repository."""

    repository: str
    framework: str = Field(..., description="soc2, iso27001, etc.")
    collected_at: datetime
    evidence: dict[str, Any] = Field(..., description="Control-mapped evidence")


class DependencyGraph(BaseModel):
    """Complete dependency graph including transitive dependencies."""

    repository: str
    timestamp: datetime
    dependency_graph: dict[str, Any]
    licenses: dict[str, Any]
    vulnerabilities: list[DependencyVulnerability]


class FrontendObservationTelemetry(BaseModel):
    """Telemetry emitted from the Cerebro frontend during analyst workflows."""

    event_type: str = Field(..., description="Classifier for the user interaction")
    component: str | None = Field(
        None, description="UI component emitting the telemetry"
    )
    agent_session_id: UUID | None = Field(
        None,
        description="Optional agent session identifier tied to the observation",
    )
    context: dict[str, Any] | None = Field(
        None,
        description="Lightweight context describing the analyst state (filters, scopes)",
    )
    metadata: dict[str, Any] | None = Field(
        None,
        description="Arbitrary metadata payload relevant to the event",
    )
    occurred_at: datetime | None = Field(
        None,
        description="Timestamp when the observation took place (defaults to request time)",
    )
