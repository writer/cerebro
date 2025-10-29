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


class ProcessSnapshot(BaseModel):
    """Process state captured on the endpoint."""

    pid: int = Field(..., description="Process identifier")
    parent_pid: Optional[int] = Field(None, description="Parent process identifier")
    name: str = Field(..., description="Executable name")
    command: Optional[str] = Field(None, description="Full command line")
    binary_hash: Optional[str] = Field(
        None,
        description="SHA256 hash of the executable binary",
    )
    user: Optional[str] = Field(None, description="Owning user account")
    start_time: Optional[datetime] = Field(None, description="Process start time")
    integrity_level: Optional[str] = Field(None, description="Integrity level or sandbox tier")
    network_ports: Optional[List[int]] = Field(
        None,
        description="Local ports opened by this process",
    )


class NetworkConnection(BaseModel):
    """Network connection snapshot."""

    protocol: str = Field(..., description="Protocol (tcp, udp, unix)")
    local_address: str = Field(..., description="Local IP or path")
    local_port: int = Field(..., description="Local port or 0 for unix sockets")
    remote_address: Optional[str] = Field(None, description="Remote IP if applicable")
    remote_port: Optional[int] = Field(None, description="Remote port")
    status: Optional[str] = Field(None, description="Connection state (LISTEN, ESTABLISHED, etc.)")
    process_id: Optional[int] = Field(None, description="Owning process identifier")


class SoftwarePackage(BaseModel):
    """Installed software inventory entry."""

    name: str
    version: str
    source: Optional[str] = Field(None, description="Package manager or installer")
    install_time: Optional[datetime] = Field(None, description="Installation timestamp")
    vendor: Optional[str] = Field(None, description="Software vendor if known")
    signature: Optional[Dict[str, Any]] = Field(
        None,
        description="Digital signature metadata (subject, issuer, status)",
    )


class AgentHealth(BaseModel):
    """Agent self-reported health information."""

    status: str = Field(..., description="Status indicator: healthy, degraded, or error")
    last_heartbeat: datetime = Field(..., description="Timestamp of last successful heartbeat")
    issues: Optional[List[str]] = Field(None, description="Outstanding health issues")


class HostTelemetry(BaseModel):
    """Endpoint telemetry emitted by the Cerebro desktop agent."""

    organization: Optional[str] = Field(
        None,
        description="Owning organization name; defaults to endpoint-devices if omitted",
    )
    site: Optional[str] = Field(None, description="Location or business unit tag")
    host_id: str = Field(..., description="Stable host identifier (UUID, device ID)")
    hostname: str = Field(..., description="System hostname")
    serial_number: Optional[str] = Field(None, description="Hardware serial number")
    agent_version: str = Field(..., description="Desktop agent version")
    os_family: str = Field(..., description="Operating system family (windows, darwin, linux)")
    os_version: Optional[str] = Field(None, description="Operating system version")
    kernel_version: Optional[str] = Field(None, description="Kernel or build version")
    architecture: Optional[str] = Field(None, description="CPU architecture")
    collected_at: datetime = Field(..., description="Collection timestamp")

    ip_addresses: List[str] = Field(default_factory=list, description="Observed IP addresses")
    mac_addresses: Optional[List[str]] = Field(None, description="MAC addresses")
    logged_in_users: Optional[List[str]] = Field(None, description="Interactive users at collection time")
    tags: Optional[Dict[str, str]] = Field(None, description="Arbitrary device metadata tags")

    health: Optional[AgentHealth] = Field(None, description="Agent health snapshot")
    processes: List[ProcessSnapshot] = Field(default_factory=list, description="Active process inventory")
    network_connections: Optional[List[NetworkConnection]] = Field(
        None,
        description="Active network connections",
    )
    installed_packages: Optional[List[SoftwarePackage]] = Field(
        None,
        description="Installed software inventory",
    )
    security_events: Optional[List[SecurityEvent]] = Field(
        None,
        description="Security-relevant events observed on the host",
    )
    configuration_drift: Optional[List[ConfigurationDrift]] = Field(
        None,
        description="Detected configuration drift items",
    )


class HostEvent(BaseModel):
    """Discrete host event emitted by the desktop agent."""

    event_id: Optional[UUID] = Field(None, description="Unique identifier for the event")
    host_id: str = Field(..., description="Host identifier associated with the event")
    hostname: Optional[str] = Field(None, description="Host name associated with the event")
    category: str = Field(..., description="Logical category for the event (process, network, etc.)")
    event_type: str = Field(..., description="Specific event type name")
    severity: Optional[str] = Field(None, description="Severity label (info, high, etc.)")
    timestamp: datetime = Field(..., description="Timestamp recorded by the agent")
    process_id: Optional[int] = Field(None, description="Process identifier if relevant")
    parent_pid: Optional[int] = Field(None, description="Parent process identifier")
    user: Optional[str] = Field(None, description="User associated with the event")
    command_line: Optional[str] = Field(None, description="Command line for process events")
    source: str = Field(..., description="Collector source that produced the event")
    payload: Optional[Dict[str, Any]] = Field(None, description="Arbitrary event metadata")


class HostEventBatch(BaseModel):
    """Batch transport envelope for host events."""

    host_id: str = Field(..., description="Host identifier")
    hostname: Optional[str] = Field(None, description="Host name")
    organization: Optional[str] = Field(None, description="Organization identifier")
    site: Optional[str] = Field(None, description="Optional site/location tag")
    agent_version: str = Field(..., description="Agent version transmitting the batch")
    collected_at: datetime = Field(..., description="Batch collection timestamp")
    events: List[HostEvent] = Field(..., description="List of events included in the batch")


class ArtifactTaskDefinition(BaseModel):
    """Task specification delivered to an endpoint agent via artifact packs."""

    task_id: UUID = Field(..., description="Unique identifier for the artifact task")
    name: str = Field(..., description="Human readable task name")
    collector: str = Field(..., description="Registered collector name the agent should execute")
    interval_seconds: Optional[int] = Field(
        None,
        description="Execution interval expressed in seconds; falls back to agent defaults when omitted",
    )
    tags: Optional[Dict[str, str]] = Field(
        None,
        description="Additional telemetry tags to annotate results emitted by this task",
    )
    config: Optional[Dict[str, Any]] = Field(
        None,
        description="Collector-specific configuration payload",
    )
    discovery: Optional[List[str]] = Field(
        None,
        description="Discovery predicates evaluated by the agent before executing the task",
    )
    parameters: Optional[List["ArtifactTaskParameter"]] = Field(
        None,
        description="Parameter definitions expected by the collector",
    )
    parameter_values: Optional[Dict[str, Any]] = Field(
        None,
        description="Resolved parameter values provided by the control plane",
    )
    resources: Optional["ArtifactTaskResources"] = Field(
        None,
        description="Resource hints including timeouts and thresholds",
    )
    tools: Optional[List["ArtifactTool"]] = Field(
        None,
        description="Tool bundle metadata required by this task",
    )


class ArtifactTaskParameter(BaseModel):
    """Parameter metadata describing allowed values and defaults."""

    name: str = Field(..., description="Parameter name")
    type: Optional[str] = Field(None, description="Parameter type hint")
    description: Optional[str] = Field(None, description="Description of the parameter")
    default: Optional[Any] = Field(None, description="Default value applied when not supplied")
    required: Optional[bool] = Field(None, description="Whether the parameter is required")
    choices: Optional[List[str]] = Field(None, description="Enumerated set of allowed values")


class ArtifactTaskResources(BaseModel):
    """Resource limits and execution hints for a pack task."""

    timeout_seconds: Optional[int] = Field(None, description="Max execution time for the task")
    max_rows: Optional[int] = Field(None, description="Maximum rows to collect before truncation")
    max_upload_bytes: Optional[int] = Field(None, description="Maximum bytes to upload")
    ops_per_second: Optional[int] = Field(None, description="Suggested ops/second throttle")


class ArtifactTool(BaseModel):
    """External tool dependency required by a pack task."""

    name: str = Field(..., description="Tool identifier")
    url: Optional[str] = Field(None, description="Download URL for the tool")
    expected_hash: Optional[str] = Field(None, description="Expected SHA256 hash of the tool")
    serve_url: Optional[str] = Field(None, description="Server-hosted URL when distributed centrally")
    version: Optional[str] = Field(None, description="Tool version identifier")


class ArtifactPackTrigger(BaseModel):
    trigger_id: UUID
    trigger_type: str
    match_value: str
    minimum_severity: Optional[str] = None
    expires_after_seconds: Optional[int] = None


class ArtifactPackTriggerCreate(BaseModel):
    trigger_type: str
    match_value: str
    minimum_severity: Optional[str] = None
    expires_after_seconds: Optional[int] = None


class ArtifactPackTaskCreate(BaseModel):
    name: str
    collector: str
    interval_seconds: Optional[int] = None
    tags: Optional[Dict[str, str]] = None
    config: Optional[Dict[str, Any]] = None
    discovery: Optional[List[str]] = None
    parameters: Optional[List[ArtifactTaskParameter]] = None
    parameter_values: Optional[Dict[str, Any]] = None
    resources: Optional[ArtifactTaskResources] = None
    tools: Optional[List[ArtifactTool]] = None


class ArtifactPackCreate(BaseModel):
    name: str
    version: Optional[str] = None
    description: Optional[str] = None
    selectors: Optional[Dict[str, Any]] = None
    enabled: bool = True
    approval_state: Optional[str] = None
    approval_notes: Optional[str] = None
    schedule_interval_seconds: Optional[int] = None
    tasks: List[ArtifactPackTaskCreate]
    triggers: Optional[List[ArtifactPackTriggerCreate]] = None


class ArtifactPackUpdate(BaseModel):
    name: Optional[str] = None
    version: Optional[str] = None
    description: Optional[str] = None
    selectors: Optional[Dict[str, Any]] = None
    enabled: Optional[bool] = None
    approval_state: Optional[str] = None
    approval_notes: Optional[str] = None
    schedule_interval_seconds: Optional[int] = None
    tasks: Optional[List[ArtifactPackTaskCreate]] = None
    triggers: Optional[List[ArtifactPackTriggerCreate]] = None


class ArtifactPackDefinition(BaseModel):
    """Pack definition returned to agents based on eligibility selectors."""

    pack_id: UUID = Field(..., description="Identifier for the artifact pack")
    name: str = Field(..., description="Pack name")
    version: Optional[str] = Field(None, description="Semantic version of the pack contents")
    description: Optional[str] = Field(None, description="Short description of the pack purpose")
    selectors: Optional[Dict[str, Any]] = Field(
        None,
        description="Selector criteria (tags, sites, OS families) used to target eligible agents",
    )
    tasks: List[ArtifactTaskDefinition] = Field(..., description="Task definitions included in the pack")
    enabled: bool = Field(True, description="Whether the pack is active for distribution")
    approval_state: str = Field("draft", description="Approval workflow state for the pack")
    approval_notes: Optional[str] = Field(None, description="Reviewer notes attached to the pack")
    schedule_interval_seconds: Optional[int] = Field(None, description="Optional recurring schedule for the pack")
    last_deployed_at: Optional[datetime] = Field(None, description="Timestamp of the most recent deployment")
    triggers: Optional[List[ArtifactPackTrigger]] = Field(None, description="Automation triggers associated with the pack")

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

