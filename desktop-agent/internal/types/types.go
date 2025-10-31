package types

import "time"

// HostTelemetry captures a point-in-time snapshot of host state that the agent
// posts to Cerebro. It is deliberately broad to support multiple downstream
// use cases (inventory, drift, detection).
type HostTelemetry struct {
	Organization       string               `json:"organization,omitempty"`
	Site               string               `json:"site,omitempty"`
	HostID             string               `json:"host_id"`
	Hostname           string               `json:"hostname"`
	SerialNumber       string               `json:"serial_number,omitempty"`
	AgentVersion       string               `json:"agent_version"`
	OSFamily           string               `json:"os_family"`
	OSVersion          string               `json:"os_version,omitempty"`
	KernelVersion      string               `json:"kernel_version,omitempty"`
	Architecture       string               `json:"architecture,omitempty"`
	CollectedAt        time.Time            `json:"collected_at"`
	IPAddresses        []string             `json:"ip_addresses,omitempty"`
	MacAddresses       []string             `json:"mac_addresses,omitempty"`
	LoggedInUsers      []string             `json:"logged_in_users,omitempty"`
	Tags               map[string]string    `json:"tags,omitempty"`
	Health             *AgentHealth         `json:"health,omitempty"`
	Processes          []ProcessSnapshot    `json:"processes,omitempty"`
	NetworkConnections []NetworkConnection  `json:"network_connections,omitempty"`
	InstalledPackages  []SoftwarePackage    `json:"installed_packages,omitempty"`
	SecurityEvents     []SecurityEvent      `json:"security_events,omitempty"`
	ConfigurationDrift []ConfigurationDrift `json:"configuration_drift,omitempty"`
	SecuritySoftware   []SecuritySoftware   `json:"security_software,omitempty"`
}

// AgentHealth summarises the agent's liveness at collection time.
type AgentHealth struct {
	Status        string    `json:"status"`
	LastHeartbeat time.Time `json:"last_heartbeat"`
	Issues        []string  `json:"issues,omitempty"`
}

// ProcessSnapshot provides lightweight process metadata used in snapshots and
// delta calculations.
type ProcessSnapshot struct {
	PID        int        `json:"pid"`
	ParentPID  int        `json:"parent_pid,omitempty"`
	Name       string     `json:"name"`
	Command    string     `json:"command,omitempty"`
	BinaryHash string     `json:"binary_hash,omitempty"`
	User       string     `json:"user,omitempty"`
	StartTime  *time.Time `json:"start_time,omitempty"`
}

// NetworkConnection describes an active socket observed during snapshot
// collection.
type NetworkConnection struct {
	Protocol      string `json:"protocol"`
	LocalAddress  string `json:"local_address"`
	LocalPort     int    `json:"local_port"`
	RemoteAddress string `json:"remote_address,omitempty"`
	RemotePort    int    `json:"remote_port,omitempty"`
	Status        string `json:"status,omitempty"`
	ProcessID     int    `json:"process_id,omitempty"`
}

// SoftwarePackage records installed software for inventory use cases.
type SoftwarePackage struct {
	Name      string    `json:"name"`
	Version   string    `json:"version"`
	Source    string    `json:"source,omitempty"`
	InstallAt time.Time `json:"install_time,omitempty"`
	Vendor    string    `json:"vendor,omitempty"`
}

// SecurityEvent models host-level security events collected from the agent or
// operating system.
type SecurityEvent struct {
	EventType string         `json:"event_type"`
	Timestamp time.Time      `json:"timestamp"`
	Severity  string         `json:"severity"`
	SourceIP  string         `json:"source_ip,omitempty"`
	UserID    string         `json:"user_id,omitempty"`
	Details   map[string]any `json:"details"`
}

// SecuritySoftware describes third-party security agents discovered on the host.
type SecuritySoftware struct {
	Vendor      string            `json:"vendor"`
	Product     string            `json:"product"`
	Installed   bool              `json:"installed"`
	Running     bool              `json:"running"`
	InstallPath string            `json:"install_path,omitempty"`
	Notes       map[string]string `json:"notes,omitempty"`
}

// ConfigurationDrift captures deviations between expected and observed host
// settings.
type ConfigurationDrift struct {
	ConfigKey     string `json:"config_key"`
	ExpectedValue any    `json:"expected_value"`
	ActualValue   any    `json:"actual_value"`
	DriftType     string `json:"drift_type"`
}

// HostEvent represents an individual event emitted by an EventCollector.
type HostEvent struct {
	EventID     string         `json:"event_id,omitempty"`
	HostID      string         `json:"host_id"`
	Hostname    string         `json:"hostname"`
	Category    string         `json:"category"`
	EventType   string         `json:"event_type"`
	Severity    string         `json:"severity,omitempty"`
	Timestamp   time.Time      `json:"timestamp"`
	ProcessID   int            `json:"process_id,omitempty"`
	ParentPID   int            `json:"parent_pid,omitempty"`
	User        string         `json:"user,omitempty"`
	CommandLine string         `json:"command_line,omitempty"`
	Source      string         `json:"source"`
	Payload     map[string]any `json:"payload,omitempty"`
}

// HostEventBatch aggregates host events for transport to the backend.
type HostEventBatch struct {
	HostID       string      `json:"host_id"`
	Hostname     string      `json:"hostname"`
	Organization string      `json:"organization,omitempty"`
	Site         string      `json:"site,omitempty"`
	AgentVersion string      `json:"agent_version"`
	CollectedAt  time.Time   `json:"collected_at"`
	Events       []HostEvent `json:"events"`
}

// ArtifactTaskDefinition describes a single task assigned to the agent as part
// of an artifact pack.
type ArtifactTaskDefinition struct {
	TaskID          string                  `json:"task_id"`
	Name            string                  `json:"name"`
	Collector       string                  `json:"collector"`
	IntervalSeconds int                     `json:"interval_seconds,omitempty"`
	Tags            map[string]string       `json:"tags,omitempty"`
	Config          map[string]any          `json:"config,omitempty"`
	Discovery       []string                `json:"discovery,omitempty"`
	Parameters      []ArtifactTaskParameter `json:"parameters,omitempty"`
	ParameterValues map[string]any          `json:"parameter_values,omitempty"`
	Resources       *ArtifactTaskResources  `json:"resources,omitempty"`
	Tools           []ArtifactTool          `json:"tools,omitempty"`
}

// ArtifactPackDefinition bundles tasks and metadata that agents can schedule
// locally. It mirrors the backend schema for remote packs.
type ArtifactPackDefinition struct {
	PackID      string                   `json:"pack_id"`
	Name        string                   `json:"name"`
	Version     string                   `json:"version,omitempty"`
	Description string                   `json:"description,omitempty"`
	Selectors   map[string]any           `json:"selectors,omitempty"`
	Tasks       []ArtifactTaskDefinition `json:"tasks"`
}

// ArtifactTaskParameter defines a configurable parameter exposed to pack
// authors.
type ArtifactTaskParameter struct {
	Name        string   `json:"name"`
	Type        string   `json:"type,omitempty"`
	Description string   `json:"description,omitempty"`
	Default     any      `json:"default,omitempty"`
	Required    bool     `json:"required,omitempty"`
	Choices     []string `json:"choices,omitempty"`
}

// ArtifactTaskResources conveys resource hints to collectors (timeouts, row
// limits, throttling).
type ArtifactTaskResources struct {
	TimeoutSeconds int   `json:"timeout_seconds,omitempty"`
	MaxRows        int   `json:"max_rows,omitempty"`
	MaxUploadBytes int64 `json:"max_upload_bytes,omitempty"`
	OpsPerSecond   int   `json:"ops_per_second,omitempty"`
}

// ArtifactTool identifies optional supporting binaries that a task requires.
type ArtifactTool struct {
	Name         string `json:"name"`
	URL          string `json:"url,omitempty"`
	ExpectedHash string `json:"expected_hash,omitempty"`
	ServeURL     string `json:"serve_url,omitempty"`
	Version      string `json:"version,omitempty"`
}
