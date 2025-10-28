package types

import "time"

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
}

type AgentHealth struct {
	Status        string    `json:"status"`
	LastHeartbeat time.Time `json:"last_heartbeat"`
	Issues        []string  `json:"issues,omitempty"`
}

type ProcessSnapshot struct {
	PID        int        `json:"pid"`
	ParentPID  int        `json:"parent_pid,omitempty"`
	Name       string     `json:"name"`
	Command    string     `json:"command,omitempty"`
	BinaryHash string     `json:"binary_hash,omitempty"`
	User       string     `json:"user,omitempty"`
	StartTime  *time.Time `json:"start_time,omitempty"`
}

type NetworkConnection struct {
	Protocol      string `json:"protocol"`
	LocalAddress  string `json:"local_address"`
	LocalPort     int    `json:"local_port"`
	RemoteAddress string `json:"remote_address,omitempty"`
	RemotePort    int    `json:"remote_port,omitempty"`
	Status        string `json:"status,omitempty"`
	ProcessID     int    `json:"process_id,omitempty"`
}

type SoftwarePackage struct {
	Name      string    `json:"name"`
	Version   string    `json:"version"`
	Source    string    `json:"source,omitempty"`
	InstallAt time.Time `json:"install_time,omitempty"`
	Vendor    string    `json:"vendor,omitempty"`
}

type SecurityEvent struct {
	EventType string         `json:"event_type"`
	Timestamp time.Time      `json:"timestamp"`
	Severity  string         `json:"severity"`
	SourceIP  string         `json:"source_ip,omitempty"`
	UserID    string         `json:"user_id,omitempty"`
	Details   map[string]any `json:"details"`
}

type ConfigurationDrift struct {
	ConfigKey     string `json:"config_key"`
	ExpectedValue any    `json:"expected_value"`
	ActualValue   any    `json:"actual_value"`
	DriftType     string `json:"drift_type"`
}

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

type HostEventBatch struct {
	HostID       string      `json:"host_id"`
	Hostname     string      `json:"hostname"`
	Organization string      `json:"organization,omitempty"`
	Site         string      `json:"site,omitempty"`
	AgentVersion string      `json:"agent_version"`
	CollectedAt  time.Time   `json:"collected_at"`
	Events       []HostEvent `json:"events"`
}
