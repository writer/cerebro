package sentinelone

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/writer/cerebro/internal/primitives"
)

var sentinelOneEmailPattern = regexp.MustCompile(`(?i)^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}$`)

// agentRecord captures fields returned by /web/api/v2.1/agents.
type agentRecord struct {
	agentIdentityRecord
	agentLifecycleRecord
	agentStatusRecord
	agentHardwareRecord
	agentLocationRecord
	agentTagsRecord
	raw json.RawMessage
}

type agentIdentityRecord struct {
	ID           string `json:"id"`
	AccountID    string `json:"accountId"`
	AccountName  string `json:"accountName"`
	ComputerName string `json:"computerName"`
	UUID         string `json:"uuid"`
	ExternalID   string `json:"externalId"`
	ModelName    string `json:"modelName"`
	SerialNumber string `json:"serialNumber"`
}

type agentLifecycleRecord struct {
	CreatedAt              string `json:"createdAt"`
	UpdatedAt              string `json:"updatedAt"`
	RegisteredAt           string `json:"registeredAt"`
	LastActiveDate         string `json:"lastActiveDate"`
	LastSuccessfulScanDate string `json:"lastSuccessfulScanDate"`
	AgentVersion           string `json:"agentVersion"`
	IsUpToDate             bool   `json:"isUpToDate"`
	InstallerType          string `json:"installerType"`
}

type agentStatusRecord struct {
	IsActive                 bool          `json:"isActive"`
	IsDecommissioned         bool          `json:"isDecommissioned"`
	IsPendingUninstall       bool          `json:"isPendingUninstall"`
	IsUninstalled            bool          `json:"isUninstalled"`
	Infected                 bool          `json:"infected"`
	ActiveThreats            int           `json:"activeThreats"`
	FirewallEnabled          *flexibleBool `json:"firewallEnabled"`
	NetworkStatus            string        `json:"networkStatus"`
	OperationalState         string        `json:"operationalState"`
	ScanStatus               string        `json:"scanStatus"`
	MitigationMode           string        `json:"mitigationMode"`
	MitigationModeSuspicious string        `json:"mitigationModeSuspicious"`
	DetectionState           string        `json:"detectionState"`
	AppsVulnerabilityStatus  string        `json:"appsVulnerabilityStatus"`
	ShowAlertIcon            bool          `json:"showAlertIcon"`
	InRemoteShellSession     bool          `json:"inRemoteShellSession"`
}

type agentHardwareRecord struct {
	CoreCount   int    `json:"coreCount"`
	CPUCount    int    `json:"cpuCount"`
	MachineType string `json:"machineType"`
	OSArch      string `json:"osArch"`
	OSName      string `json:"osName"`
	OSRevision  string `json:"osRevision"`
	OSType      string `json:"osType"`
	OSUsername  string `json:"osUsername"`
	TotalMemory int    `json:"totalMemory"`
	LicenseKey  string `json:"licenseKey"`
}

type agentLocationRecord struct {
	Domain               string `json:"domain"`
	ExternalIP           string `json:"externalIp"`
	GroupID              string `json:"groupId"`
	GroupName            string `json:"groupName"`
	GroupIP              string `json:"groupIp"`
	LastIPToMgmt         string `json:"lastIpToMgmt"`
	LastLoggedInUserName string `json:"lastLoggedInUserName"`
	SiteID               string `json:"siteId"`
	SiteName             string `json:"siteName"`
	StorageName          string `json:"storageName"`
	StorageType          string `json:"storageType"`
	RebootRequired       bool   `json:"rebootRequired"`
}

type agentTagsRecord struct {
	Tags              map[string]any `json:"tags"`
	UserActionsNeeded []string       `json:"userActionsNeeded"`
}

func (r *agentRecord) setRaw(raw json.RawMessage) { r.raw = raw }
func (r *agentRecord) rawBytes() json.RawMessage  { return r.raw }

type agentDetectionInfoRecord struct {
	AccountID                 string `json:"accountId"`
	AccountName               string `json:"accountName"`
	AgentDetectionState       string `json:"agentDetectionState"`
	AgentDomain               string `json:"agentDomain"`
	AgentIPV4                 string `json:"agentIpV4"`
	AgentIPV6                 string `json:"agentIpV6"`
	AgentLastLoggedInUserMail string `json:"agentLastLoggedInUserMail"`
	AgentLastLoggedInUserName string `json:"agentLastLoggedInUserName"`
	AgentMitigationMode       string `json:"agentMitigationMode"`
	AgentOSName               string `json:"agentOsName"`
	AgentOSRevision           string `json:"agentOsRevision"`
	AgentRegisteredAt         string `json:"agentRegisteredAt"`
	AgentUUID                 string `json:"agentUuid"`
	AgentVersion              string `json:"agentVersion"`
	ExternalIP                string `json:"externalIp"`
	GroupID                   string `json:"groupId"`
	GroupName                 string `json:"groupName"`
	SiteID                    string `json:"siteId"`
	SiteName                  string `json:"siteName"`
}

type agentRealtimeInfoRecord struct {
	agentRealtimeIdentity
	agentRealtimeStatus
}

type agentRealtimeIdentity struct {
	AccountID         string `json:"accountId"`
	AccountName       string `json:"accountName"`
	AgentComputerName string `json:"agentComputerName"`
	AgentDomain       string `json:"agentDomain"`
	AgentID           string `json:"agentId"`
	AgentMachineType  string `json:"agentMachineType"`
	AgentUUID         string `json:"agentUuid"`
	AgentVersion      string `json:"agentVersion"`
	GroupID           string `json:"groupId"`
	GroupName         string `json:"groupName"`
	SiteID            string `json:"siteId"`
	SiteName          string `json:"siteName"`
	StorageName       string `json:"storageName"`
}

type agentRealtimeStatus struct {
	ActiveThreats         int    `json:"activeThreats"`
	AgentInfected         bool   `json:"agentInfected"`
	AgentIsActive         bool   `json:"agentIsActive"`
	AgentIsDecommissioned bool   `json:"agentIsDecommissioned"`
	AgentMitigationMode   string `json:"agentMitigationMode"`
	AgentNetworkStatus    string `json:"agentNetworkStatus"`
	AgentOSName           string `json:"agentOsName"`
	AgentOSRevision       string `json:"agentOsRevision"`
	AgentOSType           string `json:"agentOsType"`
	OperationalState      string `json:"operationalState"`
	RebootRequired        bool   `json:"rebootRequired"`
	ScanStatus            string `json:"scanStatus"`
}

// payloads -- emitted JSON shapes for agents.

type agentPayload struct {
	agentIdentityPayload
	agentLifecyclePayloadFields
	agentStatusPayload
	agentLocationPayload
	TenantHost string         `json:"tenant_host"`
	Tags       map[string]any `json:"tags,omitempty"`
	Raw        map[string]any `json:"raw,omitempty"`
}

type agentIdentityPayload struct {
	ID           string `json:"id"`
	ComputerName string `json:"computer_name"`
	Hostname     string `json:"hostname,omitempty"`
	UUID         string `json:"uuid,omitempty"`
	AccountID    string `json:"account_id,omitempty"`
	AccountName  string `json:"account_name,omitempty"`
	ModelName    string `json:"model_name,omitempty"`
	SerialNumber string `json:"serial_number,omitempty"`
	MachineType  string `json:"machine_type,omitempty"`
	OSName       string `json:"os_name,omitempty"`
	OSType       string `json:"os_type,omitempty"`
	OSArch       string `json:"os_arch,omitempty"`
	OSRevision   string `json:"os_revision,omitempty"`
}

type agentLifecyclePayloadFields struct {
	AgentVersion       string `json:"agent_version,omitempty"`
	LastActiveDate     string `json:"last_active_date,omitempty"`
	LastSuccessfulScan string `json:"last_successful_scan_at,omitempty"`
	RegisteredAt       string `json:"registered_at,omitempty"`
	CreatedAt          string `json:"created_at,omitempty"`
	UpdatedAt          string `json:"updated_at,omitempty"`
}

type agentStatusPayload struct {
	IsActive           bool     `json:"is_active"`
	IsDecommissioned   bool     `json:"is_decommissioned"`
	IsUpToDate         bool     `json:"is_up_to_date"`
	IsUninstalled      bool     `json:"is_uninstalled"`
	IsPendingUninstall bool     `json:"is_pending_uninstall"`
	Infected           bool     `json:"is_infected"`
	ActiveThreats      int      `json:"active_threats"`
	NetworkStatus      string   `json:"network_status,omitempty"`
	OperationalState   string   `json:"operational_state,omitempty"`
	MitigationMode     string   `json:"mitigation_mode,omitempty"`
	UserActionsNeeded  []string `json:"user_actions_needed,omitempty"`
}

type agentLocationPayload struct {
	Domain       string `json:"domain,omitempty"`
	ExternalIP   string `json:"external_ip,omitempty"`
	GroupIP      string `json:"group_ip,omitempty"`
	IP           string `json:"ip,omitempty"`
	IPAddresses  string `json:"ip_addresses,omitempty"`
	LastIPToMgmt string `json:"last_ip_to_mgmt,omitempty"`
	GroupID      string `json:"group_id,omitempty"`
	GroupName    string `json:"group_name,omitempty"`
	SiteID       string `json:"site_id,omitempty"`
	SiteName     string `json:"site_name,omitempty"`
	UserName     string `json:"user_name,omitempty"`
}

// event builders

func agentEvent(s settings, record agentRecord) (*primitives.Event, error) {
	occurredAt := eventOccurredAt(
		parseTimestamp(record.UpdatedAt),
		parseTimestamp(record.LastActiveDate),
		parseTimestamp(record.CreatedAt),
		parseTimestamp(record.RegisteredAt),
	)
	raw, err := decodeRaw(record.raw, "sentinelone agent")
	if err != nil {
		return nil, err
	}
	payload, err := json.Marshal(agentPayload{
		agentIdentityPayload: agentIdentityPayload{
			ID:           record.ID,
			ComputerName: record.ComputerName,
			Hostname:     record.ComputerName,
			UUID:         record.UUID,
			AccountID:    record.AccountID,
			AccountName:  record.AccountName,
			ModelName:    record.ModelName,
			SerialNumber: record.SerialNumber,
			MachineType:  record.MachineType,
			OSName:       record.OSName,
			OSType:       record.OSType,
			OSArch:       record.OSArch,
			OSRevision:   record.OSRevision,
		},
		agentLifecyclePayloadFields: agentLifecyclePayloadFields{
			AgentVersion:       record.AgentVersion,
			LastActiveDate:     record.LastActiveDate,
			LastSuccessfulScan: record.LastSuccessfulScanDate,
			RegisteredAt:       record.RegisteredAt,
			CreatedAt:          record.CreatedAt,
			UpdatedAt:          record.UpdatedAt,
		},
		agentStatusPayload: agentStatusPayload{
			IsActive:           record.IsActive,
			IsDecommissioned:   record.IsDecommissioned,
			IsUpToDate:         record.IsUpToDate,
			IsUninstalled:      record.IsUninstalled,
			IsPendingUninstall: record.IsPendingUninstall,
			Infected:           record.Infected,
			ActiveThreats:      record.ActiveThreats,
			NetworkStatus:      record.NetworkStatus,
			OperationalState:   record.OperationalState,
			MitigationMode:     record.MitigationMode,
			UserActionsNeeded:  record.UserActionsNeeded,
		},
		agentLocationPayload: agentLocationPayload{
			Domain:       record.Domain,
			ExternalIP:   record.ExternalIP,
			GroupIP:      record.GroupIP,
			IP:           firstNonEmpty(record.ExternalIP, record.LastIPToMgmt, record.GroupIP),
			IPAddresses:  joinedEndpointIPs(record.ExternalIP, record.LastIPToMgmt, record.GroupIP),
			LastIPToMgmt: record.LastIPToMgmt,
			GroupID:      record.GroupID,
			GroupName:    record.GroupName,
			SiteID:       record.SiteID,
			SiteName:     record.SiteName,
			UserName:     sentinelOneAgentUserName(record),
		},
		TenantHost: s.host,
		Tags:       record.Tags,
		Raw:        raw,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal sentinelone agent payload: %w", err)
	}
	return &primitives.Event{
		Id:         eventID("sentinelone-agent", s, record.ID),
		TenantId:   s.host,
		SourceId:   "sentinelone",
		Kind:       "sentinelone.agent",
		OccurredAt: toTimestamp(occurredAt),
		SchemaRef:  "sentinelone/agent/v1",
		Payload:    payload,
		Attributes: agentAttributes(s, record),
	}, nil
}

func agentAttributes(s settings, record agentRecord) map[string]string {
	attrs := map[string]string{
		"family":               familyAgent,
		"agent_id":             record.ID,
		"tenant_host":          s.host,
		"is_active":            boolString(record.IsActive),
		"is_decommissioned":    boolString(record.IsDecommissioned),
		"is_uninstalled":       boolString(record.IsUninstalled),
		"is_pending_uninstall": boolString(record.IsPendingUninstall),
		"is_up_to_date":        boolString(record.IsUpToDate),
		"infected":             boolString(record.Infected),
		"active_threats":       intToString(record.ActiveThreats),
	}
	if record.FirewallEnabled != nil {
		attrs["firewall_enabled"] = boolString(bool(*record.FirewallEnabled))
	}
	addAttribute(attrs, "computer_name", record.ComputerName)
	addAttribute(attrs, "hostname", record.ComputerName)
	addAttribute(attrs, "uuid", record.UUID)
	addAttribute(attrs, "os_name", record.OSName)
	addAttribute(attrs, "os_type", record.OSType)
	addAttribute(attrs, "os_arch", record.OSArch)
	addAttribute(attrs, "os_revision", record.OSRevision)
	addAttribute(attrs, "agent_version", record.AgentVersion)
	addAttribute(attrs, "last_active_date", record.LastActiveDate)
	addAttribute(attrs, "registered_at", record.RegisteredAt)
	addAttribute(attrs, "domain", record.Domain)
	addAttribute(attrs, "external_ip", record.ExternalIP)
	addAttribute(attrs, "group_ip", record.GroupIP)
	addAttribute(attrs, "ip", firstNonEmpty(record.ExternalIP, record.LastIPToMgmt, record.GroupIP))
	addAttribute(attrs, "ip_addresses", joinedEndpointIPs(record.ExternalIP, record.LastIPToMgmt, record.GroupIP))
	addAttribute(attrs, "last_ip_to_mgmt", record.LastIPToMgmt)
	addAttribute(attrs, "site_id", record.SiteID)
	addAttribute(attrs, "site_name", record.SiteName)
	addAttribute(attrs, "group_id", record.GroupID)
	addAttribute(attrs, "group_name", record.GroupName)
	userName := sentinelOneAgentUserName(record)
	addAttribute(attrs, "user_name", userName)
	addAttribute(attrs, "user_email", sentinelOneEmailLike(userName))
	addAttribute(attrs, "account_id", record.AccountID)
	addAttribute(attrs, "account_name", record.AccountName)
	addAttribute(attrs, "machine_type", record.MachineType)
	addAttribute(attrs, "model_name", record.ModelName)
	addAttribute(attrs, "serial_number", record.SerialNumber)
	addAttribute(attrs, "operational_state", record.OperationalState)
	addAttribute(attrs, "network_status", record.NetworkStatus)
	addAttribute(attrs, "mitigation_mode", record.MitigationMode)
	if len(record.UserActionsNeeded) != 0 {
		attrs["user_actions_needed"] = strings.Join(record.UserActionsNeeded, ",")
	}
	return attrs
}

func sentinelOneAgentUserName(record agentRecord) string {
	return firstNonEmpty(record.LastLoggedInUserName, record.OSUsername)
}

func sentinelOneEmailLike(value string) string {
	trimmed := strings.TrimSpace(value)
	if sentinelOneEmailPattern.MatchString(trimmed) {
		return strings.ToLower(trimmed)
	}
	return ""
}
