package sentinelone

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/primitives"
)

var sentinelOneEmailPattern = regexp.MustCompile(`(?i)^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}$`)

// raw types are used to capture the raw response body alongside the decoded fields so that
// downstream projection can read details that we did not statically model.

type rawCarrier interface {
	setRaw(json.RawMessage)
	rawBytes() json.RawMessage
}

type flexibleBool bool

func (b *flexibleBool) UnmarshalJSON(raw []byte) error {
	if strings.TrimSpace(string(raw)) == "null" {
		*b = false
		return nil
	}
	var value bool
	if err := json.Unmarshal(raw, &value); err == nil {
		*b = flexibleBool(value)
		return nil
	}
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		switch strings.ToLower(strings.TrimSpace(text)) {
		case "", "0", "false", "n", "no", "none", "null":
			*b = false
			return nil
		case "1", "true", "y", "yes":
			*b = true
			return nil
		default:
			*b = false
			return nil
		}
	}
	return fmt.Errorf("invalid bool value %s", string(raw))
}

type flexibleString string

func (s *flexibleString) UnmarshalJSON(raw []byte) error {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "null" {
		*s = ""
		return nil
	}
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		*s = flexibleString(text)
		return nil
	}
	var value any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return err
	}
	switch typed := value.(type) {
	case nil:
		*s = ""
	case bool:
		*s = flexibleString(fmt.Sprint(typed))
	case json.Number:
		*s = flexibleString(typed.String())
	default:
		var compact bytes.Buffer
		if err := json.Compact(&compact, raw); err != nil {
			return err
		}
		*s = flexibleString(compact.String())
	}
	return nil
}

// threatRecord captures the high-value fields returned by /web/api/v2.1/threats.
type threatRecord struct {
	ID                 string                   `json:"id"`
	ThreatInfo         threatInfoRecord         `json:"threatInfo"`
	AgentDetectionInfo agentDetectionInfoRecord `json:"agentDetectionInfo"`
	AgentRealtimeInfo  agentRealtimeInfoRecord  `json:"agentRealtimeInfo"`
	Indicators         []threatIndicatorRecord  `json:"indicators"`
	MitigationStatus   []mitigationStatusRecord `json:"mitigationStatus"`
	WhiteningOptions   []string                 `json:"whiteningOptions"`
	raw                json.RawMessage
}

func (r *threatRecord) setRaw(raw json.RawMessage) { r.raw = raw }
func (r *threatRecord) rawBytes() json.RawMessage  { return r.raw }

type threatInfoRecord struct {
	threatClassificationRecord
	threatLifecycleRecord
	threatFileRecord
}

type threatClassificationRecord struct {
	AnalystVerdict        string `json:"analystVerdict"`
	Classification        string `json:"classification"`
	ClassificationSource  string `json:"classificationSource"`
	ConfidenceLevel       string `json:"confidenceLevel"`
	IncidentStatus        string `json:"incidentStatus"`
	MitigationStatus      string `json:"mitigationStatus"`
	IsFileless            bool   `json:"isFileless"`
	ThreatName            string `json:"threatName"`
	DetectionType         string `json:"detectionType"`
	AutomaticallyResolved bool   `json:"automaticallyResolved"`
}

type threatLifecycleRecord struct {
	CreatedAt              string `json:"createdAt"`
	IdentifiedAt           string `json:"identifiedAt"`
	UpdatedAt              string `json:"updatedAt"`
	InitiatedBy            string `json:"initiatedBy"`
	InitiatedByDescription string `json:"initiatedByDescription"`
	InitiatingUserID       string `json:"initiatingUserId"`
	InitiatingUsername     string `json:"initiatingUsername"`
	OriginatorProcess      string `json:"originatorProcess"`
	StorylineID            string `json:"storyline"`
	ExternalTicketID       string `json:"externalTicketId"`
}

type threatFileRecord struct {
	FilePath          string `json:"filePath"`
	FileSize          int64  `json:"fileSize"`
	FileExtension     string `json:"fileExtension"`
	FileExtensionType string `json:"fileExtensionType"`
	Sha1              string `json:"sha1"`
	Sha256            string `json:"sha256"`
	Md5               string `json:"md5"`
}

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

type threatIndicatorRecord struct {
	Category    string            `json:"category"`
	IDs         []int             `json:"ids"`
	Tactics     []indicatorTactic `json:"tactics"`
	Description string            `json:"description"`
	Categories  []string          `json:"categories"`
}

type indicatorTactic struct {
	Name       string             `json:"name"`
	Source     string             `json:"source"`
	Techniques []indicatorTactic2 `json:"techniques"`
}

type indicatorTactic2 struct {
	Link string `json:"link"`
	Name string `json:"name"`
}

type mitigationStatusRecord struct {
	Action              string         `json:"action"`
	ActionsCounters     map[string]int `json:"actionsCounters"`
	LastUpdate          string         `json:"lastUpdate"`
	MitigationStartedAt string         `json:"mitigationStartedAt"`
	MitigationEndedAt   string         `json:"mitigationEndedAt"`
	Status              string         `json:"status"`
	ReportID            string         `json:"reportId"`
}

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

// siteRecord captures fields from /web/api/v2.1/sites.
type siteRecord struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	AccountID     string `json:"accountId"`
	AccountName   string `json:"accountName"`
	State         string `json:"state"`
	IsDefault     bool   `json:"isDefault"`
	CreatedAt     string `json:"createdAt"`
	UpdatedAt     string `json:"updatedAt"`
	Description   string `json:"description"`
	Expiration    string `json:"expiration"`
	HealthStatus  bool   `json:"healthStatus"`
	SiteType      string `json:"siteType"`
	TotalLicenses int    `json:"totalLicenses"`
	UsedLicenses  int    `json:"activeLicenses"`
	raw           json.RawMessage
}

func (r *siteRecord) setRaw(raw json.RawMessage) { r.raw = raw }
func (r *siteRecord) rawBytes() json.RawMessage  { return r.raw }

// groupRecord captures fields from /web/api/v2.1/groups.
type groupRecord struct {
	ID                string `json:"id"`
	Name              string `json:"name"`
	Description       string `json:"description"`
	Type              string `json:"type"`
	IsDefault         bool   `json:"isDefault"`
	Inherits          bool   `json:"inherits"`
	Rank              int    `json:"rank"`
	SiteID            string `json:"siteId"`
	TotalAgents       int    `json:"totalAgents"`
	FilterID          string `json:"filterId"`
	FilterName        string `json:"filterName"`
	CreatedAt         string `json:"createdAt"`
	UpdatedAt         string `json:"updatedAt"`
	Creator           string `json:"creator"`
	CreatorID         string `json:"creatorId"`
	RegistrationToken string `json:"registrationToken"`
	raw               json.RawMessage
}

func (r *groupRecord) setRaw(raw json.RawMessage) { r.raw = raw }
func (r *groupRecord) rawBytes() json.RawMessage  { return r.raw }

// exclusionRecord captures fields from /web/api/v2.1/exclusions.
type exclusionRecord struct {
	ID                string         `json:"id"`
	Type              string         `json:"type"`
	Mode              string         `json:"mode"`
	Source            string         `json:"source"`
	OSType            string         `json:"osType"`
	PathExclusionType string         `json:"pathExclusionType"`
	IncludeChildren   flexibleBool   `json:"includeChildren"`
	IncludeParents    flexibleBool   `json:"includeParents"`
	Imported          flexibleBool   `json:"imported"`
	NotRecommended    flexibleBool   `json:"notRecommended"`
	Description       string         `json:"description"`
	ApplicationName   string         `json:"applicationName"`
	UserID            string         `json:"userId"`
	UserName          string         `json:"userName"`
	Scope             flexibleString `json:"scope"`
	ScopeName         flexibleString `json:"scopeName"`
	ScopePath         flexibleString `json:"scopePath"`
	Value             flexibleString `json:"value"`
	Actions           []string       `json:"actions"`
	CreatedAt         string         `json:"createdAt"`
	UpdatedAt         string         `json:"updatedAt"`
	raw               json.RawMessage
}

func (r *exclusionRecord) setRaw(raw json.RawMessage) { r.raw = raw }
func (r *exclusionRecord) rawBytes() json.RawMessage  { return r.raw }

// activityRecord captures fields from /web/api/v2.1/activities.
type activityRecord struct {
	ID                   string         `json:"id"`
	AccountID            string         `json:"accountId"`
	AccountName          string         `json:"accountName"`
	ActivityType         int            `json:"activityType"`
	ActivityUUID         string         `json:"activityUuid"`
	AgentID              string         `json:"agentId"`
	AgentUpdatedVersion  string         `json:"agentUpdatedVersion"`
	Comments             string         `json:"comments"`
	CreatedAt            string         `json:"createdAt"`
	Data                 map[string]any `json:"data"`
	Description          string         `json:"description"`
	GroupID              string         `json:"groupId"`
	GroupName            string         `json:"groupName"`
	Hash                 string         `json:"hash"`
	OSFamily             string         `json:"osFamily"`
	PrimaryDescription   string         `json:"primaryDescription"`
	SecondaryDescription string         `json:"secondaryDescription"`
	SiteID               string         `json:"siteId"`
	SiteName             string         `json:"siteName"`
	ThreatID             string         `json:"threatId"`
	UpdatedAt            string         `json:"updatedAt"`
	UserID               string         `json:"userId"`
	raw                  json.RawMessage
}

func (r *activityRecord) setRaw(raw json.RawMessage) { r.raw = raw }
func (r *activityRecord) rawBytes() json.RawMessage  { return r.raw }

// applicationRecord is the per-agent installed application inventory entry.
type applicationRecord struct {
	AgentID       string `json:"-"`
	Name          string `json:"name"`
	Publisher     string `json:"publisher"`
	Version       string `json:"version"`
	InstalledDate string `json:"installedDate"`
	Size          int64  `json:"size"`
	raw           json.RawMessage
}

func (r *applicationRecord) setRaw(raw json.RawMessage) { r.raw = raw }
func (r *applicationRecord) rawBytes() json.RawMessage  { return r.raw }

func applicationID(_ settings, app applicationRecord) string {
	parts := []string{app.Publisher, app.Name, app.Version}
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		v := strings.TrimSpace(p)
		if v == "" {
			continue
		}
		out = append(out, strings.ReplaceAll(v, " ", "_"))
	}
	if len(out) == 0 {
		return "unknown"
	}
	return strings.Join(out, "::")
}

// payloads -- emitted JSON shapes.

type threatPayload struct {
	ID                string                    `json:"id"`
	TenantHost        string                    `json:"tenant_host"`
	ThreatInfo        threatInfoPayload         `json:"threat_info"`
	AgentDetection    agentDetectionPayload     `json:"agent_detection"`
	AgentRealtime     agentRealtimePayload      `json:"agent_realtime"`
	Indicators        indicatorPayload          `json:"indicators"`
	MitigationActions []mitigationActionPayload `json:"mitigation_actions,omitempty"`
	WhiteningOptions  []string                  `json:"whitening_options,omitempty"`
	Raw               map[string]any            `json:"raw,omitempty"`
}

type threatInfoPayload struct {
	threatClassificationPayload
	threatLifecyclePayload
	threatFilePayload
}

type threatClassificationPayload struct {
	AnalystVerdict        string `json:"analyst_verdict"`
	Classification        string `json:"classification"`
	ClassificationSource  string `json:"classification_source"`
	ConfidenceLevel       string `json:"confidence_level"`
	IncidentStatus        string `json:"incident_status"`
	MitigationStatus      string `json:"mitigation_status"`
	IsFileless            bool   `json:"is_fileless,omitempty"`
	ThreatName            string `json:"threat_name,omitempty"`
	DetectionType         string `json:"detection_type,omitempty"`
	AutomaticallyResolved bool   `json:"automatically_resolved,omitempty"`
}

type threatLifecyclePayload struct {
	CreatedAt              string `json:"created_at,omitempty"`
	IdentifiedAt           string `json:"identified_at,omitempty"`
	UpdatedAt              string `json:"updated_at,omitempty"`
	InitiatedBy            string `json:"initiated_by,omitempty"`
	InitiatedByDescription string `json:"initiated_by_description,omitempty"`
	InitiatingUserID       string `json:"initiating_user_id,omitempty"`
	InitiatingUsername     string `json:"initiating_username,omitempty"`
	OriginatorProcess      string `json:"originator_process,omitempty"`
	StorylineID            string `json:"storyline_id,omitempty"`
	ExternalTicketID       string `json:"external_ticket_id,omitempty"`
}

type threatFilePayload struct {
	FilePath          string `json:"file_path,omitempty"`
	FileSize          int64  `json:"file_size,omitempty"`
	FileExtension     string `json:"file_extension,omitempty"`
	FileExtensionType string `json:"file_extension_type,omitempty"`
	Sha1              string `json:"sha1,omitempty"`
	Sha256            string `json:"sha256,omitempty"`
	Md5               string `json:"md5,omitempty"`
}

type agentDetectionPayload struct {
	AccountID    string `json:"account_id,omitempty"`
	AccountName  string `json:"account_name,omitempty"`
	Domain       string `json:"domain,omitempty"`
	IPV4         string `json:"ip_v4,omitempty"`
	IPV6         string `json:"ip_v6,omitempty"`
	IPAddresses  string `json:"ip_addresses,omitempty"`
	OSName       string `json:"os_name,omitempty"`
	OSRevision   string `json:"os_revision,omitempty"`
	RegisteredAt string `json:"registered_at,omitempty"`
	UUID         string `json:"uuid,omitempty"`
	Version      string `json:"version,omitempty"`
	ExternalIP   string `json:"external_ip,omitempty"`
	GroupID      string `json:"group_id,omitempty"`
	GroupName    string `json:"group_name,omitempty"`
	SiteID       string `json:"site_id,omitempty"`
	SiteName     string `json:"site_name,omitempty"`
	UserMail     string `json:"user_mail,omitempty"`
	UserName     string `json:"user_name,omitempty"`
}

type agentRealtimePayload struct {
	AgentID          string `json:"agent_id,omitempty"`
	ComputerName     string `json:"computer_name,omitempty"`
	Hostname         string `json:"hostname,omitempty"`
	OSName           string `json:"os_name,omitempty"`
	OSType           string `json:"os_type,omitempty"`
	OSRevision       string `json:"os_revision,omitempty"`
	IsActive         bool   `json:"is_active"`
	IsDecommissioned bool   `json:"is_decommissioned"`
	Infected         bool   `json:"is_infected"`
	ActiveThreats    int    `json:"active_threats"`
	NetworkStatus    string `json:"network_status,omitempty"`
	OperationalState string `json:"operational_state,omitempty"`
	RebootRequired   bool   `json:"reboot_required,omitempty"`
	ScanStatus       string `json:"scan_status,omitempty"`
	MitigationMode   string `json:"mitigation_mode,omitempty"`
	UUID             string `json:"uuid,omitempty"`
	Version          string `json:"version,omitempty"`
	GroupID          string `json:"group_id,omitempty"`
	GroupName        string `json:"group_name,omitempty"`
	SiteID           string `json:"site_id,omitempty"`
	SiteName         string `json:"site_name,omitempty"`
}

type indicatorPayload struct {
	Categories      []string `json:"categories,omitempty"`
	MitreTactics    []string `json:"mitre_tactics,omitempty"`
	MitreTechniques []string `json:"mitre_techniques,omitempty"`
	Descriptions    []string `json:"descriptions,omitempty"`
}

type mitigationActionPayload struct {
	Action     string `json:"action"`
	Status     string `json:"status,omitempty"`
	StartedAt  string `json:"started_at,omitempty"`
	EndedAt    string `json:"ended_at,omitempty"`
	LastUpdate string `json:"last_update,omitempty"`
	ReportID   string `json:"report_id,omitempty"`
}

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

type sitePayload struct {
	ID            string         `json:"id"`
	TenantHost    string         `json:"tenant_host"`
	Name          string         `json:"name,omitempty"`
	State         string         `json:"state,omitempty"`
	SiteType      string         `json:"site_type,omitempty"`
	Description   string         `json:"description,omitempty"`
	Expiration    string         `json:"expiration,omitempty"`
	IsDefault     bool           `json:"is_default,omitempty"`
	HealthStatus  bool           `json:"health_status,omitempty"`
	TotalLicenses int            `json:"total_licenses,omitempty"`
	UsedLicenses  int            `json:"used_licenses,omitempty"`
	AccountID     string         `json:"account_id,omitempty"`
	AccountName   string         `json:"account_name,omitempty"`
	CreatedAt     string         `json:"created_at,omitempty"`
	UpdatedAt     string         `json:"updated_at,omitempty"`
	Raw           map[string]any `json:"raw,omitempty"`
}

type groupPayload struct {
	ID              string         `json:"id"`
	TenantHost      string         `json:"tenant_host"`
	Name            string         `json:"name,omitempty"`
	Type            string         `json:"type,omitempty"`
	Description     string         `json:"description,omitempty"`
	IsDefault       bool           `json:"is_default,omitempty"`
	Inherits        bool           `json:"inherits,omitempty"`
	Rank            int            `json:"rank,omitempty"`
	SiteID          string         `json:"site_id,omitempty"`
	TotalAgents     int            `json:"total_agents,omitempty"`
	FilterID        string         `json:"filter_id,omitempty"`
	FilterName      string         `json:"filter_name,omitempty"`
	Creator         string         `json:"creator,omitempty"`
	CreatorID       string         `json:"creator_id,omitempty"`
	HasRegistration bool           `json:"has_registration_token,omitempty"`
	CreatedAt       string         `json:"created_at,omitempty"`
	UpdatedAt       string         `json:"updated_at,omitempty"`
	Raw             map[string]any `json:"raw,omitempty"`
}

type exclusionPayload struct {
	ID                string         `json:"id"`
	TenantHost        string         `json:"tenant_host"`
	Type              string         `json:"type,omitempty"`
	Mode              string         `json:"mode,omitempty"`
	Source            string         `json:"source,omitempty"`
	OSType            string         `json:"os_type,omitempty"`
	PathExclusionType string         `json:"path_exclusion_type,omitempty"`
	IncludeChildren   bool           `json:"include_children,omitempty"`
	IncludeParents    bool           `json:"include_parents,omitempty"`
	Imported          bool           `json:"imported,omitempty"`
	NotRecommended    bool           `json:"not_recommended,omitempty"`
	Description       string         `json:"description,omitempty"`
	ApplicationName   string         `json:"application_name,omitempty"`
	UserID            string         `json:"user_id,omitempty"`
	UserName          string         `json:"user_name,omitempty"`
	Scope             string         `json:"scope,omitempty"`
	ScopeName         string         `json:"scope_name,omitempty"`
	ScopePath         string         `json:"scope_path,omitempty"`
	Value             string         `json:"value,omitempty"`
	Actions           []string       `json:"actions,omitempty"`
	CreatedAt         string         `json:"created_at,omitempty"`
	UpdatedAt         string         `json:"updated_at,omitempty"`
	Raw               map[string]any `json:"raw,omitempty"`
}

type activityPayload struct {
	ID                   string         `json:"id"`
	TenantHost           string         `json:"tenant_host"`
	ActivityType         int            `json:"activity_type,omitempty"`
	ActivityUUID         string         `json:"activity_uuid,omitempty"`
	AgentID              string         `json:"agent_id,omitempty"`
	AgentUpdatedVersion  string         `json:"agent_updated_version,omitempty"`
	CreatedAt            string         `json:"created_at,omitempty"`
	UpdatedAt            string         `json:"updated_at,omitempty"`
	Description          string         `json:"description,omitempty"`
	PrimaryDescription   string         `json:"primary_description,omitempty"`
	SecondaryDescription string         `json:"secondary_description,omitempty"`
	Comments             string         `json:"comments,omitempty"`
	GroupID              string         `json:"group_id,omitempty"`
	GroupName            string         `json:"group_name,omitempty"`
	OSFamily             string         `json:"os_family,omitempty"`
	SiteID               string         `json:"site_id,omitempty"`
	SiteName             string         `json:"site_name,omitempty"`
	AccountID            string         `json:"account_id,omitempty"`
	AccountName          string         `json:"account_name,omitempty"`
	ThreatID             string         `json:"threat_id,omitempty"`
	UserID               string         `json:"user_id,omitempty"`
	Hash                 string         `json:"hash,omitempty"`
	Data                 map[string]any `json:"data,omitempty"`
	Raw                  map[string]any `json:"raw,omitempty"`
}

type applicationPayload struct {
	AgentID       string         `json:"agent_id"`
	TenantHost    string         `json:"tenant_host"`
	Name          string         `json:"name,omitempty"`
	Publisher     string         `json:"publisher,omitempty"`
	Version       string         `json:"version,omitempty"`
	InstalledDate string         `json:"installed_date,omitempty"`
	SizeBytes     int64          `json:"size_bytes,omitempty"`
	Raw           map[string]any `json:"raw,omitempty"`
}

// event builders

func threatEvent(s settings, record threatRecord) (*primitives.Event, error) {
	occurredAt := eventOccurredAt(
		parseTimestamp(record.ThreatInfo.UpdatedAt),
		parseTimestamp(record.ThreatInfo.IdentifiedAt),
		parseTimestamp(record.ThreatInfo.CreatedAt),
	)
	raw, err := decodeRaw(record.raw, "sentinelone threat")
	if err != nil {
		return nil, err
	}
	indicators := buildIndicatorPayload(record.Indicators)
	mitigations := buildMitigationActions(record.MitigationStatus)
	payload, err := json.Marshal(threatPayload{
		ID:                record.ID,
		TenantHost:        s.host,
		ThreatInfo:        toThreatInfoPayload(record.ThreatInfo),
		AgentDetection:    toAgentDetectionPayload(record.AgentDetectionInfo),
		AgentRealtime:     toAgentRealtimePayload(record.AgentRealtimeInfo),
		Indicators:        indicators,
		MitigationActions: mitigations,
		WhiteningOptions:  record.WhiteningOptions,
		Raw:               raw,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal sentinelone threat payload: %w", err)
	}
	return &primitives.Event{
		Id:         eventID("sentinelone-threat", s, record.ID),
		TenantId:   s.host,
		SourceId:   "sentinelone",
		Kind:       "sentinelone.threat",
		OccurredAt: toTimestamp(occurredAt),
		SchemaRef:  "sentinelone/threat/v1",
		Payload:    payload,
		Attributes: threatAttributes(s, record, indicators),
	}, nil
}

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

func siteEvent(s settings, record siteRecord) (*primitives.Event, error) {
	occurredAt := eventOccurredAt(
		parseTimestamp(record.UpdatedAt),
		parseTimestamp(record.CreatedAt),
	)
	raw, err := decodeRaw(record.raw, "sentinelone site")
	if err != nil {
		return nil, err
	}
	payload, err := json.Marshal(sitePayload{
		ID:            record.ID,
		TenantHost:    s.host,
		Name:          record.Name,
		State:         record.State,
		SiteType:      record.SiteType,
		Description:   record.Description,
		Expiration:    record.Expiration,
		IsDefault:     record.IsDefault,
		HealthStatus:  record.HealthStatus,
		TotalLicenses: record.TotalLicenses,
		UsedLicenses:  record.UsedLicenses,
		AccountID:     record.AccountID,
		AccountName:   record.AccountName,
		CreatedAt:     record.CreatedAt,
		UpdatedAt:     record.UpdatedAt,
		Raw:           raw,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal sentinelone site payload: %w", err)
	}
	attrs := map[string]string{
		"family":      familySite,
		"site_id":     record.ID,
		"tenant_host": s.host,
	}
	addAttribute(attrs, "site_name", record.Name)
	addAttribute(attrs, "state", record.State)
	addAttribute(attrs, "site_type", record.SiteType)
	addAttribute(attrs, "account_id", record.AccountID)
	addAttribute(attrs, "account_name", record.AccountName)
	addAttribute(attrs, "is_default", boolString(record.IsDefault))
	return &primitives.Event{
		Id:         eventID("sentinelone-site", s, record.ID),
		TenantId:   s.host,
		SourceId:   "sentinelone",
		Kind:       "sentinelone.site",
		OccurredAt: toTimestamp(occurredAt),
		SchemaRef:  "sentinelone/site/v1",
		Payload:    payload,
		Attributes: attrs,
	}, nil
}

func groupEvent(s settings, record groupRecord) (*primitives.Event, error) {
	occurredAt := eventOccurredAt(
		parseTimestamp(record.UpdatedAt),
		parseTimestamp(record.CreatedAt),
	)
	raw, err := decodeRaw(record.raw, "sentinelone group")
	if err != nil {
		return nil, err
	}
	payload, err := json.Marshal(groupPayload{
		ID:              record.ID,
		TenantHost:      s.host,
		Name:            record.Name,
		Type:            record.Type,
		Description:     record.Description,
		IsDefault:       record.IsDefault,
		Inherits:        record.Inherits,
		Rank:            record.Rank,
		SiteID:          record.SiteID,
		TotalAgents:     record.TotalAgents,
		FilterID:        record.FilterID,
		FilterName:      record.FilterName,
		Creator:         record.Creator,
		CreatorID:       record.CreatorID,
		HasRegistration: strings.TrimSpace(record.RegistrationToken) != "",
		CreatedAt:       record.CreatedAt,
		UpdatedAt:       record.UpdatedAt,
		Raw:             raw,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal sentinelone group payload: %w", err)
	}
	attrs := map[string]string{
		"family":      familyGroup,
		"group_id":    record.ID,
		"tenant_host": s.host,
	}
	addAttribute(attrs, "group_name", record.Name)
	addAttribute(attrs, "site_id", record.SiteID)
	addAttribute(attrs, "type", record.Type)
	addAttribute(attrs, "is_default", boolString(record.IsDefault))
	addAttribute(attrs, "total_agents", intToString(record.TotalAgents))
	return &primitives.Event{
		Id:         eventID("sentinelone-group", s, record.ID),
		TenantId:   s.host,
		SourceId:   "sentinelone",
		Kind:       "sentinelone.group",
		OccurredAt: toTimestamp(occurredAt),
		SchemaRef:  "sentinelone/group/v1",
		Payload:    payload,
		Attributes: attrs,
	}, nil
}

func exclusionEvent(s settings, record exclusionRecord) (*primitives.Event, error) {
	occurredAt := eventOccurredAt(
		parseTimestamp(record.UpdatedAt),
		parseTimestamp(record.CreatedAt),
	)
	raw, err := decodeRaw(record.raw, "sentinelone exclusion")
	if err != nil {
		return nil, err
	}
	payload, err := json.Marshal(exclusionPayload{
		ID:                record.ID,
		TenantHost:        s.host,
		Type:              record.Type,
		Mode:              record.Mode,
		Source:            record.Source,
		OSType:            record.OSType,
		PathExclusionType: record.PathExclusionType,
		IncludeChildren:   bool(record.IncludeChildren),
		IncludeParents:    bool(record.IncludeParents),
		Imported:          bool(record.Imported),
		NotRecommended:    bool(record.NotRecommended),
		Description:       record.Description,
		ApplicationName:   record.ApplicationName,
		UserID:            record.UserID,
		UserName:          record.UserName,
		Scope:             string(record.Scope),
		ScopeName:         string(record.ScopeName),
		ScopePath:         string(record.ScopePath),
		Value:             string(record.Value),
		Actions:           record.Actions,
		CreatedAt:         record.CreatedAt,
		UpdatedAt:         record.UpdatedAt,
		Raw:               raw,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal sentinelone exclusion payload: %w", err)
	}
	attrs := map[string]string{
		"family":       familyExclusion,
		"exclusion_id": record.ID,
		"tenant_host":  s.host,
	}
	addAttribute(attrs, "exclusion_type", record.Type)
	addAttribute(attrs, "mode", record.Mode)
	addAttribute(attrs, "source", record.Source)
	addAttribute(attrs, "os_type", record.OSType)
	addAttribute(attrs, "path_exclusion_type", record.PathExclusionType)
	addAttribute(attrs, "scope", string(record.Scope))
	addAttribute(attrs, "scope_name", string(record.ScopeName))
	addAttribute(attrs, "scope_path", string(record.ScopePath))
	addAttribute(attrs, "value", string(record.Value))
	addAttribute(attrs, "not_recommended", boolString(bool(record.NotRecommended)))
	addAttribute(attrs, "include_children", boolString(bool(record.IncludeChildren)))
	addAttribute(attrs, "include_parents", boolString(bool(record.IncludeParents)))
	addAttribute(attrs, "imported", boolString(bool(record.Imported)))
	if len(record.Actions) != 0 {
		attrs["actions"] = strings.Join(record.Actions, ",")
	}
	return &primitives.Event{
		Id:         eventID("sentinelone-exclusion", s, record.ID),
		TenantId:   s.host,
		SourceId:   "sentinelone",
		Kind:       "sentinelone.exclusion",
		OccurredAt: toTimestamp(occurredAt),
		SchemaRef:  "sentinelone/exclusion/v1",
		Payload:    payload,
		Attributes: attrs,
	}, nil
}

func activityEvent(s settings, record activityRecord) (*primitives.Event, error) {
	occurredAt := eventOccurredAt(
		parseTimestamp(record.CreatedAt),
		parseTimestamp(record.UpdatedAt),
	)
	raw, err := decodeRaw(record.raw, "sentinelone activity")
	if err != nil {
		return nil, err
	}
	payload, err := json.Marshal(activityPayload{
		ID:                   record.ID,
		TenantHost:           s.host,
		ActivityType:         record.ActivityType,
		ActivityUUID:         record.ActivityUUID,
		AgentID:              record.AgentID,
		AgentUpdatedVersion:  record.AgentUpdatedVersion,
		CreatedAt:            record.CreatedAt,
		UpdatedAt:            record.UpdatedAt,
		Description:          record.Description,
		PrimaryDescription:   record.PrimaryDescription,
		SecondaryDescription: record.SecondaryDescription,
		Comments:             record.Comments,
		GroupID:              record.GroupID,
		GroupName:            record.GroupName,
		OSFamily:             record.OSFamily,
		SiteID:               record.SiteID,
		SiteName:             record.SiteName,
		AccountID:            record.AccountID,
		AccountName:          record.AccountName,
		ThreatID:             record.ThreatID,
		UserID:               record.UserID,
		Hash:                 record.Hash,
		Data:                 record.Data,
		Raw:                  raw,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal sentinelone activity payload: %w", err)
	}
	attrs := map[string]string{
		"family":        familyActivity,
		"activity_id":   record.ID,
		"tenant_host":   s.host,
		"activity_type": intToString(record.ActivityType),
	}
	addAttribute(attrs, "activity_uuid", record.ActivityUUID)
	addAttribute(attrs, "agent_id", record.AgentID)
	addAttribute(attrs, "site_id", record.SiteID)
	addAttribute(attrs, "group_id", record.GroupID)
	addAttribute(attrs, "threat_id", record.ThreatID)
	addAttribute(attrs, "user_id", record.UserID)
	addAttribute(attrs, "primary_description", record.PrimaryDescription)
	addAttribute(attrs, "os_family", record.OSFamily)
	return &primitives.Event{
		Id:         eventID("sentinelone-activity", s, record.ID),
		TenantId:   s.host,
		SourceId:   "sentinelone",
		Kind:       "sentinelone.activity",
		OccurredAt: toTimestamp(occurredAt),
		SchemaRef:  "sentinelone/activity/v1",
		Payload:    payload,
		Attributes: attrs,
	}, nil
}

func applicationEvent(s settings, record applicationRecord) (*primitives.Event, error) {
	agentID := applicationAgentID(s, record)
	occurredAt := eventOccurredAt(parseTimestamp(record.InstalledDate))
	raw, err := decodeRaw(record.raw, "sentinelone application")
	if err != nil {
		return nil, err
	}
	payload, err := json.Marshal(applicationPayload{
		AgentID:       agentID,
		TenantHost:    s.host,
		Name:          record.Name,
		Publisher:     record.Publisher,
		Version:       record.Version,
		InstalledDate: record.InstalledDate,
		SizeBytes:     record.Size,
		Raw:           raw,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal sentinelone application payload: %w", err)
	}
	attrs := map[string]string{
		"family":      familyApplication,
		"agent_id":    agentID,
		"tenant_host": s.host,
	}
	addAttribute(attrs, "application_name", record.Name)
	addAttribute(attrs, "publisher", record.Publisher)
	addAttribute(attrs, "version", record.Version)
	addAttribute(attrs, "installed_date", record.InstalledDate)
	return &primitives.Event{
		Id:         eventID("sentinelone-application", s, agentID, applicationID(s, record)),
		TenantId:   s.host,
		SourceId:   "sentinelone",
		Kind:       "sentinelone.application_inventory",
		OccurredAt: toTimestamp(occurredAt),
		SchemaRef:  "sentinelone/application_inventory/v1",
		Payload:    payload,
		Attributes: attrs,
	}, nil
}

func applicationAgentID(s settings, record applicationRecord) string {
	return firstNonEmpty(record.AgentID, s.agentID)
}

func toThreatInfoPayload(info threatInfoRecord) threatInfoPayload {
	return threatInfoPayload{
		threatClassificationPayload: threatClassificationPayload(info.threatClassificationRecord),
		threatLifecyclePayload:      threatLifecyclePayload(info.threatLifecycleRecord),
		threatFilePayload:           threatFilePayload(info.threatFileRecord),
	}
}

func toAgentDetectionPayload(info agentDetectionInfoRecord) agentDetectionPayload {
	return agentDetectionPayload{
		AccountID:    info.AccountID,
		AccountName:  info.AccountName,
		Domain:       info.AgentDomain,
		IPV4:         info.AgentIPV4,
		IPV6:         info.AgentIPV6,
		IPAddresses:  joinedEndpointIPs(info.AgentIPV4, info.AgentIPV6, info.ExternalIP),
		OSName:       info.AgentOSName,
		OSRevision:   info.AgentOSRevision,
		RegisteredAt: info.AgentRegisteredAt,
		UUID:         info.AgentUUID,
		Version:      info.AgentVersion,
		ExternalIP:   info.ExternalIP,
		GroupID:      info.GroupID,
		GroupName:    info.GroupName,
		SiteID:       info.SiteID,
		SiteName:     info.SiteName,
		UserMail:     info.AgentLastLoggedInUserMail,
		UserName:     info.AgentLastLoggedInUserName,
	}
}

func toAgentRealtimePayload(info agentRealtimeInfoRecord) agentRealtimePayload {
	return agentRealtimePayload{
		AgentID:          info.AgentID,
		ComputerName:     info.AgentComputerName,
		Hostname:         info.AgentComputerName,
		OSName:           info.AgentOSName,
		OSType:           info.AgentOSType,
		OSRevision:       info.AgentOSRevision,
		IsActive:         info.AgentIsActive,
		IsDecommissioned: info.AgentIsDecommissioned,
		Infected:         info.AgentInfected,
		ActiveThreats:    info.ActiveThreats,
		NetworkStatus:    info.AgentNetworkStatus,
		OperationalState: info.OperationalState,
		RebootRequired:   info.RebootRequired,
		ScanStatus:       info.ScanStatus,
		MitigationMode:   info.AgentMitigationMode,
		UUID:             info.AgentUUID,
		Version:          info.AgentVersion,
		GroupID:          info.GroupID,
		GroupName:        info.GroupName,
		SiteID:           info.SiteID,
		SiteName:         info.SiteName,
	}
}

func buildIndicatorPayload(records []threatIndicatorRecord) indicatorPayload {
	categories := map[string]struct{}{}
	tactics := map[string]struct{}{}
	techniques := map[string]struct{}{}
	descs := map[string]struct{}{}
	for _, ind := range records {
		if cat := strings.TrimSpace(ind.Category); cat != "" {
			categories[cat] = struct{}{}
		}
		for _, c := range ind.Categories {
			if c = strings.TrimSpace(c); c != "" {
				categories[c] = struct{}{}
			}
		}
		if d := strings.TrimSpace(ind.Description); d != "" {
			descs[d] = struct{}{}
		}
		for _, tac := range ind.Tactics {
			if name := strings.TrimSpace(tac.Name); name != "" {
				tactics[name] = struct{}{}
			}
			for _, technique := range tac.Techniques {
				if name := strings.TrimSpace(technique.Name); name != "" {
					techniques[name] = struct{}{}
				}
			}
		}
	}
	return indicatorPayload{
		Categories:      sortedStrings(mapKeys(categories)),
		MitreTactics:    sortedStrings(mapKeys(tactics)),
		MitreTechniques: sortedStrings(mapKeys(techniques)),
		Descriptions:    sortedStrings(mapKeys(descs)),
	}
}

func buildMitigationActions(records []mitigationStatusRecord) []mitigationActionPayload {
	actions := make([]mitigationActionPayload, 0, len(records))
	for _, m := range records {
		actions = append(actions, mitigationActionPayload{
			Action:     m.Action,
			Status:     m.Status,
			StartedAt:  m.MitigationStartedAt,
			EndedAt:    m.MitigationEndedAt,
			LastUpdate: m.LastUpdate,
			ReportID:   m.ReportID,
		})
	}
	return actions
}

func mapKeys(values map[string]struct{}) []string {
	out := make([]string, 0, len(values))
	for k := range values {
		out = append(out, k)
	}
	return out
}

func threatAttributes(s settings, record threatRecord, indicators indicatorPayload) map[string]string {
	attrs := map[string]string{
		"family":            familyThreat,
		"threat_id":         record.ID,
		"tenant_host":       s.host,
		"is_active":         boolString(record.AgentRealtimeInfo.AgentIsActive),
		"is_decommissioned": boolString(record.AgentRealtimeInfo.AgentIsDecommissioned),
		"is_infected":       boolString(record.AgentRealtimeInfo.AgentInfected),
		"is_fileless":       boolString(record.ThreatInfo.IsFileless),
	}
	addAttribute(attrs, "classification", record.ThreatInfo.Classification)
	addAttribute(attrs, "classification_norm", normalizeSentinelOnePostureValue(record.ThreatInfo.Classification))
	addAttribute(attrs, "classification_source", record.ThreatInfo.ClassificationSource)
	addAttribute(attrs, "analyst_verdict", record.ThreatInfo.AnalystVerdict)
	addAttribute(attrs, "analyst_verdict_norm", normalizeSentinelOnePostureValue(record.ThreatInfo.AnalystVerdict))
	addAttribute(attrs, "incident_status", record.ThreatInfo.IncidentStatus)
	addAttribute(attrs, "incident_status_norm", normalizeSentinelOnePostureValue(record.ThreatInfo.IncidentStatus))
	addAttribute(attrs, "confidence_level", record.ThreatInfo.ConfidenceLevel)
	addAttribute(attrs, "mitigation_status", record.ThreatInfo.MitigationStatus)
	addAttribute(attrs, "mitigation_status_norm", normalizeSentinelOnePostureValue(record.ThreatInfo.MitigationStatus))
	addAttribute(attrs, "automatically_resolved", boolString(record.ThreatInfo.AutomaticallyResolved))
	addAttribute(attrs, "detection_type", record.ThreatInfo.DetectionType)
	addAttribute(attrs, "threat_name", record.ThreatInfo.ThreatName)
	addAttribute(attrs, "file_path", record.ThreatInfo.FilePath)
	addAttribute(attrs, "sha256", record.ThreatInfo.Sha256)
	addAttribute(attrs, "agent_id", firstNonEmpty(record.AgentRealtimeInfo.AgentID, record.AgentDetectionInfo.AgentUUID))
	addAttribute(attrs, "agent_uuid", record.AgentDetectionInfo.AgentUUID)
	addAttribute(attrs, "agent_name", record.AgentRealtimeInfo.AgentComputerName)
	addAttribute(attrs, "computer_name", record.AgentRealtimeInfo.AgentComputerName)
	addAttribute(attrs, "hostname", record.AgentRealtimeInfo.AgentComputerName)
	addAttribute(attrs, "site_id", firstNonEmpty(record.AgentDetectionInfo.SiteID, record.AgentRealtimeInfo.SiteID))
	addAttribute(attrs, "group_id", firstNonEmpty(record.AgentDetectionInfo.GroupID, record.AgentRealtimeInfo.GroupID))
	addAttribute(attrs, "site_name", firstNonEmpty(record.AgentDetectionInfo.SiteName, record.AgentRealtimeInfo.SiteName))
	addAttribute(attrs, "group_name", firstNonEmpty(record.AgentDetectionInfo.GroupName, record.AgentRealtimeInfo.GroupName))
	addAttribute(attrs, "account_id", firstNonEmpty(record.AgentDetectionInfo.AccountID, record.AgentRealtimeInfo.AccountID))
	addAttribute(attrs, "account_name", firstNonEmpty(record.AgentDetectionInfo.AccountName, record.AgentRealtimeInfo.AccountName))
	addAttribute(attrs, "agent_os_name", firstNonEmpty(record.AgentDetectionInfo.AgentOSName, record.AgentRealtimeInfo.AgentOSName))
	addAttribute(attrs, "agent_os_type", record.AgentRealtimeInfo.AgentOSType)
	addAttribute(attrs, "agent_ip_v4", record.AgentDetectionInfo.AgentIPV4)
	addAttribute(attrs, "agent_ip_v6", record.AgentDetectionInfo.AgentIPV6)
	addAttribute(attrs, "external_ip", record.AgentDetectionInfo.ExternalIP)
	addAttribute(attrs, "ip", firstNonEmpty(record.AgentDetectionInfo.AgentIPV4, record.AgentDetectionInfo.ExternalIP, record.AgentDetectionInfo.AgentIPV6))
	addAttribute(attrs, "ip_addresses", joinedEndpointIPs(record.AgentDetectionInfo.AgentIPV4, record.AgentDetectionInfo.AgentIPV6, record.AgentDetectionInfo.ExternalIP))
	addAttribute(attrs, "user_mail", record.AgentDetectionInfo.AgentLastLoggedInUserMail)
	addAttribute(attrs, "user_name", record.AgentDetectionInfo.AgentLastLoggedInUserName)
	if len(indicators.MitreTactics) != 0 {
		attrs["mitre_tactics"] = strings.Join(indicators.MitreTactics, ",")
	}
	if len(indicators.MitreTechniques) != 0 {
		attrs["mitre_techniques"] = strings.Join(indicators.MitreTechniques, ",")
	}
	if len(indicators.Categories) != 0 {
		attrs["indicator_categories"] = strings.Join(indicators.Categories, ",")
	}
	return attrs
}

func normalizeSentinelOnePostureValue(value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	normalized = strings.ReplaceAll(normalized, "-", "_")
	normalized = strings.ReplaceAll(normalized, " ", "_")
	return normalized
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

func joinedEndpointIPs(values ...string) string {
	cleaned := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		ip := strings.TrimSpace(value)
		if ip == "" {
			continue
		}
		if _, ok := seen[ip]; ok {
			continue
		}
		seen[ip] = struct{}{}
		cleaned = append(cleaned, ip)
	}
	return strings.Join(cleaned, ",")
}

// timeFormatter helper kept to avoid removing time import if not used elsewhere.
var _ = time.RFC3339
