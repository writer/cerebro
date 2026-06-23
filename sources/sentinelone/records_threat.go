package sentinelone

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/writer/cerebro/internal/primitives"
)

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

// payloads -- emitted JSON shapes for threats.

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
