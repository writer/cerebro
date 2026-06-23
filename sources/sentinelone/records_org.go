package sentinelone

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/writer/cerebro/internal/primitives"
)

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

// payloads -- emitted JSON shapes for org structures.

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

// event builders

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
