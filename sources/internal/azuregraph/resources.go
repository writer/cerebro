package azuregraph

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/primitives"
	"github.com/writer/cerebro/internal/sourcecdk"
)

const (
	FamilyAuthenticationMethodsPolicy = "authentication_methods_policy"
	FamilyConditionalAccessPolicy     = "conditional_access_policy"
	FamilyDefenderAlert               = "defender_alert"
	FamilyDefenderIncident            = "defender_incident"
	FamilyIdentityRiskDetection       = "identity_risk_detection"
	FamilyIdentityRiskyUser           = "identity_risky_user"
	FamilyPurviewRetentionLabel       = "purview_retention_label"
	FamilyPurviewSensitivityLabel     = "purview_sensitivity_label"
	FamilySecureScore                 = "secure_score"
	FamilySecureScoreControl          = "secure_score_control"
)

type ResourceDefinition struct {
	Name         string
	Label        string
	Path         string
	Kind         string
	SchemaRef    string
	URNKind      string
	ResourceType string
	Singleton    bool
	Attributes   func(Settings, Record) map[string]string
	OccurredAt   func(Record) time.Time
}

type Settings struct {
	TenantID string
}

type Record struct {
	ID          string          `json:"id"`
	DisplayName string          `json:"displayName"`
	Name        string          `json:"name"`
	Title       string          `json:"title"`
	Description string          `json:"description"`
	Raw         json.RawMessage `json:"-"`
}

type Page struct {
	Value        []json.RawMessage `json:"value"`
	ODataNext    string            `json:"@odata.nextLink"`
	NextPageLink string            `json:"nextLink"`
}

type JSONGetter[Src any, S any] func(context.Context, Src, S, string, url.Values, any) error

type EventEmitter[S any] func(S, string, string, string, []byte, map[string]string, time.Time) (*primitives.Event, error)

var ResourceDefinitions = []ResourceDefinition{
	{
		Name:         FamilyConditionalAccessPolicy,
		Label:        "azure conditional access policies",
		Path:         "/v1.0/identity/conditionalAccess/policies",
		Kind:         "azure.conditional_access_policy",
		SchemaRef:    "azure/conditional_access_policy/v1",
		URNKind:      "azure_conditional_access_policy",
		ResourceType: "conditional_access_policy",
		Attributes:   conditionalAccessPolicyAttributes,
		OccurredAt:   graphTimeFrom("modifiedDateTime", "createdDateTime"),
	},
	{
		Name:         FamilyAuthenticationMethodsPolicy,
		Label:        "azure authentication methods policy",
		Path:         "/v1.0/policies/authenticationMethodsPolicy",
		Kind:         "azure.authentication_methods_policy",
		SchemaRef:    "azure/authentication_methods_policy/v1",
		URNKind:      "azure_authentication_methods_policy",
		ResourceType: "authentication_methods_policy",
		Singleton:    true,
		Attributes:   authenticationMethodsPolicyAttributes,
	},
	{
		Name:         FamilyIdentityRiskyUser,
		Label:        "azure identity protection risky users",
		Path:         "/v1.0/identityProtection/riskyUsers",
		Kind:         "azure.identity_risky_user",
		SchemaRef:    "azure/identity_risky_user/v1",
		URNKind:      "azure_identity_risky_user",
		ResourceType: "identity_risky_user",
		Attributes:   identityRiskyUserAttributes,
		OccurredAt:   graphTimeFrom("riskLastUpdatedDateTime", "lastUpdatedDateTime"),
	},
	{
		Name:         FamilyIdentityRiskDetection,
		Label:        "azure identity protection risk detections",
		Path:         "/v1.0/identityProtection/riskDetections",
		Kind:         "azure.identity_risk_detection",
		SchemaRef:    "azure/identity_risk_detection/v1",
		URNKind:      "azure_identity_risk_detection",
		ResourceType: "identity_risk_detection",
		Attributes:   identityRiskDetectionAttributes,
		OccurredAt:   graphTimeFrom("detectedDateTime", "activityDateTime"),
	},
	{
		Name:         FamilyDefenderIncident,
		Label:        "azure defender incidents",
		Path:         "/v1.0/security/incidents",
		Kind:         "azure.defender_incident",
		SchemaRef:    "azure/defender_incident/v1",
		URNKind:      "azure_defender_incident",
		ResourceType: "defender_incident",
		Attributes:   defenderIncidentAttributes,
		OccurredAt:   graphTimeFrom("lastUpdateDateTime", "createdDateTime"),
	},
	{
		Name:         FamilyDefenderAlert,
		Label:        "azure defender alerts",
		Path:         "/v1.0/security/alerts_v2",
		Kind:         "azure.defender_alert",
		SchemaRef:    "azure/defender_alert/v1",
		URNKind:      "azure_defender_alert",
		ResourceType: "defender_alert",
		Attributes:   defenderAlertAttributes,
		OccurredAt:   graphTimeFrom("lastUpdateDateTime", "createdDateTime"),
	},
	{
		Name:         FamilySecureScore,
		Label:        "azure secure scores",
		Path:         "/v1.0/security/secureScores",
		Kind:         "azure.secure_score",
		SchemaRef:    "azure/secure_score/v1",
		URNKind:      "azure_secure_score",
		ResourceType: "secure_score",
		Attributes:   secureScoreAttributes,
		OccurredAt:   graphTimeFrom("createdDateTime"),
	},
	{
		Name:         FamilySecureScoreControl,
		Label:        "azure secure score controls",
		Path:         "/v1.0/security/secureScoreControlProfiles",
		Kind:         "azure.secure_score_control",
		SchemaRef:    "azure/secure_score_control/v1",
		URNKind:      "azure_secure_score_control",
		ResourceType: "secure_score_control",
		Attributes:   secureScoreControlAttributes,
	},
	{
		Name:         FamilyPurviewSensitivityLabel,
		Label:        "microsoft purview sensitivity labels",
		Path:         "/beta/security/informationProtection/sensitivityLabels",
		Kind:         "azure.purview_sensitivity_label",
		SchemaRef:    "azure/purview_sensitivity_label/v1",
		URNKind:      "azure_purview_sensitivity_label",
		ResourceType: "purview_sensitivity_label",
		Attributes:   purviewSensitivityLabelAttributes,
	},
	{
		Name:         FamilyPurviewRetentionLabel,
		Label:        "microsoft purview retention labels",
		Path:         "/beta/security/labels/retentionLabels",
		Kind:         "azure.purview_retention_label",
		SchemaRef:    "azure/purview_retention_label/v1",
		URNKind:      "azure_purview_retention_label",
		ResourceType: "purview_retention_label",
		Attributes:   purviewRetentionLabelAttributes,
	},
}

func Families[Src any, S any](source Src, tenantID func(S) string, perPage func(S) int, query func(S, int) url.Values, queryForPageToken func(string, url.Values) url.Values, getJSON JSONGetter[Src, S], emit EventEmitter[S]) []sourcecdk.Family[S] {
	families := make([]sourcecdk.Family[S], 0, len(ResourceDefinitions))
	for _, definition := range ResourceDefinitions {
		definition := definition
		family := sourcecdk.Family[S]{
			Name:                 definition.Name,
			IncrementalWatermark: definition.OccurredAt != nil,
			Check: func(ctx context.Context, settings S) error {
				_, _, err := listResources(ctx, source, settings, "", 1, definition, query, queryForPageToken, getJSON)
				if err != nil {
					return fmt.Errorf("lookup %s for %s: %w", definition.Label, tenantID(settings), err)
				}
				return nil
			},
			Discover: func(ctx context.Context, settings S) ([]sourcecdk.URN, error) {
				records, _, err := listResources(ctx, source, settings, "", perPage(settings), definition, query, queryForPageToken, getJSON)
				if err != nil {
					return nil, fmt.Errorf("lookup %s for %s: %w", definition.Label, tenantID(settings), err)
				}
				return urnsFor(tenantID(settings), definition, records)
			},
			Read: func(ctx context.Context, settings S, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
				records, next, err := listResources(ctx, source, settings, strings.TrimSpace(cursor.GetOpaque()), perPage(settings), definition, query, queryForPageToken, getJSON)
				if err != nil {
					return sourcecdk.Pull{}, fmt.Errorf("lookup %s for %s: %w", definition.Label, tenantID(settings), err)
				}
				return pullFromRecords(records, next, func(record Record) (*primitives.Event, error) {
					return event(settings, tenantID(settings), definition, record, emit)
				})
			},
		}
		if definition.OccurredAt != nil {
			family.ReadWithCheckpoint = func(ctx context.Context, settings S, cursor *cerebrov1.SourceCursor, checkpoint *cerebrov1.SourceCheckpoint) (sourcecdk.Pull, error) {
				readCheckpoint := sourcecdk.IncrementalCheckpointForCursor("azure", definition.Name, cursor, checkpoint)
				pageToken := sourcecdk.IncrementalCursorToken("azure", definition.Name, cursor, checkpoint)
				records, next, err := listResources(ctx, source, settings, pageToken, perPage(settings), definition, query, queryForPageToken, getJSON)
				if err != nil {
					return sourcecdk.Pull{}, fmt.Errorf("lookup %s for %s: %w", definition.Label, tenantID(settings), err)
				}
				return sourcecdk.IncrementalPullFromRecords("azure", definition.Name, records, next, readCheckpoint, func(record Record) (*primitives.Event, error) {
					return event(settings, tenantID(settings), definition, record, emit)
				})
			}
		}
		families = append(families, family)
	}
	return families
}

func listResources[Src any, S any](ctx context.Context, source Src, settings S, pageToken string, limit int, definition ResourceDefinition, query func(S, int) url.Values, queryForPageToken func(string, url.Values) url.Values, getJSON JSONGetter[Src, S]) ([]Record, string, error) {
	if definition.Singleton {
		var values map[string]any
		if err := getJSON(ctx, source, settings, definition.Path, nil, &values); err != nil {
			return nil, "", err
		}
		record := recordFromMap(values)
		if strings.TrimSpace(record.ID) == "" {
			record.ID = definition.Name
		}
		return []Record{record}, "", nil
	}
	graphQuery := query(settings, limit)
	var response Page
	if err := getJSON(ctx, source, settings, firstNonEmpty(pageToken, definition.Path), queryForPageToken(pageToken, graphQuery), &response); err != nil {
		return nil, "", err
	}
	records, err := sourcecdk.DecodeRecords(response.Value, definition.Label, func(record *Record, raw json.RawMessage) {
		record.Raw = append(json.RawMessage(nil), raw...)
	})
	return records, firstNonEmpty(response.ODataNext, response.NextPageLink), err
}

func event[S any](settings S, tenantID string, definition ResourceDefinition, record Record, emit EventEmitter[S]) (*primitives.Event, error) {
	graphSettings := Settings{TenantID: tenantID}
	attributes := Attributes(graphSettings, definition, record)
	if definition.Attributes != nil {
		setAttributes(attributes, definition.Attributes(graphSettings, record))
	}
	payload, err := payload(record, map[string]any{"tenant_id": tenantID})
	if err != nil {
		return nil, err
	}
	eventID := "azure-" + strings.ReplaceAll(definition.Name, "_", "-") + "-" + RecordID(definition, record)
	return emit(settings, eventID, definition.Kind, definition.SchemaRef, payload, attributes, OccurredAt(definition, record, time.Now().UTC()))
}

func urnsFor(tenantID string, definition ResourceDefinition, records []Record) ([]sourcecdk.URN, error) {
	urns := make([]sourcecdk.URN, 0, len(records))
	for _, record := range records {
		urn, err := sourcecdk.ParseURN(fmt.Sprintf("urn:cerebro:%s:%s:%s", tenantID, definition.URNKind, RecordID(definition, record)))
		if err != nil {
			return nil, err
		}
		urns = append(urns, urn)
	}
	return urns, nil
}

func pullFromRecords(records []Record, next string, build func(Record) (*primitives.Event, error)) (sourcecdk.Pull, error) {
	if len(records) == 0 {
		if next == "" {
			return sourcecdk.Pull{}, nil
		}
		return sourcecdk.Pull{NextCursor: &cerebrov1.SourceCursor{Opaque: next}}, nil
	}
	events := make([]*primitives.Event, 0, len(records))
	for _, record := range records {
		event, err := build(record)
		if err != nil {
			return sourcecdk.Pull{}, err
		}
		events = append(events, event)
	}
	pull := sourcecdk.Pull{Events: events, Checkpoint: &cerebrov1.SourceCheckpoint{Watermark: events[len(events)-1].OccurredAt, CursorOpaque: firstNonEmpty(next, events[len(events)-1].GetId())}}
	if next != "" {
		pull.NextCursor = &cerebrov1.SourceCursor{Opaque: next}
	}
	return pull, nil
}

func setAttributes(attributes map[string]string, values map[string]string) {
	for key, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			delete(attributes, key)
			continue
		}
		attributes[key] = value
	}
}

func Attributes(settings Settings, definition ResourceDefinition, record Record) map[string]string {
	resourceID := RecordID(definition, record)
	resourceName := firstNonEmpty(record.DisplayName, record.Name, record.Title, record.Description, resourceID)
	attributes := map[string]string{
		"domain":            settings.TenantID,
		"family":            definition.Name,
		"provider":          "microsoft_graph",
		"resource_id":       resourceID,
		"resource_name":     resourceName,
		"resource_provider": "azure",
		"resource_type":     firstNonEmpty(definition.ResourceType, definition.Name),
		"source_provider":   "microsoft_graph",
		"tenant_id":         settings.TenantID,
	}
	if record.Description != "" {
		attributes["description"] = record.Description
	}
	return attributes
}

func payload(record Record, values map[string]any) ([]byte, error) {
	payload := map[string]any{}
	for key, value := range values {
		payload[key] = value
	}
	if len(record.Raw) != 0 {
		var decoded any
		if err := json.Unmarshal(record.Raw, &decoded); err != nil {
			return nil, err
		}
		payload["raw"] = decoded
	}
	return json.Marshal(payload)
}

func OccurredAt(definition ResourceDefinition, record Record, fallback time.Time) time.Time {
	if definition.OccurredAt == nil {
		return fallback.UTC()
	}
	if parsed := definition.OccurredAt(record); !parsed.IsZero() {
		return parsed.UTC()
	}
	return fallback.UTC()
}

func RecordID(definition ResourceDefinition, record Record) string {
	return firstNonEmpty(record.ID, record.Name, record.DisplayName, record.Title, definition.Name)
}

func recordFromMap(values map[string]any) Record {
	raw, _ := json.Marshal(values)
	var record Record
	_ = json.Unmarshal(raw, &record)
	record.Raw = append(json.RawMessage(nil), raw...)
	return record
}

func (record Record) values() map[string]any {
	values := map[string]any{}
	if len(record.Raw) == 0 {
		return values
	}
	if err := json.Unmarshal(record.Raw, &values); err != nil {
		return map[string]any{}
	}
	return values
}

func conditionalAccessPolicyAttributes(_ Settings, record Record) map[string]string {
	values := record.values()
	conditions := mapFromAny(values["conditions"])
	users := mapFromAny(conditions["users"])
	apps := mapFromAny(conditions["applications"])
	grant := mapFromAny(values["grantControls"])
	platforms := mapFromAny(conditions["platforms"])
	locations := mapFromAny(conditions["locations"])
	attributes := map[string]string{
		"created_at":               stringFromAny(values["createdDateTime"]),
		"grant_controls":           strings.Join(graphStrings(grant["builtInControls"]), ","),
		"grant_operator":           stringFromAny(grant["operator"]),
		"group_exclude_ids":        strings.Join(graphStrings(users["excludeGroups"]), ","),
		"group_include_ids":        strings.Join(graphStrings(users["includeGroups"]), ","),
		"app_exclude_ids":          strings.Join(graphStrings(apps["excludeApplications"]), ","),
		"app_include_ids":          strings.Join(graphStrings(apps["includeApplications"]), ","),
		"include_app_ids":          strings.Join(graphStrings(apps["includeApplications"]), ","),
		"include_group_ids":        strings.Join(graphStrings(users["includeGroups"]), ","),
		"include_platforms":        strings.Join(graphStrings(platforms["includePlatforms"]), ","),
		"include_role_ids":         strings.Join(graphStrings(users["includeRoles"]), ","),
		"include_user_ids":         strings.Join(graphStrings(users["includeUsers"]), ","),
		"modified_at":              stringFromAny(values["modifiedDateTime"]),
		"network_zone_exclude_ids": strings.Join(graphStrings(locations["excludeLocations"]), ","),
		"network_zone_include_ids": strings.Join(graphStrings(locations["includeLocations"]), ","),
		"policy_id":                firstNonEmpty(record.ID, record.DisplayName),
		"policy_name":              firstNonEmpty(record.DisplayName, record.Name),
		"policy_rule_id":           firstNonEmpty(record.ID, record.DisplayName),
		"policy_rule_name":         firstNonEmpty(record.DisplayName, record.Name),
		"policy_state":             stringFromAny(values["state"]),
		"policy_status":            stringFromAny(values["state"]),
		"policy_type":              "conditional_access",
		"platform_types":           strings.Join(graphStrings(platforms["includePlatforms"]), ","),
		"session_controls":         strings.Join(graphMapKeys(mapFromAny(values["sessionControls"])), ","),
		"sign_in_risk_levels":      strings.Join(graphStrings(conditions["signInRiskLevels"]), ","),
		"status":                   stringFromAny(values["state"]),
		"user_exclude_ids":         strings.Join(graphStrings(users["excludeUsers"]), ","),
		"user_include_ids":         strings.Join(graphStrings(users["includeUsers"]), ","),
		"user_risk_levels":         strings.Join(graphStrings(conditions["userRiskLevels"]), ","),
	}
	return attributes
}

func authenticationMethodsPolicyAttributes(_ Settings, record Record) map[string]string {
	values := record.values()
	registration := mapFromAny(nestedValue(values, "registrationEnforcement", "authenticationMethodsRegistrationCampaign"))
	reportSuspicious := mapFromAny(values["reportSuspiciousActivitySettings"])
	return map[string]string{
		"method_ids":                                strings.Join(graphValuesFromArray(values, []string{"authenticationMethodConfigurations"}, "id"), ","),
		"method_states":                             strings.Join(graphValuesFromArray(values, []string{"authenticationMethodConfigurations"}, "state"), ","),
		"policy_id":                                 firstNonEmpty(record.ID, FamilyAuthenticationMethodsPolicy),
		"policy_name":                               firstNonEmpty(record.DisplayName, "Authentication methods policy"),
		"policy_status":                             stringFromAny(values["policyVersion"]),
		"policy_type":                               "authentication_methods",
		"registration_campaign_state":               stringFromAny(registration["state"]),
		"registration_campaign_snooze_days":         stringFromAny(registration["snoozeDurationInDays"]),
		"report_suspicious_activity_state":          stringFromAny(reportSuspicious["state"]),
		"system_credential_preferences_state":       stringFromAny(nestedValue(values, "systemCredentialPreferences", "state")),
		"system_credential_preferences_exclude_ids": strings.Join(graphValuesFromArray(values, []string{"systemCredentialPreferences", "excludeTargets"}, "id"), ","),
	}
}

func identityRiskyUserAttributes(_ Settings, record Record) map[string]string {
	values := record.values()
	upn := emailLike(stringFromAny(values["userPrincipalName"]))
	return map[string]string{
		"display_name":         stringFromAny(values["userDisplayName"]),
		"email":                upn,
		"is_deleted":           stringFromAny(values["isDeleted"]),
		"login":                upn,
		"risk_detail":          stringFromAny(values["riskDetail"]),
		"risk_last_updated_at": stringFromAny(values["riskLastUpdatedDateTime"]),
		"risk_level":           stringFromAny(values["riskLevel"]),
		"risk_state":           stringFromAny(values["riskState"]),
		"status":               stringFromAny(values["riskState"]),
		"subject_email":        upn,
		"subject_id":           firstNonEmpty(stringFromAny(values["userId"]), record.ID),
		"subject_login":        upn,
		"subject_name":         stringFromAny(values["userDisplayName"]),
		"user_id":              firstNonEmpty(stringFromAny(values["userId"]), record.ID),
		"user_principal_name":  stringFromAny(values["userPrincipalName"]),
	}
}

func identityRiskDetectionAttributes(_ Settings, record Record) map[string]string {
	values := record.values()
	upn := emailLike(stringFromAny(values["userPrincipalName"]))
	return map[string]string{
		"activity":              stringFromAny(values["activity"]),
		"activity_at":           stringFromAny(values["activityDateTime"]),
		"detected_at":           stringFromAny(values["detectedDateTime"]),
		"detection_timing_type": stringFromAny(values["detectionTimingType"]),
		"ip_address":            stringFromAny(values["ipAddress"]),
		"location_city":         stringFromAny(nestedValue(values, "location", "city")),
		"location_country":      stringFromAny(nestedValue(values, "location", "countryOrRegion")),
		"request_id":            stringFromAny(values["requestId"]),
		"risk_detail":           stringFromAny(values["riskDetail"]),
		"risk_event_type":       stringFromAny(values["riskEventType"]),
		"risk_level":            stringFromAny(values["riskLevel"]),
		"risk_state":            stringFromAny(values["riskState"]),
		"source":                stringFromAny(values["source"]),
		"status":                stringFromAny(values["riskState"]),
		"subject_email":         upn,
		"subject_id":            stringFromAny(values["userId"]),
		"subject_login":         upn,
		"subject_name":          stringFromAny(values["userDisplayName"]),
		"user_id":               stringFromAny(values["userId"]),
	}
}

func defenderIncidentAttributes(_ Settings, record Record) map[string]string {
	values := record.values()
	return map[string]string{
		"alert_count":          graphCount(values["alerts"]),
		"assigned_to":          stringFromAny(values["assignedTo"]),
		"classification":       stringFromAny(values["classification"]),
		"created_at":           stringFromAny(values["createdDateTime"]),
		"determination":        stringFromAny(values["determination"]),
		"incident_id":          firstNonEmpty(record.ID, stringFromAny(values["incidentId"])),
		"incident_url":         stringFromAny(values["incidentWebUrl"]),
		"last_updated_at":      stringFromAny(values["lastUpdateDateTime"]),
		"redirect_incident_id": stringFromAny(values["redirectIncidentId"]),
		"severity":             stringFromAny(values["severity"]),
		"status":               stringFromAny(values["status"]),
		"title":                firstNonEmpty(record.DisplayName, record.Title),
	}
}

func defenderAlertAttributes(_ Settings, record Record) map[string]string {
	values := record.values()
	return map[string]string{
		"alert_id":          record.ID,
		"assigned_to":       stringFromAny(values["assignedTo"]),
		"category":          stringFromAny(values["category"]),
		"classification":    stringFromAny(values["classification"]),
		"created_at":        stringFromAny(values["createdDateTime"]),
		"detection_source":  stringFromAny(values["detectionSource"]),
		"determination":     stringFromAny(values["determination"]),
		"evidence_count":    graphCount(values["evidence"]),
		"incident_id":       stringFromAny(values["incidentId"]),
		"last_updated_at":   stringFromAny(values["lastUpdateDateTime"]),
		"mitre_techniques":  strings.Join(graphStrings(values["mitreTechniques"]), ","),
		"provider_alert_id": stringFromAny(values["providerAlertId"]),
		"service_source":    stringFromAny(values["serviceSource"]),
		"severity":          stringFromAny(values["severity"]),
		"status":            stringFromAny(values["status"]),
		"title":             firstNonEmpty(record.Title, record.DisplayName),
	}
}

func secureScoreAttributes(_ Settings, record Record) map[string]string {
	values := record.values()
	return map[string]string{
		"active_user_count":   stringFromAny(values["activeUserCount"]),
		"control_count":       graphCount(values["controlScores"]),
		"created_at":          stringFromAny(values["createdDateTime"]),
		"current_score":       stringFromAny(values["currentScore"]),
		"enabled_services":    strings.Join(graphStrings(values["enabledServices"]), ","),
		"licensed_user_count": stringFromAny(values["licensedUserCount"]),
		"max_score":           stringFromAny(values["maxScore"]),
		"score_id":            record.ID,
		"vendor":              stringFromAny(nestedValue(values, "vendorInformation", "provider")),
	}
}

func secureScoreControlAttributes(_ Settings, record Record) map[string]string {
	values := record.values()
	return map[string]string{
		"action_type":                stringFromAny(values["actionType"]),
		"action_url":                 stringFromAny(values["actionUrl"]),
		"category":                   stringFromAny(values["controlCategory"]),
		"control_id":                 record.ID,
		"control_state_update_count": graphCount(values["controlStateUpdates"]),
		"deprecated":                 stringFromAny(values["deprecated"]),
		"implementation_cost":        stringFromAny(values["implementationCost"]),
		"last_synced_at":             stringFromAny(values["lastSyncedDateTime"]),
		"max_score":                  stringFromAny(values["maxScore"]),
		"rank":                       stringFromAny(values["rank"]),
		"remediation":                stringFromAny(values["remediation"]),
		"threats":                    strings.Join(graphStrings(values["threats"]), ","),
		"title":                      firstNonEmpty(record.Title, record.DisplayName),
		"tier":                       stringFromAny(values["tier"]),
		"vendor":                     stringFromAny(nestedValue(values, "vendorInformation", "provider")),
	}
}

func purviewSensitivityLabelAttributes(_ Settings, record Record) map[string]string {
	values := record.values()
	return map[string]string{
		"color":           stringFromAny(values["color"]),
		"content_formats": strings.Join(graphStrings(values["contentFormats"]), ","),
		"has_protection":  stringFromAny(values["hasProtection"]),
		"label_id":        record.ID,
		"label_name":      firstNonEmpty(record.DisplayName, record.Name),
		"parent_id":       stringFromAny(nestedValue(values, "parent", "id")),
		"parent_name":     stringFromAny(nestedValue(values, "parent", "displayName")),
		"priority":        stringFromAny(values["priority"]),
		"purview_family":  "information_protection",
		"sensitivity":     stringFromAny(values["sensitivity"]),
		"status":          boolActiveStatus(values["isActive"]),
		"tooltip":         stringFromAny(values["tooltip"]),
	}
}

func purviewRetentionLabelAttributes(_ Settings, record Record) map[string]string {
	values := record.values()
	return map[string]string{
		"action_after_retention":    stringFromAny(values["actionAfterRetentionPeriod"]),
		"behavior_during_retention": stringFromAny(values["behaviorDuringRetentionPeriod"]),
		"default_record_behavior":   stringFromAny(values["defaultRecordBehavior"]),
		"duration_days":             firstNonEmpty(stringFromAny(nestedValue(values, "retentionDuration", "days")), stringFromAny(values["retentionDurationInDays"])),
		"is_in_use":                 stringFromAny(values["isInUse"]),
		"label_id":                  record.ID,
		"label_name":                firstNonEmpty(record.DisplayName, record.Name),
		"purview_family":            "records_management",
		"retention_trigger":         stringFromAny(values["retentionTrigger"]),
		"status":                    boolActiveStatus(values["isInUse"]),
	}
}

func graphTimeFrom(keys ...string) func(Record) time.Time {
	return func(record Record) time.Time {
		values := record.values()
		for _, key := range keys {
			if parsed, ok := parseGraphTime(stringFromAny(values[key])); ok {
				return parsed
			}
		}
		return time.Time{}
	}
}

func parseGraphTime(value string) (time.Time, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, false
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, false
	}
	return parsed.UTC(), true
}

func graphStrings(value any) []string {
	values := make([]string, 0)
	switch typed := value.(type) {
	case []any:
		for _, item := range typed {
			values = append(values, stringFromAny(item))
		}
	case []string:
		values = append(values, typed...)
	case string:
		values = append(values, typed)
	}
	return uniqueStrings(values)
}

func graphValuesFromArray(values map[string]any, path []string, field string) []string {
	items := arrayFromAny(nestedValue(values, path...))
	out := make([]string, 0, len(items))
	for _, item := range items {
		itemMap := mapFromAny(item)
		if itemMap == nil {
			continue
		}
		out = append(out, stringFromAny(itemMap[field]))
	}
	return uniqueStrings(out)
}

func graphMapKeys(values map[string]any) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	return uniqueStrings(keys)
}

func graphCount(value any) string {
	switch typed := value.(type) {
	case []any:
		return fmt.Sprintf("%d", len(typed))
	case []string:
		return fmt.Sprintf("%d", len(typed))
	default:
		return ""
	}
}

func boolActiveStatus(value any) string {
	switch typed := value.(type) {
	case bool:
		if typed {
			return "ACTIVE"
		}
		return "DISABLED"
	case string:
		if strings.EqualFold(typed, "true") || strings.EqualFold(typed, "active") || strings.EqualFold(typed, "enabled") {
			return "ACTIVE"
		}
		if strings.EqualFold(typed, "false") || strings.EqualFold(typed, "disabled") {
			return "DISABLED"
		}
	}
	return ""
}

func nestedValue(values map[string]any, keys ...string) any {
	if len(keys) == 0 {
		return values
	}
	var current any = values
	for _, key := range keys {
		currentMap := mapFromAny(current)
		if currentMap == nil {
			return nil
		}
		current = currentMap[key]
	}
	return current
}

func mapFromAny(value any) map[string]any {
	if value == nil {
		return nil
	}
	if typed, ok := value.(map[string]any); ok {
		return typed
	}
	return nil
}

func arrayFromAny(value any) []any {
	if value == nil {
		return nil
	}
	if typed, ok := value.([]any); ok {
		return typed
	}
	return nil
}

func stringFromAny(value any) string {
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case bool:
		return strconv.FormatBool(typed)
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	case int:
		return strconv.Itoa(typed)
	case json.Number:
		return typed.String()
	default:
		return ""
	}
}

func uniqueStrings(values []string) []string {
	seen := map[string]struct{}{}
	unique := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		unique = append(unique, value)
	}
	sort.Strings(unique)
	return unique
}

func emailLike(value string) string {
	trimmed := strings.TrimSpace(value)
	if strings.Contains(trimmed, "@") {
		return strings.ToLower(trimmed)
	}
	return ""
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
