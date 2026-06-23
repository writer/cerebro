package gcpcloud

import (
	"bytes"
	"encoding/json"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/primitives"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var cloudIDSResourceLabelIDFilterRE = regexp.MustCompile(`resource\.labels\.id\s*(?:=|:)\s*"?([^"\s)]+)"?`)

var gcsContentEmailRE = regexp.MustCompile(`[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}`)

var gcsContentClassificationRE = regexp.MustCompile(`\b(restricted|confidential|internal|public)\b`)

var gcsContentSecretRE = regexp.MustCompile(`(?i)(api[_-]?key|secret|token|password|passwd|private[_-]?key)\s*[:=]\s*["']?[a-z0-9_./+=\-]{12,}`)

var gcsContentSSNRE = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)

const FindingCheckpointLookback = 2 * time.Minute

func CheckpointStart(checkpoint *cerebrov1.SourceCheckpoint, lookback time.Duration) (time.Time, bool) {
	if checkpoint == nil || checkpoint.GetWatermark() == nil {
		return time.Time{}, false
	}
	watermark := checkpoint.GetWatermark().AsTime().UTC()
	if watermark.IsZero() {
		return time.Time{}, false
	}
	if lookback > 0 {
		watermark = watermark.Add(-lookback)
	}
	return watermark, true
}

func CombineFilters(existing string, incremental string) string {
	existing = strings.TrimSpace(existing)
	incremental = strings.TrimSpace(incremental)
	switch {
	case existing == "":
		return incremental
	case incremental == "":
		return existing
	default:
		return "(" + existing + ") AND (" + incremental + ")"
	}
}

type Settings struct {
	ProjectID           string
	TenantID            string
	Location            string
	CustomerID          string
	GroupKey            string
	ServiceAccountEmail string
}

type PayloadValues map[string]any

func ComputeAggregatedRawRecords[T any](items map[string]T, get func(T) []json.RawMessage, scopeField string) []json.RawMessage {
	rawRecords := make([]json.RawMessage, 0)
	for scope, scoped := range items {
		field := computeAggregatedScopeField(scope, scopeField)
		fieldNeedle := []byte(`"` + field + `"`)
		for _, raw := range get(scoped) {
			if len(raw) == 0 {
				continue
			}
			rawRecords = append(rawRecords, raw)
			if field != "" && scope != "" && !bytes.Contains(raw, fieldNeedle) {
				var withScope map[string]any
				if err := json.Unmarshal(raw, &withScope); err == nil {
					withScope[field] = scope
					if patched, err := json.Marshal(withScope); err == nil {
						rawRecords[len(rawRecords)-1] = patched
					}
				}
			}
		}
	}
	return rawRecords
}

func computeAggregatedScopeField(scope string, fallback string) string {
	switch {
	case strings.HasPrefix(scope, "regions/"):
		return "region"
	case strings.HasPrefix(scope, "zones/"):
		return "zone"
	default:
		return fallback
	}
}

type AuditRecord struct {
	InsertID     string        `json:"insertId"`
	Timestamp    string        `json:"timestamp"`
	ProtoPayload AuditProto    `json:"protoPayload"`
	Resource     AuditResource `json:"resource"`
	Raw          json.RawMessage
}

type AuditProto struct {
	MethodName         string                  `json:"methodName"`
	ServiceName        string                  `json:"serviceName"`
	ResourceName       string                  `json:"resourceName"`
	AuthenticationInfo AuditAuthenticationInfo `json:"authenticationInfo"`
}

type AuditAuthenticationInfo struct {
	PrincipalEmail   string `json:"principalEmail"`
	PrincipalSubject string `json:"principalSubject"`
}

type AuditResource struct {
	Type   string            `json:"type"`
	Labels map[string]string `json:"labels"`
}

func AuditEvent(settings Settings, record AuditRecord) (*primitives.Event, error) {
	resourceID := firstNonEmpty(record.ProtoPayload.ResourceName, record.Resource.Labels["project_id"], settings.ProjectID)
	attributes := map[string]string{
		"actor_alternate_id": firstNonEmpty(record.ProtoPayload.AuthenticationInfo.PrincipalEmail, record.ProtoPayload.AuthenticationInfo.PrincipalSubject),
		"actor_email":        emailLike(record.ProtoPayload.AuthenticationInfo.PrincipalEmail),
		"actor_id":           firstNonEmpty(record.ProtoPayload.AuthenticationInfo.PrincipalSubject, record.ProtoPayload.AuthenticationInfo.PrincipalEmail),
		"domain":             settings.TenantID,
		"event_name":         record.ProtoPayload.MethodName,
		"event_type":         record.ProtoPayload.MethodName,
		"family":             "audit",
		"resource_id":        resourceID,
		"resource_name":      resourceID,
		"resource_type":      firstNonEmpty(record.Resource.Type, record.ProtoPayload.ServiceName, "resource"),
	}
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	occurredAt := time.Now().UTC()
	if record.Timestamp != "" {
		if parsed, err := time.Parse(time.RFC3339Nano, record.Timestamp); err == nil {
			occurredAt = parsed.UTC()
		}
	}
	return sourceEventAt(settings, "gcp-audit-"+firstNonEmpty(record.InsertID, record.ProtoPayload.MethodName), "gcp.audit", "gcp/audit/v1", payload, attributes, occurredAt)
}

func publicPrincipal(value string) bool {
	normalized := strings.ToLower(strings.TrimSpace(value))
	return normalized == "allusers" || normalized == "allauthenticatedusers" || normalized == "all_users" || normalized == "all_authenticated_users"
}

func uniqueSortedStrings(values []string) []string {
	unique := []string{}
	for _, value := range values {
		unique = appendUnique(unique, value)
	}
	sort.Strings(unique)
	return unique
}

func appendUnique(values []string, value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return values
	}
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func unixMillisTime(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	millis, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return value
	}
	return time.UnixMilli(millis).UTC().Format(time.RFC3339)
}

func parentResourceName(name string, childCollection string) string {
	marker := "/" + strings.Trim(childCollection, "/") + "/"
	if index := strings.LastIndex(name, marker); index > 0 {
		return name[:index]
	}
	return ""
}

func firstString(values []string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func cloudResourceAttributes(settings Settings, family string, resourceID string, resourceName string, resourceType string, location string, labels map[string]string) map[string]string {
	attributes := map[string]string{
		"domain":            settings.TenantID,
		"family":            family,
		"gcp_project_id":    settings.ProjectID,
		"location":          location,
		"project_id":        settings.ProjectID,
		"region":            location,
		"resource_id":       resourceID,
		"resource_name":     firstNonEmpty(resourceName, resourceID),
		"resource_provider": "gcp",
		"resource_type":     resourceType,
		"source_provider":   "gcp",
	}
	addLabelAttributes(attributes, labels)
	return attributes
}

func addLabelAttributes(attributes map[string]string, labels map[string]string) {
	if len(labels) == 0 {
		return
	}
	if encoded, err := json.Marshal(labels); err == nil {
		attributes["labels"] = string(encoded)
	}
	attributes["owner"] = labelLookup(labels, "owner", "application_owner", "business_owner", "service_owner")
	attributes["team"] = labelLookup(labels, "team", "squad", "group")
	attributes["environment"] = labelLookup(labels, "environment", "env", "stage")
	for key, value := range labels {
		normalized := normalizeLabelKey(key)
		if normalized == "" || strings.TrimSpace(value) == "" {
			continue
		}
		attributes["label_"+normalized] = value
	}
}

func payloadWithRaw(raw json.RawMessage, values map[string]any) ([]byte, error) {
	payload := map[string]any{}
	for key, value := range values {
		payload[key] = value
	}
	if len(raw) != 0 {
		var decoded any
		if err := json.Unmarshal(raw, &decoded); err != nil {
			return nil, err
		}
		payload["raw"] = decoded
	}
	return json.Marshal(payload)
}

func PayloadWithRaw(raw json.RawMessage, values PayloadValues) ([]byte, error) {
	return payloadWithRaw(raw, values)
}

func sourceEvent(settings Settings, id string, kind string, schemaRef string, payload []byte, attributes map[string]string) (*primitives.Event, error) {
	return sourceEventAt(settings, id, kind, schemaRef, payload, attributes, time.Now().UTC())
}

func sourceEventAt(settings Settings, id string, kind string, schemaRef string, payload []byte, attributes map[string]string, occurredAt time.Time) (*primitives.Event, error) {
	trimEmptyAttributes(attributes)
	return &primitives.Event{
		Id:         sanitizeEventID(id),
		TenantId:   settings.TenantID,
		SourceId:   "gcp",
		Kind:       kind,
		OccurredAt: timestamppb.New(occurredAt.UTC()),
		SchemaRef:  schemaRef,
		Payload:    payload,
		Attributes: attributes,
	}, nil
}

func labelLookup(labels map[string]string, keys ...string) string {
	if len(labels) == 0 {
		return ""
	}
	normalized := map[string]string{}
	for key, value := range labels {
		normalized[normalizeLabelKey(key)] = value
	}
	for _, key := range keys {
		if value := strings.TrimSpace(normalized[normalizeLabelKey(key)]); value != "" {
			return value
		}
	}
	return ""
}

func LabelLookup(labels map[string]string, keys ...string) string {
	return labelLookup(labels, keys...)
}

func normalizeLabelKey(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.ReplaceAll(value, "-", "_")
	value = strings.ReplaceAll(value, " ", "_")
	return value
}

func CriticalityFromLabels(labels map[string]string) string {
	for _, value := range labels {
		normalized := strings.ToLower(strings.TrimSpace(value))
		switch normalized {
		case "critical", "high", "tier0", "tier_0", "tier-0", "crown_jewel", "crown-jewel":
			return "critical"
		}
	}
	return ""
}

func CrownJewelFromLabels(labels map[string]string) bool {
	for _, key := range []string{"crown_jewel", "crown-jewel", "tier0", "tier_0", "business_critical"} {
		if value := strings.ToLower(labelLookup(labels, key)); value == "true" || value == "yes" || value == "1" || value == "critical" {
			return true
		}
	}
	return strings.EqualFold(CriticalityFromLabels(labels), "critical")
}

func boolString(value bool) string {
	return strconv.FormatBool(value)
}

func disabledStatus(disabled bool) string {
	if disabled {
		return "DISABLED"
	}
	return "ACTIVE"
}

func emailLike(value string) string {
	trimmed := strings.TrimSpace(value)
	if strings.Contains(trimmed, "@") {
		return strings.ToLower(trimmed)
	}
	return ""
}

func locationFromResourceName(value string) string {
	parts := strings.Split(strings.Trim(value, "/"), "/")
	for index, part := range parts {
		if part == "locations" && index+1 < len(parts) {
			return parts[index+1]
		}
		if part == "zones" && index+1 < len(parts) {
			return parts[index+1]
		}
	}
	return ""
}

func LocationFromResourceName(value string) string {
	return locationFromResourceName(value)
}

func lastPathSegment(value string) string {
	value = strings.Trim(strings.TrimSpace(value), "/")
	if value == "" {
		return ""
	}
	parts := strings.Split(value, "/")
	return parts[len(parts)-1]
}

func LastPathSegment(value string) string {
	return lastPathSegment(value)
}

func EscapePathSegments(value string) string {
	parts := strings.Split(strings.Trim(value, "/"), "/")
	for index, part := range parts {
		parts[index] = url.PathEscape(part)
	}
	return strings.Join(parts, "/")
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func trimEmptyAttributes(attributes map[string]string) {
	for key, value := range attributes {
		if strings.TrimSpace(value) == "" {
			delete(attributes, key)
			continue
		}
		attributes[key] = strings.TrimSpace(value)
	}
}

func TrimEmptyAttributes(attributes map[string]string) {
	trimEmptyAttributes(attributes)
}

func sanitizeEventID(value string) string {
	value = strings.ReplaceAll(value, " ", "-")
	value = strings.ReplaceAll(value, "/", "-")
	value = strings.ReplaceAll(value, ":", "-")
	return strings.Trim(value, "-")
}

func SanitizeEventID(value string) string {
	return sanitizeEventID(value)
}

func SanitizeURNPart(value string) string {
	value = strings.ReplaceAll(value, ":", "_")
	value = strings.ReplaceAll(value, "/", "_")
	value = strings.ReplaceAll(value, " ", "_")
	return strings.Trim(value, "_")
}
