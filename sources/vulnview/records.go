package vulnview

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/writer/cerebro/internal/primitives"
	"github.com/writer/cerebro/internal/sourcecdk"
)

type record struct {
	Raw    json.RawMessage
	Values map[string]any
	ID     string
}

type listResponse struct {
	Items      []json.RawMessage `json:"items"`
	NextCursor string            `json:"nextCursor"`
}

func recordFromRaw(family string, raw json.RawMessage) (record, error) {
	values := map[string]any{}
	if err := json.Unmarshal(raw, &values); err != nil {
		return record{}, fmt.Errorf("decode VulnView %s record: %w", family, err)
	}
	return record{Raw: cloneRaw(raw), Values: values, ID: recordID(family, values)}, nil
}

func recordID(family string, values map[string]any) string {
	switch family {
	case familySite:
		return firstValueString(values, "siteId", "id", "name")
	case familyScan:
		return firstValueString(values, "scanId", "id", "name")
	case familyVulnerability:
		return stableID(
			firstValueString(values, "scanId"),
			firstValueString(values, "templateId", "template-id", "id", "name"),
			firstValueString(values, "matchedAt", "matched-at", "host"),
		)
	case familyAsset:
		return firstValueString(values, "asset", "host", "matchedAt", "matched-at")
	default:
		return firstValueString(values, "id", "name")
	}
}

func urnsFor(settings settings, family string, records []record) ([]sourcecdk.URN, error) {
	urns := make([]sourcecdk.URN, 0, len(records))
	for _, record := range records {
		urn, err := sourcecdk.ParseURN(fmt.Sprintf("urn:cerebro:%s:vulnview_%s:%s", settings.tenantID, family, normalizeID(record.ID)))
		if err != nil {
			return nil, err
		}
		urns = append(urns, urn)
	}
	return urns, nil
}

func pullFromRecords(settings settings, family string, records []record, next string) (sourcecdk.Pull, error) {
	return sourcecdk.PullFromRecords(records, next,
		func(rec record) (*primitives.Event, error) {
			return eventFromRecord(settings, family, rec), nil
		},
		func(rec record) string { return strings.TrimSpace(rec.ID) },
	)
}

func eventFromRecord(settings settings, family string, record record) *primitives.Event {
	occurredAt := occurredAtFor(record.Values)
	return &primitives.Event{
		Id:         eventID(settings, family, record.ID),
		TenantId:   settings.tenantID,
		SourceId:   sourceID,
		Kind:       sourceID + "." + family,
		OccurredAt: timestamppb.New(occurredAt),
		SchemaRef:  sourceID + "/" + family + "/v1",
		Payload:    cloneRaw(record.Raw),
		Attributes: attributesFor(family, record),
	}
}

func eventID(settings settings, family string, recordID string) string {
	return strings.Join([]string{
		sourceID,
		normalizeID(settings.tenantID),
		runtimeScope(settings),
		normalizeID(family),
		normalizeID(recordID),
	}, "-")
}

func runtimeScope(settings settings) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		settings.baseURL,
		settings.clientID,
		settings.scope,
	}, "\x00")))
	return hex.EncodeToString(sum[:])[:12]
}

func attributesFor(family string, record record) map[string]string {
	values := record.Values
	attrs := map[string]string{
		"external_id":     record.ID,
		"family":          family,
		"provider":        sourceID,
		"source_provider": sourceID,
	}
	switch family {
	case familySite:
		copyFields(attrs, values, map[string]string{
			"site_id": "siteId",
			"name":    "name",
		})
	case familyScan:
		copyFields(attrs, values, map[string]string{
			"scan_id":          "scanId",
			"site_id":          "siteId",
			"name":             "name",
			"scan_type":        "scanType",
			"target":           "target",
			"status":           "status",
			"findings_count":   "findingsCount",
			"results_key":      "resultsKey",
			"created_at":       "createdAt",
			"started_at":       "startedAt",
			"completed_at":     "completedAt",
			"cloud_account_id": "cloudAccountId",
		})
	case familyVulnerability:
		copyFields(attrs, values, map[string]string{
			"vulnerability_id": "templateId",
			"template_id":      "templateId",
			"name":             "name",
			"severity":         "severity",
			"type":             "type",
			"target_id":        "host",
			"target_name":      "host",
			"host":             "host",
			"matched_at":       "matchedAt",
			"description":      "description",
			"remediation":      "remediation",
			"scan_id":          "scanId",
			"scan_name":        "scanName",
			"site_id":          "siteId",
			"site_name":        "siteName",
			"timestamp":        "timestamp",
		})
		addVulnViewFindingStateAttributes(attrs, values)
		if attrs["template_id"] == "" {
			copyFields(attrs, values, map[string]string{"template_id": "template-id", "vulnerability_id": "template-id"})
		}
		if attrs["matched_at"] == "" {
			copyFields(attrs, values, map[string]string{"matched_at": "matched-at"})
		}
		attrs["target_type"] = "external_asset"
		attrs["vulnerability_type"] = firstNonEmpty(attrs["type"], "vulnview")
	case familyAsset:
		copyFields(attrs, values, map[string]string{
			"asset_id":          "asset",
			"asset_name":        "asset",
			"target_id":         "asset",
			"target_name":       "asset",
			"highest_severity":  "highestSeverity",
			"findings_count":    "findingsCount",
			"sites":             "sites",
			"scan_names":        "scanNames",
			"critical_count":    "severityCounts.critical",
			"high_count":        "severityCounts.high",
			"medium_count":      "severityCounts.medium",
			"low_count":         "severityCounts.low",
			"info_count":        "severityCounts.info",
			"dns_alerts_count":  "dnsAlertSummary.total",
			"dns_highest_alert": "dnsAlertSummary.highestSeverity",
		})
		attrs["target_type"] = "external_asset"
	case familyDNSAlert:
		copyFields(attrs, values, map[string]string{
			"asset_id":     "asset",
			"asset_name":   "asset",
			"target_id":    "asset",
			"target_name":  "asset",
			"alert":        "alert",
			"name":         "alert",
			"severity":     "severity",
			"description":  "description",
			"record_type":  "recordType",
			"record_value": "recordValue",
			"sites":        "siteNames",
			"scan_names":   "scanNames",
		})
		addVulnViewFindingStateAttributes(attrs, values)
		attrs["target_type"] = "external_asset"
	}
	trimEmptyAttributes(attrs)
	return attrs
}

func addVulnViewFindingStateAttributes(attrs map[string]string, values map[string]any) {
	stateFields := map[string][]string{
		"vulnview_status":            {"status"},
		"vulnview_state":             {"state"},
		"vulnview_finding_status":    {"findingStatus", "finding_status"},
		"vulnview_remediation_state": {"remediationState", "remediation_state"},
		"vulnview_lifecycle_state":   {"lifecycleState", "lifecycle_state"},
	}
	for attr, fields := range stateFields {
		if value := firstValueString(values, fields...); value != "" {
			attrs[attr] = value
		}
	}
	attrs["vulnview_finding_state"] = firstNonEmpty(
		attrs["vulnview_status"],
		attrs["vulnview_state"],
		attrs["vulnview_finding_status"],
		attrs["vulnview_remediation_state"],
		attrs["vulnview_lifecycle_state"],
	)
}

func occurredAtFor(values map[string]any) time.Time {
	for _, key := range []string{"timestamp", "completedAt", "startedAt", "createdAt", "matchedAt", "matched-at"} {
		if parsed, ok := parseTime(valueString(valueAt(values, key))); ok {
			return parsed
		}
	}
	return time.Now().UTC()
}

func parseTime(raw string) (time.Time, bool) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02"} {
		parsed, err := time.Parse(layout, value)
		if err == nil {
			return parsed.UTC(), true
		}
	}
	return time.Time{}, false
}

func copyFields(attrs map[string]string, values map[string]any, fields map[string]string) {
	for attr, field := range fields {
		if value := valueString(valueAt(values, field)); value != "" {
			attrs[attr] = value
		}
	}
}

func firstValueString(values map[string]any, keys ...string) string {
	for _, key := range keys {
		if value := valueString(valueAt(values, key)); value != "" {
			return value
		}
	}
	return ""
}

func valueAt(values map[string]any, path string) any {
	current := any(values)
	for _, part := range strings.Split(path, ".") {
		object, ok := current.(map[string]any)
		if !ok {
			return nil
		}
		current = object[part]
	}
	return current
}

func valueString(value any) string {
	return sourcecdk.JSONScalar{Value: value}.Flattened()
}

func stableID(parts ...string) string {
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		if value := strings.TrimSpace(part); value != "" {
			values = append(values, value)
		}
	}
	return strings.Join(values, ":")
}

func normalizeID(value string) string {
	if normalized := strings.TrimSpace(value); normalized != "" {
		return strings.NewReplacer(" ", "-", "/", "-", ":", "-", "\n", "-", "\t", "-").Replace(normalized)
	}
	return "unknown"
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func trimEmptyAttributes(attrs map[string]string) {
	for key, value := range attrs {
		if strings.TrimSpace(value) == "" {
			delete(attrs, key)
			continue
		}
		attrs[key] = strings.TrimSpace(value)
	}
}

func cloneRaw(raw json.RawMessage) json.RawMessage {
	return append(json.RawMessage(nil), raw...)
}
