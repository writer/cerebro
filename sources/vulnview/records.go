package vulnview

import (
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
	return record{Raw: sourcecdk.CloneRawMessage(raw), Values: values, ID: recordID(family, values)}, nil
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
	case familyCloudIdentityFinding:
		return stableID(firstValueString(values, "findingId"), firstValueString(values, "version"))
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

func eventFromRecord(settings settings, family string, record record) *primitives.Event {
	occurredAt := occurredAtFor(record.Values)
	return &primitives.Event{
		Id:         eventID(settings, family, record.ID),
		TenantId:   settings.tenantID,
		SourceId:   sourceID,
		Kind:       sourceID + "." + family,
		OccurredAt: timestamppb.New(occurredAt),
		SchemaRef:  sourceID + "/" + family + "/v1",
		Payload:    sourcecdk.CloneRawMessage(record.Raw),
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
	return sourcecdk.ScopeHash(settings.baseURL, settings.clientID, settings.scope)
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
		copyFields(attrs, values, map[string]string{"site_id": "siteId", "name": "name"})
	case familyScan:
		copyFields(attrs, values, map[string]string{"scan_id": "scanId", "site_id": "siteId", "name": "name", "scan_type": "scanType", "target": "target", "status": "status", "findings_count": "findingsCount", "results_key": "resultsKey", "created_at": "createdAt", "started_at": "startedAt", "completed_at": "completedAt", "cloud_account_id": "cloudAccountId"})
	case familyVulnerability:
		copyFields(attrs, values, map[string]string{"vulnerability_id": "templateId", "template_id": "templateId", "name": "name", "severity": "severity", "type": "type", "target_id": "host", "target_name": "host", "host": "host", "matched_at": "matchedAt", "description": "description", "remediation": "remediation", "scan_id": "scanId", "scan_name": "scanName", "site_id": "siteId", "site_name": "siteName", "timestamp": "timestamp"})
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
		copyFields(attrs, values, map[string]string{"asset_id": "asset", "asset_name": "asset", "target_id": "asset", "target_name": "asset", "highest_severity": "highestSeverity", "findings_count": "findingsCount", "sites": "sites", "scan_names": "scanNames", "critical_count": "severityCounts.critical", "high_count": "severityCounts.high", "medium_count": "severityCounts.medium", "low_count": "severityCounts.low", "info_count": "severityCounts.info", "dns_alerts_count": "dnsAlertSummary.total", "dns_highest_alert": "dnsAlertSummary.highestSeverity"})
		attrs["target_type"] = "external_asset"
	case familyDNSAlert:
		copyFields(attrs, values, map[string]string{"asset_id": "asset", "asset_name": "asset", "target_id": "asset", "target_name": "asset", "alert": "alert", "name": "alert", "severity": "severity", "description": "description", "record_type": "recordType", "record_value": "recordValue", "sites": "siteNames", "scan_names": "scanNames"})
		addVulnViewFindingStateAttributes(attrs, values)
		attrs["target_type"] = "external_asset"
	case familyCloudIdentityFinding:
		copyFields(attrs, values, map[string]string{"finding_id": "findingId", "check_id": "checkId", "check_version": "checkVersion", "detector_version": "detectorVersion", "status": "status", "severity": "severity", "title": "title", "cloud_provider": "provider", "account_id": "account", "project_id": "project", "principal_id": "principalId", "principal_kind": "principalKind", "cohort_scope": "cohortScope", "evidence_stream": "evidenceStream", "version": "version", "first_seen_at": "firstSeenAt", "last_seen_at": "lastSeenAt", "last_evaluated_at": "lastEvaluatedAt", "fixed_at": "fixedAt", "reopened_at": "reopenedAt", "updated_at": "updatedAt", "last_scan_id": "lastScanId", "last_run_id": "lastRunId", "side": "side", "drift": "drift", "evidence_bundle_key": "evidence.bundleKey", "evidence_bundle_sha256": "evidence.bundleSha256", "evidence_principal_evidence_sha256": "evidence.principalEvidenceSha256", "evidence_collected_at": "evidence.collectedAt", "gap_codes": "gapCodes"})
		attrs["source_severity"] = firstValueString(values, "severity")
		attrs["target_type"] = "cloud_identity_finding"
		if consumers := cloudIdentityConsumersSummary(values); consumers != "" {
			attrs["consumers"] = consumers
		}
	}
	trimEmptyAttributes(attrs)
	return attrs
}

func addVulnViewFindingStateAttributes(attrs map[string]string, values map[string]any) {
	stateFields := map[string][]string{"vulnview_status": {"status"}, "vulnview_state": {"state"}, "vulnview_finding_status": {"findingStatus", "finding_status"}, "vulnview_remediation_state": {"remediationState", "remediation_state"}, "vulnview_lifecycle_state": {"lifecycleState", "lifecycle_state"}}
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

// vulnviewTimeLayouts are the timestamp formats VulnView's export and legacy
// list endpoints use; sourcecdk.JSONObject.FieldTime tries them in order.
var vulnviewTimeLayouts = []string{time.RFC3339Nano, time.RFC3339, "2006-01-02"}

func occurredAtFor(values map[string]any) time.Time {
	if occurredAt := sourcecdk.JSONObject(values).FieldTime(vulnviewTimeLayouts, "timestamp", "completedAt", "evaluatedAt", "lastEvaluatedAt", "updatedAt", "startedAt", "createdAt", "matchedAt", "matched-at"); !occurredAt.IsZero() {
		return occurredAt
	}
	return time.Now().UTC()
}

// copyFields and firstValueString read dot-separated provider field paths
// (e.g. "severityCounts.critical") via sourcecdk.JSONObject, which flattens
// a decoded JSON value to the same normalized string form regardless of
// nesting depth.
func copyFields(attrs map[string]string, values map[string]any, fields map[string]string) {
	sourcecdk.JSONObject(values).CopyFields(attrs, fields)
}

func firstValueString(values map[string]any, keys ...string) string {
	return sourcecdk.JSONObject(values).FirstFieldString(keys...)
}

// cloudIdentityConsumersSummary flattens the bounded "consumers" array a
// cloud_identity_finding export item carries into a comma-joined list of
// cluster-qualified "<cluster>/<namespace>/<serviceAccount>" identifiers,
// so a consumer can never be confused with a same-named service account in
// a different cluster once read back from a flattened string attribute.
// Field names are camelCase ("serviceAccount"), matching the VulnView
// export wire format.
func cloudIdentityConsumersSummary(values map[string]any) string {
	raw := sourcecdk.JSONObject(values).Array("consumers")
	if raw == nil {
		return ""
	}
	parts := make([]string, 0, len(raw))
	for _, item := range raw {
		consumer, ok := item.(map[string]any)
		if !ok {
			continue
		}
		cluster := sourcecdk.JSONScalar{Value: consumer["cluster"]}.Flattened()
		namespace := sourcecdk.JSONScalar{Value: consumer["namespace"]}.Flattened()
		serviceAccount := sourcecdk.JSONScalar{Value: consumer["serviceAccount"]}.Flattened()
		if cluster == "" || namespace == "" || serviceAccount == "" {
			continue
		}
		parts = append(parts, cluster+"/"+namespace+"/"+serviceAccount)
	}
	return strings.Join(parts, ",")
}

func stableID(parts ...string) string { return sourcecdk.StableID(parts...) }

func normalizeID(value string) string { return sourcecdk.NormalizeID(value) }

func firstNonEmpty(values ...string) string { return sourcecdk.FirstNonEmpty(values...) }

func trimEmptyAttributes(attrs map[string]string) { sourcecdk.TrimEmptyAttributes(attrs) }
