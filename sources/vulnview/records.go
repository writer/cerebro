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
	case familyAsset:
		return firstValueString(values, "asset", "host", "matchedAt", "matched-at")
	case familyFinding:
		return firstValueString(values, "findingId")
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
		Id:         eventID(settings, family, record),
		TenantId:   settings.tenantID,
		SourceId:   sourceID,
		Kind:       sourceID + "." + family,
		OccurredAt: timestamppb.New(occurredAt),
		SchemaRef:  sourceID + "/" + family + "/v1",
		Payload:    sourcecdk.CloneRawMessage(record.Raw),
		Attributes: attributesFor(family, record),
	}
}

// eventID scopes an event to tenant/runtime/family/record. Finding events also
// carry the numeric version so append-log message-ID deduplication keeps every
// version while a replay of one version keeps the same ID.
func eventID(settings settings, family string, record record) string {
	parts := []string{
		sourceID,
		normalizeID(settings.tenantID),
		runtimeScope(settings),
		normalizeID(family),
		normalizeID(record.ID),
	}
	if family == familyFinding {
		if version := firstValueString(record.Values, "version"); version != "" {
			parts = append(parts, normalizeID(version))
		}
	}
	return strings.Join(parts, "-")
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
	case familyAsset:
		copyFields(attrs, values, map[string]string{"asset_id": "asset", "asset_name": "asset", "target_id": "asset", "target_name": "asset", "highest_severity": "highestSeverity", "findings_count": "findingsCount", "sites": "sites", "scan_names": "scanNames", "critical_count": "severityCounts.critical", "high_count": "severityCounts.high", "medium_count": "severityCounts.medium", "low_count": "severityCounts.low", "info_count": "severityCounts.info"})
		attrs["target_type"] = "external_asset"
	case familyFinding:
		attributesForFinding(attrs, values)
	}
	trimEmptyAttributes(attrs)
	return attrs
}

// attributesForFinding flattens a vulnview-finding-export/v1 item (Contract C7)
// onto bounded event attributes, including the source-specific details object.
func attributesForFinding(attrs map[string]string, values map[string]any) {
	copyFields(attrs, values, map[string]string{
		"finding_id":                         "findingId",
		"check_id":                           "checkId",
		"title":                              "title",
		"description":                        "description",
		"severity":                           "severity",
		"status":                             "status",
		"location":                           "location",
		"resource_provider":                  "resource.provider",
		"resource_account":                   "resource.account",
		"resource_account_name":              "resource.accountName",
		"resource_project":                   "resource.project",
		"resource_region":                    "resource.region",
		"resource_type":                      "resource.resourceType",
		"resource_name":                      "resource.resourceName",
		"resource_kind":                      "resource.kind",
		"resource_port":                      "resource.port",
		"resource_protocol":                  "resource.protocol",
		"remediation":                        "remediation",
		"references":                         "references",
		"triage_state":                       "triage.state",
		"triage_reason":                      "triage.reason",
		"triage_by":                          "triage.by",
		"triage_at":                          "triage.at",
		"triage_expires_at":                  "triage.expiresAt",
		"first_seen_at":                      "lifecycle.firstSeenAt",
		"last_seen_at":                       "lifecycle.lastSeenAt",
		"last_evaluated_at":                  "lifecycle.lastEvaluatedAt",
		"fixed_at":                           "lifecycle.fixedAt",
		"reopened_at":                        "lifecycle.reopenedAt",
		"reopen_count":                       "lifecycle.reopenCount",
		"last_scan_id":                       "provenance.lastScanId",
		"last_run_id":                        "provenance.lastRunId",
		"last_site_id":                       "provenance.lastSiteId",
		"provenance_integration_attribution": "provenance.integrationAttribution",
		"version":                            "version",
		"updated_at":                         "updatedAt",
	})
	provenance := sourcecdk.JSONObject(values).Nested("provenance")
	attrs["provenance_integrations"] = provenance.Array("integrations").SortedJoinObjects(",", vulnviewIntegrationRef)
	attrs["provenance_repository_integrations"] = provenance.Array("repositoryIntegrations").SortedJoinObjects(",", vulnviewIntegrationRef)
	attrs["source"] = firstValueString(values, "source")
	attrs["source_severity"] = firstValueString(values, "severity")
	if asset := firstValueString(values, "asset"); asset != "" {
		attrs["asset"] = asset
		attrs["asset_id"] = asset
		attrs["target_type"] = "external_asset"
	}
	details, ok := values["details"].(map[string]any)
	if !ok {
		return
	}
	copyFields(attrs, details, map[string]string{
		"principal_id":                       "principalId",
		"principal_kind":                     "principalKind",
		"cohort_scope":                       "cohortScope",
		"check_version":                      "checkVersion",
		"detector_version":                   "detectorVersion",
		"side":                               "side",
		"drift":                              "drift",
		"gap_codes":                          "gapCodes",
		"evidence_bundle_key":                "evidence.bundleKey",
		"evidence_bundle_sha256":             "evidence.bundleSha256",
		"evidence_principal_evidence_sha256": "evidence.principalEvidenceSha256",
		"evidence_collected_at":              "evidence.collectedAt",
		"matcher":                            "matcher",
		"template_path":                      "templatePath",
		"sharing_services":                   "sharing.services",
		"sharing_consumer_ids":               "sharing.consumerIds",
		"detail_truncated":                   "detailTruncated",
		"excess_declared_count":              "excessSummary.declared",
		"excess_observed_count":              "excessSummary.observed",
		"sharing_services_count":             "sharingSummary.services",
		"sharing_consumer_ids_count":         "sharingSummary.consumerIds",
	})
	if complete, ok := details["consumersComplete"].(bool); ok {
		attrs["consumers_complete"] = fmt.Sprintf("%t", complete)
	}
	if consumers := cloudIdentityConsumersSummary(details); consumers != "" {
		attrs["consumers"] = consumers
	}
	for _, side := range []string{"declared", "observed"} {
		if summary := cloudIdentityExcessSummary(details, side); summary != "" {
			attrs["excess_"+side] = summary
		}
	}
}

// vulnviewTimeLayouts are the timestamp formats VulnView's export and legacy
// list endpoints use; sourcecdk.JSONObject.FieldTime tries them in order.
var vulnviewTimeLayouts = []string{time.RFC3339Nano, time.RFC3339, "2006-01-02"}

func occurredAtFor(values map[string]any) time.Time {
	if occurredAt := sourcecdk.JSONObject(values).FieldTime(vulnviewTimeLayouts, "updatedAt", "timestamp", "completedAt", "startedAt", "createdAt", "matchedAt", "matched-at"); !occurredAt.IsZero() {
		return occurredAt
	}
	return time.Now().UTC()
}

// copyFields and firstValueString read dot-separated field paths via sourcecdk.JSONObject.
func copyFields(attrs map[string]string, values map[string]any, fields map[string]string) {
	sourcecdk.JSONObject(values).CopyFields(attrs, fields)
}

func firstValueString(values map[string]any, keys ...string) string {
	return sourcecdk.JSONObject(values).FirstFieldString(keys...)
}

// vulnviewIntegrationRef renders one provenance.integrations/
// repositoryIntegrations element ({kind,id}) as "kind:id"; an element
// missing either field is skipped by the caller's SortedJoinObjects.
func vulnviewIntegrationRef(o sourcecdk.JSONObject) string {
	return o.JoinFieldsIfAllPresent(":", "kind", "id")
}

// cloudIdentityConsumersSummary joins details.consumers as cluster-qualified
// "<cluster>/<namespace>/<serviceAccount>" identifiers.
func cloudIdentityConsumersSummary(details sourcecdk.JSONObject) string {
	return details.Array("consumers").JoinObjects(",", func(consumer sourcecdk.JSONObject) string {
		return consumer.JoinFieldsIfAllPresent("/", "cluster", "namespace", "serviceAccount")
	})
}

// cloudIdentityExcessSummary joins one details.excess side as
// "action(resources)[required:...]" items; a null or missing excess yields "".
func cloudIdentityExcessSummary(details sourcecdk.JSONObject, side string) string {
	return details.Nested("excess").Array(side).JoinObjects(";", func(item sourcecdk.JSONObject) string {
		action := item.FieldString("action")
		if action == "" {
			return ""
		}
		if resources := item.FieldString("resources"); resources != "" {
			action += "(" + resources + ")"
		}
		if required := item.FieldString("requiredResources"); required != "" {
			action += "[required:" + required + "]"
		}
		return action
	})
}

func normalizeID(value string) string { return sourcecdk.NormalizeID(value) }

func firstNonEmpty(values ...string) string { return sourcecdk.FirstNonEmpty(values...) }

func trimEmptyAttributes(attrs map[string]string) { sourcecdk.TrimEmptyAttributes(attrs) }
