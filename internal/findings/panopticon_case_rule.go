package findings

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

const (
	panopticonCuratedCaseRuleID         = "panopticon-curated-case"
	panopticonSourceID                  = "panopticon"
	panopticonCaseEventKind             = "panopticon.case"
	maxPanopticonCaseAlertEvidencePaths = 20
)

var panopticonCuratedCaseControlRefs = []ports.FindingControlRef{
	{FrameworkName: "SOC 2", ControlID: "CC7.2"},
	{FrameworkName: "ISO 27001:2022", ControlID: "A.5.24"},
}

var panopticonCaseSignalAttributeKeys = []string{
	"lookup_table",
	"preprocessing_decision",
	"preprocessing_reason",
	"upstream_alert_count",
	"upstream_alert_ids",
	"upstream_detection_id",
	"upstream_detection_name",
	"upstream_siem",
}

// panopticonClosedCaseStatuses is the source-of-truth case status map Cerebro
// uses to mirror Panopticon lifecycle state without locally closing cases.
var panopticonClosedCaseStatuses = map[string]struct{}{
	"accepted_risk":  {},
	"archived":       {},
	"canceled":       {},
	"cancelled":      {},
	"closed":         {},
	"complete":       {},
	"completed":      {},
	"dismissed":      {},
	"done":           {},
	"duplicate":      {},
	"false_positive": {},
	"ignored":        {},
	"resolved":       {},
	"risk_accepted":  {},
	"suppressed":     {},
}

type panopticonCuratedCaseRule struct {
	Rule
	definition RuleDefinition
}

func newPanopticonCuratedCaseRule() Rule {
	definition := panopticonCuratedCaseDefinition()
	return &panopticonCuratedCaseRule{
		Rule: newEventRule(eventRuleConfig{
			definition: definition,
			sourceID:   panopticonSourceID,
			match:      matchesPanopticonCuratedCase,
			build:      buildPanopticonCuratedCaseFinding,
		}),
		definition: definition,
	}
}

func panopticonCuratedCaseDefinition() RuleDefinition {
	return RuleDefinition{
		ID:                 panopticonCuratedCaseRuleID,
		Name:               "Panopticon Curated Case",
		Description:        "Represent Panopticon cases as the curated security-operations finding boundary after SIEM alert preprocessing.",
		SourceID:           panopticonSourceID,
		EventKinds:         []string{panopticonCaseEventKind},
		OutputKind:         "finding.panopticon_curated_case",
		Severity:           "dynamic",
		Status:             findingStatusOpen,
		Maturity:           RuleMaturityCandidate,
		Tags:               []string{"panopticon", "soc", "case-management", "security-operations", "external-lifecycle"},
		References:         []string{"https://github.com/WriterInternal/panopticon"},
		FalsePositives:     []string{"Panopticon case was opened for testing, duplicate triage, or an accepted-risk workflow that should be closed in Panopticon."},
		Runbook:            "Triage and resolve the case in Panopticon. Use Cerebro for graph context, evidence correlation, and risk analysis without bypassing Panopticon's SIEM preprocessing.",
		RequiredAttributes: []string{"case_id", "status"},
		FingerprintFields:  []string{"tenant_id", "case_id"},
		ControlRefs:        panopticonCuratedCaseControlRefs,
		Lifecycle:          Lifecycle{Kind: LifecycleDurableState, Anchor: AnchorSourceState},
	}
}

var panopticonCaseKindMatcher = eventKindMatcher(panopticonCaseEventKind)

func (r *panopticonCuratedCaseRule) RuleMetadata() RuleDefinition {
	if r == nil {
		return RuleDefinition{}
	}
	return cloneRuleDefinition(r.definition)
}

func (r *panopticonCuratedCaseRule) OpenAnchor(attributes map[string]string) string {
	return panopticonCaseAnchor(firstNonEmpty(attributes["case_id"], attributes["external_id"], attributes["external_ref_id"]))
}

func (r *panopticonCuratedCaseRule) CloseOnEvent(event Event) (string, bool) {
	if !panopticonCaseKindMatcher(event) {
		return "", false
	}
	attrs := eventAttributes(event)
	caseID := firstNonEmpty(attrs["case_id"], panopticonCasePayloadString(event, "case_id"))
	if caseID == "" {
		return "", false
	}
	if panopticonCaseSourceOpen(firstNonEmpty(attrs["status"], panopticonCasePayloadString(event, "status", "state"))) {
		return "", false
	}
	return panopticonCaseAnchor(caseID), true
}

func matchesPanopticonCuratedCase(event *cerebrov1.EventEnvelope) bool {
	if !panopticonCaseKindMatcher(event) {
		return false
	}
	attrs := eventAttributes(event)
	if !hasRequiredAttributes(event, "case_id", "status") {
		return false
	}
	return panopticonCaseSourceOpen(attrs["status"])
}

func buildPanopticonCuratedCaseFinding(ctx context.Context, runtime *cerebrov1.SourceRuntime, event *cerebrov1.EventEnvelope) (*ports.FindingRecord, error) {
	attrs := eventAttributes(event)
	caseID := strings.TrimSpace(attrs["case_id"])
	if caseID == "" {
		return nil, nil
	}
	projectedContext, err := buildFindingProjectionContext(ctx, event, findingProjectionContextOptions{
		PrimaryEntityType:  "panopticon.case",
		CollectAllEntities: true,
		ResourceFallbacks:  []string{attrs["title"], caseID},
	})
	if err != nil {
		return nil, fmt.Errorf("project Panopticon case finding context for event %q: %w", event.GetId(), err)
	}
	observedAt := time.Time{}
	if event.GetOccurredAt() != nil {
		observedAt = event.GetOccurredAt().AsTime().UTC()
	}
	title := firstNonEmpty(attrs["title"], panopticonCasePayloadString(event, "title", "case_name", "name"), caseID)
	status := strings.TrimSpace(attrs["status"])
	severity := panopticonCaseSeverity(event, attrs)
	url := panopticonCaseURL(event, attrs)
	statusReason := panopticonCaseStatusReason(event, attrs)
	findingAttributes := map[string]string{
		"case_id":                  caseID,
		"case_status":              status,
		"case_title":               title,
		"event_id":                 strings.TrimSpace(event.GetId()),
		"event_kind":               strings.TrimSpace(event.GetKind()),
		"external_ref_id":          caseID,
		"external_ref_kind":        "case",
		"external_ref_status":      status,
		"external_ref_system":      panopticonSourceID,
		"lifecycle_owner":          "external_owned",
		"primary_resource_urn":     projectedContext.PrimaryResourceURN,
		"severity":                 severity,
		"source_runtime_id":        strings.TrimSpace(runtime.GetId()),
		"source_system":            panopticonSourceID,
		"status_reason":            statusReason,
		"tenant_id":                strings.TrimSpace(event.GetTenantId()),
		"upstream_signal_boundary": "panopticon_case",
	}
	if url != "" {
		findingAttributes["case_url"] = url
	}
	evidenceObjectIDs := panopticonCaseEvidenceCASObjectIDs(event, attrs)
	if len(evidenceObjectIDs) != 0 {
		findingAttributes["evidence_cas_object_ids"] = strings.Join(evidenceObjectIDs, ",")
	}
	mergePanopticonCaseFindingAttributes(findingAttributes, panopticonCaseSignalAttributes(event, attrs))
	for key, value := range attrs {
		if _, exists := findingAttributes[key]; !exists {
			findingAttributes[key] = strings.TrimSpace(value)
		}
	}
	definition := panopticonCuratedCaseDefinition()
	for key, value := range definition.AttributeMap() {
		findingAttributes["rule_"+key] = value
	}
	trimEmptyAttributes(findingAttributes)
	fingerprint := hashFindingFingerprint(panopticonCuratedCaseRuleID, event.GetTenantId(), caseID)
	graphEvidenceAttributes := map[string]string{
		"case_id":              caseID,
		"case_status":          status,
		"case_title":           title,
		"event_id":             strings.TrimSpace(event.GetId()),
		"primary_resource_urn": projectedContext.PrimaryResourceURN,
		"source_runtime_id":    strings.TrimSpace(runtime.GetId()),
	}
	for _, key := range panopticonCaseSignalAttributeKeys {
		graphEvidenceAttributes[key] = findingAttributes[key]
	}
	casePaths := panopticonCaseAlertEvidencePaths(event, caseID, title, projectedContext.PrimaryResourceURN, findingAttributes)
	casePaths = append(casePaths, panopticonCaseEvidenceCASPaths(event, caseID, title, projectedContext.PrimaryResourceURN, evidenceObjectIDs)...)
	graphRows := []*cerebrov1.GraphEvidenceRow{
		newGraphEvidenceRow("panopticon_case", graphEvidenceAttributes, casePaths...),
	}
	return &ports.FindingRecord{
		ID:                fingerprint,
		Fingerprint:       fingerprint,
		TenantID:          strings.TrimSpace(event.GetTenantId()),
		RuntimeID:         strings.TrimSpace(runtime.GetId()),
		RuleID:            panopticonCuratedCaseRuleID,
		Title:             "Panopticon Curated Case",
		Severity:          severity,
		Status:            findingStatusOpen,
		Summary:           panopticonCaseSummary(caseID, title, status),
		ResourceURNs:      projectedContext.ResourceURNs,
		EventIDs:          []string{strings.TrimSpace(event.GetId())},
		PolicyID:          caseID,
		PolicyName:        title,
		CheckID:           panopticonCuratedCaseRuleID,
		CheckName:         "Panopticon Curated Case",
		ControlRefs:       cloneFindingControlRefs(definition.ControlRefs),
		GraphEvidenceRows: graphRows,
		FindingWorkflow: ports.FindingWorkflow{
			ExternalRefs: []ports.FindingExternalRef{
				{
					System:               panopticonSourceID,
					Kind:                 "case",
					ExternalID:           caseID,
					URL:                  url,
					ExternalStatus:       status,
					ExternalStatusReason: statusReason,
					LifecycleOwner:       "external_owned",
					ObservedAt:           observedAt,
				},
			},
		},
		Attributes:      findingAttributes,
		FirstObservedAt: observedAt,
		LastObservedAt:  observedAt,
	}, nil
}

func panopticonCaseAnchor(caseID string) string {
	caseID = strings.TrimSpace(caseID)
	if caseID == "" {
		return ""
	}
	return "panopticon.case:" + caseID
}

func panopticonCaseAlertEvidencePaths(event *cerebrov1.EventEnvelope, caseID string, caseTitle string, caseURN string, attrs map[string]string) []*cerebrov1.GraphEvidencePath {
	caseURN = strings.TrimSpace(caseURN)
	if caseURN == "" || strings.TrimSpace(attrs["upstream_alert_ids"]) == "" {
		return nil
	}
	tenantID := ""
	if event != nil {
		tenantID = strings.TrimSpace(event.GetTenantId())
	}
	if tenantID == "" {
		tenantID = strings.TrimSpace(attrs["tenant_id"])
	}
	if tenantID == "" {
		return nil
	}
	observedAt := ""
	if event != nil && event.GetOccurredAt() != nil {
		observedAt = event.GetOccurredAt().AsTime().UTC().Format(time.RFC3339Nano)
	}
	paths := []*cerebrov1.GraphEvidencePath{}
	collectPanopticonCaseAlertIDs(attrs["upstream_alert_ids"], func(alertID string) {
		if len(paths) >= maxPanopticonCaseAlertEvidencePaths {
			return
		}
		alertID = strings.TrimSpace(alertID)
		if alertID == "" {
			return
		}
		paths = append(paths, newGraphEvidencePath(
			caseURN,
			firstNonEmpty(caseTitle, caseID),
			"panopticon.case",
			"contains",
			panopticonAlertEvidenceURN(tenantID, alertID),
			alertID,
			"panopticon.alert",
			map[string]string{
				"case_id":                 strings.TrimSpace(caseID),
				"upstream_alert_id":       alertID,
				"upstream_siem":           attrs["upstream_siem"],
				"upstream_detection_id":   attrs["upstream_detection_id"],
				"upstream_detection_name": attrs["upstream_detection_name"],
				"preprocessing_decision":  attrs["preprocessing_decision"],
				"preprocessing_reason":    attrs["preprocessing_reason"],
				"lookup_table":            attrs["lookup_table"],
				"observed_at":             observedAt,
			},
		))
	})
	return paths
}

func panopticonAlertEvidenceURN(tenantID string, alertID string) string {
	return fmt.Sprintf("urn:cerebro:%s:panopticon_alert:%s", strings.TrimSpace(tenantID), strings.TrimSpace(alertID))
}

// panopticonCaseEvidenceCASObjectIDs extracts stable Evidence CAS object
// identifiers from a Panopticon case payload using the same identity precedence
// the Evidence CAS source applies (evidence_id, then CAS URI/digest). The result
// is deterministic (deduped, sorted) so downstream correlation and fingerprints
// stay stable across syncs.
func panopticonCaseEvidenceCASObjectIDs(event *cerebrov1.EventEnvelope, attrs map[string]string) []string {
	if promoted := strings.TrimSpace(attrs["evidence_cas_object_ids"]); promoted != "" {
		return panopticonDedupeSortedIDs(strings.Split(promoted, ","))
	}
	payload := panopticonCasePayloadObject(event)
	var ids []string
	for _, key := range []string{"evidence", "evidences", "evidence_pointers", "captures"} {
		for _, evidence := range panopticonCasePayloadObjects(payload, key) {
			id := firstNonEmpty(
				panopticonCaseMapString(evidence, "evidence_id", "id"),
				panopticonCaseMapString(evidence, "evidence_cas", "evidence_cas_uri", "uri", "cas_uri", "pointer"),
				panopticonCaseMapString(evidence, "sha256", "digest"),
			)
			if id != "" {
				ids = append(ids, id)
			}
		}
	}
	return panopticonDedupeSortedIDs(ids)
}

func panopticonDedupeSortedIDs(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	sort.Strings(out)
	return out
}

func panopticonCasePayloadObjects(payload map[string]interface{}, key string) []map[string]interface{} {
	switch typed := payload[key].(type) {
	case []map[string]interface{}:
		return typed
	case []interface{}:
		objects := make([]map[string]interface{}, 0, len(typed))
		for _, item := range typed {
			if object, ok := item.(map[string]interface{}); ok {
				objects = append(objects, object)
			}
		}
		return objects
	case map[string]interface{}:
		return []map[string]interface{}{typed}
	default:
		return nil
	}
}

// panopticonCaseEvidenceCASPaths emits graph-visible correlation paths from a
// Panopticon case to the canonical Evidence CAS object projections so the case
// finding deterministically joins its evidence references to Evidence CAS state.
func panopticonCaseEvidenceCASPaths(event *cerebrov1.EventEnvelope, caseID string, caseTitle string, caseURN string, objectIDs []string) []*cerebrov1.GraphEvidencePath {
	caseURN = strings.TrimSpace(caseURN)
	if caseURN == "" || len(objectIDs) == 0 {
		return nil
	}
	tenantID := ""
	if event != nil {
		tenantID = strings.TrimSpace(event.GetTenantId())
	}
	if tenantID == "" {
		return nil
	}
	observedAt := ""
	if event != nil && event.GetOccurredAt() != nil {
		observedAt = event.GetOccurredAt().AsTime().UTC().Format(time.RFC3339Nano)
	}
	seen := map[string]struct{}{}
	paths := []*cerebrov1.GraphEvidencePath{}
	for _, objectID := range objectIDs {
		objectID = strings.TrimSpace(objectID)
		if objectID == "" {
			continue
		}
		if len(paths) >= maxPanopticonCaseAlertEvidencePaths {
			break
		}
		objectURN := panopticonEvidenceCASObjectURN(tenantID, objectID)
		if objectURN == "" {
			continue
		}
		if _, ok := seen[objectURN]; ok {
			continue
		}
		seen[objectURN] = struct{}{}
		paths = append(paths, newGraphEvidencePath(
			caseURN,
			firstNonEmpty(caseTitle, caseID),
			"panopticon.case",
			"has_evidence",
			objectURN,
			objectID,
			"runtime.evidence",
			map[string]string{
				"case_id":                 strings.TrimSpace(caseID),
				"evidence_cas_object_id":  objectID,
				"evidence_cas_object_urn": objectURN,
				"observed_at":             observedAt,
			},
		))
	}
	return paths
}

func panopticonEvidenceCASObjectURN(tenantID string, objectID string) string {
	tenantID = strings.TrimSpace(tenantID)
	objectID = strings.TrimSpace(objectID)
	if tenantID == "" || objectID == "" {
		return ""
	}
	return fmt.Sprintf("urn:cerebro:%s:runtime_evidence:%s", tenantID, objectID)
}

func panopticonCaseSourceOpen(status string) bool {
	normalized := normalizePanopticonCaseStatus(status)
	if normalized == "" {
		return false
	}
	if _, closed := panopticonClosedCaseStatuses[normalized]; closed {
		return false
	}
	return true
}

func normalizePanopticonCaseStatus(status string) string {
	normalized := strings.ToLower(strings.TrimSpace(status))
	normalized = strings.ReplaceAll(normalized, "-", "_")
	normalized = strings.ReplaceAll(normalized, " ", "_")
	return normalized
}

func panopticonCaseSeverity(event *cerebrov1.EventEnvelope, attrs map[string]string) string {
	raw := firstNonEmpty(attrs["severity"], attrs["case_severity"], attrs["priority"], panopticonCasePayloadString(event, "severity", "case_severity", "priority"))
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "p0", "sev0", "severe":
		return "CRITICAL"
	case "p1", "sev1":
		return "HIGH"
	case "p2", "sev2":
		return "MEDIUM"
	case "p3", "sev3":
		return "LOW"
	case "p4", "sev4":
		return "INFO"
	default:
		return normalizeFindingSeverity(raw)
	}
}

func panopticonCaseURL(event *cerebrov1.EventEnvelope, attrs map[string]string) string {
	return firstNonEmpty(
		attrs["case_url"],
		attrs["url"],
		attrs["html_url"],
		attrs["external_url"],
		attrs["link"],
		attrs["permalink"],
		panopticonCasePayloadString(event, "case_url", "url", "html_url", "external_url", "link", "permalink"),
	)
}

func panopticonCaseStatusReason(event *cerebrov1.EventEnvelope, attrs map[string]string) string {
	return firstNonEmpty(
		attrs["status_reason"],
		attrs["resolution"],
		attrs["resolution_reason"],
		attrs["close_reason"],
		panopticonCasePayloadString(event, "status_reason", "resolution", "resolution_reason", "close_reason"),
	)
}

func panopticonCaseSummary(caseID string, title string, status string) string {
	label := firstNonEmpty(title, caseID, "Panopticon case")
	status = strings.TrimSpace(status)
	if status == "" {
		return fmt.Sprintf("Panopticon escalated %s as a curated case after SIEM preprocessing", label)
	}
	return fmt.Sprintf("Panopticon escalated %s as case %s with status %s after SIEM preprocessing", label, caseID, status)
}

func panopticonCaseSignalAttributes(event *cerebrov1.EventEnvelope, attrs map[string]string) map[string]string {
	payload := panopticonCasePayloadObject(event)
	attributes := map[string]string{}
	alertIDs := firstNonEmpty(attrs["upstream_alert_ids"], strings.Join(panopticonCasePayloadAlertIDs(payload), ","))
	if alertIDs != "" {
		attributes["upstream_alert_ids"] = alertIDs
	}
	if count := firstNonEmpty(
		attrs["upstream_alert_count"],
		panopticonCaseMapString(payload, "upstream_alert_count", "alert_count", "alerts_count", "source_alert_count"),
		panopticonAlertIDCount(alertIDs),
	); count != "" {
		attributes["upstream_alert_count"] = count
	}
	if value := firstNonEmpty(
		attrs["upstream_siem"],
		panopticonCaseMapString(payload, "upstream_siem", "siem", "source_system", "alert_source_system", "alert_source", "event_source", "provider", "vendor"),
		panopticonCasePayloadAlertString(payload, "upstream_siem", "siem", "source_system", "alert_source_system", "alert_source", "event_source", "source", "provider", "vendor"),
	); value != "" {
		attributes["upstream_siem"] = value
	}
	if value := firstNonEmpty(
		attrs["upstream_detection_id"],
		panopticonCaseMapString(payload, "upstream_detection_id", "detection_id", "rule_id", "alert_rule_id", "panther_rule_id"),
		panopticonCasePayloadAlertString(payload, "upstream_detection_id", "detection_id", "rule_id", "alert_rule_id", "panther_rule_id"),
	); value != "" {
		attributes["upstream_detection_id"] = value
	}
	if value := firstNonEmpty(
		attrs["upstream_detection_name"],
		panopticonCaseMapString(payload, "upstream_detection_name", "detection_name", "rule_name", "alert_rule_name", "panther_rule_name"),
		panopticonCasePayloadAlertString(payload, "upstream_detection_name", "detection_name", "rule_name", "alert_rule_name", "panther_rule_name", "title"),
	); value != "" {
		attributes["upstream_detection_name"] = value
	}
	if value := firstNonEmpty(
		attrs["preprocessing_decision"],
		panopticonCaseMapString(payload, "preprocessing_decision", "triage_decision", "decision", "disposition", "classification", "case_disposition"),
	); value != "" {
		attributes["preprocessing_decision"] = value
	}
	if value := firstNonEmpty(
		attrs["preprocessing_reason"],
		panopticonCaseMapString(payload, "preprocessing_reason", "triage_reason", "decision_reason", "reason", "rationale", "lookup_reason"),
	); value != "" {
		attributes["preprocessing_reason"] = value
	}
	if value := firstNonEmpty(
		attrs["lookup_table"],
		panopticonCaseMapString(payload, "lookup_table", "lookup_table_id", "allowlist_table", "decision_table"),
	); value != "" {
		attributes["lookup_table"] = value
	}
	if len(attributes) == 0 {
		return nil
	}
	return attributes
}

func mergePanopticonCaseFindingAttributes(dst map[string]string, src map[string]string) {
	for key, value := range src {
		trimmedKey := strings.TrimSpace(key)
		trimmedValue := strings.TrimSpace(value)
		if trimmedKey == "" || trimmedValue == "" {
			continue
		}
		if strings.TrimSpace(dst[trimmedKey]) == "" {
			dst[trimmedKey] = trimmedValue
		}
	}
}

func panopticonCasePayloadString(event *cerebrov1.EventEnvelope, keys ...string) string {
	payload := panopticonCasePayloadObject(event)
	return panopticonCaseMapString(payload, keys...)
}

func panopticonCasePayloadObject(event *cerebrov1.EventEnvelope) map[string]interface{} {
	if event == nil || len(event.GetPayload()) == 0 {
		return nil
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(event.GetPayload(), &payload); err != nil {
		return nil
	}
	return payload
}

func panopticonCaseMapString(payload map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		if value := panopticonPayloadScalarString(payload[strings.TrimSpace(key)]); value != "" {
			return value
		}
	}
	return ""
}

func panopticonCasePayloadAlertString(payload map[string]interface{}, keys ...string) string {
	for _, collectionKey := range []string{"alerts", "source_alerts", "upstream_alerts", "related_alerts"} {
		switch alerts := payload[collectionKey].(type) {
		case []interface{}:
			for _, alert := range alerts {
				alertMap, ok := alert.(map[string]interface{})
				if !ok {
					continue
				}
				if value := panopticonCaseMapString(alertMap, keys...); value != "" {
					return value
				}
			}
		case []map[string]interface{}:
			for _, alertMap := range alerts {
				if value := panopticonCaseMapString(alertMap, keys...); value != "" {
					return value
				}
			}
		}
	}
	return ""
}

func panopticonCasePayloadAlertIDs(payload map[string]interface{}) []string {
	var ids []string
	seen := map[string]struct{}{}
	add := func(value string) {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			return
		}
		if _, ok := seen[trimmed]; ok {
			return
		}
		seen[trimmed] = struct{}{}
		ids = append(ids, trimmed)
	}
	for _, key := range []string{"upstream_alert_ids", "alert_ids", "source_alert_ids", "related_alert_ids"} {
		collectPanopticonCaseAlertIDs(payload[strings.TrimSpace(key)], add)
	}
	for _, key := range []string{"alerts", "source_alerts", "upstream_alerts", "related_alerts"} {
		collectPanopticonCaseAlertIDs(payload[strings.TrimSpace(key)], add)
	}
	return ids
}

func collectPanopticonCaseAlertIDs(value interface{}, add func(string)) {
	switch typed := value.(type) {
	case string:
		for _, part := range strings.FieldsFunc(typed, func(r rune) bool {
			return r == ',' || r == ';' || r == '\n' || r == '\t' || r == ' '
		}) {
			add(part)
		}
	case []interface{}:
		for _, item := range typed {
			collectPanopticonCaseAlertIDs(item, add)
		}
	case []string:
		for _, item := range typed {
			add(item)
		}
	case []map[string]interface{}:
		for _, item := range typed {
			collectPanopticonCaseAlertIDs(item, add)
		}
	case map[string]interface{}:
		add(panopticonCaseMapString(typed, "alert_id", "id", "external_id", "panther_alert_id"))
	}
}

func panopticonAlertIDCount(alertIDs string) string {
	if strings.TrimSpace(alertIDs) == "" {
		return ""
	}
	var count int
	collectPanopticonCaseAlertIDs(alertIDs, func(string) { count++ })
	if count == 0 {
		return ""
	}
	return strconv.Itoa(count)
}

func panopticonPayloadScalarString(value interface{}) string {
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case json.Number:
		return strings.TrimSpace(typed.String())
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(typed)
	default:
		return ""
	}
}
