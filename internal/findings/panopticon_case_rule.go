package findings

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

const (
	panopticonCuratedCaseRuleID = "panopticon-curated-case"
	panopticonSourceID          = "panopticon"
	panopticonCaseEventKind     = "panopticon.case"
)

var panopticonCuratedCaseControlRefs = []ports.FindingControlRef{
	{FrameworkName: "SOC 2", ControlID: "CC7.2"},
	{FrameworkName: "ISO 27001:2022", ControlID: "A.5.24"},
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
	graphRows := []*cerebrov1.GraphEvidenceRow{
		newGraphEvidenceRow("panopticon_case", map[string]string{
			"case_id":              caseID,
			"case_status":          status,
			"case_title":           title,
			"event_id":             strings.TrimSpace(event.GetId()),
			"primary_resource_urn": projectedContext.PrimaryResourceURN,
			"source_runtime_id":    strings.TrimSpace(runtime.GetId()),
		}),
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

func panopticonCaseSourceOpen(status string) bool {
	normalized := strings.ToLower(strings.TrimSpace(status))
	normalized = strings.ReplaceAll(normalized, "-", "_")
	normalized = strings.ReplaceAll(normalized, " ", "_")
	switch normalized {
	case "":
		return false
	case "closed", "resolved", "complete", "completed", "done", "dismissed", "archived", "cancelled", "canceled", "false_positive", "duplicate", "accepted_risk", "risk_accepted", "suppressed", "ignored":
		return false
	default:
		return true
	}
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

func panopticonCasePayloadString(event *cerebrov1.EventEnvelope, keys ...string) string {
	if event == nil || len(event.GetPayload()) == 0 {
		return ""
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(event.GetPayload(), &payload); err != nil {
		return ""
	}
	for _, key := range keys {
		if value := panopticonPayloadScalarString(payload[strings.TrimSpace(key)]); value != "" {
			return value
		}
	}
	return ""
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
