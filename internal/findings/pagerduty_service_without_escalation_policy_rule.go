package findings

import (
	"context"
	"fmt"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

const (
	pagerDutyServiceWithoutEscalationRuleID    = "pagerduty-service-without-escalation-policy"
	pagerDutyServiceWithoutEscalationTitle     = "PagerDuty Service Without Escalation Policy"
	pagerDutyServiceWithoutEscalationSeverity  = "MEDIUM"
	pagerDutyServiceWithoutEscalationCheckID   = "pagerduty-service-without-escalation-policy-current"
	pagerDutyServiceWithoutEscalationCheckName = "PagerDuty Service Without Escalation Policy (current state)"
)

var pagerDutyServiceWithoutEscalationControlRefs = []ports.FindingControlRef{
	{FrameworkName: "SOC 2", ControlID: "CC7.4"},
	{FrameworkName: "ISO 27001:2022", ControlID: "A.5.26"},
}

type pagerDutyServiceWithoutEscalationRule struct {
	Rule
	definition RuleDefinition
}

var pagerDutyServiceWithoutEscalationDefinition = RuleDefinition{
	ID:                 pagerDutyServiceWithoutEscalationRuleID,
	Name:               pagerDutyServiceWithoutEscalationTitle,
	Description:        "Detect active PagerDuty services with no escalation policy linked, leaving incidents on the service without a defined responder escalation path so alerts can go unacknowledged.",
	SourceID:           "pagerduty",
	EventKinds:         []string{"pagerduty.service"},
	OutputKind:         "finding.pagerduty_service_without_escalation_policy",
	Severity:           pagerDutyServiceWithoutEscalationSeverity,
	Status:             findingStatusOpen,
	Maturity:           "test",
	Tags:               []string{"pagerduty", "incident-response", "escalation", "availability", "coverage"},
	References:         []string{"https://support.pagerduty.com/docs/escalation-policies"},
	FalsePositives:     []string{"Services intentionally routed through another service's escalation policy, or inventory-only services that should be disabled rather than paged."},
	Runbook:            "Confirm whether the active PagerDuty service should page responders; if so, attach a valid escalation policy (or route it through one), otherwise disable or remove the service.",
	RequiredAttributes: []string{"service_id"},
	FingerprintFields:  []string{"pagerduty_service_urn"},
	ControlRefs:        pagerDutyServiceWithoutEscalationControlRefs,
	Lifecycle:          Lifecycle{Kind: LifecycleDurableState, Anchor: AnchorSourceState},
}

var pagerDutyServiceWithoutEscalationKindMatcher = eventKindMatcher(pagerDutyServiceWithoutEscalationDefinition.EventKinds...)

func newPagerDutyServiceWithoutEscalationRule() Rule {
	rule := newEventRule(eventRuleConfig{
		definition: pagerDutyServiceWithoutEscalationDefinition,
		match:      matchesPagerDutyServiceWithoutEscalation,
		build: func(ctx context.Context, runtime *cerebrov1.SourceRuntime, event *cerebrov1.EventEnvelope) (*ports.FindingRecord, error) {
			return pagerDutyServiceWithoutEscalationFinding(event, runtime.GetId())
		},
	})
	return &pagerDutyServiceWithoutEscalationRule{
		Rule:       rule,
		definition: pagerDutyServiceWithoutEscalationDefinition,
	}
}

func (r *pagerDutyServiceWithoutEscalationRule) RuleMetadata() RuleDefinition {
	if r == nil {
		return RuleDefinition{}
	}
	return cloneRuleDefinition(r.definition)
}

func (r *pagerDutyServiceWithoutEscalationRule) OpenAnchor(attributes map[string]string) string {
	return pagerDutyServiceWithoutEscalationAnchor(attributes)
}

// CloseOnEvent resolves an open finding when a later snapshot of the same
// PagerDuty service shows a valid escalation policy linked (remediation) or
// shows the service disabled/removed, so remediated or decommissioned services
// do not leave stale open findings.
func (r *pagerDutyServiceWithoutEscalationRule) CloseOnEvent(event Event) (string, bool) {
	if !pagerDutyServiceWithoutEscalationKindMatcher(event) || !hasRequiredAttributes(event, pagerDutyServiceWithoutEscalationDefinition.RequiredAttributes...) {
		return "", false
	}
	attributes := eventAttributes(event)
	if pagerDutyServiceMissingEscalationCoverage(attributes) {
		return "", false
	}
	serviceURN := pagerDutyServiceFindingURN(event.GetTenantId(), attributes["service_id"])
	anchor := pagerDutyServiceWithoutEscalationAnchor(map[string]string{"pagerduty_service_urn": serviceURN})
	return anchor, anchor != ""
}

func matchesPagerDutyServiceWithoutEscalation(event *cerebrov1.EventEnvelope) bool {
	if !pagerDutyServiceWithoutEscalationKindMatcher(event) || !hasRequiredAttributes(event, pagerDutyServiceWithoutEscalationDefinition.RequiredAttributes...) {
		return false
	}
	return pagerDutyServiceMissingEscalationCoverage(eventAttributes(event))
}

func pagerDutyServiceWithoutEscalationFinding(event *cerebrov1.EventEnvelope, runtimeID string) (*ports.FindingRecord, error) {
	attrs := event.GetAttributes()
	serviceID := strings.TrimSpace(attrs["service_id"])
	tenantID := strings.TrimSpace(event.GetTenantId())
	serviceURN := pagerDutyServiceFindingURN(tenantID, serviceID)
	if serviceURN == "" {
		return nil, nil
	}
	label := firstNonEmpty(strings.TrimSpace(attrs["name"]), strings.TrimSpace(attrs["summary"]), serviceID)
	attributes := map[string]string{
		"pagerduty_service_urn": serviceURN,
		"service_id":            serviceID,
		"service_name":          strings.TrimSpace(attrs["name"]),
		"service_status":        strings.TrimSpace(attrs["status"]),
		"has_escalation_policy": "false",
		"event_id":              strings.TrimSpace(event.GetId()),
		"source_runtime_id":     strings.TrimSpace(attrs[ports.EventAttributeSourceRuntimeID]),
		"primary_resource_urn":  serviceURN,
	}
	for key, value := range pagerDutyServiceWithoutEscalationDefinition.AttributeMap() {
		attributes["rule_"+key] = value
	}
	trimEmptyAttributes(attributes)
	observedAt := time.Time{}
	if timestamp := event.GetOccurredAt(); timestamp != nil {
		observedAt = timestamp.AsTime().UTC()
	}
	fingerprint := hashFindingFingerprint(pagerDutyServiceWithoutEscalationRuleID, serviceURN)
	return &ports.FindingRecord{
		ID:              fingerprint,
		Fingerprint:     fingerprint,
		TenantID:        tenantID,
		RuntimeID:       strings.TrimSpace(runtimeID),
		RuleID:          pagerDutyServiceWithoutEscalationRuleID,
		Title:           pagerDutyServiceWithoutEscalationTitle,
		Severity:        pagerDutyServiceWithoutEscalationSeverity,
		Status:          findingStatusOpen,
		Summary:         pagerDutyServiceWithoutEscalationSummary(label),
		ResourceURNs:    []string{serviceURN},
		EventIDs:        []string{strings.TrimSpace(event.GetId())},
		CheckID:         pagerDutyServiceWithoutEscalationCheckID,
		CheckName:       pagerDutyServiceWithoutEscalationCheckName,
		ControlRefs:     cloneFindingControlRefs(pagerDutyServiceWithoutEscalationDefinition.ControlRefs),
		Attributes:      attributes,
		FirstObservedAt: observedAt,
		LastObservedAt:  observedAt,
	}, nil
}

// pagerDutyServiceMissingEscalationCoverage reports whether an active PagerDuty
// service currently has no escalation policy linked. Disabled or removed
// services are excluded so decommissioned services do not surface as a coverage
// gap.
func pagerDutyServiceMissingEscalationCoverage(attributes map[string]string) bool {
	if pagerDutyServiceDecommissioned(attributes) {
		return false
	}
	return strings.TrimSpace(attributes["escalation_policy_id"]) == ""
}

func pagerDutyServiceDecommissioned(attributes map[string]string) bool {
	switch strings.ToLower(strings.TrimSpace(attributes["status"])) {
	case "disabled", "deleted", "inactive", "removed":
		return true
	default:
		return false
	}
}

func pagerDutyServiceFindingURN(tenantID string, serviceID string) string {
	tenantID = strings.TrimSpace(tenantID)
	serviceID = strings.TrimSpace(serviceID)
	if tenantID == "" || serviceID == "" {
		return ""
	}
	return fmt.Sprintf("urn:cerebro:%s:pagerduty_service:%s", tenantID, serviceID)
}

func pagerDutyServiceWithoutEscalationAnchor(attributes map[string]string) string {
	return identityCounterEventAnchor(map[string]string{
		"pagerduty_service_urn": strings.TrimSpace(attributes["pagerduty_service_urn"]),
	}, "pagerduty_service_urn")
}

func pagerDutyServiceWithoutEscalationSummary(label string) string {
	return fmt.Sprintf("PagerDuty service %s has no escalation policy", firstNonEmpty(label, "unknown service"))
}
