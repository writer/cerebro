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
	trustedEndpointActiveTrustGateFailureRuleID    = "trusted-endpoint-active-trust-gate-failure"
	trustedEndpointActiveTrustGateFailureTitle     = "Trusted Endpoint Active Trust-Gate Failure"
	trustedEndpointActiveTrustGateFailureCheckID   = "trusted-endpoint-active-trust-gate-failure-current"
	trustedEndpointActiveTrustGateFailureCheckName = "Trusted Endpoint Active Trust-Gate Failure (current state)"
	trustedEndpointTrustGateEventKind              = "trusted_endpoint.trust_gate_decision"
)

var trustedEndpointActiveTrustGateFailureControlRefs = []ports.FindingControlRef{
	{FrameworkName: "SOC 2", ControlID: "CC6.1"},
	{FrameworkName: "ISO 27001:2022", ControlID: "A.8.16"},
}

type trustedEndpointActiveTrustGateFailureRule struct {
	Rule
	definition RuleDefinition
}

var trustedEndpointActiveTrustGateFailureDefinition = RuleDefinition{
	ID:                 trustedEndpointActiveTrustGateFailureRuleID,
	Name:               trustedEndpointActiveTrustGateFailureTitle,
	Description:        "Detect Trusted Endpoint agents whose latest trust-gate decision denies a gated action, indicating the workstation currently fails the endpoint posture/trust checks required to perform the action until its posture is remediated.",
	SourceID:           "trusted_endpoint",
	EventKinds:         []string{trustedEndpointTrustGateEventKind},
	OutputKind:         "finding.trusted_endpoint_active_trust_gate_failure",
	Severity:           "HIGH",
	Status:             findingStatusOpen,
	Maturity:           "test",
	Tags:               []string{"trusted-endpoint", "endpoint", "trust-gate", "device-posture", "zero-trust"},
	References:         []string{"https://github.com/writer/cerebro/blob/main/docs/ENDPOINT_SECURITY_PLATFORM_INTEGRATION.md"},
	FalsePositives:     []string{"A trust-gate denial issued during an approved maintenance window or risk-accepted exception that has not yet been reflected as an allow decision."},
	Runbook:            "Inspect the agent's failing endpoint posture/trust checks, remediate the underlying gap, and confirm the next trust-gate decision for the action allows it.",
	RequiredAttributes: []string{"agent_id", "action", "decision"},
	FingerprintFields:  []string{"trusted_endpoint_gate_urn"},
	ControlRefs:        trustedEndpointActiveTrustGateFailureControlRefs,
	Lifecycle:          Lifecycle{Kind: LifecycleDurableState, Anchor: AnchorSourceState},
}

var trustedEndpointTrustGateKindMatcher = eventKindMatcher(trustedEndpointActiveTrustGateFailureDefinition.EventKinds...)

func newTrustedEndpointActiveTrustGateFailureRule() Rule {
	rule := newEventRule(eventRuleConfig{
		definition: trustedEndpointActiveTrustGateFailureDefinition,
		match:      matchesTrustedEndpointActiveTrustGateFailure,
		build: func(ctx context.Context, runtime *cerebrov1.SourceRuntime, event *cerebrov1.EventEnvelope) (*ports.FindingRecord, error) {
			return trustedEndpointActiveTrustGateFailureFinding(event, runtime.GetId())
		},
	})
	return &trustedEndpointActiveTrustGateFailureRule{
		Rule:       rule,
		definition: trustedEndpointActiveTrustGateFailureDefinition,
	}
}

func (r *trustedEndpointActiveTrustGateFailureRule) RuleMetadata() RuleDefinition {
	if r == nil {
		return RuleDefinition{}
	}
	return cloneRuleDefinition(r.definition)
}

func (r *trustedEndpointActiveTrustGateFailureRule) OpenAnchor(attributes map[string]string) string {
	return trustedEndpointActiveTrustGateFailureAnchor(attributes)
}

// CloseOnEvent resolves an open finding only when a later trust-gate decision
// for the same agent/action allows the action. Endpoint-reported lifecycle
// fields are retained as context but are not authoritative enough to close or
// suppress a current trust-gate failure.
func (r *trustedEndpointActiveTrustGateFailureRule) CloseOnEvent(event Event) (string, bool) {
	if !trustedEndpointTrustGateKindMatcher(event) || !hasRequiredAttributes(event, trustedEndpointActiveTrustGateFailureDefinition.RequiredAttributes...) {
		return "", false
	}
	attributes := eventAttributes(event)
	if !trustedEndpointGateRemediated(attributes) {
		return "", false
	}
	gateURN := trustedEndpointTrustGateURN(event.GetTenantId(), attributes["agent_id"], attributes["action"])
	anchor := trustedEndpointActiveTrustGateFailureAnchor(map[string]string{"trusted_endpoint_gate_urn": gateURN})
	return anchor, anchor != ""
}

func matchesTrustedEndpointActiveTrustGateFailure(event *cerebrov1.EventEnvelope) bool {
	if !trustedEndpointTrustGateKindMatcher(event) || !hasRequiredAttributes(event, trustedEndpointActiveTrustGateFailureDefinition.RequiredAttributes...) {
		return false
	}
	return trustedEndpointGateDenied(eventAttributes(event))
}

func trustedEndpointActiveTrustGateFailureFinding(event *cerebrov1.EventEnvelope, runtimeID string) (*ports.FindingRecord, error) {
	attrs := event.GetAttributes()
	agentID := strings.TrimSpace(attrs["agent_id"])
	action := strings.TrimSpace(attrs["action"])
	tenantID := strings.TrimSpace(event.GetTenantId())
	gateURN := trustedEndpointTrustGateURN(tenantID, agentID, action)
	agentURN := trustedEndpointAgentURN(tenantID, agentID)
	if gateURN == "" || agentURN == "" {
		return nil, nil
	}
	decision := trustedEndpointNormalizeDecisionValue(attrs["decision"])
	severity := normalizeFindingSeverity(firstNonEmpty(attrs["severity"], trustedEndpointActiveTrustGateFailureDefinition.Severity))
	label := firstNonEmpty(strings.TrimSpace(attrs["hostname"]), agentID)
	attributes := map[string]string{
		"trusted_endpoint_gate_urn":  gateURN,
		"trusted_endpoint_agent_urn": agentURN,
		"agent_id":                   agentID,
		"action":                     action,
		"decision":                   decision,
		"reason":                     strings.TrimSpace(attrs["reason"]),
		"hostname":                   strings.TrimSpace(attrs["hostname"]),
		"severity":                   severity,
		"event_id":                   strings.TrimSpace(event.GetId()),
		"source_runtime_id":          firstNonEmpty(strings.TrimSpace(attrs[ports.EventAttributeSourceRuntimeID]), strings.TrimSpace(runtimeID)),
		"primary_resource_urn":       agentURN,
	}
	for key, value := range trustedEndpointActiveTrustGateFailureDefinition.AttributeMap() {
		attributes["rule_"+key] = value
	}
	trimEmptyAttributes(attributes)
	observedAt := time.Time{}
	if timestamp := event.GetOccurredAt(); timestamp != nil {
		observedAt = timestamp.AsTime().UTC()
	}
	fingerprint := hashFindingFingerprint(trustedEndpointActiveTrustGateFailureRuleID, gateURN)
	return &ports.FindingRecord{
		ID:              fingerprint,
		Fingerprint:     fingerprint,
		TenantID:        tenantID,
		RuntimeID:       strings.TrimSpace(runtimeID),
		RuleID:          trustedEndpointActiveTrustGateFailureRuleID,
		Title:           trustedEndpointActiveTrustGateFailureTitle,
		Severity:        severity,
		Status:          findingStatusOpen,
		Summary:         trustedEndpointActiveTrustGateFailureSummary(label, action),
		ResourceURNs:    []string{agentURN},
		EventIDs:        []string{strings.TrimSpace(event.GetId())},
		PolicyID:        action,
		CheckID:         trustedEndpointActiveTrustGateFailureCheckID,
		CheckName:       trustedEndpointActiveTrustGateFailureCheckName,
		ControlRefs:     cloneFindingControlRefs(trustedEndpointActiveTrustGateFailureDefinition.ControlRefs),
		Attributes:      attributes,
		FirstObservedAt: observedAt,
		LastObservedAt:  observedAt,
	}, nil
}

func trustedEndpointGateDenied(attributes map[string]string) bool {
	switch trustedEndpointNormalizeDecisionValue(attributes["decision"]) {
	case "deny", "error":
		return true
	default:
		return false
	}
}

func trustedEndpointGateRemediated(attributes map[string]string) bool {
	return trustedEndpointNormalizeDecisionValue(attributes["decision"]) == "allow"
}

func trustedEndpointNormalizeDecisionValue(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "deny", "denied", "block", "blocked", "fail", "failed", "reject", "rejected":
		return "deny"
	case "allow", "allowed", "pass", "passed", "ok", "permit", "permitted", "approved":
		return "allow"
	case "error", "errored":
		return "error"
	default:
		return strings.ToLower(strings.TrimSpace(value))
	}
}

func trustedEndpointTrustGateURN(tenantID string, agentID string, action string) string {
	tenantID = strings.TrimSpace(tenantID)
	agentID = strings.TrimSpace(agentID)
	action = strings.TrimSpace(action)
	if tenantID == "" || agentID == "" || action == "" {
		return ""
	}
	return fmt.Sprintf("urn:cerebro:%s:trusted_endpoint_trust_gate:%s:%s", tenantID, agentID, action)
}

func trustedEndpointAgentURN(tenantID string, agentID string) string {
	tenantID = strings.TrimSpace(tenantID)
	agentID = strings.TrimSpace(agentID)
	if tenantID == "" || agentID == "" {
		return ""
	}
	return fmt.Sprintf("urn:cerebro:%s:trusted_endpoint_agent:%s", tenantID, agentID)
}

func trustedEndpointActiveTrustGateFailureAnchor(attributes map[string]string) string {
	return identityCounterEventAnchor(map[string]string{
		"trusted_endpoint_gate_urn": strings.TrimSpace(attributes["trusted_endpoint_gate_urn"]),
	}, "trusted_endpoint_gate_urn")
}

func trustedEndpointActiveTrustGateFailureSummary(label string, action string) string {
	return fmt.Sprintf("Trusted Endpoint agent %s is failing the trust gate for action %s", firstNonEmpty(label, "unknown agent"), firstNonEmpty(action, "unknown action"))
}
