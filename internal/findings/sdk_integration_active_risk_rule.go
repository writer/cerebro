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
	sdkIntegrationActiveRiskRuleID    = "sdk-integration-active-risk"
	sdkIntegrationActiveRiskTitle     = "SDK Integration Reporting Active Risk Posture"
	sdkIntegrationActiveRiskSeverity  = "HIGH"
	sdkIntegrationActiveRiskStatus    = "open"
	sdkIntegrationActiveRiskCheckID   = "sdk-integration-active-risk-current"
	sdkIntegrationActiveRiskCheckName = "SDK Integration Reporting Active Risk Posture (current state)"
)

var sdkIntegrationActiveRiskControlRefs = []ports.FindingControlRef{
	{FrameworkName: "SOC 2", ControlID: "CC6.1"},
	{FrameworkName: "ISO 27001:2022", ControlID: "A.5.36"},
}

type sdkIntegrationActiveRiskRule struct {
	Rule
	definition RuleDefinition
}

var sdkIntegrationActiveRiskDefinition = RuleDefinition{
	ID:                 sdkIntegrationActiveRiskRuleID,
	Name:               sdkIntegrationActiveRiskTitle,
	Description:        "Detect resources an SDK-onboarded integration reports as currently at risk for a named security control, so a durable finding tracks the control gap until the integration reports the resource as secure again.",
	SourceID:           "sdk",
	EventKinds:         []string{"sdk.integration_posture"},
	OutputKind:         "finding.sdk_integration_active_risk",
	Severity:           sdkIntegrationActiveRiskSeverity,
	Status:             sdkIntegrationActiveRiskStatus,
	Maturity:           "test",
	Tags:               []string{"sdk", "integration", "posture", "control-gap"},
	References:         []string{"https://github.com/writer/cerebro/blob/main/docs/SOURCE_RUNTIME_GUIDE.md"},
	FalsePositives:     []string{"Integrations that report a transient at-risk posture during a planned maintenance window where the control gap is documented and risk-accepted."},
	Runbook:            "Review the reported control gap for the affected resource and remediate it; the finding resolves automatically once the integration reports the resource as secure.",
	RequiredAttributes: []string{"integration", "resource_urn", "control"},
	FingerprintFields:  []string{"sdk_posture_urn"},
	ControlRefs:        sdkIntegrationActiveRiskControlRefs,
	Lifecycle:          Lifecycle{Kind: LifecycleDurableState, Anchor: AnchorSourceState},
}

var sdkIntegrationActiveRiskKindMatcher = eventKindMatcher(sdkIntegrationActiveRiskDefinition.EventKinds...)

func newSDKIntegrationActiveRiskRule() Rule {
	rule := newEventRule(eventRuleConfig{
		definition: sdkIntegrationActiveRiskDefinition,
		match:      matchesSDKIntegrationActiveRisk,
		build: func(ctx context.Context, runtime *cerebrov1.SourceRuntime, event *cerebrov1.EventEnvelope) (*ports.FindingRecord, error) {
			return sdkIntegrationActiveRiskFinding(event, runtime.GetId())
		},
	})
	return &sdkIntegrationActiveRiskRule{
		Rule:       rule,
		definition: sdkIntegrationActiveRiskDefinition,
	}
}

func (r *sdkIntegrationActiveRiskRule) RuleMetadata() RuleDefinition {
	if r == nil {
		return RuleDefinition{}
	}
	return cloneRuleDefinition(r.definition)
}

func (r *sdkIntegrationActiveRiskRule) OpenAnchor(attributes map[string]string) string {
	return sdkIntegrationActiveRiskAnchor(attributes)
}

// CloseOnEvent resolves an open finding when a later integration posture report
// shows the same resource/control is secure again, so remediated control gaps
// do not leave stale open findings.
func (r *sdkIntegrationActiveRiskRule) CloseOnEvent(event Event) (string, bool) {
	if !sdkIntegrationActiveRiskKindMatcher(event) || !hasRequiredAttributes(event, sdkIntegrationActiveRiskDefinition.RequiredAttributes...) {
		return "", false
	}
	attributes := eventAttributes(event)
	if !sdkPostureSecure(attributes) {
		return "", false
	}
	postureURN := sdkIntegrationPostureFindingURN(event.GetTenantId(), attributes["integration"], attributes["control"], attributes["resource_urn"])
	anchor := sdkIntegrationActiveRiskAnchor(map[string]string{"sdk_posture_urn": postureURN})
	return anchor, anchor != ""
}

func matchesSDKIntegrationActiveRisk(event *cerebrov1.EventEnvelope) bool {
	if !sdkIntegrationActiveRiskKindMatcher(event) || !hasRequiredAttributes(event, sdkIntegrationActiveRiskDefinition.RequiredAttributes...) {
		return false
	}
	return sdkPostureAtRisk(eventAttributes(event))
}

func sdkIntegrationActiveRiskFinding(event *cerebrov1.EventEnvelope, runtimeID string) (*ports.FindingRecord, error) {
	attrs := event.GetAttributes()
	tenantID := strings.TrimSpace(event.GetTenantId())
	integration := strings.TrimSpace(attrs["integration"])
	control := strings.TrimSpace(attrs["control"])
	resourceURN := strings.TrimSpace(attrs["resource_urn"])
	postureURN := sdkIntegrationPostureFindingURN(tenantID, integration, control, resourceURN)
	if postureURN == "" {
		return nil, nil
	}
	label := firstNonEmpty(strings.TrimSpace(attrs["resource_label"]), resourceURN)
	attributes := map[string]string{
		"sdk_posture_urn":      postureURN,
		"integration":          integration,
		"control":              control,
		"resource_urn":         resourceURN,
		"resource_label":       strings.TrimSpace(attrs["resource_label"]),
		"posture_status":       strings.TrimSpace(attrs["posture_status"]),
		"risk_reason":          strings.TrimSpace(attrs["risk_reason"]),
		"event_id":             strings.TrimSpace(event.GetId()),
		"source_runtime_id":    strings.TrimSpace(attrs[ports.EventAttributeSourceRuntimeID]),
		"primary_resource_urn": resourceURN,
	}
	for key, value := range sdkIntegrationActiveRiskDefinition.AttributeMap() {
		attributes["rule_"+key] = value
	}
	trimEmptyAttributes(attributes)
	observedAt := time.Time{}
	if timestamp := event.GetOccurredAt(); timestamp != nil {
		observedAt = timestamp.AsTime().UTC()
	}
	fingerprint := hashFindingFingerprint(sdkIntegrationActiveRiskRuleID, postureURN)
	return &ports.FindingRecord{
		ID:              fingerprint,
		Fingerprint:     fingerprint,
		TenantID:        tenantID,
		RuntimeID:       strings.TrimSpace(runtimeID),
		RuleID:          sdkIntegrationActiveRiskRuleID,
		Title:           sdkIntegrationActiveRiskTitle,
		Severity:        sdkIntegrationActiveRiskSeverity,
		Status:          sdkIntegrationActiveRiskStatus,
		Summary:         sdkIntegrationActiveRiskSummary(integration, control, label),
		ResourceURNs:    []string{resourceURN},
		EventIDs:        []string{strings.TrimSpace(event.GetId())},
		CheckID:         sdkIntegrationActiveRiskCheckID,
		CheckName:       sdkIntegrationActiveRiskCheckName,
		ControlRefs:     cloneFindingControlRefs(sdkIntegrationActiveRiskDefinition.ControlRefs),
		Attributes:      attributes,
		FirstObservedAt: observedAt,
		LastObservedAt:  observedAt,
	}, nil
}

func sdkPostureAtRisk(attributes map[string]string) bool {
	return strings.EqualFold(strings.TrimSpace(attributes["posture_status"]), "at_risk")
}

func sdkPostureSecure(attributes map[string]string) bool {
	return strings.EqualFold(strings.TrimSpace(attributes["posture_status"]), "secure")
}

func sdkIntegrationPostureFindingURN(tenantID string, integration string, control string, resourceURN string) string {
	tenantID = strings.TrimSpace(tenantID)
	integration = strings.TrimSpace(integration)
	control = strings.TrimSpace(control)
	resourceURN = strings.TrimSpace(resourceURN)
	if tenantID == "" || integration == "" || control == "" || resourceURN == "" {
		return ""
	}
	key := strings.TrimPrefix(resourceURN, "urn:cerebro:"+tenantID+":")
	key = strings.TrimPrefix(key, "urn:cerebro:")
	key = strings.ReplaceAll(key, ":", "/")
	return fmt.Sprintf("urn:cerebro:%s:sdk_integration_posture:%s:%s:%s", tenantID, integration, control, key)
}

func sdkIntegrationActiveRiskAnchor(attributes map[string]string) string {
	return identityCounterEventAnchor(map[string]string{
		"sdk_posture_urn": strings.TrimSpace(attributes["sdk_posture_urn"]),
	}, "sdk_posture_urn")
}

func sdkIntegrationActiveRiskSummary(integration string, control string, label string) string {
	return fmt.Sprintf("SDK integration %s reports %s at risk for control %s", firstNonEmpty(integration, "unknown"), firstNonEmpty(label, "an unknown resource"), firstNonEmpty(control, "unknown"))
}
