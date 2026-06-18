package findings

import (
	"context"
	"fmt"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/securitytooling"
)

const (
	securityToolingMapCoverageGapRuleID    = "security-tooling-map-control-coverage-gap"
	securityToolingMapCoverageGapTitle     = "Security Tooling Control Coverage Gap"
	securityToolingMapCoverageGapSeverity  = "MEDIUM"
	securityToolingMapCoverageGapCheckID   = "security-tooling-map-control-coverage-gap-current"
	securityToolingMapCoverageGapCheckName = "Security Tooling Control Coverage Gap (current state)"
)

var securityToolingMapCoverageGapControlRefs = []ports.FindingControlRef{
	{FrameworkName: "SOC 2", ControlID: "CC4.1"},
	{FrameworkName: "ISO 27001:2022", ControlID: "A.5.36"},
}

type securityToolingMapCoverageGapRule struct {
	Rule
	definition RuleDefinition
}

var securityToolingMapCoverageGapDefinition = RuleDefinition{
	ID:                 securityToolingMapCoverageGapRuleID,
	Name:               securityToolingMapCoverageGapTitle,
	Description:        "Detect security controls whose tooling-map coverage is an active, unremediated gap (for example partial, planned, or missing coverage), leaving the mapped control without adequate tooling support. The finding resolves when coverage is reported as covered or the control is retired, and reopens on a stable fingerprint if the gap recurs.",
	SourceID:           "security_tooling_map",
	EventKinds:         []string{"security_tooling_map.control_mapping"},
	OutputKind:         "finding.security_tooling_map_control_coverage_gap",
	Severity:           securityToolingMapCoverageGapSeverity,
	Status:             findingStatusOpen,
	Maturity:           "test",
	Tags:               []string{"security-tooling-map", "grc", "control-coverage", "posture", "gap"},
	References:         []string{"https://www.aicpa-cima.com/topic/audit-assurance/audit-and-assurance-greater-than-soc-2"},
	FalsePositives:     []string{"Controls intentionally covered by a different tool whose mapping is recorded elsewhere, or inventory-only mappings for controls that are out of scope and should be marked not-applicable instead of partial."},
	Runbook:            "Confirm whether the mapped control still requires tooling coverage; if so, extend the tool to fully cover the control or map a tool that does, otherwise mark the control coverage as not-applicable or retire the mapping.",
	RequiredAttributes: []string{"tool_id", "control_id"},
	FingerprintFields:  []string{"security_tool_control_coverage_urn"},
	ControlRefs:        securityToolingMapCoverageGapControlRefs,
	Lifecycle:          Lifecycle{Kind: LifecycleDurableState, Anchor: AnchorSourceState},
}

var securityToolingMapCoverageGapKindMatcher = eventKindMatcher(securityToolingMapCoverageGapDefinition.EventKinds...)

func newSecurityToolingMapControlCoverageGapRule() Rule {
	rule := newEventRule(eventRuleConfig{
		definition: securityToolingMapCoverageGapDefinition,
		match:      matchesSecurityToolingMapCoverageGap,
		build: func(ctx context.Context, runtime *cerebrov1.SourceRuntime, event *cerebrov1.EventEnvelope) (*ports.FindingRecord, error) {
			return securityToolingMapCoverageGapFinding(event, runtime.GetId())
		},
	})
	return &securityToolingMapCoverageGapRule{
		Rule:       rule,
		definition: securityToolingMapCoverageGapDefinition,
	}
}

func (r *securityToolingMapCoverageGapRule) RuleMetadata() RuleDefinition {
	if r == nil {
		return RuleDefinition{}
	}
	return cloneRuleDefinition(r.definition)
}

func (r *securityToolingMapCoverageGapRule) OpenAnchor(attributes map[string]string) string {
	return securityToolingMapCoverageGapAnchor(attributes)
}

// CloseOnEvent resolves an open finding when a later snapshot of the same
// tool-control mapping reports covered coverage (remediation) or shows the
// control retired/not-applicable, so remediated or decommissioned mappings do
// not leave stale open findings.
func (r *securityToolingMapCoverageGapRule) CloseOnEvent(event Event) (string, bool) {
	if !securityToolingMapCoverageGapKindMatcher(event) || !hasRequiredAttributes(event, securityToolingMapCoverageGapDefinition.RequiredAttributes...) {
		return "", false
	}
	attributes := eventAttributes(event)
	if !securityToolingMapControlCoverageResolved(attributes) {
		return "", false
	}
	coverageURN := securityToolingMapControlCoverageURN(event.GetTenantId(), attributes)
	anchor := securityToolingMapCoverageGapAnchor(map[string]string{"security_tool_control_coverage_urn": coverageURN})
	return anchor, anchor != ""
}

func matchesSecurityToolingMapCoverageGap(event *cerebrov1.EventEnvelope) bool {
	if !securityToolingMapCoverageGapKindMatcher(event) || !hasRequiredAttributes(event, securityToolingMapCoverageGapDefinition.RequiredAttributes...) {
		return false
	}
	return securityToolingMapControlCoverageGap(eventAttributes(event))
}

func securityToolingMapCoverageGapFinding(event *cerebrov1.EventEnvelope, runtimeID string) (*ports.FindingRecord, error) {
	attrs := event.GetAttributes()
	tenantID := strings.TrimSpace(event.GetTenantId())
	coverageURN := securityToolingMapControlCoverageURN(tenantID, attrs)
	if coverageURN == "" {
		return nil, nil
	}
	toolID := securityToolingMapToolID(attrs)
	controlID := strings.TrimSpace(attrs["control_id"])
	framework := firstNonEmpty(strings.TrimSpace(attrs["framework"]), "security")
	controlURN := securityToolingMapControlURN(tenantID, framework, controlID)
	toolURN := securityToolingMapToolURN(tenantID, toolID)
	controlLabel := firstNonEmpty(strings.TrimSpace(attrs["control_name"]), controlID)
	toolLabel := firstNonEmpty(strings.TrimSpace(attrs["tool_name"]), toolID)
	coverage := firstNonEmpty(strings.TrimSpace(attrs["coverage"]), "gap")
	attributes := map[string]string{
		"security_tool_control_coverage_urn": coverageURN,
		"tool_id":                            toolID,
		"tool_name":                          strings.TrimSpace(attrs["tool_name"]),
		"control_id":                         controlID,
		"control_name":                       strings.TrimSpace(attrs["control_name"]),
		"framework":                          strings.TrimSpace(attrs["framework"]),
		"coverage":                           coverage,
		"coverage_status":                    "gap",
		"gap_reason":                         strings.TrimSpace(attrs["gap_reason"]),
		"security_tool_urn":                  toolURN,
		"control_urn":                        controlURN,
		"event_id":                           strings.TrimSpace(event.GetId()),
		"source_runtime_id":                  strings.TrimSpace(attrs[ports.EventAttributeSourceRuntimeID]),
		"primary_resource_urn":               controlURN,
	}
	for key, value := range securityToolingMapCoverageGapDefinition.AttributeMap() {
		attributes["rule_"+key] = value
	}
	trimEmptyAttributes(attributes)
	observedAt := time.Time{}
	if timestamp := event.GetOccurredAt(); timestamp != nil {
		observedAt = timestamp.AsTime().UTC()
	}
	fingerprint := hashFindingFingerprint(securityToolingMapCoverageGapRuleID, coverageURN)
	resourceURNs := []string{controlURN}
	if toolURN != "" {
		resourceURNs = append(resourceURNs, toolURN)
	}
	return &ports.FindingRecord{
		ID:              fingerprint,
		Fingerprint:     fingerprint,
		TenantID:        tenantID,
		RuntimeID:       strings.TrimSpace(runtimeID),
		RuleID:          securityToolingMapCoverageGapRuleID,
		Title:           securityToolingMapCoverageGapTitle,
		Severity:        securityToolingMapCoverageGapSeverity,
		Status:          findingStatusOpen,
		Summary:         securityToolingMapCoverageGapSummary(toolLabel, controlLabel),
		ResourceURNs:    resourceURNs,
		EventIDs:        []string{strings.TrimSpace(event.GetId())},
		CheckID:         securityToolingMapCoverageGapCheckID,
		CheckName:       securityToolingMapCoverageGapCheckName,
		ControlRefs:     cloneFindingControlRefs(securityToolingMapCoverageGapDefinition.ControlRefs),
		Attributes:      attributes,
		FirstObservedAt: observedAt,
		LastObservedAt:  observedAt,
	}, nil
}

// securityToolingMapControlCoverageGap reports whether a tool-control mapping
// currently represents an active coverage gap. Retired or not-applicable
// controls are excluded so decommissioned mappings do not surface as gaps.
func securityToolingMapControlCoverageGap(attributes map[string]string) bool {
	if securityToolingMapControlDecommissioned(attributes) {
		return false
	}
	return securityToolingMapCoverageGapStatus(attributes) == "gap"
}

func securityToolingMapControlCoverageResolved(attributes map[string]string) bool {
	return securityToolingMapControlDecommissioned(attributes) || securityToolingMapCoverageGapStatus(attributes) == "covered"
}

func securityToolingMapCoverageGapStatus(attributes map[string]string) string {
	if status := strings.ToLower(strings.TrimSpace(attributes["coverage_status"])); status != "" {
		switch status {
		case "covered", "gap":
			return status
		}
	}
	return securitytooling.CoverageStatus(attributes["coverage"])
}

func securityToolingMapControlDecommissioned(attributes map[string]string) bool {
	switch strings.ToLower(strings.TrimSpace(attributes["control_status"])) {
	case "retired", "deprecated", "removed", "inactive", "not_applicable", "n/a", "na":
		return true
	default:
		return false
	}
}

func securityToolingMapToolID(attributes map[string]string) string {
	return firstNonEmpty(strings.TrimSpace(attributes["tool_id"]), strings.TrimSpace(attributes["tool_name"]))
}

func securityToolingMapControlCoverageURN(tenantID string, attributes map[string]string) string {
	tenantID = strings.TrimSpace(tenantID)
	toolID := securityToolingMapToolID(attributes)
	controlID := strings.TrimSpace(attributes["control_id"])
	if tenantID == "" || toolID == "" || controlID == "" {
		return ""
	}
	framework := firstNonEmpty(strings.TrimSpace(attributes["framework"]), "security")
	return fmt.Sprintf("urn:cerebro:%s:security_tool_control_coverage:%s:%s:%s", tenantID, toolID, framework, controlID)
}

func securityToolingMapControlURN(tenantID string, framework string, controlID string) string {
	tenantID = strings.TrimSpace(tenantID)
	controlID = strings.TrimSpace(controlID)
	if tenantID == "" || controlID == "" {
		return ""
	}
	return fmt.Sprintf("urn:cerebro:%s:control:%s:%s", tenantID, firstNonEmpty(strings.TrimSpace(framework), "security"), controlID)
}

func securityToolingMapToolURN(tenantID string, toolID string) string {
	tenantID = strings.TrimSpace(tenantID)
	toolID = strings.TrimSpace(toolID)
	if tenantID == "" || toolID == "" {
		return ""
	}
	return fmt.Sprintf("urn:cerebro:%s:security_tool:%s", tenantID, toolID)
}

func securityToolingMapCoverageGapAnchor(attributes map[string]string) string {
	return identityCounterEventAnchor(map[string]string{
		"security_tool_control_coverage_urn": strings.TrimSpace(attributes["security_tool_control_coverage_urn"]),
	}, "security_tool_control_coverage_urn")
}

func securityToolingMapCoverageGapSummary(toolLabel string, controlLabel string) string {
	return fmt.Sprintf("Security control %s has a tooling coverage gap (%s)", firstNonEmpty(controlLabel, "unknown control"), firstNonEmpty(toolLabel, "unknown tool"))
}
