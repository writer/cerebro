package findings

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

const (
	sentinelOneRetiredUnresolvedThreatRuleID    = "sentinelone-unresolved-threat"
	sentinelOneRetiredMaliciousOrFilelessRuleID = "sentinelone-malicious-or-fileless-threat"
	sentinelOneRetiredInfectedEndpointRuleID    = "sentinelone-infected-endpoint"
	sentinelOneEndpointActiveInfectionRuleID    = "sentinelone-endpoint-active-infection"
	sentinelOneMitigationFailedRuleID           = "sentinelone-mitigation-failed"
	sentinelOneAgentStaleRuleID                 = "sentinelone-agent-stale"
	sentinelOneAgentDetectOnlyModeRuleID        = "sentinelone-agent-detect-only-mode"
	sentinelOneProtectionControlTamperingRuleID = "sentinelone-protection-control-tampering"
	sentinelOneRiskyExclusionRuleID             = "sentinelone-risky-exclusion"
	sentinelOneThreatEntityType                 = "sentinelone.threat"
	sentinelOneAgentEntityType                  = "sentinelone.agent"
	sentinelOneActivityEntityType               = "sentinelone.activity"
	sentinelOneExclusionEntityType              = "sentinelone.exclusion"
	sentinelOneEndpointActiveInfectionAction    = "endpoint_active_infection"
	sentinelOneMitigationFailedAction           = "mitigation_failed"
	sentinelOneAgentStaleAction                 = "agent_stale"
	sentinelOneAgentDetectOnlyModeAction        = "agent_detect_only_mode"
	sentinelOneProtectionControlTamperingAction = "protection_control_tampering"
	sentinelOneRiskyExclusionAction             = "risky_exclusion"
	sentinelOneAgentStaleThreshold              = 14 * 24 * time.Hour
)

var (
	sentinelOneThreatResponseControlRefs = []ports.FindingControlRef{
		{FrameworkName: "SOC 2", ControlID: "CC7.2"},
		{FrameworkName: "ISO 27001:2022", ControlID: "A.5.25"},
	}
	sentinelOneMitigationControlRefs = []ports.FindingControlRef{
		{FrameworkName: "SOC 2", ControlID: "CC7.3"},
		{FrameworkName: "ISO 27001:2022", ControlID: "A.5.26"},
	}
	sentinelOneEndpointCoverageControlRefs = []ports.FindingControlRef{
		{FrameworkName: "SOC 2", ControlID: "CC6.6"},
		{FrameworkName: "ISO 27001:2022", ControlID: "A.8.16"},
	}
	sentinelOneEndpointProtectionControlRefs = []ports.FindingControlRef{
		{FrameworkName: "SOC 2", ControlID: "CC6.8"},
		{FrameworkName: "ISO 27001:2022", ControlID: "A.8.7"},
	}
	sentinelOneExclusionControlRefs = []ports.FindingControlRef{
		{FrameworkName: "SOC 2", ControlID: "CC6.8"},
		{FrameworkName: "ISO 27001:2022", ControlID: "A.8.9"},
	}
)

type sentinelOneFindingOptions struct {
	definition         RuleDefinition
	action             string
	primaryEntityType  string
	collectAllEntities bool
	collectAllLinkURNs bool
	primaryRelations   []string
	severity           func(map[string]string) string
	summary            func(map[string]string, findingProjectionContext) string
	policyID           func(map[string]string) string
	fingerprint        func(*cerebrov1.EventEnvelope, map[string]string, findingProjectionContext) []string
	enrichAttributes   func(sourceAttributes, findingAttributes map[string]string)
}

type sentinelOneProtectionControlTamperingRule struct {
	Rule
	definition RuleDefinition
}

func newSentinelOneEndpointActiveInfectionRule() Rule {
	definition := sentinelOneRuleDefinition(
		sentinelOneEndpointActiveInfectionRuleID,
		"SentinelOne Endpoint Active Infection",
		"Detect endpoint-level active infection state from SentinelOne without mirroring each threat as a finding.",
		[]string{sentinelOneAgentEntityType, sentinelOneThreatEntityType},
		"finding.sentinelone_endpoint_active_infection",
		"CRITICAL",
		[]string{"sentinelone", "endpoint", "infection", "malware", "attack.impact"},
		[]string{"agent_id"},
		[]string{"agent_id"},
		sentinelOneThreatResponseControlRefs,
	)
	definition.Lifecycle = Lifecycle{Kind: LifecycleDurableState, Anchor: AnchorGraphAnchored}
	return &sentinelOneEndpointActiveInfectionGraphRule{definition: definition}
}

func newSentinelOneMitigationFailedRule() Rule {
	definition := sentinelOneRuleDefinition(
		sentinelOneMitigationFailedRuleID,
		"SentinelOne Mitigation Failed",
		"Detect SentinelOne containment or mitigation workflows that failed or require manual action.",
		[]string{sentinelOneThreatEntityType},
		"finding.sentinelone_mitigation_failed",
		"HIGH",
		[]string{"sentinelone", "mitigation", "containment", "response", "attack.impact"},
		[]string{"agent_id", "mitigation_status"},
		[]string{"agent_id", "mitigation_status"},
		sentinelOneMitigationControlRefs,
	)
	return newSentinelOneEventRule(definition, matchesSentinelOneMitigationFailed, sentinelOneFindingOptions{
		action:             sentinelOneMitigationFailedAction,
		primaryEntityType:  sentinelOneAgentEntityType,
		collectAllLinkURNs: true,
		severity:           sentinelOneMitigationFailedSeverity,
		summary:            sentinelOneMitigationFailedSummary,
		policyID:           sentinelOneAgentPolicyID,
	})
}

func newSentinelOneAgentStaleRule() Rule {
	definition := sentinelOneRuleDefinition(
		sentinelOneAgentStaleRuleID,
		"SentinelOne Agent Stale",
		"Detect active inventory endpoints whose SentinelOne agent has not checked in recently.",
		[]string{sentinelOneAgentEntityType},
		"finding.sentinelone_agent_stale",
		"MEDIUM",
		[]string{"sentinelone", "endpoint", "coverage", "stale-agent"},
		[]string{"agent_id", "last_active_date"},
		[]string{"agent_id"},
		sentinelOneEndpointCoverageControlRefs,
	)
	definition.Lifecycle = Lifecycle{Kind: LifecycleDurableState, Anchor: AnchorGraphAnchored}
	return &sentinelOneAgentStaleGraphRule{definition: definition}
}

func newSentinelOneAgentDetectOnlyModeRule() Rule {
	definition := sentinelOneRuleDefinition(
		sentinelOneAgentDetectOnlyModeRuleID,
		"SentinelOne Agent Detect Only Mode",
		"Detect endpoints where SentinelOne is configured to detect but not block or protect.",
		[]string{sentinelOneAgentEntityType},
		"finding.sentinelone_agent_detect_only_mode",
		"HIGH",
		[]string{"sentinelone", "endpoint", "prevention", "detect-only"},
		[]string{"agent_id", "mitigation_mode"},
		[]string{"agent_id"},
		sentinelOneEndpointProtectionControlRefs,
	)
	return newSentinelOneEventRule(definition, matchesSentinelOneAgentDetectOnlyMode, sentinelOneFindingOptions{
		action:             sentinelOneAgentDetectOnlyModeAction,
		primaryEntityType:  sentinelOneAgentEntityType,
		collectAllLinkURNs: true,
		summary:            sentinelOneAgentDetectOnlyModeSummary,
		policyID:           sentinelOneAgentPolicyID,
	})
}

func newSentinelOneProtectionControlTamperingRule() Rule {
	definition := sentinelOneRuleDefinition(
		sentinelOneProtectionControlTamperingRuleID,
		"SentinelOne Protection Control Tampering",
		"Detect SentinelOne agents where a named protection control remains in a tampered state.",
		[]string{sentinelOneAgentEntityType},
		"finding.sentinelone_protection_control_tampering",
		"HIGH",
		[]string{"sentinelone", "control-plane", "tampering", "defense-evasion", "attack.t1562"},
		[]string{"agent_id"},
		[]string{"agent_id", "control_type"},
		sentinelOneEndpointProtectionControlRefs,
	)
	definition.Lifecycle = Lifecycle{Kind: LifecycleDurableState, Anchor: AnchorGraphAnchored}
	rule := newSentinelOneEventRule(definition, matchesSentinelOneProtectionControlTampering, sentinelOneFindingOptions{
		action:             sentinelOneProtectionControlTamperingAction,
		primaryEntityType:  sentinelOneAgentEntityType,
		collectAllEntities: true,
		collectAllLinkURNs: true,
		summary:            sentinelOneProtectionControlTamperingSummary,
		fingerprint:        sentinelOneProtectionControlTamperingFingerprintInputs,
		enrichAttributes:   sentinelOneProtectionControlTamperingAttributes,
		policyID: func(attributes map[string]string) string {
			return sentinelOneProtectionControlTamperingPolicyID(attributes)
		},
	})
	return &sentinelOneProtectionControlTamperingRule{
		Rule:       rule,
		definition: definition,
	}
}

func newSentinelOneRiskyExclusionRule() Rule {
	definition := sentinelOneRuleDefinition(
		sentinelOneRiskyExclusionRuleID,
		"SentinelOne Risky Exclusion",
		"Detect SentinelOne exclusions that are not recommended or materially broaden endpoint protection bypass scope.",
		[]string{sentinelOneExclusionEntityType},
		"finding.sentinelone_risky_exclusion",
		"MEDIUM",
		[]string{"sentinelone", "exclusion", "endpoint", "defense-evasion", "attack.t1562"},
		[]string{"exclusion_id"},
		[]string{"exclusion_id"},
		sentinelOneExclusionControlRefs,
	)
	return newSentinelOneEventRule(definition, matchesSentinelOneRiskyExclusion, sentinelOneFindingOptions{
		action:             sentinelOneRiskyExclusionAction,
		primaryEntityType:  sentinelOneExclusionEntityType,
		collectAllEntities: true,
		severity:           sentinelOneExclusionSeverity,
		summary:            sentinelOneRiskyExclusionSummary,
		policyID: func(attributes map[string]string) string {
			return firstNonEmpty(attributes["exclusion_id"], attributes["value"])
		},
	})
}

func newRetiredSentinelOneRule(id string, name string, outputKind string) Rule {
	definition := sentinelOneRuleDefinition(
		id,
		name,
		"Retired SentinelOne threat-mirror rule retained temporarily so stale open findings are resolved after rule redesign.",
		[]string{sentinelOneThreatEntityType},
		outputKind,
		"INFO",
		[]string{"sentinelone", "retired", "cleanup"},
		nil,
		nil,
		nil,
	)
	definition.Maturity = "retired"
	definition.Lifecycle = Lifecycle{Kind: LifecycleRetired, Anchor: AnchorNone}
	return newEventRule(eventRuleConfig{
		definition:         definition,
		sourceID:           "sentinelone",
		retireOpenFindings: true,
		match:              func(*cerebrov1.EventEnvelope) bool { return false },
		build: func(context.Context, *cerebrov1.SourceRuntime, *cerebrov1.EventEnvelope) (*ports.FindingRecord, error) {
			return nil, nil
		},
	})
}

func newSentinelOneEventRule(definition RuleDefinition, match eventRuleMatcher, options sentinelOneFindingOptions) Rule {
	options.definition = definition
	return newEventRule(eventRuleConfig{
		definition: definition,
		sourceID:   "sentinelone",
		match:      match,
		build: func(ctx context.Context, runtime *cerebrov1.SourceRuntime, event *cerebrov1.EventEnvelope) (*ports.FindingRecord, error) {
			return buildSentinelOneFinding(ctx, runtime, event, options)
		},
	})
}

func sentinelOneRuleDefinition(id, name, description string, eventKinds []string, outputKind, severity string, tags, requiredAttributes, fingerprintFields []string, controlRefs []ports.FindingControlRef) RuleDefinition {
	return RuleDefinition{
		ID:                 id,
		Name:               name,
		Description:        description,
		SourceID:           "sentinelone",
		EventKinds:         eventKinds,
		OutputKind:         outputKind,
		Severity:           severity,
		Status:             findingStatusOpen,
		Maturity:           "test",
		Tags:               tags,
		References:         []string{"https://docs.sentinelone.com/"},
		FalsePositives:     []string{"Approved security testing, decommissioned endpoint, documented exception, or SentinelOne false positive reviewed by security."},
		Runbook:            "Review SentinelOne endpoint state, linked threat/activity evidence, policy scope, and documented exceptions before remediation or closure.",
		RequiredAttributes: requiredAttributes,
		FingerprintFields:  fingerprintFields,
		ControlRefs:        cloneFindingControlRefs(controlRefs),
		Lifecycle:          Lifecycle{Kind: LifecycleDurableState, Anchor: AnchorSourceState},
	}
}

func buildSentinelOneFinding(ctx context.Context, runtime *cerebrov1.SourceRuntime, event *cerebrov1.EventEnvelope, options sentinelOneFindingOptions) (*ports.FindingRecord, error) {
	attributes := eventAttributes(event)
	projectedContext, err := buildFindingProjectionContext(ctx, event, findingProjectionContextOptions{
		PrimaryRelations:   options.primaryRelations,
		PrimaryEntityType:  options.primaryEntityType,
		CollectAllEntities: options.collectAllEntities,
		CollectAllLinkURNs: options.collectAllLinkURNs,
		ResourceFallbacks: []string{
			attributes["computer_name"],
			attributes["agent_name"],
			attributes["threat_name"],
			attributes["primary_description"],
			attributes["value"],
			attributes["agent_id"],
			attributes["exclusion_id"],
			attributes["activity_id"],
		},
	})
	if err != nil {
		return nil, fmt.Errorf("project SentinelOne finding context for event %q: %w", event.GetId(), err)
	}
	policyID := ""
	if options.policyID != nil {
		policyID = strings.TrimSpace(options.policyID(attributes))
	}
	policyID = firstNonEmpty(policyID, projectedContext.PrimaryResourceURN, event.GetId())
	observedAt := time.Time{}
	if timestamp := event.GetOccurredAt(); timestamp != nil {
		observedAt = timestamp.AsTime().UTC()
	}
	severity := options.definition.Severity
	if options.severity != nil {
		severity = options.severity(attributes)
	}
	findingAttributes := map[string]string{
		"action":               options.action,
		"event_id":             strings.TrimSpace(event.GetId()),
		"event_kind":           strings.TrimSpace(event.GetKind()),
		"primary_resource_urn": projectedContext.PrimaryResourceURN,
		"resource_id":          policyID,
		"resource_label":       projectedContext.ResourceLabel,
		"resource_type":        strings.TrimSpace(event.GetKind()),
		"source_family":        "sentinelone",
		"source_id":            strings.TrimSpace(event.GetSourceId()),
		"source_runtime_id":    strings.TrimSpace(runtime.GetId()),
		"tenant_id":            strings.TrimSpace(event.GetTenantId()),
	}
	for key, value := range attributes {
		if _, exists := findingAttributes[key]; !exists {
			findingAttributes[key] = strings.TrimSpace(value)
		}
	}
	if options.enrichAttributes != nil {
		options.enrichAttributes(attributes, findingAttributes)
	}
	for key, value := range options.definition.AttributeMap() {
		findingAttributes["rule_"+key] = value
	}
	trimEmptyAttributes(findingAttributes)
	observedPolicyIDs := []string{}
	if policyID != "" {
		observedPolicyIDs = append(observedPolicyIDs, policyID)
	}
	summary := options.definition.Name
	if options.summary != nil {
		summary = options.summary(attributes, projectedContext)
	}
	fingerprintInputs := []string{options.definition.ID, event.GetTenantId(), runtime.GetId(), policyID}
	if options.fingerprint != nil {
		fingerprintInputs = append([]string{options.definition.ID}, options.fingerprint(event, attributes, projectedContext)...)
	}
	fingerprint := hashFindingFingerprint(fingerprintInputs...)
	return &ports.FindingRecord{
		ID:                fingerprint,
		Fingerprint:       fingerprint,
		TenantID:          strings.TrimSpace(event.GetTenantId()),
		RuntimeID:         strings.TrimSpace(runtime.GetId()),
		RuleID:            options.definition.ID,
		Title:             options.definition.Name,
		Severity:          normalizeFindingSeverity(severity),
		Status:            findingStatusOpen,
		Summary:           summary,
		ResourceURNs:      projectedContext.ResourceURNs,
		EventIDs:          []string{strings.TrimSpace(event.GetId())},
		ObservedPolicyIDs: observedPolicyIDs,
		PolicyID:          policyID,
		PolicyName:        firstNonEmpty(attributes["computer_name"], attributes["agent_name"], attributes["threat_name"], attributes["value"], attributes["primary_description"], projectedContext.ResourceLabel),
		CheckID:           options.definition.ID,
		CheckName:         options.definition.Name,
		ControlRefs:       cloneFindingControlRefs(options.definition.ControlRefs),
		Attributes:        findingAttributes,
		FirstObservedAt:   observedAt,
		LastObservedAt:    observedAt,
	}, nil
}

func (r *sentinelOneProtectionControlTamperingRule) RuleMetadata() RuleDefinition {
	if r == nil {
		return RuleDefinition{}
	}
	return cloneRuleDefinition(r.definition)
}

func (r *sentinelOneProtectionControlTamperingRule) OpenAnchor(attributes map[string]string) string {
	return sentinelOneProtectionControlTamperingAnchor(attributes)
}

func (r *sentinelOneProtectionControlTamperingRule) CloseOnEvent(event Event) (string, bool) {
	if !eventKindMatcher(sentinelOneAgentEntityType)(event) || !hasRequiredAttributes(event, "agent_id") {
		return "", false
	}
	attributes := eventAttributes(event)
	tampered, known := sentinelOneProtectionControlTampered(attributes)
	if !known || tampered {
		return "", false
	}
	anchor := sentinelOneProtectionControlTamperingAnchor(attributes)
	return anchor, anchor != ""
}

func matchesSentinelOneMitigationFailed(event *cerebrov1.EventEnvelope) bool {
	if !eventKindMatcher(sentinelOneThreatEntityType)(event) || !hasRequiredAttributes(event, "agent_id", "mitigation_status") {
		return false
	}
	attributes := eventAttributes(event)
	return !sentinelOneFalsePositive(attributes) && sentinelOneMitigationNeedsAction(attributes["mitigation_status"])
}

func matchesSentinelOneAgentDetectOnlyMode(event *cerebrov1.EventEnvelope) bool {
	if !eventKindMatcher(sentinelOneAgentEntityType)(event) || !hasRequiredAttributes(event, "agent_id") {
		return false
	}
	attributes := eventAttributes(event)
	return !sentinelOneAgentRetired(attributes) && sentinelOneDetectOnlyMode(firstNonEmpty(attributes["mitigation_mode"], attributes["mitigation_mode_suspicious"], attributes["agent_mitigation_mode"]))
}

func matchesSentinelOneProtectionControlTampering(event *cerebrov1.EventEnvelope) bool {
	if !eventKindMatcher(sentinelOneAgentEntityType)(event) || !hasRequiredAttributes(event, "agent_id") {
		return false
	}
	attributes := eventAttributes(event)
	if sentinelOneAgentRetired(attributes) {
		return false
	}
	if sentinelOneProtectionControlType(attributes) == "" {
		return false
	}
	tampered, known := sentinelOneProtectionControlTampered(attributes)
	return known && tampered
}

func matchesSentinelOneRiskyExclusion(event *cerebrov1.EventEnvelope) bool {
	if !eventKindMatcher(sentinelOneExclusionEntityType)(event) || !hasRequiredAttributes(event, "exclusion_id") {
		return false
	}
	attributes := eventAttributes(event)
	return findingAttributeBool(attributes, "not_recommended") ||
		findingAttributeBool(attributes, "include_children", "include_parents") ||
		sentinelOneBroadExclusionValue(attributes["value"]) ||
		sentinelOneBroadExclusionValue(attributes["scope_path"])
}

func sentinelOneAgentPolicyID(attributes map[string]string) string {
	return firstNonEmpty(attributes["agent_id"], attributes["agent_uuid"], attributes["uuid"], attributes["computer_name"], attributes["agent_name"])
}

func sentinelOneProtectionControlTamperingAnchor(attributes map[string]string) string {
	agentID := strings.TrimSpace(attributes["agent_id"])
	controlType := sentinelOneProtectionControlType(attributes)
	if agentID == "" || controlType == "" {
		return ""
	}
	return agentID + "|" + controlType
}

func sentinelOneProtectionControlTamperingPolicyID(attributes map[string]string) string {
	agentID := strings.TrimSpace(attributes["agent_id"])
	controlType := sentinelOneProtectionControlType(attributes)
	if agentID == "" {
		return controlType
	}
	if controlType == "" {
		return agentID
	}
	return agentID + ":" + controlType
}

func sentinelOneProtectionControlTamperingFingerprintInputs(event *cerebrov1.EventEnvelope, attributes map[string]string, _ findingProjectionContext) []string {
	agentID := strings.TrimSpace(attributes["agent_id"])
	controlType := sentinelOneProtectionControlType(attributes)
	if agentID == "" || controlType == "" {
		return nil
	}
	return []string{strings.TrimSpace(event.GetTenantId()), agentID, controlType}
}

func sentinelOneProtectionControlType(attributes map[string]string) string {
	controlType := sentinelOneStatus(firstNonEmpty(
		attributes["control_type"],
		attributes["protection_control"],
		attributes["control_name"],
		attributes["control"],
	))
	if controlType != "" {
		return controlType
	}
	if _, ok := sentinelOneAttributeBool(attributes, "firewall_enabled"); ok {
		return "firewall"
	}
	return ""
}

func sentinelOneProtectionControlState(attributes map[string]string) string {
	state := firstNonEmpty(
		attributes["control_state"],
		attributes["protection_control_state"],
		attributes["tamper_state"],
		attributes["control_status"],
		attributes["status"],
	)
	if state != "" {
		return sentinelOneStatus(state)
	}
	if firewallEnabled, ok := sentinelOneAttributeBool(attributes, "firewall_enabled"); ok {
		if firewallEnabled {
			return "enabled"
		}
		return "disabled"
	}
	return ""
}

func sentinelOneProtectionControlTampered(attributes map[string]string) (bool, bool) {
	for _, key := range []string{"control_tampered", "is_control_tampered", "protection_control_tampered", "tampered"} {
		if raw := strings.TrimSpace(attributes[key]); raw != "" {
			return sentinelOneProtectionControlTamperedValue(raw)
		}
	}
	state := sentinelOneProtectionControlState(attributes)
	if state == "" {
		return false, false
	}
	return sentinelOneProtectionControlTamperedValue(state)
}

func sentinelOneProtectionControlTamperingAttributes(sourceAttributes, findingAttributes map[string]string) {
	if controlType := sentinelOneProtectionControlType(sourceAttributes); controlType != "" {
		findingAttributes["control_type"] = controlType
	}
	if controlState := sentinelOneProtectionControlState(sourceAttributes); controlState != "" {
		findingAttributes["control_state"] = controlState
	}
}

func sentinelOneAttributeBool(attributes map[string]string, keys ...string) (bool, bool) {
	for _, key := range keys {
		value := sentinelOneStatus(attributes[key])
		switch value {
		case "1", "t", "true", "yes", "y", "enabled", "active", "on", "protected", "healthy":
			return true, true
		case "0", "f", "false", "no", "n", "disabled", "inactive", "off", "unprotected", "not_protected":
			return false, true
		}
	}
	return false, false
}

func sentinelOneProtectionControlTamperedValue(value string) (bool, bool) {
	normalized := sentinelOneStatus(value)
	switch normalized {
	case "1", "true", "yes", "y", "tampered", "disabled", "deactivated", "suspended", "unprotected", "not_protected", "off", "bypassed", "detect", "detect_only", "detection", "monitor", "monitor_only", "uninstalled", "pending_uninstall", "modified_unauthorized":
		return true, true
	case "0", "false", "no", "n", "restored", "enabled", "active", "protected", "on", "healthy", "normal", "compliant", "not_tampered":
		return false, true
	default:
		return false, false
	}
}

func sentinelOneFalsePositive(attributes map[string]string) bool {
	value := strings.ToLower(strings.Join([]string{
		attributes["analyst_verdict"],
		attributes["classification"],
		attributes["mitigation_status"],
	}, " "))
	return containsAny(value, "false_positive", "false positive", "benign", "whitelisted")
}

func sentinelOneThreatOpen(attributes map[string]string) bool {
	incidentStatus := sentinelOneStatus(attributes["incident_status"])
	switch incidentStatus {
	case "resolved", "closed", "mitigated", "remediated", "false_positive", "benign":
		return false
	}
	mitigationStatus := sentinelOneStatus(attributes["mitigation_status"])
	switch mitigationStatus {
	case "mitigated", "remediated", "resolved", "success", "successful", "completed", "not_found":
		return false
	default:
		return true
	}
}

func sentinelOneMitigationNeedsAction(value string) bool {
	switch sentinelOneStatus(value) {
	case "failed", "failure", "partial", "partially_mitigated", "action_required", "requires_action":
		return true
	default:
		return false
	}
}

func sentinelOneAgentRetired(attributes map[string]string) bool {
	return findingAttributeBool(attributes, "is_decommissioned", "is_uninstalled", "is_pending_uninstall")
}

func sentinelOneDetectOnlyMode(value string) bool {
	normalized := sentinelOneStatus(value)
	switch normalized {
	case "detect", "detect_only", "detection", "monitor", "monitor_only":
		return true
	default:
		return strings.Contains(normalized, "detect") && !strings.Contains(normalized, "protect")
	}
}

func sentinelOneStatus(value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	normalized = strings.ReplaceAll(normalized, "-", "_")
	normalized = strings.ReplaceAll(normalized, " ", "_")
	return normalized
}

func sentinelOneIntAttribute(attributes map[string]string, key string) int {
	value, err := strconv.Atoi(strings.TrimSpace(attributes[key]))
	if err != nil {
		return 0
	}
	return value
}

func sentinelOneParseTimestamp(value string) (time.Time, bool) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" || strings.HasPrefix(trimmed, "1970-01-01") {
		return time.Time{}, false
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05", "2006-01-02"} {
		parsed, err := time.Parse(layout, trimmed)
		if err == nil {
			return parsed.UTC(), true
		}
	}
	return time.Time{}, false
}

func sentinelOneMitigationFailedSeverity(attributes map[string]string) string {
	switch sentinelOneStatus(attributes["mitigation_status"]) {
	case "failed", "failure", "action_required", "requires_action":
		return "CRITICAL"
	default:
		return "HIGH"
	}
}

func sentinelOneExclusionSeverity(attributes map[string]string) string {
	if findingAttributeBool(attributes, "include_children", "include_parents") || sentinelOneBroadExclusionValue(attributes["value"]) || sentinelOneBroadExclusionValue(attributes["scope_path"]) {
		return "HIGH"
	}
	return "MEDIUM"
}

func sentinelOneBroadExclusionValue(value string) bool {
	normalized := strings.ToLower(strings.TrimSpace(strings.ReplaceAll(value, "\\", "/")))
	normalized = strings.TrimRight(normalized, "/")
	switch normalized {
	case "", "approved", "none":
		return false
	case "*", "/", "/applications", "/library", "/system", "/users", "/home", "/tmp", "/private/tmp", "c:", "c:/", "c:/windows", "c:/users", "c:/program files", "c:/programdata", "c:/temp":
		return true
	default:
		return strings.HasSuffix(normalized, "/*") ||
			strings.Contains(normalized, "/tmp/") ||
			strings.Contains(normalized, "/temp/") ||
			strings.Contains(normalized, "/windows/temp")
	}
}

func sentinelOneMitigationFailedSummary(attributes map[string]string, context findingProjectionContext) string {
	endpoint := firstNonEmpty(context.ResourceLabel, attributes["computer_name"], attributes["agent_name"], attributes["agent_id"], "unknown endpoint")
	threat := firstNonEmpty(attributes["threat_name"], attributes["classification"], attributes["threat_id"], "threat")
	return fmt.Sprintf("SentinelOne mitigation %s for %s on %s", firstNonEmpty(attributes["mitigation_status"], "failed"), threat, endpoint)
}

func sentinelOneAgentDetectOnlyModeSummary(attributes map[string]string, context findingProjectionContext) string {
	endpoint := firstNonEmpty(context.ResourceLabel, attributes["computer_name"], attributes["agent_id"], "unknown endpoint")
	return fmt.Sprintf("SentinelOne agent %s is in %s mitigation mode", endpoint, firstNonEmpty(attributes["mitigation_mode"], attributes["mitigation_mode_suspicious"], "detect-only"))
}

func sentinelOneProtectionControlTamperingSummary(attributes map[string]string, context findingProjectionContext) string {
	target := firstNonEmpty(context.ResourceLabel, attributes["computer_name"], attributes["agent_name"], attributes["agent_id"], "unknown endpoint")
	controlType := firstNonEmpty(sentinelOneProtectionControlType(attributes), attributes["control_type"], attributes["protection_control"], attributes["control_name"], "protection")
	state := firstNonEmpty(sentinelOneProtectionControlState(attributes), attributes["control_state"], attributes["protection_control_state"], attributes["tamper_state"], "tampered")
	return fmt.Sprintf("SentinelOne %s control is %s on %s", controlType, state, target)
}

func sentinelOneRiskyExclusionSummary(attributes map[string]string, context findingProjectionContext) string {
	exclusion := firstNonEmpty(attributes["value"], attributes["scope_path"], context.ResourceLabel, attributes["exclusion_id"], "unknown exclusion")
	if findingAttributeBool(attributes, "not_recommended") {
		return fmt.Sprintf("SentinelOne exclusion %s is not recommended", exclusion)
	}
	return fmt.Sprintf("SentinelOne exclusion %s broadens endpoint protection bypass scope", exclusion)
}
