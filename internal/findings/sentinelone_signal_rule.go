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
	sentinelOneUnresolvedThreatRuleID    = "sentinelone-unresolved-threat"
	sentinelOneMaliciousOrFilelessRuleID = "sentinelone-malicious-or-fileless-threat"
	sentinelOneInfectedEndpointRuleID    = "sentinelone-infected-endpoint"
	sentinelOneRiskyExclusionRuleID      = "sentinelone-risky-exclusion"
	sentinelOneThreatEntityType          = "sentinelone.threat"
	sentinelOneAgentEntityType           = "sentinelone.agent"
	sentinelOneExclusionEntityType       = "sentinelone.exclusion"
	sentinelOneUnresolvedThreatAction    = "unresolved_not_mitigated"
	sentinelOneMaliciousOrFilelessAction = "malicious_or_fileless_threat"
	sentinelOneInfectedEndpointAction    = "infected_endpoint"
	sentinelOneRiskyExclusionAction      = "risky_exclusion"
)

var sentinelOneControlRefs = []ports.FindingControlRef{
	{FrameworkName: "SOC 2", ControlID: "CC7.2"},
	{FrameworkName: "ISO 27001:2022", ControlID: "A.8.7"},
}

type sentinelOneFindingOptions struct {
	definition         RuleDefinition
	action             string
	primaryEntityType  string
	collectAllEntities bool
	collectAllLinkURNs bool
	severity           func(map[string]string) string
	summary            func(map[string]string, findingProjectionContext) string
	policyID           func(map[string]string) string
}

func newSentinelOneUnresolvedThreatRule() Rule {
	definition := sentinelOneRuleDefinition(
		sentinelOneUnresolvedThreatRuleID,
		"SentinelOne Unresolved Threat",
		"Detect SentinelOne threats that remain unresolved and not mitigated.",
		[]string{sentinelOneThreatEntityType},
		"finding.sentinelone_unresolved_threat",
		"HIGH",
		[]string{"sentinelone", "threat", "endpoint", "malware", "attack.execution"},
		[]string{"threat_id", "incident_status", "mitigation_status"},
		[]string{"threat_id"},
	)
	return newEventRule(eventRuleConfig{
		definition: definition,
		sourceID:   "sentinelone",
		match:      matchesSentinelOneUnresolvedThreat,
		build: func(ctx context.Context, runtime *cerebrov1.SourceRuntime, event *cerebrov1.EventEnvelope) (*ports.FindingRecord, error) {
			return buildSentinelOneFinding(ctx, runtime, event, sentinelOneFindingOptions{
				definition:         definition,
				action:             sentinelOneUnresolvedThreatAction,
				primaryEntityType:  sentinelOneThreatEntityType,
				collectAllLinkURNs: true,
				severity:           sentinelOneThreatSeverity,
				summary:            sentinelOneUnresolvedThreatSummary,
				policyID:           sentinelOneThreatPolicyID,
			})
		},
	})
}

func newSentinelOneMaliciousOrFilelessThreatRule() Rule {
	definition := sentinelOneRuleDefinition(
		sentinelOneMaliciousOrFilelessRuleID,
		"SentinelOne Malicious Or Fileless Threat",
		"Detect SentinelOne threats classified as malicious, high-risk malware, or fileless execution.",
		[]string{sentinelOneThreatEntityType},
		"finding.sentinelone_malicious_or_fileless_threat",
		"HIGH",
		[]string{"sentinelone", "threat", "endpoint", "malware", "fileless", "attack.defense-evasion"},
		[]string{"threat_id"},
		[]string{"threat_id"},
	)
	return newEventRule(eventRuleConfig{
		definition: definition,
		sourceID:   "sentinelone",
		match:      matchesSentinelOneMaliciousOrFilelessThreat,
		build: func(ctx context.Context, runtime *cerebrov1.SourceRuntime, event *cerebrov1.EventEnvelope) (*ports.FindingRecord, error) {
			return buildSentinelOneFinding(ctx, runtime, event, sentinelOneFindingOptions{
				definition:         definition,
				action:             sentinelOneMaliciousOrFilelessAction,
				primaryEntityType:  sentinelOneThreatEntityType,
				collectAllLinkURNs: true,
				severity:           sentinelOneThreatSeverity,
				summary:            sentinelOneMaliciousOrFilelessSummary,
				policyID:           sentinelOneThreatPolicyID,
			})
		},
	})
}

func newSentinelOneInfectedEndpointRule() Rule {
	definition := sentinelOneRuleDefinition(
		sentinelOneInfectedEndpointRuleID,
		"SentinelOne Infected Endpoint",
		"Detect endpoints SentinelOne reports as infected or carrying active threats in threat telemetry.",
		[]string{sentinelOneThreatEntityType},
		"finding.sentinelone_infected_endpoint",
		"CRITICAL",
		[]string{"sentinelone", "endpoint", "infected", "malware", "attack.impact"},
		[]string{"threat_id", "agent_id"},
		[]string{"agent_id", "threat_id"},
	)
	return newEventRule(eventRuleConfig{
		definition: definition,
		sourceID:   "sentinelone",
		match:      matchesSentinelOneInfectedEndpoint,
		build: func(ctx context.Context, runtime *cerebrov1.SourceRuntime, event *cerebrov1.EventEnvelope) (*ports.FindingRecord, error) {
			return buildSentinelOneFinding(ctx, runtime, event, sentinelOneFindingOptions{
				definition:         definition,
				action:             sentinelOneInfectedEndpointAction,
				primaryEntityType:  sentinelOneAgentEntityType,
				collectAllLinkURNs: true,
				severity:           func(map[string]string) string { return "CRITICAL" },
				summary:            sentinelOneInfectedEndpointSummary,
				policyID:           sentinelOneEndpointPolicyID,
			})
		},
	})
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
	)
	return newEventRule(eventRuleConfig{
		definition: definition,
		sourceID:   "sentinelone",
		match:      matchesSentinelOneRiskyExclusion,
		build: func(ctx context.Context, runtime *cerebrov1.SourceRuntime, event *cerebrov1.EventEnvelope) (*ports.FindingRecord, error) {
			return buildSentinelOneFinding(ctx, runtime, event, sentinelOneFindingOptions{
				definition:         definition,
				action:             sentinelOneRiskyExclusionAction,
				primaryEntityType:  sentinelOneExclusionEntityType,
				collectAllEntities: true,
				severity:           sentinelOneExclusionSeverity,
				summary:            sentinelOneRiskyExclusionSummary,
				policyID: func(attributes map[string]string) string {
					return firstNonEmpty(attributes["exclusion_id"], attributes["value"])
				},
			})
		},
	})
}

func sentinelOneRuleDefinition(id, name, description string, eventKinds []string, outputKind, severity string, tags, requiredAttributes, fingerprintFields []string) RuleDefinition {
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
		FalsePositives:     []string{"Approved malware test, known benign tool, or approved SentinelOne exclusion reviewed by security."},
		Runbook:            "Review SentinelOne threat details, endpoint state, mitigation status, and any related exclusions before containment or closure.",
		RequiredAttributes: requiredAttributes,
		FingerprintFields:  fingerprintFields,
		ControlRefs:        sentinelOneControlRefs,
	}
}

func buildSentinelOneFinding(ctx context.Context, runtime *cerebrov1.SourceRuntime, event *cerebrov1.EventEnvelope, options sentinelOneFindingOptions) (*ports.FindingRecord, error) {
	projectedContext, err := buildFindingProjectionContext(ctx, event, findingProjectionContextOptions{
		PrimaryEntityType:  options.primaryEntityType,
		CollectAllEntities: options.collectAllEntities,
		CollectAllLinkURNs: options.collectAllLinkURNs,
		ResourceFallbacks: []string{
			event.GetAttributes()["computer_name"],
			event.GetAttributes()["agent_name"],
			event.GetAttributes()["threat_name"],
			event.GetAttributes()["value"],
			event.GetAttributes()["threat_id"],
			event.GetAttributes()["agent_id"],
			event.GetAttributes()["exclusion_id"],
		},
	})
	if err != nil {
		return nil, fmt.Errorf("project SentinelOne finding context for event %q: %w", event.GetId(), err)
	}
	attributes := eventAttributes(event)
	policyID := firstNonEmpty(options.policyID(attributes), event.GetId())
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
		"source_runtime_id":    strings.TrimSpace(runtime.GetId()),
	}
	for key, value := range attributes {
		if _, exists := findingAttributes[key]; !exists {
			findingAttributes[key] = strings.TrimSpace(value)
		}
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
	fingerprint := hashFindingFingerprint(options.definition.ID, event.GetTenantId(), runtime.GetId(), policyID)
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
		PolicyName:        firstNonEmpty(attributes["threat_name"], attributes["value"], attributes["classification"], projectedContext.ResourceLabel),
		CheckID:           options.definition.ID,
		CheckName:         options.definition.Name,
		ControlRefs:       cloneFindingControlRefs(options.definition.ControlRefs),
		Attributes:        findingAttributes,
		FirstObservedAt:   observedAt,
		LastObservedAt:    observedAt,
	}, nil
}

func matchesSentinelOneUnresolvedThreat(event *cerebrov1.EventEnvelope) bool {
	if !eventKindMatcher(sentinelOneThreatEntityType)(event) || !hasRequiredAttributes(event, "threat_id") {
		return false
	}
	attributes := eventAttributes(event)
	return !sentinelOneFalsePositive(attributes) &&
		sentinelOneThreatUnresolved(attributes["incident_status"]) &&
		sentinelOneThreatNotMitigated(attributes["mitigation_status"])
}

func matchesSentinelOneMaliciousOrFilelessThreat(event *cerebrov1.EventEnvelope) bool {
	if !eventKindMatcher(sentinelOneThreatEntityType)(event) || !hasRequiredAttributes(event, "threat_id") {
		return false
	}
	attributes := eventAttributes(event)
	return !sentinelOneFalsePositive(attributes) && sentinelOneThreatIsHighRisk(attributes)
}

func matchesSentinelOneInfectedEndpoint(event *cerebrov1.EventEnvelope) bool {
	if !eventKindMatcher(sentinelOneThreatEntityType)(event) || !hasRequiredAttributes(event, "threat_id") {
		return false
	}
	attributes := eventAttributes(event)
	return !sentinelOneFalsePositive(attributes) &&
		(findingAttributeBool(attributes, "is_infected", "infected") || sentinelOneIntAttribute(attributes, "active_threats") > 0)
}

func matchesSentinelOneRiskyExclusion(event *cerebrov1.EventEnvelope) bool {
	if !eventKindMatcher(sentinelOneExclusionEntityType)(event) || !hasRequiredAttributes(event, "exclusion_id") {
		return false
	}
	attributes := eventAttributes(event)
	return findingAttributeBool(attributes, "not_recommended") ||
		findingAttributeBool(attributes, "include_children", "include_parents") ||
		sentinelOneBroadExclusionValue(attributes["value"])
}

func sentinelOneThreatPolicyID(attributes map[string]string) string {
	return firstNonEmpty(attributes["threat_id"], attributes["sha256"], attributes["threat_name"])
}

func sentinelOneEndpointPolicyID(attributes map[string]string) string {
	return strings.Join(nonEmptyValues(attributes["agent_id"], attributes["agent_uuid"], attributes["threat_id"]), ":")
}

func nonEmptyValues(values ...string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func sentinelOneFalsePositive(attributes map[string]string) bool {
	value := strings.ToLower(strings.Join([]string{
		attributes["analyst_verdict"],
		attributes["classification"],
		attributes["mitigation_status"],
	}, " "))
	return containsAny(value, "false_positive", "false positive", "benign", "whitelisted")
}

func sentinelOneThreatUnresolved(value string) bool {
	switch sentinelOneStatus(value) {
	case "unresolved", "open", "active", "in_progress", "pending":
		return true
	default:
		return false
	}
}

func sentinelOneThreatNotMitigated(value string) bool {
	switch sentinelOneStatus(value) {
	case "not_mitigated", "unmitigated", "failed", "partial", "in_progress", "pending", "action_required":
		return true
	default:
		return false
	}
}

func sentinelOneThreatIsHighRisk(attributes map[string]string) bool {
	if findingAttributeBool(attributes, "is_fileless") {
		return true
	}
	value := strings.ToLower(strings.Join([]string{
		attributes["classification"],
		attributes["confidence_level"],
		attributes["detection_type"],
		attributes["threat_name"],
		attributes["indicator_categories"],
	}, " "))
	return containsAny(value, "malicious", "malware", "infostealer", "ransom", "trojan", "backdoor", "credential", "stealer", "fileless")
}

func sentinelOneThreatSeverity(attributes map[string]string) string {
	value := strings.ToLower(strings.Join([]string{
		attributes["classification"],
		attributes["confidence_level"],
		attributes["threat_name"],
		attributes["indicator_categories"],
	}, " "))
	if findingAttributeBool(attributes, "is_infected", "infected", "is_fileless") || containsAny(value, "ransom", "infostealer", "stealer") {
		return "CRITICAL"
	}
	if containsAny(value, "malicious", "malware", "trojan", "backdoor", "credential") {
		return "HIGH"
	}
	return "HIGH"
}

func sentinelOneExclusionSeverity(attributes map[string]string) string {
	if findingAttributeBool(attributes, "include_children", "include_parents") || sentinelOneBroadExclusionValue(attributes["value"]) {
		return "HIGH"
	}
	return "MEDIUM"
}

func sentinelOneBroadExclusionValue(value string) bool {
	normalized := strings.ToLower(strings.TrimSpace(strings.ReplaceAll(value, "\\", "/")))
	switch normalized {
	case "", "*", "/", "/applications", "/library", "/users", "c:/", "c:", "c:/*":
		return normalized != ""
	default:
		return strings.HasSuffix(normalized, "/*") || strings.Contains(normalized, "/tmp/")
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

func sentinelOneUnresolvedThreatSummary(attributes map[string]string, context findingProjectionContext) string {
	threat := firstNonEmpty(attributes["threat_name"], attributes["classification"], attributes["threat_id"], "unknown threat")
	endpoint := firstNonEmpty(attributes["computer_name"], attributes["agent_name"], attributes["agent_id"], context.ResourceLabel, "unknown endpoint")
	return fmt.Sprintf("SentinelOne threat %s remains %s/%s on %s", threat, firstNonEmpty(attributes["incident_status"], "unresolved"), firstNonEmpty(attributes["mitigation_status"], "not_mitigated"), endpoint)
}

func sentinelOneMaliciousOrFilelessSummary(attributes map[string]string, context findingProjectionContext) string {
	threat := firstNonEmpty(attributes["threat_name"], attributes["classification"], attributes["threat_id"], "unknown threat")
	endpoint := firstNonEmpty(attributes["computer_name"], attributes["agent_name"], attributes["agent_id"], context.ResourceLabel, "unknown endpoint")
	return fmt.Sprintf("SentinelOne reported high-risk threat %s on %s", threat, endpoint)
}

func sentinelOneInfectedEndpointSummary(attributes map[string]string, context findingProjectionContext) string {
	endpoint := firstNonEmpty(context.ResourceLabel, attributes["computer_name"], attributes["agent_name"], attributes["agent_id"], "unknown endpoint")
	threat := firstNonEmpty(attributes["threat_name"], attributes["classification"], attributes["threat_id"], "unknown threat")
	return fmt.Sprintf("SentinelOne reports infected endpoint %s for threat %s", endpoint, threat)
}

func sentinelOneRiskyExclusionSummary(attributes map[string]string, context findingProjectionContext) string {
	exclusion := firstNonEmpty(attributes["value"], context.ResourceLabel, attributes["exclusion_id"], "unknown exclusion")
	if findingAttributeBool(attributes, "not_recommended") {
		return fmt.Sprintf("SentinelOne exclusion %s is not recommended", exclusion)
	}
	return fmt.Sprintf("SentinelOne exclusion %s broadens endpoint protection bypass scope", exclusion)
}
