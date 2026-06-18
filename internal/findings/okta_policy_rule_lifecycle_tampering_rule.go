package findings

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

const (
	oktaPolicyRuleLifecycleTamperingRuleID    = "identity-okta-policy-rule-lifecycle-tampering"
	oktaPolicyRuleLifecycleTamperingTitle     = "Okta Policy Rule Lifecycle Tampering"
	oktaPolicyRuleLifecycleTamperingSeverity  = "HIGH"
	oktaPolicyRuleLifecycleTamperingStatus    = "open"
	oktaPolicyRuleLifecycleTamperingCheckID   = "identity-okta-policy-rule-lifecycle-tampering-30d"
	oktaPolicyRuleLifecycleTamperingCheckName = "Okta Policy Rule Lifecycle Tampering (30 days)"
)

var (
	oktaPolicyRuleLifecycleTamperingControlRefs = []ports.FindingControlRef{
		{
			FrameworkName: "SOC 2",
			ControlID:     "CC6.2",
		},
		{
			FrameworkName: "ISO 27001:2022",
			ControlID:     "A.8.9",
		},
	}
)

type oktaPolicyRuleLifecycleTamperingRule struct {
	Rule
	definition RuleDefinition
}

var oktaPolicyRuleLifecycleTamperingDefinition = RuleDefinition{
	ID:                 oktaPolicyRuleLifecycleTamperingRuleID,
	Name:               oktaPolicyRuleLifecycleTamperingTitle,
	Description:        "Detect Okta policy rules that remain deactivated, disabled, or inactive in projected identity state.",
	SourceID:           "okta",
	EventKinds:         []string{"okta.policy_rule"},
	OutputKind:         "finding.okta_policy_rule_lifecycle_tampering",
	Severity:           oktaPolicyRuleLifecycleTamperingSeverity,
	Status:             oktaPolicyRuleLifecycleTamperingStatus,
	Maturity:           "test",
	Tags:               []string{"okta", "identity", "policy", "defense-evasion", "attack.t1562"},
	References:         []string{"https://help.okta.com/en-us/content/topics/reports/reports_syslog.htm"},
	FalsePositives:     []string{"Authorized identity platform administration during approved change windows."},
	Runbook:            "Review actor, target policy rule, administrative change ticket, and adjacent identity events before reverting or escalating.",
	RequiredAttributes: []string{"policy_id", "policy_rule_id", "status"},
	FingerprintFields:  []string{"okta_policy_rule_urn"},
	ControlRefs:        oktaPolicyRuleLifecycleTamperingControlRefs,
	Lifecycle:          Lifecycle{Kind: LifecycleDurableState, Anchor: AnchorGraphAnchored},
}

var oktaPolicyRuleLifecycleTamperingKindMatcher = eventKindMatcher(oktaPolicyRuleLifecycleTamperingDefinition.EventKinds...)

func newOktaPolicyRuleLifecycleTamperingRule() Rule {
	rule := newEventRule(eventRuleConfig{
		definition: oktaPolicyRuleLifecycleTamperingDefinition,
		match:      matchesOktaPolicyRuleLifecycleTampering,
		build: func(ctx context.Context, runtime *cerebrov1.SourceRuntime, event *cerebrov1.EventEnvelope) (*ports.FindingRecord, error) {
			return oktaPolicyRuleLifecycleTamperingFinding(ctx, event, runtime.GetId())
		},
	})
	return &oktaPolicyRuleLifecycleTamperingRule{
		Rule:       rule,
		definition: oktaPolicyRuleLifecycleTamperingDefinition,
	}
}

func (r *oktaPolicyRuleLifecycleTamperingRule) RuleMetadata() RuleDefinition {
	if r == nil {
		return RuleDefinition{}
	}
	return cloneRuleDefinition(r.definition)
}

func (r *oktaPolicyRuleLifecycleTamperingRule) OpenAnchor(attributes map[string]string) string {
	return oktaPolicyRuleLifecycleTamperingAnchor(attributes)
}

func (r *oktaPolicyRuleLifecycleTamperingRule) CloseOnEvent(event Event) (string, bool) {
	if !oktaPolicyRuleLifecycleTamperingKindMatcher(event) || !hasRequiredAttributes(event, oktaPolicyRuleLifecycleTamperingDefinition.RequiredAttributes...) {
		return "", false
	}
	attributes := eventAttributes(event)
	if !oktaPolicyRuleLifecycleTamperingRestored(attributes) {
		return "", false
	}
	anchor := oktaPolicyRuleLifecycleTamperingAnchor(oktaPolicyRuleLifecycleTamperingAttributesForEvent(event))
	return anchor, anchor != ""
}

func matchesOktaPolicyRuleLifecycleTampering(event *cerebrov1.EventEnvelope) bool {
	if !oktaPolicyRuleLifecycleTamperingKindMatcher(event) || !hasRequiredAttributes(event, oktaPolicyRuleLifecycleTamperingDefinition.RequiredAttributes...) {
		return false
	}
	return oktaPolicyRuleLifecycleTamperingOpen(eventAttributes(event))
}

func oktaPolicyRuleLifecycleTamperingFinding(ctx context.Context, event *cerebrov1.EventEnvelope, runtimeID string) (*ports.FindingRecord, error) {
	projectedContext, err := buildFindingProjectionContext(ctx, event, findingProjectionContextOptions{
		PrimaryRelations:  []string{"acted_on"},
		ActorFallbacks:    []string{event.GetAttributes()["actor_alternate_id"], event.GetAttributes()["actor_display_name"], event.GetAttributes()["actor_id"]},
		ResourceFallbacks: []string{event.GetAttributes()["resource_id"], event.GetAttributes()["resource_type"]},
	})
	if err != nil {
		return nil, fmt.Errorf("project finding context for event %q: %w", event.GetId(), err)
	}
	eventAttrs := event.GetAttributes()
	policyID := oktaPolicyRuleLifecycleTamperingPolicyID(eventAttrs)
	policyRuleID := oktaPolicyRuleLifecycleTamperingPolicyRuleID(eventAttrs)
	policyName := firstNonEmpty(eventAttrs["name"], eventAttrs["policy_rule_name"], projectedContext.ResourceLabel, policyRuleID, policyID)
	observedPolicyIDs := []string{}
	if policyID != "" {
		observedPolicyIDs = append(observedPolicyIDs, policyID)
	}
	policyRuleURN := oktaPolicyRuleLifecycleTamperingURN(event.GetTenantId(), eventAttrs, projectedContext.PrimaryResourceURN)
	if policyRuleURN == "" {
		return nil, nil
	}
	policyRuleState := oktaPolicyRuleLifecycleTamperingState(eventAttrs)
	attributes := map[string]string{
		"event_id":             strings.TrimSpace(event.GetId()),
		"event_type":           strings.TrimSpace(eventAttrs["event_type"]),
		"okta_policy_rule_urn": policyRuleURN,
		"outcome_result":       strings.TrimSpace(eventAttrs["outcome_result"]),
		"policy_id":            policyID,
		"policy_rule_id":       policyRuleID,
		"policy_type":          strings.TrimSpace(eventAttrs["policy_type"]),
		"policy_rule_name":     firstNonEmpty(eventAttrs["name"], eventAttrs["policy_rule_name"]),
		"policy_rule_status":   policyRuleState,
		"priority":             strings.TrimSpace(eventAttrs["priority"]),
		"system":               strings.TrimSpace(eventAttrs["system"]),
		"source_runtime_id":    strings.TrimSpace(eventAttrs[ports.EventAttributeSourceRuntimeID]),
		"primary_actor_urn":    projectedContext.PrimaryActorURN,
		"primary_resource_urn": policyRuleURN,
	}
	for key, value := range oktaPolicyRuleLifecycleTamperingDefinition.AttributeMap() {
		attributes["rule_"+key] = value
	}
	trimEmptyAttributes(attributes)
	observedAt := time.Time{}
	if timestamp := event.GetOccurredAt(); timestamp != nil {
		observedAt = timestamp.AsTime().UTC()
	}
	tenantID := strings.TrimSpace(event.GetTenantId())
	normalizedRuntimeID := strings.TrimSpace(runtimeID)
	fingerprint := hashFindingFingerprint(oktaPolicyRuleLifecycleTamperingRuleID, policyRuleURN)
	return &ports.FindingRecord{
		ID:                fingerprint,
		Fingerprint:       fingerprint,
		TenantID:          tenantID,
		RuntimeID:         normalizedRuntimeID,
		RuleID:            oktaPolicyRuleLifecycleTamperingRuleID,
		Title:             oktaPolicyRuleLifecycleTamperingTitle,
		Severity:          oktaPolicyRuleLifecycleTamperingSeverity,
		Status:            oktaPolicyRuleLifecycleTamperingStatus,
		Summary:           oktaPolicyRuleLifecycleTamperingSummary(policyName, policyRuleState),
		ResourceURNs:      deduplicateStrings(append([]string{policyRuleURN}, projectedContext.ResourceURNs...)),
		EventIDs:          []string{strings.TrimSpace(event.GetId())},
		ObservedPolicyIDs: observedPolicyIDs,
		PolicyID:          policyID,
		PolicyName:        policyName,
		CheckID:           oktaPolicyRuleLifecycleTamperingCheckID,
		CheckName:         oktaPolicyRuleLifecycleTamperingCheckName,
		ControlRefs:       cloneFindingControlRefs(oktaPolicyRuleLifecycleTamperingDefinition.ControlRefs),
		Attributes:        attributes,
		FirstObservedAt:   observedAt,
		LastObservedAt:    observedAt,
	}, nil
}

func oktaPolicyRuleLifecycleTamperingOpen(attributes map[string]string) bool {
	return oktaPolicyRuleLifecycleTamperingStateIsInactive(oktaPolicyRuleLifecycleTamperingState(attributes))
}

func oktaPolicyRuleLifecycleTamperingRestored(attributes map[string]string) bool {
	return oktaPolicyRuleLifecycleTamperingStateIsActive(oktaPolicyRuleLifecycleTamperingState(attributes))
}

func oktaPolicyRuleLifecycleTamperingState(attributes map[string]string) string {
	for _, key := range []string{
		"okta_policy_rule_status",
		"policy_rule_status",
		"policy_rule_lifecycle_status",
		"lifecycle_status",
		"rule_status",
		"status",
		"state",
	} {
		if value := strings.ToLower(strings.TrimSpace(attributes[key])); value != "" {
			return value
		}
	}
	if parseBoolAttribute(attributes, "deleted") {
		return "deleted"
	}
	if parseBoolAttribute(attributes, "deactivated") || parseBoolAttribute(attributes, "disabled") {
		return "deactivated"
	}
	if active, ok := parseOptionalBoolAttribute(attributes, "active"); ok {
		if active {
			return "active"
		}
		return "deactivated"
	}
	return ""
}

func parseBoolAttribute(attributes map[string]string, key string) bool {
	value, ok := parseOptionalBoolAttribute(attributes, key)
	return ok && value
}

func parseOptionalBoolAttribute(attributes map[string]string, key string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(attributes[key])) {
	case "1", "t", "true", "yes", "y", "enabled", "on", "active":
		return true, true
	case "0", "f", "false", "no", "n", "disabled", "off", "inactive":
		return false, true
	default:
		return false, false
	}
}

func oktaPolicyRuleLifecycleTamperingStateIsInactive(state string) bool {
	switch strings.ToLower(strings.TrimSpace(state)) {
	case "deactivate", "deactivated", "disabled", "inactive":
		return true
	default:
		return false
	}
}

func oktaPolicyRuleLifecycleTamperingStateIsActive(state string) bool {
	switch strings.ToLower(strings.TrimSpace(state)) {
	case "active", "activate", "activated", "enabled", "enable":
		return true
	default:
		return false
	}
}

func oktaPolicyRuleLifecycleTamperingPolicyID(attributes map[string]string) string {
	return firstNonEmpty(attributes["policy_id"], attributes["policy"])
}

func oktaPolicyRuleLifecycleTamperingPolicyRuleID(attributes map[string]string) string {
	return firstNonEmpty(attributes["policy_rule_id"], attributes["rule_id"], attributes["resource_id"])
}

func oktaPolicyRuleLifecycleTamperingURN(tenantID string, attributes map[string]string, projectedResourceURN string) string {
	policyID := oktaPolicyRuleLifecycleTamperingPolicyID(attributes)
	policyRuleID := oktaPolicyRuleLifecycleTamperingPolicyRuleID(attributes)
	if strings.TrimSpace(policyID) != "" && strings.TrimSpace(policyRuleID) != "" && strings.TrimSpace(tenantID) != "" {
		return fmt.Sprintf("urn:cerebro:%s:okta_policy_rule:%s:%s", strings.TrimSpace(tenantID), strings.TrimSpace(policyID), strings.TrimSpace(policyRuleID))
	}
	for _, candidate := range []string{
		attributes["okta_policy_rule_urn"],
		attributes["policy_rule_urn"],
		attributes["primary_resource_urn"],
		projectedResourceURN,
	} {
		candidate = strings.TrimSpace(candidate)
		if oktaPolicyRuleLifecycleTamperingURNLooksLikePolicyRule(candidate) {
			return candidate
		}
	}
	return ""
}

func oktaPolicyRuleLifecycleTamperingURNLooksLikePolicyRule(candidate string) bool {
	candidate = strings.ToLower(strings.TrimSpace(candidate))
	return strings.Contains(candidate, ":okta_policy_rule:")
}

func oktaPolicyRuleLifecycleTamperingAnchor(attributes map[string]string) string {
	return identityCounterEventAnchor(map[string]string{
		"okta_policy_rule_urn": strings.TrimSpace(attributes["okta_policy_rule_urn"]),
	}, "okta_policy_rule_urn")
}

func oktaPolicyRuleLifecycleTamperingAttributesForEvent(event Event) map[string]string {
	attributes := cloneStringMap(eventAttributes(event))
	if attributes == nil {
		attributes = map[string]string{}
	}
	if value := oktaPolicyRuleLifecycleTamperingURN(event.GetTenantId(), attributes, ""); value != "" {
		attributes["okta_policy_rule_urn"] = value
	}
	if value := oktaPolicyRuleLifecycleTamperingPolicyID(attributes); value != "" {
		attributes["policy_id"] = value
	}
	if value := oktaPolicyRuleLifecycleTamperingPolicyRuleID(attributes); value != "" {
		attributes["policy_rule_id"] = value
	}
	return attributes
}

func oktaPolicyRuleLifecycleTamperingSummary(policyRuleName string, state string) string {
	name := firstNonEmpty(policyRuleName, "unknown policy rule")
	if normalizedState := strings.ToUpper(strings.TrimSpace(state)); normalizedState != "" {
		return fmt.Sprintf("Okta policy rule %s is %s", name, normalizedState)
	}
	return fmt.Sprintf("Okta policy rule %s is inactive", name)
}

func entityLabel(entity *ports.ProjectedEntity, fallbacks ...string) string {
	if entity != nil && strings.TrimSpace(entity.Label) != "" {
		return strings.TrimSpace(entity.Label)
	}
	for _, fallback := range fallbacks {
		if strings.TrimSpace(fallback) != "" {
			return strings.TrimSpace(fallback)
		}
	}
	return ""
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func trimEmptyAttributes(attributes map[string]string) {
	for key, value := range attributes {
		if strings.TrimSpace(value) == "" {
			delete(attributes, key)
		}
	}
}

func cloneFindingControlRefs(values []ports.FindingControlRef) []ports.FindingControlRef {
	if len(values) == 0 {
		return nil
	}
	cloned := make([]ports.FindingControlRef, 0, len(values))
	for _, value := range values {
		frameworkName := strings.TrimSpace(value.FrameworkName)
		controlID := strings.TrimSpace(value.ControlID)
		if frameworkName == "" || controlID == "" {
			continue
		}
		cloned = append(cloned, ports.FindingControlRef{
			FrameworkName: frameworkName,
			ControlID:     controlID,
		})
	}
	return cloned
}

func hashFindingFingerprint(parts ...string) string {
	hash := sha256.New()
	for _, part := range parts {
		_, _ = hash.Write([]byte(strings.TrimSpace(part)))
		_, _ = hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil))
}
