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
	oktaPolicyRuleLifecycleTamperingEventTypes = map[string]struct{}{
		"policy.rule.update":     {},
		"policy.rule.deactivate": {},
		"policy.rule.delete":     {},
	}
	oktaPolicyRuleLifecycleTamperingOutcomes = map[string]struct{}{
		"success": {},
		"allow":   {},
		"allowed": {},
	}
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

var oktaPolicyRuleLifecycleTamperingDefinition = RuleDefinition{
	ID:                 oktaPolicyRuleLifecycleTamperingRuleID,
	Name:               oktaPolicyRuleLifecycleTamperingTitle,
	Description:        "Detect successful Okta policy rule update, deactivate, or delete events replayed from one source runtime.",
	SourceID:           "okta",
	EventKinds:         []string{"okta.audit"},
	OutputKind:         "finding.okta_policy_rule_lifecycle_tampering",
	Severity:           oktaPolicyRuleLifecycleTamperingSeverity,
	Status:             oktaPolicyRuleLifecycleTamperingStatus,
	Maturity:           "test",
	Tags:               []string{"okta", "identity", "policy", "defense-evasion", "attack.t1562"},
	References:         []string{"https://help.okta.com/en-us/content/topics/reports/reports_syslog.htm"},
	FalsePositives:     []string{"Authorized identity platform administration during approved change windows."},
	Runbook:            "Review actor, target policy rule, administrative change ticket, and adjacent identity events before reverting or escalating.",
	RequiredAttributes: []string{"event_type", "resource_id"},
	FingerprintFields:  []string{"event_id"},
	ControlRefs:        oktaPolicyRuleLifecycleTamperingControlRefs,
}

var oktaAuditKindMatcher = eventKindMatcher(oktaPolicyRuleLifecycleTamperingDefinition.EventKinds...)

func newOktaPolicyRuleLifecycleTamperingRule() Rule {
	return newEventRule(eventRuleConfig{
		definition: oktaPolicyRuleLifecycleTamperingDefinition,
		match:      matchesOktaPolicyRuleLifecycleTampering,
		build: func(ctx context.Context, runtime *cerebrov1.SourceRuntime, event *cerebrov1.EventEnvelope) (*ports.FindingRecord, error) {
			return oktaPolicyRuleLifecycleTamperingFinding(ctx, event, runtime.GetId())
		},
	})
}

func matchesOktaPolicyRuleLifecycleTampering(event *cerebrov1.EventEnvelope) bool {
	if !oktaAuditKindMatcher(event) || !hasRequiredAttributes(event, "event_type") {
		return false
	}
	attributes := eventAttributes(event)
	eventType := strings.ToLower(strings.TrimSpace(attributes["event_type"]))
	if _, ok := oktaPolicyRuleLifecycleTamperingEventTypes[eventType]; !ok {
		return false
	}
	outcome := strings.ToLower(strings.TrimSpace(attributes["outcome_result"]))
	if outcome == "" {
		outcome = "success"
	}
	_, ok := oktaPolicyRuleLifecycleTamperingOutcomes[outcome]
	return ok
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
	policyID := strings.TrimSpace(event.GetAttributes()["resource_id"])
	policyName := firstNonEmpty(projectedContext.ResourceLabel, policyID)
	observedPolicyIDs := []string{}
	if policyID != "" {
		observedPolicyIDs = append(observedPolicyIDs, policyID)
	}
	attributes := map[string]string{
		"event_id":             strings.TrimSpace(event.GetId()),
		"event_type":           strings.TrimSpace(event.GetAttributes()["event_type"]),
		"outcome_result":       strings.TrimSpace(event.GetAttributes()["outcome_result"]),
		"source_runtime_id":    strings.TrimSpace(event.GetAttributes()[ports.EventAttributeSourceRuntimeID]),
		"primary_actor_urn":    projectedContext.PrimaryActorURN,
		"primary_resource_urn": projectedContext.PrimaryResourceURN,
	}
	for key, value := range oktaPolicyRuleLifecycleTamperingDefinition.AttributeMap() {
		attributes["rule_"+key] = value
	}
	trimEmptyAttributes(attributes)
	observedAt := time.Time{}
	if timestamp := event.GetOccurredAt(); timestamp != nil {
		observedAt = timestamp.AsTime().UTC()
	}
	fingerprint := hashFindingFingerprint(oktaPolicyRuleLifecycleTamperingRuleID, event.GetId())
	return &ports.FindingRecord{
		ID:                fingerprint,
		Fingerprint:       fingerprint,
		TenantID:          strings.TrimSpace(event.GetTenantId()),
		RuntimeID:         strings.TrimSpace(runtimeID),
		RuleID:            oktaPolicyRuleLifecycleTamperingRuleID,
		Title:             oktaPolicyRuleLifecycleTamperingTitle,
		Severity:          oktaPolicyRuleLifecycleTamperingSeverity,
		Status:            oktaPolicyRuleLifecycleTamperingStatus,
		Summary:           findingSummary(event, projectedContext.ActorLabel, projectedContext.ResourceLabel),
		ResourceURNs:      projectedContext.ResourceURNs,
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

func findingSummary(event *cerebrov1.EventEnvelope, actorLabel string, resourceLabel string) string {
	eventType := strings.TrimSpace(event.GetAttributes()["event_type"])
	actor := firstNonEmpty(actorLabel, event.GetAttributes()["actor_alternate_id"], event.GetAttributes()["actor_display_name"], event.GetAttributes()["actor_id"], "unknown actor")
	resource := firstNonEmpty(resourceLabel, event.GetAttributes()["resource_id"], event.GetAttributes()["resource_type"], "unknown resource")
	return fmt.Sprintf("%s performed %s on %s", actor, eventType, resource)
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
