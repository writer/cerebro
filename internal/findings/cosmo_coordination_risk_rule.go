package findings

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

const (
	cosmoCoordinationActiveRiskRuleID    = "cosmo-coordination-active-risk"
	cosmoCoordinationActiveRiskTitle     = "Cosmo Agent Memory Coordination Risk Active"
	cosmoCoordinationActiveRiskSeverity  = "HIGH"
	cosmoCoordinationActiveRiskStatus    = "open"
	cosmoCoordinationActiveRiskCheckID   = "cosmo-coordination-active-risk-current"
	cosmoCoordinationActiveRiskCheckName = "Cosmo Agent Memory Coordination Risk Active (current state)"
)

var cosmoCoordinationActiveRiskControlRefs = []ports.FindingControlRef{
	{FrameworkName: "SOC 2", ControlID: "CC7.1"},
	{FrameworkName: "ISO 27001:2022", ControlID: "A.5.7"},
}

type cosmoCoordinationActiveRiskRule struct {
	Rule
	definition RuleDefinition
}

var cosmoCoordinationActiveRiskDefinition = RuleDefinition{
	ID:                 cosmoCoordinationActiveRiskRuleID,
	Name:               cosmoCoordinationActiveRiskTitle,
	Description:        "Detect Cosmo agent-memory facts that record an active coordination-risk pattern in a session, so a durable finding tracks the risky condition until the agent memory records it resolved.",
	SourceID:           "cosmo",
	EventKinds:         []string{"cosmo.fact"},
	OutputKind:         "finding.cosmo_coordination_active_risk",
	Severity:           cosmoCoordinationActiveRiskSeverity,
	Status:             cosmoCoordinationActiveRiskStatus,
	Maturity:           "test",
	Tags:               []string{"cosmo", "agent-memory", "coordination", "posture"},
	References:         []string{"https://github.com/writer/cerebro/blob/main/docs/SOURCE_RUNTIME_GUIDE.md"},
	FalsePositives:     []string{"Memory facts that record a historical coordination-risk pattern that has already been remediated but were not updated to a resolved state in agent memory."},
	Runbook:            "Review the coordination-risk pattern recorded for the affected session and remediate the underlying risky coordination; the finding resolves automatically once the agent memory records the fact as resolved.",
	RequiredAttributes: []string{"key"},
	FingerprintFields:  []string{"cosmo_risk_urn"},
	ControlRefs:        cosmoCoordinationActiveRiskControlRefs,
	Lifecycle:          Lifecycle{Kind: LifecycleDurableState, Anchor: AnchorSourceState},
}

var cosmoCoordinationActiveRiskKindMatcher = eventKindMatcher(cosmoCoordinationActiveRiskDefinition.EventKinds...)

func newCosmoCoordinationActiveRiskRule() Rule {
	rule := newEventRule(eventRuleConfig{
		definition: cosmoCoordinationActiveRiskDefinition,
		match:      matchesCosmoCoordinationActiveRisk,
		build: func(ctx context.Context, runtime *cerebrov1.SourceRuntime, event *cerebrov1.EventEnvelope) (*ports.FindingRecord, error) {
			return cosmoCoordinationActiveRiskFinding(event, runtime.GetId())
		},
	})
	return &cosmoCoordinationActiveRiskRule{
		Rule:       rule,
		definition: cosmoCoordinationActiveRiskDefinition,
	}
}

func (r *cosmoCoordinationActiveRiskRule) RuleMetadata() RuleDefinition {
	if r == nil {
		return RuleDefinition{}
	}
	return cloneRuleDefinition(r.definition)
}

func (r *cosmoCoordinationActiveRiskRule) OpenAnchor(attributes map[string]string) string {
	return cosmoCoordinationActiveRiskAnchor(attributes)
}

// CloseOnEvent resolves an open finding when a later memory fact records the
// same coordination-risk pattern as resolved, so remediated coordination risk
// does not leave stale open findings.
func (r *cosmoCoordinationActiveRiskRule) CloseOnEvent(event Event) (string, bool) {
	if !cosmoCoordinationActiveRiskKindMatcher(event) || !hasRequiredAttributes(event, cosmoCoordinationActiveRiskDefinition.RequiredAttributes...) {
		return "", false
	}
	if cosmoFactRiskState(event) != "resolved" {
		return "", false
	}
	riskURN := cosmoCoordinationRiskURN(event.GetTenantId(), cosmoEventRuntimeID(event, ""), cosmoFactSessionID(event), cosmoFactKey(event))
	anchor := cosmoCoordinationActiveRiskAnchor(map[string]string{"cosmo_risk_urn": riskURN})
	return anchor, anchor != ""
}

func matchesCosmoCoordinationActiveRisk(event *cerebrov1.EventEnvelope) bool {
	if !cosmoCoordinationActiveRiskKindMatcher(event) || !hasRequiredAttributes(event, cosmoCoordinationActiveRiskDefinition.RequiredAttributes...) {
		return false
	}
	return cosmoFactRiskState(event) == "active"
}

func cosmoCoordinationActiveRiskFinding(event *cerebrov1.EventEnvelope, runtimeID string) (*ports.FindingRecord, error) {
	tenantID := strings.TrimSpace(event.GetTenantId())
	factKey := cosmoFactKey(event)
	sessionID := cosmoFactSessionID(event)
	sourceRuntimeID := cosmoEventRuntimeID(event, runtimeID)
	riskURN := cosmoCoordinationRiskURN(tenantID, sourceRuntimeID, sessionID, factKey)
	if riskURN == "" {
		return nil, nil
	}
	factURN := cosmoFactResourceURN(tenantID, factKey)
	resourceURNs := []string{factURN}
	if sessionURN := cosmoSessionResourceURN(tenantID, sessionID); sessionURN != "" {
		resourceURNs = append(resourceURNs, sessionURN)
	}
	attrs := event.GetAttributes()
	attributes := map[string]string{
		"cosmo_risk_urn":       riskURN,
		"fact_key":             factKey,
		"session_id":           sessionID,
		"category":             cosmoFactCategory(event),
		"risk_state":           "active",
		"risk_reason":          firstNonEmpty(strings.TrimSpace(attrs["risk_reason"]), cosmoFactPayloadString(event, "risk_reason", "reason", "summary")),
		"risk_severity":        firstNonEmpty(strings.TrimSpace(attrs["risk_severity"]), cosmoFactPayloadString(event, "risk_severity", "severity")),
		"event_id":             strings.TrimSpace(event.GetId()),
		"source_runtime_id":    sourceRuntimeID,
		"primary_resource_urn": factURN,
	}
	for key, value := range cosmoCoordinationActiveRiskDefinition.AttributeMap() {
		attributes["rule_"+key] = value
	}
	trimEmptyAttributes(attributes)
	observedAt := time.Time{}
	if timestamp := event.GetOccurredAt(); timestamp != nil {
		observedAt = timestamp.AsTime().UTC()
	}
	fingerprint := hashFindingFingerprint(cosmoCoordinationActiveRiskRuleID, riskURN)
	return &ports.FindingRecord{
		ID:              fingerprint,
		Fingerprint:     fingerprint,
		TenantID:        tenantID,
		RuntimeID:       strings.TrimSpace(runtimeID),
		RuleID:          cosmoCoordinationActiveRiskRuleID,
		Title:           cosmoCoordinationActiveRiskTitle,
		Severity:        cosmoCoordinationActiveRiskSeverity,
		Status:          cosmoCoordinationActiveRiskStatus,
		Summary:         cosmoCoordinationActiveRiskSummary(),
		ResourceURNs:    resourceURNs,
		EventIDs:        []string{strings.TrimSpace(event.GetId())},
		CheckID:         cosmoCoordinationActiveRiskCheckID,
		CheckName:       cosmoCoordinationActiveRiskCheckName,
		ControlRefs:     cloneFindingControlRefs(cosmoCoordinationActiveRiskDefinition.ControlRefs),
		Attributes:      attributes,
		FirstObservedAt: observedAt,
		LastObservedAt:  observedAt,
	}, nil
}

// cosmoFactRiskState resolves a coordination-risk memory fact into a durable
// "active" or "resolved" state from the event attributes the Cosmo source emits
// and the raw fact payload. It returns an empty string for facts that are not in
// a coordination-risk category or that lack explicit state evidence so benign
// and ambiguous memory facts never open HIGH findings.
func cosmoFactRiskState(event *cerebrov1.EventEnvelope) string {
	if !cosmoCoordinationRiskCategory(cosmoFactCategory(event)) {
		return ""
	}
	attrs := event.GetAttributes()
	switch strings.ToLower(firstNonEmpty(attrs["risk_state"], cosmoFactPayloadString(event, "risk_state", "state", "status"))) {
	case "resolved", "closed", "mitigated", "inactive", "remediated":
		return "resolved"
	case "active", "open", "ongoing", "current":
		return "active"
	}
	if raw := firstNonEmpty(attrs["resolved"], cosmoFactPayloadString(event, "resolved")); raw != "" {
		if resolved, err := strconv.ParseBool(raw); err == nil {
			if resolved {
				return "resolved"
			}
			return "active"
		}
	}
	return ""
}

func cosmoCoordinationRiskCategory(category string) bool {
	switch strings.ToLower(strings.TrimSpace(category)) {
	case "coordination_risk", "coordination-risk", "security_risk", "security-risk":
		return true
	default:
		return false
	}
}

func cosmoFactCategory(event *cerebrov1.EventEnvelope) string {
	return firstNonEmpty(strings.TrimSpace(event.GetAttributes()["category"]), cosmoFactPayloadString(event, "category"))
}

func cosmoFactKey(event *cerebrov1.EventEnvelope) string {
	return firstNonEmpty(strings.TrimSpace(event.GetAttributes()["key"]), cosmoFactPayloadString(event, "key"))
}

func cosmoFactSessionID(event *cerebrov1.EventEnvelope) string {
	source := firstNonEmpty(strings.TrimSpace(event.GetAttributes()["source"]), cosmoFactPayloadString(event, "source"))
	if strings.HasPrefix(source, "session:") {
		return strings.TrimSpace(strings.TrimPrefix(source, "session:"))
	}
	return ""
}

func cosmoFactPayloadString(event *cerebrov1.EventEnvelope, keys ...string) string {
	if event == nil || len(event.GetPayload()) == 0 {
		return ""
	}
	var payload map[string]any
	if err := json.Unmarshal(event.GetPayload(), &payload); err != nil {
		return ""
	}
	for _, key := range keys {
		if value := cosmoScalarString(payload[strings.TrimSpace(key)]); value != "" {
			return value
		}
	}
	return ""
}

func cosmoScalarString(value any) string {
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(typed)
	default:
		return ""
	}
}

func cosmoEventRuntimeID(event *cerebrov1.EventEnvelope, fallback string) string {
	if event == nil {
		return strings.TrimSpace(fallback)
	}
	return firstNonEmpty(strings.TrimSpace(event.GetAttributes()[ports.EventAttributeSourceRuntimeID]), strings.TrimSpace(fallback))
}

func cosmoCoordinationRiskURN(tenantID string, runtimeID string, sessionID string, factKey string) string {
	tenantID = strings.TrimSpace(tenantID)
	runtimeID = strings.TrimSpace(runtimeID)
	factKey = strings.TrimSpace(factKey)
	if tenantID == "" || runtimeID == "" || factKey == "" {
		return ""
	}
	session := strings.TrimSpace(sessionID)
	if session == "" {
		session = "memory"
	}
	key := hashFindingFingerprint("cosmo_coordination_risk", tenantID, runtimeID, session, factKey)
	return fmt.Sprintf("urn:cerebro:%s:cosmo_coordination_risk:%s", tenantID, key)
}

func cosmoFactResourceURN(tenantID string, factKey string) string {
	tenantID = strings.TrimSpace(tenantID)
	factKey = strings.TrimSpace(factKey)
	if tenantID == "" || factKey == "" {
		return ""
	}
	return fmt.Sprintf("urn:cerebro:%s:cosmo_fact:%s", tenantID, cosmoExternalIDKey(factKey))
}

func cosmoSessionResourceURN(tenantID string, sessionID string) string {
	tenantID = strings.TrimSpace(tenantID)
	sessionID = strings.TrimSpace(sessionID)
	if tenantID == "" || sessionID == "" {
		return ""
	}
	return fmt.Sprintf("urn:cerebro:%s:cosmo_session:%s", tenantID, cosmoExternalIDKey(sessionID))
}

func cosmoExternalIDKey(value string) string {
	normalized := strings.TrimSpace(value)
	if normalized == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(normalized))
	return "id-" + hex.EncodeToString(sum[:16])
}

func cosmoCoordinationActiveRiskAnchor(attributes map[string]string) string {
	return identityCounterEventAnchor(map[string]string{
		"cosmo_risk_urn": strings.TrimSpace(attributes["cosmo_risk_urn"]),
	}, "cosmo_risk_urn")
}

func cosmoCoordinationActiveRiskSummary() string {
	return "Cosmo agent memory records active coordination risk"
}
