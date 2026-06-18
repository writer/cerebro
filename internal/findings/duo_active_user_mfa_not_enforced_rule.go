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
	duoActiveUserMFANotEnforcedRuleID    = "duo-active-user-mfa-not-enforced"
	duoActiveUserMFANotEnforcedTitle     = "Duo Active User Without Enforced MFA"
	duoActiveUserMFANotEnforcedSeverity  = "MEDIUM"
	duoActiveUserMFANotEnforcedStatus    = "open"
	duoActiveUserMFANotEnforcedCheckID   = "duo-active-user-mfa-not-enforced-current"
	duoActiveUserMFANotEnforcedCheckName = "Duo Active User Without Enforced MFA (current state)"
)

var duoActiveUserMFANotEnforcedControlRefs = []ports.FindingControlRef{
	{FrameworkName: "SOC 2", ControlID: "CC6.1"},
	{FrameworkName: "ISO 27001:2022", ControlID: "A.8.5"},
}

// duoUserDeprovisionedStatuses captures Duo account states where the identity
// can no longer authenticate, so a missing MFA factor is not an active access
// risk and any open finding should resolve rather than linger.
var duoUserDeprovisionedStatuses = map[string]struct{}{
	"disabled":         {},
	"pending deletion": {},
	"deleted":          {},
	"removed":          {},
	"inactive":         {},
	"deactivated":      {},
	"locked out":       {},
	"lockedout":        {},
}

type duoActiveUserMFANotEnforcedRule struct {
	Rule
	definition RuleDefinition
}

var duoActiveUserMFANotEnforcedDefinition = RuleDefinition{
	ID:                 duoActiveUserMFANotEnforcedRuleID,
	Name:               duoActiveUserMFANotEnforcedTitle,
	Description:        "Detect active Duo users who can authenticate without multi-factor protection because they are in MFA bypass mode or are not enrolled in any factor, leaving a current authentication control gap on the identity.",
	SourceID:           "duo",
	EventKinds:         []string{"duo.user"},
	OutputKind:         "finding.duo_active_user_mfa_not_enforced",
	Severity:           duoActiveUserMFANotEnforcedSeverity,
	Status:             duoActiveUserMFANotEnforcedStatus,
	Maturity:           "test",
	Tags:               []string{"duo", "identity", "mfa", "authentication", "access-control"},
	References:         []string{"https://duo.com/docs/adminapi"},
	FalsePositives:     []string{"Service or break-glass identities that are intentionally placed in MFA bypass under a documented, risk-accepted exception."},
	Runbook:            "Confirm whether the Duo user should authenticate with MFA; if so, remove the bypass status or complete factor enrollment so the identity is protected by multi-factor authentication.",
	RequiredAttributes: []string{"user_id"},
	FingerprintFields:  []string{"duo_user_urn"},
	ControlRefs:        duoActiveUserMFANotEnforcedControlRefs,
	Lifecycle:          Lifecycle{Kind: LifecycleDurableState, Anchor: AnchorSourceState},
}

var duoActiveUserMFANotEnforcedKindMatcher = eventKindMatcher(duoActiveUserMFANotEnforcedDefinition.EventKinds...)

func newDuoActiveUserMFANotEnforcedRule() Rule {
	rule := newEventRule(eventRuleConfig{
		definition: duoActiveUserMFANotEnforcedDefinition,
		match:      matchesDuoActiveUserMFANotEnforced,
		build: func(ctx context.Context, runtime *cerebrov1.SourceRuntime, event *cerebrov1.EventEnvelope) (*ports.FindingRecord, error) {
			return duoActiveUserMFANotEnforcedFinding(event, runtime.GetId())
		},
	})
	return &duoActiveUserMFANotEnforcedRule{
		Rule:       rule,
		definition: duoActiveUserMFANotEnforcedDefinition,
	}
}

func (r *duoActiveUserMFANotEnforcedRule) RuleMetadata() RuleDefinition {
	if r == nil {
		return RuleDefinition{}
	}
	return cloneRuleDefinition(r.definition)
}

func (r *duoActiveUserMFANotEnforcedRule) OpenAnchor(attributes map[string]string) string {
	return duoActiveUserMFANotEnforcedAnchor(attributes)
}

// CloseOnEvent resolves an open finding when a later user snapshot shows MFA is
// enforced again (bypass removed and the user enrolled) or when the identity is
// deprovisioned/offboarded, so removed identities do not leave stale open
// findings.
func (r *duoActiveUserMFANotEnforcedRule) CloseOnEvent(event Event) (string, bool) {
	if !duoActiveUserMFANotEnforcedKindMatcher(event) || !hasRequiredAttributes(event, duoActiveUserMFANotEnforcedDefinition.RequiredAttributes...) {
		return "", false
	}
	attributes := eventAttributes(event)
	if !duoUserMFAEnforced(attributes) && !duoUserDeprovisioned(attributes) {
		return "", false
	}
	userURN := duoUserFindingURN(event.GetTenantId(), attributes["user_id"])
	anchor := duoActiveUserMFANotEnforcedAnchor(map[string]string{"duo_user_urn": userURN})
	return anchor, anchor != ""
}

func matchesDuoActiveUserMFANotEnforced(event *cerebrov1.EventEnvelope) bool {
	if !duoActiveUserMFANotEnforcedKindMatcher(event) || !hasRequiredAttributes(event, duoActiveUserMFANotEnforcedDefinition.RequiredAttributes...) {
		return false
	}
	return duoUserMFANotEnforced(eventAttributes(event))
}

func duoActiveUserMFANotEnforcedFinding(event *cerebrov1.EventEnvelope, runtimeID string) (*ports.FindingRecord, error) {
	attrs := event.GetAttributes()
	userID := strings.TrimSpace(attrs["user_id"])
	tenantID := strings.TrimSpace(event.GetTenantId())
	userURN := duoUserFindingURN(tenantID, userID)
	if userURN == "" {
		return nil, nil
	}
	label := firstNonEmpty(strings.TrimSpace(attrs["username"]), strings.TrimSpace(attrs["email"]), strings.TrimSpace(attrs["realname"]), userID)
	attributes := map[string]string{
		"duo_user_urn":         userURN,
		"user_id":              userID,
		"username":             strings.TrimSpace(attrs["username"]),
		"email":                strings.TrimSpace(attrs["email"]),
		"status":               strings.TrimSpace(attrs["status"]),
		"is_enrolled":          strings.TrimSpace(attrs["is_enrolled"]),
		"mfa_gap_reason":       duoUserMFAGapReason(attrs),
		"event_id":             strings.TrimSpace(event.GetId()),
		"source_runtime_id":    strings.TrimSpace(attrs[ports.EventAttributeSourceRuntimeID]),
		"primary_resource_urn": userURN,
	}
	for key, value := range duoActiveUserMFANotEnforcedDefinition.AttributeMap() {
		attributes["rule_"+key] = value
	}
	trimEmptyAttributes(attributes)
	observedAt := time.Time{}
	if timestamp := event.GetOccurredAt(); timestamp != nil {
		observedAt = timestamp.AsTime().UTC()
	}
	fingerprint := hashFindingFingerprint(duoActiveUserMFANotEnforcedRuleID, userURN)
	return &ports.FindingRecord{
		ID:              fingerprint,
		Fingerprint:     fingerprint,
		TenantID:        tenantID,
		RuntimeID:       strings.TrimSpace(runtimeID),
		RuleID:          duoActiveUserMFANotEnforcedRuleID,
		Title:           duoActiveUserMFANotEnforcedTitle,
		Severity:        duoActiveUserMFANotEnforcedSeverity,
		Status:          duoActiveUserMFANotEnforcedStatus,
		Summary:         duoActiveUserMFANotEnforcedSummary(label),
		ResourceURNs:    []string{userURN},
		EventIDs:        []string{strings.TrimSpace(event.GetId())},
		CheckID:         duoActiveUserMFANotEnforcedCheckID,
		CheckName:       duoActiveUserMFANotEnforcedCheckName,
		ControlRefs:     cloneFindingControlRefs(duoActiveUserMFANotEnforcedDefinition.ControlRefs),
		Attributes:      attributes,
		FirstObservedAt: observedAt,
		LastObservedAt:  observedAt,
	}, nil
}

// duoUserMFANotEnforced reports whether an active Duo identity currently lacks
// enforced MFA: either it is explicitly in bypass mode or it is unenrolled while
// still in an active state. Deprovisioned identities are excluded so offboarding
// does not surface as an MFA gap.
func duoUserMFANotEnforced(attributes map[string]string) bool {
	if duoUserDeprovisioned(attributes) {
		return false
	}
	if duoUserInBypass(attributes) {
		return true
	}
	if enrolled, ok := parseOptionalBoolAttribute(attributes, "is_enrolled"); ok && !enrolled && duoUserActive(attributes) {
		return true
	}
	return false
}

func duoUserMFAEnforced(attributes map[string]string) bool {
	if duoUserDeprovisioned(attributes) || duoUserInBypass(attributes) {
		return false
	}
	enrolled, ok := parseOptionalBoolAttribute(attributes, "is_enrolled")
	return ok && enrolled
}

func duoUserMFAGapReason(attributes map[string]string) string {
	if duoUserInBypass(attributes) {
		return "mfa_bypass"
	}
	if enrolled, ok := parseOptionalBoolAttribute(attributes, "is_enrolled"); ok && !enrolled {
		return "not_enrolled"
	}
	return ""
}

func duoUserInBypass(attributes map[string]string) bool {
	return strings.EqualFold(strings.TrimSpace(attributes["status"]), "bypass")
}

func duoUserActive(attributes map[string]string) bool {
	switch strings.ToLower(strings.TrimSpace(attributes["status"])) {
	case "", "active", "bypass":
		return true
	default:
		return false
	}
}

func duoUserDeprovisioned(attributes map[string]string) bool {
	status := strings.ToLower(strings.TrimSpace(attributes["status"]))
	_, deprovisioned := duoUserDeprovisionedStatuses[status]
	return deprovisioned
}

func duoUserFindingURN(tenantID string, userID string) string {
	tenantID = strings.TrimSpace(tenantID)
	userID = strings.TrimSpace(userID)
	if tenantID == "" || userID == "" {
		return ""
	}
	return fmt.Sprintf("urn:cerebro:%s:duo_user:%s", tenantID, userID)
}

func duoActiveUserMFANotEnforcedAnchor(attributes map[string]string) string {
	return identityCounterEventAnchor(map[string]string{
		"duo_user_urn": strings.TrimSpace(attributes["duo_user_urn"]),
	}, "duo_user_urn")
}

func duoActiveUserMFANotEnforcedSummary(label string) string {
	return fmt.Sprintf("Duo user %s is active without enforced MFA", firstNonEmpty(label, "unknown user"))
}
