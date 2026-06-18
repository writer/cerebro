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
	slackPrivilegedUserWithoutMFARuleID    = "slack-privileged-user-without-mfa"
	slackPrivilegedUserWithoutMFATitle     = "Slack Privileged User Without MFA"
	slackPrivilegedUserWithoutMFASeverity  = "HIGH"
	slackPrivilegedUserWithoutMFACheckID   = "slack-privileged-user-without-mfa-current"
	slackPrivilegedUserWithoutMFACheckName = "Slack Privileged User Without MFA (current state)"
)

var slackPrivilegedUserWithoutMFAControlRefs = []ports.FindingControlRef{
	{FrameworkName: "SOC 2", ControlID: "CC6.1"},
	{FrameworkName: "ISO 27001:2022", ControlID: "A.8.5"},
}

type slackPrivilegedUserWithoutMFARule struct {
	Rule
	definition RuleDefinition
}

var slackPrivilegedUserWithoutMFADefinition = RuleDefinition{
	ID:                 slackPrivilegedUserWithoutMFARuleID,
	Name:               slackPrivilegedUserWithoutMFATitle,
	Description:        "Detect active Slack workspace administrators or owners that can sign in without multi-factor authentication, leaving a privileged collaboration identity protected only by a password.",
	SourceID:           "slack",
	EventKinds:         []string{"slack.user"},
	OutputKind:         "finding.slack_privileged_user_without_mfa",
	Severity:           slackPrivilegedUserWithoutMFASeverity,
	Status:             findingStatusOpen,
	Maturity:           "test",
	Tags:               []string{"slack", "identity", "mfa", "privileged-access", "authentication"},
	References:         []string{"https://slack.com/help/articles/204509068-Manage-two-factor-authentication-for-your-workspace"},
	FalsePositives:     []string{"Break-glass admin identities that authenticate through enterprise SSO with MFA enforced upstream and are risk-accepted in Slack."},
	Runbook:            "Confirm whether the privileged Slack identity should retain admin or owner access; if so, require two-factor authentication (or enforce SSO/MFA at the workspace), otherwise remove the elevated role.",
	RequiredAttributes: []string{"user_id"},
	FingerprintFields:  []string{"slack_user_urn"},
	ControlRefs:        slackPrivilegedUserWithoutMFAControlRefs,
	Lifecycle:          Lifecycle{Kind: LifecycleDurableState, Anchor: AnchorSourceState},
}

var slackPrivilegedUserWithoutMFAKindMatcher = eventKindMatcher(slackPrivilegedUserWithoutMFADefinition.EventKinds...)

func newSlackPrivilegedUserWithoutMFARule() Rule {
	rule := newEventRule(eventRuleConfig{
		definition: slackPrivilegedUserWithoutMFADefinition,
		match:      matchesSlackPrivilegedUserWithoutMFA,
		build: func(ctx context.Context, runtime *cerebrov1.SourceRuntime, event *cerebrov1.EventEnvelope) (*ports.FindingRecord, error) {
			return slackPrivilegedUserWithoutMFAFinding(event, runtime.GetId())
		},
	})
	return &slackPrivilegedUserWithoutMFARule{
		Rule:       rule,
		definition: slackPrivilegedUserWithoutMFADefinition,
	}
}

func (r *slackPrivilegedUserWithoutMFARule) RuleMetadata() RuleDefinition {
	if r == nil {
		return RuleDefinition{}
	}
	return cloneRuleDefinition(r.definition)
}

func (r *slackPrivilegedUserWithoutMFARule) OpenAnchor(attributes map[string]string) string {
	return slackPrivilegedUserWithoutMFAAnchor(attributes)
}

// CloseOnEvent resolves an open finding when a later snapshot of the same Slack
// user shows MFA enabled (remediation), shows the identity is no longer
// privileged (role removed), or shows the account deactivated/deleted, so
// resolved or offboarded identities do not leave stale open findings.
func (r *slackPrivilegedUserWithoutMFARule) CloseOnEvent(event Event) (string, bool) {
	if !slackPrivilegedUserWithoutMFAKindMatcher(event) || !hasRequiredAttributes(event, slackPrivilegedUserWithoutMFADefinition.RequiredAttributes...) {
		return "", false
	}
	attributes := eventAttributes(event)
	if !slackUserMFAFindingResolved(attributes) {
		return "", false
	}
	userURN := slackUserFindingURN(event.GetTenantId(), attributes["user_id"])
	anchor := slackPrivilegedUserWithoutMFAAnchor(map[string]string{"slack_user_urn": userURN})
	return anchor, anchor != ""
}

func matchesSlackPrivilegedUserWithoutMFA(event *cerebrov1.EventEnvelope) bool {
	if !slackPrivilegedUserWithoutMFAKindMatcher(event) || !hasRequiredAttributes(event, slackPrivilegedUserWithoutMFADefinition.RequiredAttributes...) {
		return false
	}
	return slackUserMFANotEnforced(eventAttributes(event))
}

func slackPrivilegedUserWithoutMFAFinding(event *cerebrov1.EventEnvelope, runtimeID string) (*ports.FindingRecord, error) {
	attrs := event.GetAttributes()
	userID := strings.TrimSpace(attrs["user_id"])
	tenantID := strings.TrimSpace(event.GetTenantId())
	userURN := slackUserFindingURN(tenantID, userID)
	if userURN == "" {
		return nil, nil
	}
	label := firstNonEmpty(strings.TrimSpace(attrs["real_name"]), strings.TrimSpace(attrs["name"]), strings.TrimSpace(attrs["email"]), userID)
	attributes := map[string]string{
		"slack_user_urn":       userURN,
		"user_id":              userID,
		"team_id":              strings.TrimSpace(attrs["team_id"]),
		"name":                 strings.TrimSpace(attrs["name"]),
		"email":                strings.TrimSpace(attrs["email"]),
		"privilege_role":       slackUserPrivilegeRole(attrs),
		"has_mfa":              "false",
		"event_id":             strings.TrimSpace(event.GetId()),
		"source_runtime_id":    strings.TrimSpace(attrs[ports.EventAttributeSourceRuntimeID]),
		"primary_resource_urn": userURN,
	}
	for key, value := range slackPrivilegedUserWithoutMFADefinition.AttributeMap() {
		attributes["rule_"+key] = value
	}
	trimEmptyAttributes(attributes)
	observedAt := time.Time{}
	if timestamp := event.GetOccurredAt(); timestamp != nil {
		observedAt = timestamp.AsTime().UTC()
	}
	fingerprint := hashFindingFingerprint(slackPrivilegedUserWithoutMFARuleID, userURN)
	return &ports.FindingRecord{
		ID:              fingerprint,
		Fingerprint:     fingerprint,
		TenantID:        tenantID,
		RuntimeID:       strings.TrimSpace(runtimeID),
		RuleID:          slackPrivilegedUserWithoutMFARuleID,
		Title:           slackPrivilegedUserWithoutMFATitle,
		Severity:        slackPrivilegedUserWithoutMFASeverity,
		Status:          findingStatusOpen,
		Summary:         slackPrivilegedUserWithoutMFASummary(label),
		ResourceURNs:    []string{userURN},
		EventIDs:        []string{strings.TrimSpace(event.GetId())},
		CheckID:         slackPrivilegedUserWithoutMFACheckID,
		CheckName:       slackPrivilegedUserWithoutMFACheckName,
		ControlRefs:     cloneFindingControlRefs(slackPrivilegedUserWithoutMFADefinition.ControlRefs),
		Attributes:      attributes,
		FirstObservedAt: observedAt,
		LastObservedAt:  observedAt,
	}, nil
}

// slackUserMFANotEnforced reports whether an active, non-bot, privileged Slack
// identity currently lacks multi-factor authentication. Deactivated accounts,
// bots, and non-privileged members are excluded so offboarding and ordinary
// membership do not surface as an MFA control gap.
func slackUserMFANotEnforced(attributes map[string]string) bool {
	if slackUserAccountDeactivated(attributes) || parseBoolAttribute(attributes, "is_bot") {
		return false
	}
	if !slackUserAccountPrivileged(attributes) {
		return false
	}
	enabled, observed := slackUserMFAObserved(attributes)
	return observed && !enabled
}

func slackUserMFAFindingResolved(attributes map[string]string) bool {
	if slackUserAccountDeactivated(attributes) || parseBoolAttribute(attributes, "is_bot") {
		return true
	}
	if !slackUserAccountPrivileged(attributes) {
		return true
	}
	enabled, observed := slackUserMFAObserved(attributes)
	return observed && enabled
}

func slackUserAccountPrivileged(attributes map[string]string) bool {
	return parseBoolAttribute(attributes, "is_admin") ||
		parseBoolAttribute(attributes, "is_owner") ||
		parseBoolAttribute(attributes, "is_primary_owner")
}

func slackUserMFAEnabled(attributes map[string]string) bool {
	enabled, _ := slackUserMFAObserved(attributes)
	return enabled
}

func slackUserMFAObserved(attributes map[string]string) (bool, bool) {
	has2FA, observed2FA := parseOptionalBoolAttribute(attributes, "has_2fa")
	hasMFA, observedMFA := parseOptionalBoolAttribute(attributes, "has_mfa")
	if (observed2FA && has2FA) || (observedMFA && hasMFA) {
		return true, true
	}
	if observed2FA || observedMFA {
		return false, true
	}
	return false, false
}

func slackUserAccountDeactivated(attributes map[string]string) bool {
	if parseBoolAttribute(attributes, "deleted") {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(attributes["status"])) {
	case "deleted", "deactivated", "disabled", "inactive":
		return true
	default:
		return false
	}
}

func slackUserPrivilegeRole(attributes map[string]string) string {
	switch {
	case parseBoolAttribute(attributes, "is_primary_owner"):
		return "primary_owner"
	case parseBoolAttribute(attributes, "is_owner"):
		return "owner"
	case parseBoolAttribute(attributes, "is_admin"):
		return "admin"
	default:
		return ""
	}
}

func slackUserFindingURN(tenantID string, userID string) string {
	tenantID = strings.TrimSpace(tenantID)
	userID = strings.TrimSpace(userID)
	if tenantID == "" || userID == "" {
		return ""
	}
	return fmt.Sprintf("urn:cerebro:%s:slack_user:%s", tenantID, userID)
}

func slackPrivilegedUserWithoutMFAAnchor(attributes map[string]string) string {
	return identityCounterEventAnchor(map[string]string{
		"slack_user_urn": strings.TrimSpace(attributes["slack_user_urn"]),
	}, "slack_user_urn")
}

func slackPrivilegedUserWithoutMFASummary(label string) string {
	return fmt.Sprintf("Slack privileged user %s can sign in without MFA", firstNonEmpty(label, "unknown user"))
}
