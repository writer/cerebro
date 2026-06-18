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
	cerebroHighRiskAPIAccessRuleID    = "cerebro-high-risk-api-access"
	cerebroHighRiskAPIAccessTitle     = "Cerebro Active High-Risk API Access Posture"
	cerebroHighRiskAPIAccessSeverity  = "HIGH"
	cerebroHighRiskAPIAccessCheckID   = "cerebro-high-risk-api-access-current"
	cerebroHighRiskAPIAccessCheckName = "Cerebro Active High-Risk API Access Posture (current state)"
	cerebroHighRiskScoreThreshold     = 80
)

var cerebroHighRiskAPIAccessControlRefs = []ports.FindingControlRef{
	{FrameworkName: "SOC 2", ControlID: "CC6.1"},
	{FrameworkName: "ISO 27001:2022", ControlID: "A.8.3"},
}

// cerebroHighRiskAccessRiskLevels are the normalized risk_level values that
// describe a granted access whose posture is severe enough to be tracked as a
// durable, current-state risk on the acting principal.
var cerebroHighRiskAccessRiskLevels = map[string]struct{}{
	"high":     {},
	"critical": {},
	"severe":   {},
}

type cerebroHighRiskAPIAccessRule struct {
	Rule
	definition RuleDefinition
}

var cerebroHighRiskAPIAccessDefinition = RuleDefinition{
	ID:                 cerebroHighRiskAPIAccessRuleID,
	Name:               cerebroHighRiskAPIAccessTitle,
	Description:        "Detect Cerebro principals that currently hold a granted, high-risk API access posture, such as a successful cross-tenant access or an access classified as high or critical risk, so the responsible credential or identity can be scoped down or revoked.",
	SourceID:           "cerebro",
	EventKinds:         []string{"cerebro.api_access"},
	OutputKind:         "finding.cerebro_high_risk_api_access",
	Severity:           cerebroHighRiskAPIAccessSeverity,
	Status:             findingStatusOpen,
	Maturity:           "test",
	Tags:               []string{"cerebro", "access", "api", "authorization", "tenant-isolation"},
	References:         []string{"https://github.com/writer/cerebro/blob/main/docs/ARCHITECTURE.md"},
	FalsePositives:     []string{"Authorized administrative or support principals that intentionally hold elevated cross-tenant access under a documented, risk-accepted exception."},
	Runbook:            "Review the Cerebro principal and credential behind the high-risk access; revoke or scope down the credential, correct the tenant binding, or document a risk-accepted exception if the access is authorized.",
	RequiredAttributes: []string{"event_type"},
	FingerprintFields:  []string{"cerebro_principal_urn"},
	ControlRefs:        cerebroHighRiskAPIAccessControlRefs,
	Lifecycle:          Lifecycle{Kind: LifecycleDurableState, Anchor: AnchorSourceState},
}

var cerebroHighRiskAPIAccessKindMatcher = eventKindMatcher(cerebroHighRiskAPIAccessDefinition.EventKinds...)

func newCerebroHighRiskAPIAccessRule() Rule {
	rule := newEventRule(eventRuleConfig{
		definition: cerebroHighRiskAPIAccessDefinition,
		match:      matchesCerebroHighRiskAPIAccess,
		build: func(ctx context.Context, runtime *cerebrov1.SourceRuntime, event *cerebrov1.EventEnvelope) (*ports.FindingRecord, error) {
			return cerebroHighRiskAPIAccessFinding(event, runtime.GetId())
		},
	})
	return &cerebroHighRiskAPIAccessRule{
		Rule:       rule,
		definition: cerebroHighRiskAPIAccessDefinition,
	}
}

func (r *cerebroHighRiskAPIAccessRule) RuleMetadata() RuleDefinition {
	if r == nil {
		return RuleDefinition{}
	}
	return cloneRuleDefinition(r.definition)
}

func (r *cerebroHighRiskAPIAccessRule) OpenAnchor(attributes map[string]string) string {
	return cerebroHighRiskAPIAccessAnchor(attributes)
}

// CloseOnEvent resolves an open finding when a later access observation for the
// same principal demonstrates a safe granted posture (a successful access with
// no high-risk indicators), so a principal whose risky access has been scoped
// down or corrected does not leave a stale open finding.
func (r *cerebroHighRiskAPIAccessRule) CloseOnEvent(event Event) (string, bool) {
	if !cerebroHighRiskAPIAccessKindMatcher(event) || !hasRequiredAttributes(event, cerebroHighRiskAPIAccessDefinition.RequiredAttributes...) {
		return "", false
	}
	attributes := eventAttributes(event)
	if cerebroAPIAccessRouteIdentity(attributes) == "" {
		return "", false
	}
	if !cerebroAPIAccessRemediated(attributes) {
		return "", false
	}
	principalURN := cerebroPrincipalFindingURN(event.GetTenantId(), attributes)
	anchor := cerebroHighRiskAPIAccessAnchor(map[string]string{"cerebro_principal_urn": principalURN})
	return anchor, anchor != ""
}

func matchesCerebroHighRiskAPIAccess(event *cerebrov1.EventEnvelope) bool {
	if !cerebroHighRiskAPIAccessKindMatcher(event) || !hasRequiredAttributes(event, cerebroHighRiskAPIAccessDefinition.RequiredAttributes...) {
		return false
	}
	attributes := eventAttributes(event)
	if cerebroAPIAccessRouteIdentity(attributes) == "" {
		return false
	}
	if cerebroPrincipalFindingURN(event.GetTenantId(), attributes) == "" {
		return false
	}
	return cerebroAPIAccessHighRisk(attributes)
}

func cerebroHighRiskAPIAccessFinding(event *cerebrov1.EventEnvelope, runtimeID string) (*ports.FindingRecord, error) {
	attrs := event.GetAttributes()
	tenantID := strings.TrimSpace(event.GetTenantId())
	principalURN := cerebroPrincipalFindingURN(tenantID, attrs)
	if principalURN == "" {
		return nil, nil
	}
	label := cerebroAccessSubject(attrs)
	attributes := map[string]string{
		"cerebro_principal_urn": principalURN,
		"principal":             strings.TrimSpace(attrs["principal"]),
		"credential_id":         strings.TrimSpace(attrs["credential_id"]),
		"client_id":             strings.TrimSpace(attrs["client_id"]),
		"auth_mode":             strings.TrimSpace(attrs["auth_mode"]),
		"route":                 strings.TrimSpace(attrs["route"]),
		"connect_procedure":     strings.TrimSpace(attrs["connect_procedure"]),
		"method":                strings.TrimSpace(attrs["method"]),
		"operation_family":      strings.TrimSpace(attrs["operation_family"]),
		"operation_type":        strings.TrimSpace(attrs["operation_type"]),
		"outcome_result":        strings.TrimSpace(attrs["outcome_result"]),
		"risk_level":            strings.TrimSpace(attrs["risk_level"]),
		"risk_score":            strings.TrimSpace(attrs["risk_score"]),
		"tenant_mismatch":       strings.TrimSpace(attrs["tenant_mismatch"]),
		"requested_tenant_id":   strings.TrimSpace(attrs["requested_tenant_id"]),
		"effective_tenant_id":   strings.TrimSpace(attrs["effective_tenant_id"]),
		"risk_reason":           cerebroAPIAccessRiskReason(attrs),
		"event_id":              strings.TrimSpace(event.GetId()),
		"source_runtime_id":     strings.TrimSpace(attrs[ports.EventAttributeSourceRuntimeID]),
		"primary_resource_urn":  principalURN,
	}
	for key, value := range cerebroHighRiskAPIAccessDefinition.AttributeMap() {
		attributes["rule_"+key] = value
	}
	trimEmptyAttributes(attributes)
	observedAt := time.Time{}
	if timestamp := event.GetOccurredAt(); timestamp != nil {
		observedAt = timestamp.AsTime().UTC()
	}
	fingerprint := hashFindingFingerprint(cerebroHighRiskAPIAccessRuleID, principalURN)
	return &ports.FindingRecord{
		ID:              fingerprint,
		Fingerprint:     fingerprint,
		TenantID:        tenantID,
		RuntimeID:       strings.TrimSpace(runtimeID),
		RuleID:          cerebroHighRiskAPIAccessRuleID,
		Title:           cerebroHighRiskAPIAccessTitle,
		Severity:        cerebroHighRiskAPIAccessSeverity,
		Status:          findingStatusOpen,
		Summary:         cerebroHighRiskAPIAccessSummary(label),
		ResourceURNs:    []string{principalURN},
		EventIDs:        []string{strings.TrimSpace(event.GetId())},
		CheckID:         cerebroHighRiskAPIAccessCheckID,
		CheckName:       cerebroHighRiskAPIAccessCheckName,
		ControlRefs:     cloneFindingControlRefs(cerebroHighRiskAPIAccessDefinition.ControlRefs),
		Attributes:      attributes,
		FirstObservedAt: observedAt,
		LastObservedAt:  observedAt,
	}, nil
}

// cerebroAPIAccessHighRisk reports whether a granted Cerebro API access
// currently represents a high-risk posture: the access succeeded and carries at
// least one risk indicator. Blocked attempts are excluded because the control
// already denied them and they are not a granted risk on the principal.
func cerebroAPIAccessHighRisk(attributes map[string]string) bool {
	return cerebroAPIAccessAllowed(attributes) && cerebroAPIAccessRiskIndicator(attributes)
}

// cerebroAPIAccessRemediated reports whether a later access observation proves
// the principal's granted posture is now safe: a successful access with no
// high-risk indicators.
func cerebroAPIAccessRemediated(attributes map[string]string) bool {
	return cerebroAPIAccessAllowed(attributes) && !cerebroAPIAccessRiskIndicator(attributes)
}

func cerebroAPIAccessRiskIndicator(attributes map[string]string) bool {
	return cerebroAPIAccessRiskReason(attributes) != ""
}

func cerebroAPIAccessRiskReason(attributes map[string]string) string {
	if mismatch, ok := parseOptionalBoolAttribute(attributes, "tenant_mismatch"); ok && mismatch {
		return "cross_tenant_access"
	}
	if _, ok := cerebroHighRiskAccessRiskLevels[strings.ToLower(strings.TrimSpace(attributes["risk_level"]))]; ok {
		return "high_risk_level"
	}
	if score, err := strconv.ParseFloat(strings.TrimSpace(attributes["risk_score"]), 64); err == nil && score >= cerebroHighRiskScoreThreshold {
		return "high_risk_score"
	}
	return ""
}

func cerebroAPIAccessAllowed(attributes map[string]string) bool {
	if cerebroAPIAccessDenied(attributes) {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(firstNonEmpty(attributes["outcome_result"], attributes["status"]))) {
	case "allowed", "allow", "success", "succeeded", "ok":
		return true
	}
	status := strings.TrimSpace(firstNonEmpty(attributes["effective_status_code"], attributes["status_code"]))
	return strings.HasPrefix(status, "2")
}

// cerebroAPIAccessDenied reports whether telemetry carries an explicit deny
// signal. An explicit deny takes precedence over a 2xx status-code fallback so a
// blocked attempt is never misread as a granted access just because a status
// field happens to be present.
func cerebroAPIAccessDenied(attributes map[string]string) bool {
	switch strings.ToLower(strings.TrimSpace(firstNonEmpty(attributes["outcome_result"], attributes["status"]))) {
	case "denied", "deny", "blocked", "block", "forbidden", "unauthorized", "rejected", "reject", "failed", "failure", "error":
		return true
	}
	return strings.TrimSpace(attributes["denial_reason"]) != ""
}

func cerebroAccessSubject(attributes map[string]string) string {
	return firstNonEmpty(
		strings.TrimSpace(attributes["principal"]),
		strings.TrimSpace(attributes["device_id"]),
		strings.TrimSpace(attributes["client_id"]),
		strings.TrimSpace(attributes["credential_id"]),
	)
}

func cerebroAPIAccessRouteIdentity(attributes map[string]string) string {
	return firstNonEmpty(strings.TrimSpace(attributes["route"]), strings.TrimSpace(attributes["connect_procedure"]))
}

func cerebroPrincipalFindingURN(tenantID string, attributes map[string]string) string {
	tenantID = strings.TrimSpace(tenantID)
	subject := cerebroAccessSubject(attributes)
	if tenantID == "" || subject == "" {
		return ""
	}
	return fmt.Sprintf("urn:cerebro:%s:cerebro_principal:%s", tenantID, strings.ToLower(subject))
}

func cerebroHighRiskAPIAccessAnchor(attributes map[string]string) string {
	return identityCounterEventAnchor(map[string]string{
		"cerebro_principal_urn": strings.TrimSpace(attributes["cerebro_principal_urn"]),
	}, "cerebro_principal_urn")
}

func cerebroHighRiskAPIAccessSummary(label string) string {
	return fmt.Sprintf("Cerebro principal %s has an active high-risk API access posture", firstNonEmpty(label, "unknown principal"))
}
