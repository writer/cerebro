package findings

import (
	"context"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

const emailDomainAuthenticationMisconfiguredRuleID = "email-domain-authentication-misconfigured"

type emailDomainAuthenticationMisconfiguredRule struct {
	Rule
	definition RuleDefinition
}

func newEmailDomainAuthenticationMisconfiguredRule() Rule {
	definition := emailDomainAuthenticationMisconfiguredDefinition()
	return &emailDomainAuthenticationMisconfiguredRule{
		Rule: newEventRule(eventRuleConfig{
			definition: definition,
			sourceID:   definition.SourceID,
			match:      eventKindMatcher(definition.EventKinds...),
			build:      buildEmailDomainAuthenticationMisconfiguredFinding,
		}),
		definition: definition,
	}
}

func emailDomainAuthenticationMisconfiguredDefinition() RuleDefinition {
	return RuleDefinition{
		ID:          emailDomainAuthenticationMisconfiguredRuleID,
		Name:        "Email Domain Authentication Misconfigured",
		Description: "Detect tenant mail domains whose SPF, DKIM, or DMARC configuration is missing, permissive, or non-enforcing and that can be abused for spoofing.",
		SourceID:    "email_domain_health",
		EventKinds:  []string{"email_domain_health.health"},
		OutputKind:  "finding.email_domain_authentication_misconfigured",
		Severity:    "HIGH",
		Status:      findingStatusOpen,
		Maturity:    "test",
		Tags:        []string{"email", "spf", "dkim", "dmarc", "spoofing", "phishing", "mta"},
		References: []string{
			"https://datatracker.ietf.org/doc/html/rfc7208",
			"https://datatracker.ietf.org/doc/html/rfc6376",
			"https://datatracker.ietf.org/doc/html/rfc7489",
		},
		FalsePositives: []string{
			"Domains that intentionally do not send mail may legitimately omit SPF/DKIM/DMARC, but should publish a deny-all SPF and DMARC reject policy to stop spoofing.",
			"DKIM selectors outside the probed defaults (or scoped to subdomains) may exist and not be discovered by the source.",
		},
		Runbook:            "Inspect the failing_issue_codes attribute on the finding, address the most severe protocol gap first (SPF permissive/missing, DMARC missing or p=none, DKIM weak/missing), then confirm the source re-runs healthy and clears the finding.",
		RequiredAttributes: []string{"domain", "status"},
		FingerprintFields:  []string{"domain"},
		ControlRefs: []ports.FindingControlRef{
			{FrameworkName: "SOC 2", ControlID: "CC6.6"},
			{FrameworkName: "ISO 27001:2022", ControlID: "A.5.14"},
			{FrameworkName: "NIST SP 800-177", ControlID: "TLS-MAIL"},
		},
		Lifecycle: Lifecycle{Kind: LifecycleDurableState, Anchor: AnchorGraphAnchored},
	}
}

func (r *emailDomainAuthenticationMisconfiguredRule) RuleMetadata() RuleDefinition {
	if r == nil {
		return RuleDefinition{}
	}
	return cloneRuleDefinition(r.definition)
}

func (r *emailDomainAuthenticationMisconfiguredRule) OpenAnchor(attributes map[string]string) string {
	return emailDomainAuthenticationCounterAnchor(attributes["domain"])
}

func (r *emailDomainAuthenticationMisconfiguredRule) CloseOnEvent(event Event) (string, bool) {
	if !eventKindMatcher(emailDomainAuthenticationMisconfiguredDefinition().EventKinds...)(event) {
		return "", false
	}
	attributes := eventAttributes(event)
	if !strings.EqualFold(strings.TrimSpace(attributes["status"]), "HEALTHY") {
		return "", false
	}
	anchor := emailDomainAuthenticationCounterAnchor(attributes["domain"])
	if anchor == "" {
		return "", false
	}
	return anchor, true
}

func buildEmailDomainAuthenticationMisconfiguredFinding(_ context.Context, runtime *cerebrov1.SourceRuntime, event *cerebrov1.EventEnvelope) (*ports.FindingRecord, error) {
	attributes := eventAttributes(event)
	if attributes == nil {
		return nil, nil
	}
	domain := strings.ToLower(strings.TrimSpace(attributes["domain"]))
	status := strings.ToUpper(strings.TrimSpace(attributes["status"]))
	if domain == "" {
		return nil, nil
	}
	switch status {
	case "FAILING", "WARNING":
	default:
		return nil, nil
	}
	tenantID := strings.TrimSpace(event.GetTenantId())
	if tenantID == "" {
		return nil, nil
	}
	domainURN := emailDomainURN(tenantID, domain)
	if domainURN == "" {
		return nil, nil
	}
	severity := emailDomainAuthenticationSeverity(status, attributes)
	observedAt := time.Time{}
	if event.GetOccurredAt() != nil {
		observedAt = event.GetOccurredAt().AsTime().UTC()
	}
	failingCodes := strings.TrimSpace(attributes["failing_issue_codes"])
	issueCodes := strings.TrimSpace(attributes["issue_codes"])
	summary := emailDomainAuthenticationSummary(domain, status, failingCodes, issueCodes)
	action := "Publish or correct SPF, DKIM, and DMARC records on the affected mail domain. Aim for one SPF record terminating in -all, DMARC at p=quarantine or p=reject with reporting, and RSA DKIM keys of at least 2048 bits or standards-compliant Ed25519 selectors."

	findingAttributes := map[string]string{
		"action":               action,
		"domain":               domain,
		"status":               status,
		"score":                strings.TrimSpace(attributes["score"]),
		"spf_status":           strings.TrimSpace(attributes["spf_status"]),
		"dkim_status":          strings.TrimSpace(attributes["dkim_status"]),
		"dmarc_status":         strings.TrimSpace(attributes["dmarc_status"]),
		"issue_count":          strings.TrimSpace(attributes["issue_count"]),
		"failing_issue_count":  strings.TrimSpace(attributes["failing_issue_count"]),
		"issue_codes":          issueCodes,
		"failing_issue_codes":  failingCodes,
		"highest_severity":     strings.TrimSpace(attributes["highest_severity"]),
		"event_id":             strings.TrimSpace(event.GetId()),
		"event_kind":           strings.TrimSpace(event.GetKind()),
		"primary_resource_urn": domainURN,
		"resource_type":        "email_domain",
		"resource_label":       domain,
		"source_runtime_id":    strings.TrimSpace(runtime.GetId()),
	}
	definition := emailDomainAuthenticationMisconfiguredDefinition()
	for key, value := range definition.AttributeMap() {
		findingAttributes["rule_"+key] = value
	}
	trimEmptyAttributes(findingAttributes)
	fingerprint := hashFindingFingerprint(emailDomainAuthenticationMisconfiguredRuleID, tenantID, domain)
	return &ports.FindingRecord{
		ID:              fingerprint,
		Fingerprint:     fingerprint,
		TenantID:        tenantID,
		RuntimeID:       strings.TrimSpace(runtime.GetId()),
		RuleID:          emailDomainAuthenticationMisconfiguredRuleID,
		Title:           "Email Domain Authentication Misconfigured",
		Severity:        severity,
		Status:          findingStatusOpen,
		Summary:         summary,
		ResourceURNs:    []string{domainURN},
		EventIDs:        []string{event.GetId()},
		PolicyID:        domain,
		CheckID:         emailDomainAuthenticationMisconfiguredRuleID,
		CheckName:       "Email Domain Authentication Misconfigured",
		ControlRefs:     cloneFindingControlRefs(definition.ControlRefs),
		Attributes:      findingAttributes,
		FirstObservedAt: observedAt,
		LastObservedAt:  observedAt,
	}, nil
}

func emailDomainAuthenticationSeverity(status string, attributes map[string]string) string {
	if status == "WARNING" {
		return "MEDIUM"
	}
	highest := strings.ToUpper(strings.TrimSpace(attributes["highest_severity"]))
	switch highest {
	case "CRITICAL":
		return "CRITICAL"
	case "MEDIUM":
		return "MEDIUM"
	case "LOW":
		return "LOW"
	default:
		return "HIGH"
	}
}

func emailDomainAuthenticationSummary(domain string, status string, failingCodes string, issueCodes string) string {
	if status == "WARNING" {
		if issueCodes != "" {
			return "Mail domain " + domain + " has email authentication warnings: " + issueCodes
		}
		return "Mail domain " + domain + " has email authentication warnings"
	}
	if failingCodes != "" {
		return "Mail domain " + domain + " has failing SPF/DKIM/DMARC controls: " + failingCodes
	}
	return "Mail domain " + domain + " has failing SPF/DKIM/DMARC controls"
}

func emailDomainURN(tenantID string, domain string) string {
	tenant := strings.TrimSpace(tenantID)
	value := strings.ToLower(strings.TrimSpace(domain))
	if tenant == "" || value == "" {
		return ""
	}
	return "urn:cerebro:" + tenant + ":email_domain:" + value
}

func emailDomainAuthenticationCounterAnchor(domain string) string {
	value := strings.ToLower(strings.TrimSpace(domain))
	if value == "" {
		return ""
	}
	return "domain=" + value
}
