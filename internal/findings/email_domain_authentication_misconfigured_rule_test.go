package findings

import (
	"context"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestEmailDomainAuthenticationMisconfiguredFixture(t *testing.T) {
	assertRuleFixture(t, newEmailDomainAuthenticationMisconfiguredRule(), "testdata/rules/email-domain-authentication-misconfigured.json")
}

func TestEmailDomainAuthenticationMisconfiguredRuleSupportsRuntime(t *testing.T) {
	rule := newEmailDomainAuthenticationMisconfiguredRule()
	emit := &cerebrov1.SourceRuntime{Id: "writer-email-domain-health", SourceId: "email_domain_health", TenantId: "writer", Config: map[string]string{"family": "health"}}
	if !rule.SupportsRuntime(emit) {
		t.Fatalf("SupportsRuntime should match the email_domain_health/health runtime")
	}
	other := &cerebrov1.SourceRuntime{Id: "writer-okta-audit", SourceId: "okta", TenantId: "writer", Config: map[string]string{"family": "audit"}}
	if rule.SupportsRuntime(other) {
		t.Fatalf("SupportsRuntime should not match unrelated runtimes")
	}
}

func TestEmailDomainAuthenticationMisconfiguredRuleClosesOnHealthyDomainEvent(t *testing.T) {
	rule := newEmailDomainAuthenticationMisconfiguredRule()
	counterRule, ok := durableStateCounterEventRule(rule)
	if !ok {
		t.Fatal("email-domain-authentication-misconfigured does not implement durable CounterEventRule")
	}
	runtime := &cerebrov1.SourceRuntime{Id: "writer-email-domain-health", SourceId: "email_domain_health", TenantId: "writer", Config: map[string]string{"family": "health"}}
	openEvent := emailDomainAuthenticationTestEvent("email-domain-health-open", "Example.COM", "FAILING")
	records, err := rule.Evaluate(context.Background(), runtime, openEvent)
	if err != nil {
		t.Fatalf("Evaluate(open) error = %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("Evaluate(open) records = %d, want 1", len(records))
	}
	openAnchor := counterRule.OpenAnchor(records[0].Attributes)
	if openAnchor == "" {
		t.Fatalf("OpenAnchor(%v) = empty", records[0].Attributes)
	}
	closeAnchor, closes := counterRule.CloseOnEvent(emailDomainAuthenticationTestEvent("email-domain-health-healthy", "example.com", "HEALTHY"))
	if !closes || closeAnchor != openAnchor {
		t.Fatalf("CloseOnEvent(healthy) = (%q, %v), want (%q, true)", closeAnchor, closes, openAnchor)
	}
	if closeAnchor, closes = counterRule.CloseOnEvent(emailDomainAuthenticationTestEvent("email-domain-health-warning", "example.com", "WARNING")); closes || closeAnchor != "" {
		t.Fatalf("CloseOnEvent(warning) = (%q, %v), want no close", closeAnchor, closes)
	}
}

func emailDomainAuthenticationTestEvent(id string, domain string, status string) *cerebrov1.EventEnvelope {
	return &cerebrov1.EventEnvelope{
		Id:       id,
		TenantId: "writer",
		SourceId: "email_domain_health",
		Kind:     "email_domain_health.health",
		Attributes: map[string]string{
			"domain": domain,
			"status": status,
		},
	}
}
