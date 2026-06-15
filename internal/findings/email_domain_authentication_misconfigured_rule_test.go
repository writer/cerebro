package findings

import (
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
