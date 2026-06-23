package connectorpreflight

import (
	"testing"

	"github.com/writer/cerebro/internal/resourcescope"
)

func TestProviderChecksDefaultReturnsNil(t *testing.T) {
	checks := ProviderChecks("unknown_source", "", nil, resourcescope.Policy{})
	if checks != nil {
		t.Fatalf("ProviderChecks(unknown) = %v, want nil", checks)
	}
}

func TestProviderChecksTrimsSourceID(t *testing.T) {
	checks := ProviderChecks("  aws  ", "", map[string]string{}, resourcescope.Policy{})
	if len(checks) == 0 {
		t.Fatal("ProviderChecks(trimmed aws) returned no checks")
	}
}

func TestAWSProviderChecksRoleARNPasses(t *testing.T) {
	checks := ProviderChecks("aws", "", map[string]string{"role_arn": "arn:aws:iam::123:role/test"}, resourcescope.Policy{})
	found := findCheck(checks, "aws_access_model")
	if found == nil {
		t.Fatal("aws_access_model check missing")
	}
	if found.Status != "passed" {
		t.Fatalf("aws_access_model status = %q, want passed", found.Status)
	}
}

func TestAWSProviderChecksSSOProfilePasses(t *testing.T) {
	checks := ProviderChecks("aws", "aws_sso_profile", map[string]string{}, resourcescope.Policy{})
	found := findCheck(checks, "aws_access_model")
	if found == nil {
		t.Fatal("aws_access_model check missing")
	}
	if found.Status != "passed" {
		t.Fatalf("aws_access_model status = %q, want passed", found.Status)
	}
}

func TestAWSProviderChecksLongLivedKeysWarns(t *testing.T) {
	checks := ProviderChecks("aws", "access_key", map[string]string{}, resourcescope.Policy{})
	found := findCheck(checks, "aws_access_model")
	if found == nil {
		t.Fatal("aws_access_model check missing")
	}
	if found.Status != "warning" {
		t.Fatalf("aws_access_model status = %q, want warning", found.Status)
	}
	if found.NextAction != "prefer_role_or_sso" {
		t.Fatalf("aws_access_model next_action = %q, want prefer_role_or_sso", found.NextAction)
	}
}

func TestAWSProviderChecksOrganizationsExclusion(t *testing.T) {
	policy := resourcescope.Policy{
		ExcludedFamilies: []string{"organizations_account"},
	}
	checks := ProviderChecks("aws", "", map[string]string{}, policy)
	found := findCheck(checks, "aws_organizations_scope")
	if found == nil {
		t.Fatal("aws_organizations_scope check missing when family excluded")
	}
	if found.Status != "warning" {
		t.Fatalf("aws_organizations_scope status = %q, want warning", found.Status)
	}
}

func TestAWSProviderChecksNoOrganizationsExclusion(t *testing.T) {
	checks := ProviderChecks("aws", "", map[string]string{}, resourcescope.Policy{})
	found := findCheck(checks, "aws_organizations_scope")
	if found != nil {
		t.Fatal("aws_organizations_scope check should not appear when family is not excluded")
	}
}

func TestOpenAIProviderChecksAdminKeyPasses(t *testing.T) {
	checks := ProviderChecks("openai", "", map[string]string{
		"credential_kind": "admin_api_key",
	}, resourcescope.Policy{})
	if checks != nil {
		t.Fatalf("ProviderChecks(openai with admin key) = %v, want nil", checks)
	}
}

func TestOpenAIProviderChecksNoAdminKeyBlocked(t *testing.T) {
	checks := ProviderChecks("openai", "", map[string]string{}, resourcescope.Policy{})
	if len(checks) != 1 {
		t.Fatalf("ProviderChecks(openai without admin key) len = %d, want 1", len(checks))
	}
	if checks[0].ID != "openai_admin_api_key" || checks[0].Status != "blocked" {
		t.Fatalf("openai check = %+v, want blocked openai_admin_api_key", checks[0])
	}
}

func TestOpenAIProviderChecksExcludedFamilyReturnsNil(t *testing.T) {
	policy := resourcescope.Policy{
		ExcludedFamilies: []string{"user"},
	}
	checks := ProviderChecks("openai", "", map[string]string{}, policy)
	if checks != nil {
		t.Fatalf("ProviderChecks(openai, excluded) = %v, want nil", checks)
	}
}

func TestAnthropicServiceAccountOAuthPasses(t *testing.T) {
	checks := ProviderChecks("anthropic", "", map[string]string{ //nolint:gosec // test config values
		"family":            "service_account",
		"auth_model":        "bearer_token",
		"credential_kind":   "org_admin_oauth",
		"credential_scopes": "org:admin",
	}, resourcescope.Policy{})
	if len(checks) != 0 {
		t.Fatalf("anthropic service_account with valid config = %+v, want empty", checks)
	}
}

func TestAnthropicServiceAccountMissingOAuthBlocked(t *testing.T) {
	checks := ProviderChecks("anthropic", "", map[string]string{
		"family":     "service_account",
		"auth_model": "legacy_token",
	}, resourcescope.Policy{})
	found := findCheck(checks, "anthropic_org_admin_oauth")
	if found == nil {
		t.Fatal("anthropic_org_admin_oauth check missing")
	}
	if found.Status != "blocked" {
		t.Fatalf("status = %q, want blocked", found.Status)
	}
}

func TestAnthropicComplianceActivityValidPasses(t *testing.T) {
	checks := ProviderChecks("anthropic", "", map[string]string{
		"family":            "compliance_activity",
		"auth_model":        "legacy_token",
		"credential_kind":   "admin_api_key",
		"credential_scopes": "read:compliance_activities",
	}, resourcescope.Policy{})
	if len(checks) != 0 {
		t.Fatalf("anthropic compliance_activity with valid config = %+v, want empty", checks)
	}
}

func TestAnthropicComplianceActivityBearerTokenBlocked(t *testing.T) {
	checks := ProviderChecks("anthropic", "", map[string]string{
		"family":            "compliance_activity",
		"auth_model":        "bearer_token",
		"credential_scopes": "read:compliance_activities",
	}, resourcescope.Policy{})
	found := findCheck(checks, "anthropic_compliance_scope")
	if found == nil {
		t.Fatal("anthropic_compliance_scope check missing for bearer_token")
	}
	if found.Status != "blocked" {
		t.Fatalf("status = %q, want blocked", found.Status)
	}
}

func TestAnthropicComplianceOrgDataValidPasses(t *testing.T) {
	checks := ProviderChecks("anthropic", "", map[string]string{
		"family":            "compliance_organization",
		"auth_model":        "legacy_token",
		"credential_kind":   "compliance_access_key",
		"credential_scopes": "read:compliance_org_data",
	}, resourcescope.Policy{})
	if len(checks) != 0 {
		t.Fatalf("anthropic compliance_organization valid = %+v, want empty", checks)
	}
}

func TestAnthropicComplianceOrgDataMissingScopeBlocked(t *testing.T) {
	checks := ProviderChecks("anthropic", "", map[string]string{
		"family":            "compliance_organization",
		"auth_model":        "legacy_token",
		"credential_kind":   "compliance_access_key",
		"credential_scopes": "read:compliance_activities",
	}, resourcescope.Policy{})
	found := findCheck(checks, "anthropic_compliance_org_data_scope")
	if found == nil {
		t.Fatal("anthropic_compliance_org_data_scope check missing")
	}
	if found.Status != "blocked" {
		t.Fatalf("status = %q, want blocked", found.Status)
	}
}

func TestAnthropicComplianceUserDataValidPasses(t *testing.T) {
	checks := ProviderChecks("anthropic", "", map[string]string{
		"family":            "compliance_organization_user",
		"auth_model":        "legacy_token",
		"credential_kind":   "compliance_access_key",
		"credential_scopes": "read:compliance_user_data",
	}, resourcescope.Policy{})
	if len(checks) != 0 {
		t.Fatalf("anthropic compliance_organization_user valid = %+v, want empty", checks)
	}
}

func TestAnthropicComplianceOrgSettingsValidPasses(t *testing.T) {
	checks := ProviderChecks("anthropic", "", map[string]string{
		"family":            "compliance_organization_setting",
		"auth_model":        "legacy_token",
		"credential_kind":   "compliance_access_key",
		"credential_scopes": "read:compliance_org_settings",
	}, resourcescope.Policy{})
	if len(checks) != 0 {
		t.Fatalf("anthropic compliance_organization_setting valid = %+v, want empty", checks)
	}
}

func TestAnthropicSpendLimitValidPasses(t *testing.T) {
	checks := ProviderChecks("anthropic", "", map[string]string{ //nolint:gosec // test config values
		"family":            "spend_limit",
		"auth_model":        "legacy_token",
		"credential_kind":   "scoped_admin_api_key",
		"credential_scopes": "read:spend_limits",
	}, resourcescope.Policy{})
	if len(checks) != 0 {
		t.Fatalf("anthropic spend_limit valid = %+v, want empty", checks)
	}
}

func TestAnthropicSpendLimitMissingScopeBlocked(t *testing.T) {
	checks := ProviderChecks("anthropic", "", map[string]string{
		"family":     "spend_limit",
		"auth_model": "legacy_token",
	}, resourcescope.Policy{})
	found := findCheck(checks, "anthropic_spend_limit_scope")
	if found == nil {
		t.Fatal("anthropic_spend_limit_scope check missing")
	}
	if found.Status != "blocked" {
		t.Fatalf("status = %q, want blocked", found.Status)
	}
}

func TestAnthropicExcludedFamilyReturnsEmpty(t *testing.T) {
	policy := resourcescope.Policy{
		ExcludedFamilies: []string{"user"},
	}
	checks := ProviderChecks("anthropic", "", map[string]string{}, policy)
	if len(checks) != 0 {
		t.Fatalf("ProviderChecks(anthropic excluded family) = %v, want empty", checks)
	}
}

func TestNormalizedCredentialHintAliases(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"oauth", AnthropicCredentialKindOrgAdminOAuth},
		{"OAuth Bearer", AnthropicCredentialKindOrgAdminOAuth},
		{"ORG_ADMIN", AnthropicCredentialKindOrgAdminOAuth},
		{"org-admin-token", AnthropicCredentialKindOrgAdminOAuth},
		{"admin", AnthropicCredentialKindAdminAPIKey},
		{"Admin Key", AnthropicCredentialKindAdminAPIKey},
		{"admin_api", AnthropicCredentialKindAdminAPIKey},
		{"compliance", AnthropicCredentialKindComplianceAccessKey},
		{"compliance_key", AnthropicCredentialKindComplianceAccessKey},
		{"spend_limit_admin_key", AnthropicCredentialKindScopedAdminAPIKey},
		{"spend_limits_admin_key", AnthropicCredentialKindScopedAdminAPIKey},
		{"unknown_value", "unknown_value"},
		{"", ""},
	}
	for _, tt := range tests {
		got := normalizedCredentialHint(tt.input)
		if got != tt.want {
			t.Errorf("normalizedCredentialHint(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestTokenSet(t *testing.T) {
	result := tokenSet("read:compliance_activities, org:admin\tread:spend_limits")
	for _, key := range []string{"read:compliance_activities", "org:admin", "read:spend_limits"} {
		if !setContains(result, key) {
			t.Errorf("tokenSet missing %q", key)
		}
	}
}

func TestTokenSetEmpty(t *testing.T) {
	result := tokenSet("")
	if len(result) != 0 {
		t.Fatalf("tokenSet(\"\") = %v, want empty", result)
	}
}

func TestSetContainsTrimsKey(t *testing.T) {
	values := map[string]struct{}{"key": {}}
	if !setContains(values, "  key  ") {
		t.Fatal("setContains should trim key whitespace")
	}
}

func findCheck(checks []Check, id string) *Check {
	for i, check := range checks {
		if check.ID == id {
			return &checks[i]
		}
	}
	return nil
}
