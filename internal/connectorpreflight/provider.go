package connectorpreflight

import (
	"strings"

	"github.com/writer/cerebro/internal/resourcescope"
)

const (
	AnthropicCredentialKindAdminAPIKey         = "admin_api_key"
	AnthropicCredentialKindComplianceAccessKey = "compliance_access_key"
	AnthropicCredentialKindOrgAdminOAuth       = "org_admin_oauth"      // #nosec G101 -- credential kind label, not credential material.
	AnthropicCredentialKindScopedAdminAPIKey   = "scoped_admin_api_key" // #nosec G101 -- credential kind label, not credential material.
	OpenAICredentialKindAdminAPIKey            = "admin_api_key"
)

type Check struct {
	ID         string
	Label      string
	Status     string
	Severity   string
	Detail     string
	NextAction string
	Blocking   bool
}

func ProviderChecks(sourceID string, authMethod string, config map[string]string, policy resourcescope.Policy) []Check {
	switch strings.TrimSpace(sourceID) {
	case "aws":
		return awsProviderChecks(authMethod, config, policy)
	case "openai":
		return openAIProviderChecks(config, policy)
	case "anthropic":
		return anthropicProviderChecks(config, policy)
	default:
		return nil
	}
}

func awsProviderChecks(authMethod string, config map[string]string, policy resourcescope.Policy) []Check {
	checks := []Check{}
	if authMethod == "aws_sso_profile" || strings.TrimSpace(config["role_arn"]) != "" {
		checks = append(checks, Check{
			ID:       "aws_access_model",
			Label:    "AWS access model",
			Status:   "passed",
			Severity: "success",
			Detail:   "AWS access uses a role or deployment-managed SSO profile.",
		})
	} else {
		checks = append(checks, Check{
			ID:         "aws_access_model",
			Label:      "AWS access model",
			Status:     "warning",
			Severity:   "warning",
			Detail:     "Prefer AWS SSO or role assumption over long-lived access keys for production connections.",
			NextAction: "prefer_role_or_sso",
		})
	}
	if policy.ExcludesFamily("aws", "organizations_account") {
		checks = append(checks, Check{
			ID:       "aws_organizations_scope",
			Label:    "AWS Organizations coverage",
			Status:   "warning",
			Severity: "warning",
			Detail:   "Organizations families are scoped out, so account and OU discovery will be skipped.",
		})
	}
	return checks
}

func openAIProviderChecks(config map[string]string, policy resourcescope.Policy) []Check {
	family := strings.TrimSpace(config["family"])
	if family == "" {
		family = "user"
	}
	if policy.ExcludesFamily("openai", family) {
		return nil
	}
	if normalizedCredentialHint(config["credential_kind"]) == OpenAICredentialKindAdminAPIKey {
		return nil
	}
	return []Check{{
		ID:         "openai_admin_api_key",
		Label:      "OpenAI Admin API key",
		Status:     "warning",
		Severity:   "warning",
		Detail:     "OpenAI governance families read Admin API endpoints and require an Admin API key; record credential_kind=admin_api_key when configuring this runtime.",
		NextAction: "use_openai_admin_api_key",
	}}
}

func anthropicProviderChecks(config map[string]string, policy resourcescope.Policy) []Check {
	family := strings.TrimSpace(config["family"])
	if family == "" {
		family = "user"
	}
	if policy.ExcludesFamily("anthropic", family) {
		return nil
	}
	authModel := strings.ToLower(strings.TrimSpace(config["auth_model"]))
	if authModel == "" {
		authModel = "legacy_token"
	}
	credentialKind := normalizedCredentialHint(config["credential_kind"])
	scopes := tokenSet(config["credential_scopes"])
	checks := []Check{}
	switch family {
	case "service_account", "federation_issuer", "federation_rule":
		if authModel != "bearer_token" || (credentialKind != "" && credentialKind != AnthropicCredentialKindOrgAdminOAuth) || !setContains(scopes, "org:admin") {
			checks = append(checks, Check{
				ID:         "anthropic_org_admin_oauth",
				Label:      "Anthropic org admin OAuth",
				Status:     "warning",
				Severity:   "warning",
				Detail:     "Service account and workload identity federation families require an org:admin OAuth bearer token; set auth_model=bearer_token and record credential_scopes=org:admin when configuring this runtime.",
				NextAction: "use_anthropic_org_admin_oauth",
			})
		}
	case "compliance_activity":
		if authModel == "bearer_token" || (credentialKind != "" && credentialKind != AnthropicCredentialKindAdminAPIKey && credentialKind != AnthropicCredentialKindComplianceAccessKey) || !setContains(scopes, "read:compliance_activities") {
			checks = append(checks, Check{
				ID:         "anthropic_compliance_scope",
				Label:      "Anthropic compliance scope",
				Status:     "warning",
				Severity:   "warning",
				Detail:     "Compliance Activity Feed reads use x-api-key and require read:compliance_activities on an Admin API key or Compliance Access Key; record credential_kind and credential_scopes to make that explicit.",
				NextAction: "confirm_anthropic_compliance_scope",
			})
		}
	case "compliance_organization", "compliance_role", "compliance_group":
		checks = append(checks, anthropicComplianceAccessKeyCheck(authModel, credentialKind, scopes, anthropicCompliancePreflight{
			RequiredScope: "read:compliance_org_data",
			ID:            "anthropic_compliance_org_data_scope",
			Label:         "Anthropic compliance org-data scope",
			Detail:        "Compliance organization, role, and group families use x-api-key and require read:compliance_org_data on a Compliance Access Key; record credential_kind=compliance_access_key and credential_scopes=read:compliance_org_data.",
		})...)
	case "compliance_organization_user", "compliance_group_member":
		checks = append(checks, anthropicComplianceAccessKeyCheck(authModel, credentialKind, scopes, anthropicCompliancePreflight{
			RequiredScope: "read:compliance_user_data",
			ID:            "anthropic_compliance_user_data_scope",
			Label:         "Anthropic compliance user-data scope",
			Detail:        "Compliance user and group-member families use x-api-key and require read:compliance_user_data on a Compliance Access Key; record credential_kind=compliance_access_key and credential_scopes=read:compliance_user_data.",
		})...)
	case "compliance_organization_setting":
		checks = append(checks, anthropicComplianceAccessKeyCheck(authModel, credentialKind, scopes, anthropicCompliancePreflight{
			RequiredScope: "read:compliance_org_settings",
			ID:            "anthropic_compliance_org_settings_scope",
			Label:         "Anthropic compliance settings scope",
			Detail:        "Compliance organization settings use x-api-key and require read:compliance_org_settings on a Compliance Access Key; record credential_kind=compliance_access_key and credential_scopes=read:compliance_org_settings.",
		})...)
	case "spend_limit", "spend_limit_increase_request":
		if authModel == "bearer_token" || (credentialKind != "" && credentialKind != AnthropicCredentialKindScopedAdminAPIKey) || !setContains(scopes, "read:spend_limits") {
			checks = append(checks, Check{
				ID:         "anthropic_spend_limit_scope",
				Label:      "Anthropic spend-limit scope",
				Status:     "warning",
				Severity:   "warning",
				Detail:     "Read-only spend-limit families require an Enterprise scoped Admin API key with read:spend_limits in x-api-key; record credential_kind=scoped_admin_api_key and credential_scopes=read:spend_limits.",
				NextAction: "confirm_anthropic_spend_limit_scope",
			})
		}
	}
	return checks
}

type anthropicCompliancePreflight struct {
	RequiredScope string
	ID            string
	Label         string
	Detail        string
}

func anthropicComplianceAccessKeyCheck(authModel string, credentialKind string, scopes map[string]struct{}, preflight anthropicCompliancePreflight) []Check {
	if authModel != "bearer_token" && (credentialKind == "" || credentialKind == AnthropicCredentialKindComplianceAccessKey) && setContains(scopes, preflight.RequiredScope) {
		return nil
	}
	return []Check{{
		ID:         preflight.ID,
		Label:      preflight.Label,
		Status:     "warning",
		Severity:   "warning",
		Detail:     preflight.Detail,
		NextAction: "confirm_anthropic_compliance_scope",
	}}
}

func normalizedCredentialHint(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	replacer := strings.NewReplacer("-", "_", " ", "_")
	value = replacer.Replace(value)
	switch value {
	case "oauth", "oauth_bearer", "org_admin", "org_admin_token":
		return AnthropicCredentialKindOrgAdminOAuth
	case "admin", "admin_key", "admin_api":
		return AnthropicCredentialKindAdminAPIKey
	case "compliance", "compliance_key":
		return AnthropicCredentialKindComplianceAccessKey
	case "spend_limit_admin_key", "spend_limits_admin_key":
		return AnthropicCredentialKindScopedAdminAPIKey
	default:
		return value
	}
}

func tokenSet(value string) map[string]struct{} {
	tokens := map[string]struct{}{}
	for _, token := range strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\n' || r == '\t'
	}) {
		token = strings.ToLower(strings.TrimSpace(token))
		if token != "" {
			tokens[token] = struct{}{}
		}
	}
	return tokens
}

func setContains(values map[string]struct{}, key string) bool {
	_, ok := values[strings.TrimSpace(key)]
	return ok
}
