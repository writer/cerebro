package sourceprojection

import (
	"strings"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

var openAIOracleAccessProfile = aiAccessProfile{Provider: "openai"}

// anthropicOracleAccessProfile keeps ai_access_test.go's anthropic-fixture
// coverage of the shared generic aiXxx projection helpers running after
// anthropic's own Go projection writer was retired to Rust authority
// (internal/sourceprojection/anthropic.go now fails closed for every
// anthropic.* kind). The mapping below mirrors the pre-retirement dispatch
// table in registry_builtins.go exactly, so these oracle overrides exercise
// the identical generic logic and URN shapes the removed anthropic.go
// wrappers in ai_access.go used to.
var anthropicOracleAccessProfile = aiAccessProfile{Provider: "anthropic"}

func newOpenAIOracleService(
	t *testing.T,
	state ports.ProjectionStateStore,
) *Service {
	t.Helper()
	builtinRegistry.mu.RLock()
	projectors := make([]EventProjector, 0, len(builtinRegistry.projectors))
	for kind, projector := range builtinRegistry.projectors {
		if oracle := openAIOracleProjectors[kind]; oracle != nil {
			projector = oracle
		} else if oracle := anthropicOracleProjectors[kind]; oracle != nil {
			projector = oracle
		} else if oracle := langChainOracleProjectors[kind]; oracle != nil {
			projector = oracle
		}
		projectors = append(projectors, EventProjector{Kind: kind, Project: projector})
	}
	builtinRegistry.mu.RUnlock()
	registry, err := NewRegistry(projectors...)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	return NewWithRegistry(state, nil, registry)
}

var openAIOracleProjectors = map[string]ProjectFunc{
	"openai.admin_api_key":                  openAIOracleAPIKeyProjections,
	"openai.api_key":                        openAIOracleAPIKeyProjections,
	"openai.audit_log":                      openAIOracleAuditProjections,
	"openai.certificate":                    openAIOracleGovernanceControlProjections,
	"openai.cost":                           openAIOracleUsageMetricProjections,
	"openai.data_retention":                 openAIOracleGovernanceControlProjections,
	"openai.group":                          openAIOracleGroupProjections,
	"openai.group_role":                     openAIOracleGroupRoleProjections,
	"openai.group_user":                     openAIOracleGroupUserProjections,
	"openai.invite":                         openAIOracleInviteProjections,
	"openai.project":                        openAIOracleProjectProjections,
	"openai.project_api_key":                openAIOracleAPIKeyProjections,
	"openai.project_certificate":            openAIOracleGovernanceControlProjections,
	"openai.project_data_retention":         openAIOracleGovernanceControlProjections,
	"openai.project_group":                  openAIOracleProjectGroupProjections,
	"openai.project_group_role":             openAIOracleProjectGroupRoleProjections,
	"openai.project_hosted_tool_permission": openAIOracleProjectEntitlementProjections,
	"openai.project_model_permission":       openAIOracleProjectEntitlementProjections,
	"openai.project_rate_limit":             openAIOracleGovernanceControlProjections,
	"openai.project_role":                   openAIOracleRoleProjections,
	"openai.project_service_account":        openAIOracleServiceAccountProjections,
	"openai.project_spend_alert":            openAIOracleGovernanceControlProjections,
	"openai.project_user":                   openAIOracleProjectUserProjections,
	"openai.project_user_role":              openAIOracleProjectUserRoleProjections,
	"openai.role":                           openAIOracleRoleProjections,
	"openai.service_account":                openAIOracleServiceAccountProjections,
	"openai.spend_alert":                    openAIOracleGovernanceControlProjections,
	"openai.usage_audio_speech":             openAIOracleUsageMetricProjections,
	"openai.usage_audio_transcription":      openAIOracleUsageMetricProjections,
	"openai.usage_code_interpreter_session": openAIOracleUsageMetricProjections,
	"openai.usage_completion":               openAIOracleUsageMetricProjections,
	"openai.usage_embedding":                openAIOracleUsageMetricProjections,
	"openai.usage_file_search_call":         openAIOracleUsageMetricProjections,
	"openai.usage_image":                    openAIOracleUsageMetricProjections,
	"openai.usage_moderation":               openAIOracleUsageMetricProjections,
	"openai.usage_vector_store":             openAIOracleUsageMetricProjections,
	"openai.usage_web_search_call":          openAIOracleUsageMetricProjections,
	"openai.user":                           openAIOracleUserProjections,
	"openai.user_role":                      openAIOracleUserRoleProjections,
}

// anthropicOracleProjectors is intentionally a separate map from
// openAIOracleProjectors: TestOpenAIGoProjectionFailsClosedForRustAuthoritativeFamilies
// iterates openAIOracleProjectors expecting every entry to be an OpenAI kind
// that fails closed with errOpenAIRustProjectionRequired, so anthropic's
// overrides must not live in that same map.
var anthropicOracleProjectors = map[string]ProjectFunc{
	"anthropic.analytics_cost":                  anthropicOracleUsageMetricProjections,
	"anthropic.api_key":                         anthropicOracleCredentialProjections,
	"anthropic.compliance_activity":             anthropicOracleAuditProjections,
	"anthropic.compliance_group":                anthropicOracleGroupRoleAssignmentProjections,
	"anthropic.compliance_group_member":         anthropicOracleGroupMembershipProjections,
	"anthropic.compliance_organization":         anthropicOracleOrganizationProjections,
	"anthropic.compliance_organization_setting": anthropicOracleGovernanceControlProjections,
	"anthropic.compliance_organization_user":    anthropicOracleUserProjections,
	"anthropic.compliance_project":              anthropicOracleProjectProjections,
	"anthropic.compliance_project_collaborator": anthropicOracleProjectCollaboratorProjections,
	"anthropic.compliance_role":                 anthropicOracleScopedRoleProjections,
	"anthropic.compliance_role_permission":      anthropicOracleRolePermissionProjections,
	"anthropic.cost_report":                     anthropicOracleUsageMetricProjections,
	"anthropic.external_key":                    anthropicOracleCredentialProjections,
	"anthropic.federation_issuer":               anthropicOracleFederationIssuerProjections,
	"anthropic.federation_rule":                 anthropicOracleFederationRuleProjections,
	"anthropic.invite":                          anthropicOracleInviteProjections,
	"anthropic.organization":                    anthropicOracleOrganizationProjections,
	"anthropic.rate_limit":                      anthropicOracleGovernanceControlProjections,
	"anthropic.service_account":                 anthropicOracleServiceAccountProjections,
	"anthropic.spend_limit":                     anthropicOracleGovernanceControlProjections,
	"anthropic.spend_limit_increase_request":    anthropicOracleGovernanceControlProjections,
	"anthropic.usage_report_claude_code":        anthropicOracleUsageMetricProjections,
	"anthropic.usage_report_message":            anthropicOracleUsageMetricProjections,
	"anthropic.user":                            anthropicOracleUserProjections,
	"anthropic.workspace":                       anthropicOracleWorkspaceProjections,
	"anthropic.workspace_member":                anthropicOracleWorkspaceMemberProjections,
	"anthropic.workspace_rate_limit":            anthropicOracleGovernanceControlProjections,
}

func anthropicOracleUserProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return aiUserProjections(event, anthropicOracleAccessProfile)
}

func anthropicOracleProjectProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return aiProjectProjections(event, anthropicOracleAccessProfile)
}

func anthropicOracleProjectCollaboratorProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return aiProjectCollaboratorProjections(event, anthropicOracleAccessProfile)
}

func anthropicOracleOrganizationProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return aiOrganizationProjections(event, anthropicOracleAccessProfile)
}

func anthropicOracleInviteProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return aiInviteProjections(event, anthropicOracleAccessProfile)
}

func anthropicOracleWorkspaceProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return aiWorkspaceProjections(event, anthropicOracleAccessProfile)
}

func anthropicOracleWorkspaceMemberProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return aiScopedUserAccessProjections(event, anthropicOracleAccessProfile, "workspace")
}

func anthropicOracleGroupRoleAssignmentProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return aiGroupRoleAssignmentProjections(event, anthropicOracleAccessProfile)
}

func anthropicOracleGroupMembershipProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return aiGroupMembershipProjections(event, anthropicOracleAccessProfile)
}

func anthropicOracleServiceAccountProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return aiServiceAccountProjections(event, anthropicOracleAccessProfile, "organization")
}

func anthropicOracleCredentialProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return aiCredentialProjections(event, anthropicOracleAccessProfile)
}

func anthropicOracleScopedRoleProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return aiScopedRoleProjections(event, anthropicOracleAccessProfile)
}

func anthropicOracleRolePermissionProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return aiRolePermissionProjections(event, anthropicOracleAccessProfile)
}

func anthropicOracleGovernanceControlProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return aiGovernanceControlProjections(event, anthropicOracleAccessProfile)
}

func anthropicOracleUsageMetricProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return aiUsageMetricProjections(event, anthropicOracleAccessProfile)
}

func anthropicOracleFederationIssuerProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return aiFederationIssuerProjections(event, anthropicOracleAccessProfile)
}

func anthropicOracleFederationRuleProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return aiFederationRuleProjections(event, anthropicOracleAccessProfile)
}

func anthropicOracleAuditProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return aiAuditProjections(event, anthropicOracleAccessProfile)
}

// langChainOracleAccessProfile keeps langchain_langfuse_test.go's
// langchain.workspace_member coverage of the shared aiScopedUserAccessProjections
// helper running after langchain's own Go projection writer was retired to
// Rust authority (internal/sourceprojection/langchain.go now fails closed for
// every langchain.* kind), the same pattern used above for anthropic.
var langChainOracleAccessProfile = aiAccessProfile{Provider: "langchain"}

var langChainOracleProjectors = map[string]ProjectFunc{
	"langchain.workspace_member": langChainOracleWorkspaceMemberProjections,
}

func langChainOracleWorkspaceMemberProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return aiScopedUserAccessProjections(event, langChainOracleAccessProfile, "workspace")
}

func openAIOracleUserProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return aiUserProjections(event, openAIOracleAccessProfile)
}

func openAIOracleProjectProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return aiProjectProjections(event, openAIOracleAccessProfile)
}

func openAIOracleInviteProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return aiInviteProjections(event, openAIOracleAccessProfile)
}

func openAIOracleGroupProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return aiGroupProjections(event, openAIOracleAccessProfile)
}

func openAIOracleGroupUserProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return aiGroupMembershipProjections(event, openAIOracleAccessProfile)
}

func openAIOracleProjectUserProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return aiScopedUserAccessProjections(event, openAIOracleAccessProfile, "project")
}

func openAIOracleServiceAccountProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return aiServiceAccountProjections(event, openAIOracleAccessProfile, "project")
}

func openAIOracleRoleProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return aiRoleProjections(event, openAIOracleAccessProfile)
}

func openAIOracleUserRoleProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return aiSubjectRoleProjections(event, openAIOracleAccessProfile, "user", "organization")
}

func openAIOracleGroupRoleProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return aiSubjectRoleProjections(event, openAIOracleAccessProfile, "group", "organization")
}

func openAIOracleProjectUserRoleProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return aiSubjectRoleProjections(event, openAIOracleAccessProfile, "user", "project")
}

func openAIOracleProjectGroupProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return aiScopedGroupAccessProjections(event, openAIOracleAccessProfile, "project")
}

func openAIOracleProjectGroupRoleProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return aiSubjectRoleProjections(event, openAIOracleAccessProfile, "group", "project")
}

func openAIOracleProjectEntitlementProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return aiProjectEntitlementProjections(event, openAIOracleAccessProfile)
}

func openAIOracleGovernanceControlProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return aiGovernanceControlProjections(event, openAIOracleAccessProfile)
}

func openAIOracleUsageMetricProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return aiUsageMetricProjections(event, openAIOracleAccessProfile)
}

func openAIOracleAuditProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return aiAuditProjections(event, openAIOracleAccessProfile)
}

func openAIOracleAPIKeyProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	entities, links, err := aiCredentialProjections(event, openAIOracleAccessProfile)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	credentialID := firstNonEmpty(attrs["api_key_id"], attrs["external_key_id"], attrs["credential_id"], attrs["id"])
	credentialURN := projectionURN(event.GetTenantId(), "openai_credential", credentialID)
	privileged := event.GetKind() == "openai.admin_api_key" || projectionBool(attrs["privileged"]) || strings.EqualFold(strings.TrimSpace(attrs["key_class"]), "admin")
	hasOwner := strings.TrimSpace(attrs["owner_user_id"]) != "" || strings.TrimSpace(attrs["owner_service_account_id"]) != "" || strings.TrimSpace(attrs["owner_id"]) != ""
	for _, entity := range entities {
		if entity == nil || entity.URN != credentialURN {
			continue
		}
		if entity.Attributes == nil {
			entity.Attributes = map[string]string{}
		}
		entity.Attributes["privileged"] = boolString(privileged)
		entity.Attributes["has_owner"] = boolString(hasOwner)
		entity.Attributes["orphaned_owner"] = boolString(privileged && !hasOwner)
		addEndpointAttribute(entity.Attributes, "owner_type", attrs["owner_type"])
		addEndpointAttribute(entity.Attributes, "key_class", attrs["key_class"])
	}
	return entities, links, nil
}
