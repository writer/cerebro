package sourceprojection

import (
	"strings"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

var openAIOracleAccessProfile = aiAccessProfile{Provider: "openai"}

func newOpenAIOracleService(t *testing.T, state ports.ProjectionStateStore) *Service {
	t.Helper()
	builtinRegistry.mu.RLock()
	projectors := make([]EventProjector, 0, len(builtinRegistry.projectors))
	for kind, projector := range builtinRegistry.projectors {
		if oracle := openAIOracleProjectors[kind]; oracle != nil {
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
