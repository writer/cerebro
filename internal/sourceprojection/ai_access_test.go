package sourceprojection

import (
	"context"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestProjectOpenAIProjectAccessEdges(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	occurred := time.Date(2026, time.June, 18, 12, 0, 0, 0, time.UTC)

	events := []*cerebrov1.EventEnvelope{
		{
			Id:         "openai-project",
			TenantId:   "writer",
			SourceId:   "openai",
			Kind:       "openai.project",
			OccurredAt: timestamppb.New(occurred),
			Attributes: map[string]string{
				"family":     "project",
				"project_id": "proj_123",
				"name":       "Production",
				"status":     "active",
			},
		},
		{
			Id:         "openai-project-user-owner",
			TenantId:   "writer",
			SourceId:   "openai",
			Kind:       "openai.project_user",
			OccurredAt: timestamppb.New(occurred),
			Attributes: map[string]string{
				"email":      "alice@example.com",
				"family":     "project_user",
				"name":       "Alice Example",
				"project_id": "proj_123",
				"role":       "owner",
				"user_id":    "user_123",
			},
		},
		{
			Id:         "openai-project-key",
			TenantId:   "writer",
			SourceId:   "openai",
			Kind:       "openai.project_api_key",
			OccurredAt: timestamppb.New(occurred),
			Attributes: map[string]string{
				"api_key_id":    "fixture_123",
				"family":        "project_api_key",
				"name":          "prod-key",
				"owner_user_id": "user_123",
				"project_id":    "proj_123",
			},
		},
		{
			Id:         "openai-project-models",
			TenantId:   "writer",
			SourceId:   "openai",
			Kind:       "openai.project_model_permission",
			OccurredAt: timestamppb.New(occurred),
			Attributes: map[string]string{
				"family":     "project_model_permission",
				"model_ids":  "gpt-4.1,gpt-4o",
				"project_id": "proj_123",
			},
		},
	}
	for _, event := range events {
		if _, err := service.Project(context.Background(), event); err != nil {
			t.Fatalf("Project(%q) error = %v", event.GetId(), err)
		}
	}

	userURN := "urn:cerebro:writer:openai_user:user_123"
	projectURN := "urn:cerebro:writer:openai_project:proj_123"
	credentialURN := "urn:cerebro:writer:openai_credential:fixture_123" // #nosec G101 -- test credential URN fixture, not credential material.
	identityURN := "urn:cerebro:writer:identity:email:alice@example.com"
	modelURN := "urn:cerebro:writer:openai_model:gpt-4.1"

	if entity := state.entities[projectURN]; entity == nil || entity.EntityType != "openai.project" {
		t.Fatalf("project entity missing or wrong: %#v", entity)
	}
	assertProjectedLink(t, state, userURN, relationRepresentsIdentity, identityURN)
	assertProjectedLink(t, state, userURN, relationCanAdmin, projectURN)
	assertProjectedLink(t, state, userURN, relationAssignedTo, credentialURN)
	assertProjectedLink(t, state, credentialURN, relationCanPerform, projectURN)
	assertProjectedLink(t, state, projectURN, relationCanPerform, modelURN)
}

func TestProjectAnthropicProjectCollaboratorAccessEdges(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	occurred := time.Date(2026, time.June, 18, 12, 15, 0, 0, time.UTC)

	events := []*cerebrov1.EventEnvelope{
		{
			Id:         "anthropic-project",
			TenantId:   "writer",
			SourceId:   "anthropic",
			Kind:       "anthropic.compliance_project",
			OccurredAt: timestamppb.New(occurred),
			Attributes: map[string]string{
				"family":            "compliance_project",
				"name":              "Legal review",
				"organization_uuid": "org-uuid-1",
				"project_id":        "claude_proj_123",
				"status":            "active",
			},
		},
		{
			Id:         "anthropic-project-user-collaborator",
			TenantId:   "writer",
			SourceId:   "anthropic",
			Kind:       "anthropic.compliance_project_collaborator",
			OccurredAt: timestamppb.New(occurred),
			Attributes: map[string]string{
				"email":          "alice@example.com",
				"family":         "compliance_project_collaborator",
				"name":           "Alice Example",
				"principal_id":   "user_123",
				"principal_type": "user",
				"project_id":     "claude_proj_123",
				"role_id":        "project_admin",
				"role_name":      "Project admin",
				"user_id":        "user_123",
			},
		},
		{
			Id:         "anthropic-project-group-collaborator",
			TenantId:   "writer",
			SourceId:   "anthropic",
			Kind:       "anthropic.compliance_project_collaborator",
			OccurredAt: timestamppb.New(occurred),
			Attributes: map[string]string{
				"family":         "compliance_project_collaborator",
				"group_id":       "rbac_group_123",
				"name":           "Legal",
				"principal_id":   "rbac_group_123",
				"principal_type": "group",
				"project_id":     "claude_proj_123",
				"role_id":        "project_viewer",
				"role_name":      "Project viewer",
			},
		},
		{
			Id:         "anthropic-project-org-collaborator",
			TenantId:   "writer",
			SourceId:   "anthropic",
			Kind:       "anthropic.compliance_project_collaborator",
			OccurredAt: timestamppb.New(occurred),
			Attributes: map[string]string{
				"family":            "compliance_project_collaborator",
				"organization_uuid": "org-uuid-1",
				"principal_id":      "org-uuid-1",
				"principal_type":    "organization",
				"project_id":        "claude_proj_123",
				"role_id":           "project_viewer",
				"role_name":         "Project viewer",
			},
		},
	}
	for _, event := range events {
		if _, err := service.Project(context.Background(), event); err != nil {
			t.Fatalf("Project(%q) error = %v", event.GetId(), err)
		}
	}

	userURN := "urn:cerebro:writer:anthropic_user:user_123"
	groupURN := "urn:cerebro:writer:anthropic_group:rbac_group_123"
	orgURN := "urn:cerebro:writer:anthropic_org:org-uuid-1"
	projectURN := "urn:cerebro:writer:anthropic_project:claude_proj_123"
	adminRoleURN := "urn:cerebro:writer:anthropic_role:project:project_admin"
	viewerRoleURN := "urn:cerebro:writer:anthropic_role:project:project_viewer"
	identityURN := "urn:cerebro:writer:identity:email:alice@example.com"

	if entity := state.entities[projectURN]; entity == nil || entity.EntityType != "anthropic.project" {
		t.Fatalf("project entity missing or wrong: %#v", entity)
	}
	if entity := state.entities[adminRoleURN]; entity == nil || entity.EntityType != "anthropic.role" || entity.Label != "Project admin" || entity.Attributes["scope_kind"] != "project" {
		t.Fatalf("admin role entity missing or wrong: %#v", entity)
	}
	assertProjectedLink(t, state, projectURN, relationBelongsTo, orgURN)
	assertProjectedLink(t, state, userURN, relationRepresentsIdentity, identityURN)
	assertProjectedLink(t, state, userURN, relationCanAdmin, adminRoleURN)
	assertProjectedLink(t, state, userURN, relationCanAdmin, projectURN)
	assertProjectedLink(t, state, adminRoleURN, relationGrantsEntitlement, projectURN)
	assertProjectedLink(t, state, groupURN, relationAssignedTo, viewerRoleURN)
	assertProjectedLink(t, state, groupURN, relationCanPerform, projectURN)
	assertProjectedLink(t, state, orgURN, relationAssignedTo, viewerRoleURN)
	assertProjectedLink(t, state, orgURN, relationCanPerform, projectURN)
}

func TestProjectAIGovernanceControlEdges(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	occurred := time.Date(2026, time.June, 18, 12, 30, 0, 0, time.UTC)

	events := []*cerebrov1.EventEnvelope{
		{
			Id:         "openai-project-rate-limit",
			TenantId:   "writer",
			SourceId:   "openai",
			Kind:       "openai.project_rate_limit",
			OccurredAt: timestamppb.New(occurred),
			Attributes: map[string]string{
				"family":                       "project_rate_limit",
				"max_requests_per_1_minute":    "500",
				"model":                        "gpt-4o",
				"project_id":                   "proj_123",
				"rate_limit_id":                "rl_123",
				"batch_1_day_max_input_tokens": "1000000",
			},
		},
		{
			Id:         "anthropic-workspace-rate-limit",
			TenantId:   "writer",
			SourceId:   "anthropic",
			Kind:       "anthropic.workspace_rate_limit",
			OccurredAt: timestamppb.New(occurred),
			Attributes: map[string]string{
				"family":              "workspace_rate_limit",
				"model":               "claude-sonnet-4-20250514",
				"rate_limit_id":       "rl_456",
				"requests_per_minute": "100",
				"workspace_id":        "ws_123",
			},
		},
		{
			Id:         "anthropic-compliance-setting",
			TenantId:   "writer",
			SourceId:   "anthropic",
			Kind:       "anthropic.compliance_organization_setting",
			OccurredAt: timestamppb.New(occurred),
			Attributes: map[string]string{
				"family":            "compliance_organization_setting",
				"organization_uuid": "org-uuid-1",
				"setting_name":      "data_retention",
				"setting_type":      "boolean",
				"setting_value":     "true",
			},
		},
	}
	for _, event := range events {
		if _, err := service.Project(context.Background(), event); err != nil {
			t.Fatalf("Project(%q) error = %v", event.GetId(), err)
		}
	}

	openAIControlURN := "urn:cerebro:writer:openai_project_rate_limit:proj_123:rl_123:gpt-4o"
	openAIProjectURN := "urn:cerebro:writer:openai_project:proj_123"
	openAIModelURN := "urn:cerebro:writer:openai_model:gpt-4o"
	anthropicRateLimitURN := "urn:cerebro:writer:anthropic_workspace_rate_limit:ws_123:rl_456:claude-sonnet-4-20250514"
	anthropicWorkspaceURN := "urn:cerebro:writer:anthropic_workspace:ws_123"
	anthropicModelURN := "urn:cerebro:writer:anthropic_model:claude-sonnet-4-20250514"
	anthropicSettingURN := "urn:cerebro:writer:anthropic_compliance_organization_setting:org-uuid-1:data_retention"
	anthropicOrgURN := "urn:cerebro:writer:anthropic_org:org-uuid-1"

	if entity := state.entities[openAIControlURN]; entity == nil || entity.EntityType != "openai.project_rate_limit" || entity.Attributes["control_type"] != "rate_limit" || entity.Attributes["scope_kind"] != "project" {
		t.Fatalf("openai control entity missing or wrong: %#v", entity)
	}
	if entity := state.entities[anthropicSettingURN]; entity == nil || entity.EntityType != "anthropic.compliance_organization_setting" || entity.Attributes["control_type"] != "setting" {
		t.Fatalf("anthropic setting entity missing or wrong: %#v", entity)
	}
	assertProjectedLink(t, state, openAIControlURN, relationBelongsTo, openAIProjectURN)
	assertProjectedLink(t, state, openAIControlURN, relationAssociatedWith, openAIModelURN)
	assertProjectedLink(t, state, anthropicRateLimitURN, relationBelongsTo, anthropicWorkspaceURN)
	assertProjectedLink(t, state, anthropicRateLimitURN, relationAssociatedWith, anthropicModelURN)
	assertProjectedLink(t, state, anthropicSettingURN, relationBelongsTo, anthropicOrgURN)
}

func TestProjectAnthropicWorkspaceCredentialFederationAndComplianceEdges(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	occurred := time.Date(2026, time.June, 18, 13, 0, 0, 0, time.UTC)

	events := []*cerebrov1.EventEnvelope{
		{
			Id:         "anthropic-workspace",
			TenantId:   "writer",
			SourceId:   "anthropic",
			Kind:       "anthropic.workspace",
			OccurredAt: timestamppb.New(occurred),
			Attributes: map[string]string{
				"family":       "workspace",
				"name":         "Production",
				"workspace_id": "ws_123",
			},
		},
		{
			Id:         "anthropic-workspace-member",
			TenantId:   "writer",
			SourceId:   "anthropic",
			Kind:       "anthropic.workspace_member",
			OccurredAt: timestamppb.New(occurred),
			Attributes: map[string]string{
				"email":          "bob@example.com",
				"family":         "workspace_member",
				"name":           "Bob Example",
				"user_id":        "user_456",
				"workspace_id":   "ws_123",
				"workspace_role": "admin",
			},
		},
		{
			Id:         "anthropic-api-key",
			TenantId:   "writer",
			SourceId:   "anthropic",
			Kind:       "anthropic.api_key",
			OccurredAt: timestamppb.New(occurred),
			Attributes: map[string]string{
				"api_key_id":    "fixture_456",
				"family":        "api_key",
				"name":          "workspace-key",
				"owner_user_id": "user_456",
				"workspace_id":  "ws_123",
			},
		},
		{
			Id:         "anthropic-federation-rule",
			TenantId:   "writer",
			SourceId:   "anthropic",
			Kind:       "anthropic.federation_rule",
			OccurredAt: timestamppb.New(occurred),
			Attributes: map[string]string{
				"family":             "federation_rule",
				"federation_rule_id": "rule_123",
				"issuer_id":          "issuer_123",
				"service_account_id": "sa_123",
				"subject":            "repo:writer/cerebro:*",
			},
		},
		{
			Id:         "anthropic-compliance-activity",
			TenantId:   "writer",
			SourceId:   "anthropic",
			Kind:       "anthropic.compliance_activity",
			OccurredAt: timestamppb.New(occurred),
			Attributes: map[string]string{
				"activity_id":     "act_123",
				"activity_type":   "admin_api_key.created",
				"actor_email":     "bob@example.com",
				"actor_type":      "user_actor",
				"actor_user_id":   "user_456",
				"family":          "compliance_activity",
				"organization_id": "org_123",
			},
		},
	}
	for _, event := range events {
		if _, err := service.Project(context.Background(), event); err != nil {
			t.Fatalf("Project(%q) error = %v", event.GetId(), err)
		}
	}

	userURN := "urn:cerebro:writer:anthropic_user:user_456"
	workspaceURN := "urn:cerebro:writer:anthropic_workspace:ws_123"
	credentialURN := "urn:cerebro:writer:anthropic_credential:fixture_456" // #nosec G101 -- test credential URN fixture, not credential material.
	identityURN := "urn:cerebro:writer:identity:email:bob@example.com"
	ruleURN := "urn:cerebro:writer:anthropic_federation_rule:rule_123"
	serviceAccountURN := "urn:cerebro:writer:anthropic_service_account:sa_123"
	orgURN := "urn:cerebro:writer:anthropic_org:org_123"

	assertProjectedLink(t, state, userURN, relationRepresentsIdentity, identityURN)
	assertProjectedLink(t, state, userURN, relationCanAdmin, workspaceURN)
	assertProjectedLink(t, state, userURN, relationAssignedTo, credentialURN)
	assertProjectedLink(t, state, credentialURN, relationCanPerform, workspaceURN)
	assertProjectedLink(t, state, ruleURN, relationCanAssume, serviceAccountURN)
	assertProjectedLink(t, state, ruleURN, relationCanImpersonate, serviceAccountURN)
	assertProjectedLink(t, state, userURN, relationActedOn, orgURN)
}

func TestProjectAnthropicComplianceDirectoryGroupMembership(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	occurred := time.Date(2026, time.June, 18, 14, 0, 0, 0, time.UTC)

	events := []*cerebrov1.EventEnvelope{
		{
			Id:         "anthropic-compliance-group",
			TenantId:   "writer",
			SourceId:   "anthropic",
			Kind:       "anthropic.compliance_group",
			OccurredAt: timestamppb.New(occurred),
			Attributes: map[string]string{
				"family":            "compliance_group",
				"group_id":          "rbac_group_123",
				"group_name":        "Engineering",
				"organization_uuid": "org-uuid-1",
				"source_type":       "scim",
				"roles":             "rbac_role_123",
			},
		},
		{
			Id:         "anthropic-compliance-group-member",
			TenantId:   "writer",
			SourceId:   "anthropic",
			Kind:       "anthropic.compliance_group_member",
			OccurredAt: timestamppb.New(occurred),
			Attributes: map[string]string{
				"email":    "carol@example.com",
				"family":   "compliance_group_member",
				"group_id": "rbac_group_123",
				"user_id":  "user_789",
			},
		},
		{
			Id:         "anthropic-compliance-role-permission",
			TenantId:   "writer",
			SourceId:   "anthropic",
			Kind:       "anthropic.compliance_role_permission",
			OccurredAt: timestamppb.New(occurred),
			Attributes: map[string]string{
				"action":                 "read",
				"family":                 "compliance_role_permission",
				"organization_uuid":      "org-uuid-1",
				"permission_description": "Read retained chat content.",
				"permission_id":          "perm_read_chats",
				"permission_name":        "Read chats",
				"resource_type":          "chat",
				"role_id":                "rbac_role_123",
			},
		},
		{
			Id:         "anthropic-compliance-role",
			TenantId:   "writer",
			SourceId:   "anthropic",
			Kind:       "anthropic.compliance_role",
			OccurredAt: timestamppb.New(occurred),
			Attributes: map[string]string{
				"description":       "Read-only access to retained content for legal review.",
				"family":            "compliance_role",
				"name":              "Compliance Reviewer",
				"organization_uuid": "org-uuid-1",
				"role_id":           "rbac_role_123",
			},
		},
	}
	for _, event := range events {
		if _, err := service.Project(context.Background(), event); err != nil {
			t.Fatalf("Project(%q) error = %v", event.GetId(), err)
		}
	}

	userURN := "urn:cerebro:writer:anthropic_user:user_789"
	groupURN := "urn:cerebro:writer:anthropic_group:rbac_group_123"
	roleURN := "urn:cerebro:writer:anthropic_role:organization:rbac_role_123"
	entitlementURN := "urn:cerebro:writer:anthropic_entitlement:role_permission:rbac_role_123:perm_read_chats"
	capabilityURN := "urn:cerebro:writer:privileged_capability:ai_data_read"
	orgURN := "urn:cerebro:writer:anthropic_org:org-uuid-1"
	identityURN := "urn:cerebro:writer:identity:email:carol@example.com"

	if entity := state.entities[groupURN]; entity == nil || entity.EntityType != "anthropic.group" {
		t.Fatalf("group entity missing or wrong: %#v", entity)
	}
	if entity := state.entities[roleURN]; entity == nil || entity.EntityType != "anthropic.role" || entity.Label != "Compliance Reviewer" || entity.Attributes["role_id"] != "rbac_role_123" || entity.Attributes["scope_kind"] != "organization" {
		t.Fatalf("role entity missing or wrong: %#v", entity)
	}
	if entity := state.entities[entitlementURN]; entity == nil || entity.EntityType != "anthropic.entitlement" || entity.Label != "Read chats" || entity.Attributes["permission_id"] != "perm_read_chats" {
		t.Fatalf("entitlement entity missing or wrong: %#v", entity)
	}
	assertProjectedLink(t, state, groupURN, relationBelongsTo, orgURN)
	assertProjectedLink(t, state, roleURN, relationBelongsTo, orgURN)
	assertProjectedLink(t, state, roleURN, relationGrantsEntitlement, orgURN)
	assertProjectedLink(t, state, roleURN, relationGrantsEntitlement, entitlementURN)
	assertProjectedLink(t, state, entitlementURN, relationBelongsTo, orgURN)
	assertProjectedLink(t, state, entitlementURN, relationConfersCapability, capabilityURN)
	assertProjectedLink(t, state, groupURN, relationAssignedTo, roleURN)
	assertProjectedLink(t, state, groupURN, relationCanPerform, orgURN)
	assertProjectedLink(t, state, userURN, relationRepresentsIdentity, identityURN)
	assertProjectedLink(t, state, userURN, relationMemberOf, groupURN)
}
