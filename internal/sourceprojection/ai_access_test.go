package sourceprojection

import (
	"context"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
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

func TestProjectOpenAIAuditDeepAccessEvidence(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	occurred := time.Date(2026, time.June, 18, 12, 5, 0, 0, time.UTC)

	events := []*cerebrov1.EventEnvelope{
		{
			Id:         "openai-audit-api-key",
			TenantId:   "writer",
			SourceId:   "openai",
			Kind:       "openai.audit_log",
			OccurredAt: timestamppb.New(occurred),
			Attributes: map[string]string{
				"actor_api_key_id":         "key_actor",
				"actor_service_account_id": "sa_123",
				"api_key_id":               "key_target",
				"event_type":               "api_key.updated",
				"family":                   "audit_log",
			},
		},
		{
			Id:         "openai-audit-role-assignment",
			TenantId:   "writer",
			SourceId:   "openai",
			Kind:       "openai.audit_log",
			OccurredAt: timestamppb.New(occurred),
			Attributes: map[string]string{
				"actor_email":    "admin@example.com",
				"actor_user_id":  "user_admin",
				"event_type":     "role.assignment.created",
				"family":         "audit_log",
				"principal_id":   "group_123",
				"principal_type": "group",
				"resource_id":    "proj_456",
				"resource_type":  "project",
			},
		},
		{
			Id:         "openai-audit-group",
			TenantId:   "writer",
			SourceId:   "openai",
			Kind:       "openai.audit_log",
			OccurredAt: timestamppb.New(occurred),
			Attributes: map[string]string{
				"actor_email":   "admin@example.com",
				"actor_user_id": "user_admin",
				"event_type":    "group.updated",
				"family":        "audit_log",
				"group_id":      "group_999",
				"group_name":    "Engineering",
			},
		},
	}
	for _, event := range events {
		if _, err := service.Project(context.Background(), event); err != nil {
			t.Fatalf("Project(%q) error = %v", event.GetId(), err)
		}
	}

	actorCredentialURN := "urn:cerebro:writer:openai_credential:key_actor"   // #nosec G101 -- test credential URN fixture, not credential material.
	targetCredentialURN := "urn:cerebro:writer:openai_credential:key_target" // #nosec G101 -- test credential URN fixture, not credential material.
	serviceAccountURN := "urn:cerebro:writer:openai_service_account:sa_123"
	userURN := "urn:cerebro:writer:openai_user:user_admin"
	projectURN := "urn:cerebro:writer:openai_project:proj_456"
	groupURN := "urn:cerebro:writer:openai_group:group_123"
	identityURN := "urn:cerebro:writer:identity:email:admin@example.com"

	assertProjectedLink(t, state, serviceAccountURN, relationAssignedTo, actorCredentialURN)
	assertProjectedLink(t, state, actorCredentialURN, relationActedOn, targetCredentialURN)
	assertProjectedLink(t, state, userURN, relationRepresentsIdentity, identityURN)
	assertProjectedLink(t, state, userURN, relationActedOn, projectURN)
	assertProjectedLink(t, state, userURN, relationActedOn, groupURN)
	if got := state.entities[actorCredentialURN].Attributes["actor_service_account_id"]; got != "sa_123" {
		t.Fatalf("actor credential actor_service_account_id = %q, want sa_123", got)
	}
	if got := state.entities[targetCredentialURN].Attributes["actor_service_account_id"]; got != "" {
		t.Fatalf("target credential actor_service_account_id = %q, want empty", got)
	}
	link := state.links[actorCredentialURN+"|"+relationActedOn+"|"+targetCredentialURN]
	if got := link.Attributes["event_type"]; got != "api_key.updated" {
		t.Fatalf("acted_on event_type = %q, want api_key.updated", got)
	}
	if got := link.Attributes["actor_type"]; got != "credential" {
		t.Fatalf("acted_on actor_type = %q, want credential", got)
	}
}

func TestProjectAnthropicComplianceActivityResourceEvidence(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	occurred := time.Date(2026, time.June, 18, 12, 7, 0, 0, time.UTC)

	events := []*cerebrov1.EventEnvelope{
		{
			Id:         "anthropic-compliance-chat",
			TenantId:   "writer",
			SourceId:   "anthropic",
			Kind:       "anthropic.compliance_activity",
			OccurredAt: timestamppb.New(occurred),
			Attributes: map[string]string{
				"activity_id":       "activity_chat_123",
				"activity_type":     "claude_chat_created",
				"actor_email":       "alice@example.com",
				"actor_type":        "user_actor",
				"actor_user_id":     "user_123",
				"claude_chat_id":    "claude_chat_123",
				"claude_project_id": "claude_proj_123",
				"family":            "compliance_activity",
				"project_id":        "claude_proj_123",
			},
		},
		{
			Id:         "anthropic-compliance-api-access",
			TenantId:   "writer",
			SourceId:   "anthropic",
			Kind:       "anthropic.compliance_activity",
			OccurredAt: timestamppb.New(occurred),
			Attributes: map[string]string{
				"activity_id":            "activity_api_123",
				"activity_type":          "compliance_api_accessed",
				"actor_admin_api_key_id": "admin_key_123",
				"actor_type":             "admin_api_key_actor",
				"family":                 "compliance_activity",
				"organization_id":        "org_123",
				"organization_uuid":      "org-uuid-1",
			},
		},
	}
	for _, event := range events {
		if _, err := service.Project(context.Background(), event); err != nil {
			t.Fatalf("Project(%q) error = %v", event.GetId(), err)
		}
	}

	userURN := "urn:cerebro:writer:anthropic_user:user_123"
	identityURN := "urn:cerebro:writer:identity:email:alice@example.com"
	chatResourceURN := "urn:cerebro:writer:anthropic_resource:claude_chat:claude_chat_123"
	projectURN := "urn:cerebro:writer:anthropic_project:claude_proj_123"
	adminKeyURN := "urn:cerebro:writer:anthropic_credential:admin_key_123" // #nosec G101 -- test credential URN fixture, not credential material.
	orgURN := "urn:cerebro:writer:anthropic_org:org_123"

	if entity := state.entities[chatResourceURN]; entity == nil || entity.EntityType != "anthropic.resource" || entity.Attributes["resource_type"] != "claude_chat" {
		t.Fatalf("chat resource entity missing or wrong: %#v", entity)
	}
	assertProjectedLink(t, state, userURN, relationRepresentsIdentity, identityURN)
	assertProjectedLink(t, state, userURN, relationActedOn, chatResourceURN)
	assertProjectedLink(t, state, chatResourceURN, relationBelongsTo, projectURN)
	assertProjectedLink(t, state, adminKeyURN, relationActedOn, orgURN)
}

func TestProjectAIOrganizationInviteAccessIntent(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	occurred := time.Date(2026, time.June, 18, 12, 10, 0, 0, time.UTC)

	events := []*cerebrov1.EventEnvelope{
		{
			Id:         "openai-pending-invite",
			TenantId:   "writer",
			SourceId:   "openai",
			Kind:       "openai.invite",
			OccurredAt: timestamppb.New(occurred),
			Payload: []byte(`{
				"id": "invite_openai_123",
				"email": "future-owner@example.com",
				"role": "owner",
				"status": "pending",
				"projects": [
					{"id": "proj_123", "role": "owner"},
					{"id": "proj_456", "role": "member"}
				]
			}`),
			Attributes: map[string]string{
				"email":      "future-owner@example.com",
				"family":     "invite",
				"invite_id":  "invite_openai_123",
				"role":       "owner",
				"status":     "pending",
				"created_at": "2026-06-18T12:10:00Z",
				"expires_at": "2026-06-25T12:10:00Z",
			},
		},
		{
			Id:         "openai-expired-invite",
			TenantId:   "writer",
			SourceId:   "openai",
			Kind:       "openai.invite",
			OccurredAt: timestamppb.New(occurred),
			Payload: []byte(`{
				"id": "invite_openai_expired",
				"email": "expired-owner@example.com",
				"role": "owner",
				"status": "expired",
				"projects": [
					{"id": "proj_expired", "role": "owner"}
				]
			}`),
			Attributes: map[string]string{
				"email":     "expired-owner@example.com",
				"family":    "invite",
				"invite_id": "invite_openai_expired",
				"role":      "owner",
				"status":    "expired",
			},
		},
		{
			Id:         "openai-accepted-invite",
			TenantId:   "writer",
			SourceId:   "openai",
			Kind:       "openai.invite",
			OccurredAt: timestamppb.New(occurred),
			Payload: []byte(`{
				"id": "invite_openai_accepted",
				"email": "accepted-member@example.com",
				"role": "member",
				"status": "accepted",
				"projects": [
					{"id": "proj_accepted", "role": "member"}
				]
			}`),
			Attributes: map[string]string{
				"email":       "accepted-member@example.com",
				"family":      "invite",
				"invite_id":   "invite_openai_accepted",
				"role":        "member",
				"status":      "accepted",
				"accepted_at": "2026-06-18T12:12:00Z",
			},
		},
		{
			Id:         "anthropic-pending-invite",
			TenantId:   "writer",
			SourceId:   "anthropic",
			Kind:       "anthropic.invite",
			OccurredAt: timestamppb.New(occurred),
			Attributes: map[string]string{
				"email":      "future-dev@example.com",
				"family":     "invite",
				"invite_id":  "invite_anthropic_123",
				"role":       "developer",
				"status":     "pending",
				"created_at": "2026-06-18T12:10:00Z",
				"expires_at": "2026-06-25T12:10:00Z",
			},
		},
		{
			Id:         "anthropic-expired-invite",
			TenantId:   "writer",
			SourceId:   "anthropic",
			Kind:       "anthropic.invite",
			OccurredAt: timestamppb.New(occurred),
			Attributes: map[string]string{
				"email":     "expired@example.com",
				"family":    "invite",
				"invite_id": "invite_anthropic_expired",
				"role":      "admin",
				"status":    "expired",
			},
		},
	}
	for _, event := range events {
		if _, err := service.Project(context.Background(), event); err != nil {
			t.Fatalf("Project(%q) error = %v", event.GetId(), err)
		}
	}

	openAIInviteURN := "urn:cerebro:writer:openai_invite:invite_openai_123"
	openAIExpiredInviteURN := "urn:cerebro:writer:openai_invite:invite_openai_expired"
	openAIOrgURN := "urn:cerebro:writer:openai_org:openai"
	openAIRoleURN := "urn:cerebro:writer:openai_role:organization:owner"
	openAIProjectOwnerRoleURN := "urn:cerebro:writer:openai_role:project:owner"
	openAIProjectMemberRoleURN := "urn:cerebro:writer:openai_role:project:member"
	openAIProjectOwnerURN := "urn:cerebro:writer:openai_project:proj_123"
	openAIProjectMemberURN := "urn:cerebro:writer:openai_project:proj_456"
	openAIExpiredProjectURN := "urn:cerebro:writer:openai_project:proj_expired"
	openAIAcceptedInviteURN := "urn:cerebro:writer:openai_invite:invite_openai_accepted"
	openAIAcceptedProjectURN := "urn:cerebro:writer:openai_project:proj_accepted"
	anthropicInviteURN := "urn:cerebro:writer:anthropic_invite:invite_anthropic_123"
	anthropicExpiredInviteURN := "urn:cerebro:writer:anthropic_invite:invite_anthropic_expired"
	anthropicOrgURN := "urn:cerebro:writer:anthropic_org:anthropic"
	anthropicRoleURN := "urn:cerebro:writer:anthropic_role:organization:developer"
	openAIIdentityURN := "urn:cerebro:writer:identity:email:future-owner@example.com"
	anthropicIdentityURN := "urn:cerebro:writer:identity:email:future-dev@example.com"

	if entity := state.entities[openAIInviteURN]; entity == nil || entity.EntityType != "openai.invite" || entity.Attributes["access_state"] != "invited" {
		t.Fatalf("openai invite entity missing or wrong: %#v", entity)
	}
	if entity := state.entities[anthropicExpiredInviteURN]; entity == nil || entity.Attributes["access_state"] != "expired" {
		t.Fatalf("expired invite entity missing or wrong: %#v", entity)
	}
	if entity := state.entities[openAIAcceptedInviteURN]; entity == nil || entity.Attributes["access_state"] != "accepted" {
		t.Fatalf("accepted invite entity missing or wrong: %#v", entity)
	}
	assertProjectedLink(t, state, openAIInviteURN, relationBelongsTo, openAIOrgURN)
	assertProjectedLink(t, state, openAIInviteURN, relationRepresentsIdentity, openAIIdentityURN)
	assertProjectedLink(t, state, openAIInviteURN, relationCanAdmin, openAIRoleURN)
	assertProjectedLink(t, state, openAIRoleURN, relationGrantsEntitlement, openAIOrgURN)
	assertProjectedLink(t, state, openAIInviteURN, relationCanAdmin, openAIOrgURN)
	assertProjectedLink(t, state, openAIInviteURN, relationCanAdmin, openAIProjectOwnerRoleURN)
	assertProjectedLink(t, state, openAIProjectOwnerRoleURN, relationGrantsEntitlement, openAIProjectOwnerURN)
	assertProjectedLink(t, state, openAIInviteURN, relationCanAdmin, openAIProjectOwnerURN)
	assertProjectedLink(t, state, openAIInviteURN, relationAssignedTo, openAIProjectMemberRoleURN)
	assertProjectedLink(t, state, openAIProjectMemberRoleURN, relationGrantsEntitlement, openAIProjectMemberURN)
	assertProjectedLink(t, state, openAIInviteURN, relationCanPerform, openAIProjectMemberURN)
	assertProjectedLinkMissing(t, state, openAIExpiredInviteURN, relationCanAdmin, openAIExpiredProjectURN)
	assertProjectedLink(t, state, openAIAcceptedInviteURN, relationCanPerform, openAIOrgURN)
	assertProjectedLink(t, state, openAIAcceptedInviteURN, relationCanPerform, openAIAcceptedProjectURN)
	assertProjectedLink(t, state, anthropicInviteURN, relationBelongsTo, anthropicOrgURN)
	assertProjectedLink(t, state, anthropicInviteURN, relationRepresentsIdentity, anthropicIdentityURN)
	assertProjectedLink(t, state, anthropicInviteURN, relationAssignedTo, anthropicRoleURN)
	assertProjectedLink(t, state, anthropicInviteURN, relationCanPerform, anthropicOrgURN)
	assertProjectedLinkMissing(t, state, anthropicExpiredInviteURN, relationCanAdmin, anthropicOrgURN)
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
		{
			Id:         "anthropic-compliance-setting-with-org-id",
			TenantId:   "writer",
			SourceId:   "anthropic",
			Kind:       "anthropic.compliance_organization_setting",
			OccurredAt: timestamppb.New(occurred),
			Attributes: map[string]string{
				"family":            "compliance_organization_setting",
				"organization_id":   "org-id-1",
				"organization_uuid": "org-uuid-1",
				"setting_name":      "data_retention",
				"setting_type":      "boolean",
				"setting_value":     "false",
			},
		},
		{
			Id:         "openai-data-retention",
			TenantId:   "writer",
			SourceId:   "openai",
			Kind:       "openai.data_retention",
			OccurredAt: timestamppb.New(occurred),
			Attributes: map[string]string{
				"family":          "data_retention",
				"object":          "chat",
				"organization_id": "org_123",
				"retention_type":  "30d",
			},
		},
		{
			Id:         "openai-data-retention-with-org-uuid",
			TenantId:   "writer",
			SourceId:   "openai",
			Kind:       "openai.data_retention",
			OccurredAt: timestamppb.New(occurred),
			Attributes: map[string]string{
				"family":            "data_retention",
				"object":            "chat",
				"organization_id":   "org_123",
				"organization_uuid": "org_uuid_123",
				"retention_type":    "30d",
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
	anthropicUnstableSettingURN := "urn:cerebro:writer:anthropic_compliance_organization_setting:org-uuid-1:org-id-1:data_retention"
	anthropicOrgURN := "urn:cerebro:writer:anthropic_org:org-uuid-1"
	openAIDataRetentionURN := "urn:cerebro:writer:openai_data_retention:org_123:30d:chat"
	openAIUnstableDataRetentionURN := "urn:cerebro:writer:openai_data_retention:org_123:org_uuid_123:30d:chat"

	if entity := state.entities[openAIControlURN]; entity == nil || entity.EntityType != "openai.project_rate_limit" || entity.Attributes["control_type"] != "rate_limit" || entity.Attributes["scope_kind"] != "project" {
		t.Fatalf("openai control entity missing or wrong: %#v", entity)
	}
	if entity := state.entities[anthropicSettingURN]; entity == nil || entity.EntityType != "anthropic.compliance_organization_setting" || entity.Attributes["control_type"] != "setting" {
		t.Fatalf("anthropic setting entity missing or wrong: %#v", entity)
	}
	if entity := state.entities[anthropicUnstableSettingURN]; entity != nil {
		t.Fatalf("anthropic setting projected unstable dual-org URN: %#v", entity)
	}
	if entity := state.entities[openAIDataRetentionURN]; entity == nil || entity.EntityType != "openai.data_retention" || entity.Attributes["control_type"] != "data_retention" {
		t.Fatalf("openai data retention entity missing or wrong: %#v", entity)
	}
	if entity := state.entities[openAIUnstableDataRetentionURN]; entity != nil {
		t.Fatalf("openai data retention projected unstable dual-org URN: %#v", entity)
	}
	assertProjectedLink(t, state, openAIControlURN, relationBelongsTo, openAIProjectURN)
	assertProjectedLink(t, state, openAIControlURN, relationAssociatedWith, openAIModelURN)
	assertProjectedLink(t, state, anthropicRateLimitURN, relationBelongsTo, anthropicWorkspaceURN)
	assertProjectedLink(t, state, anthropicRateLimitURN, relationAssociatedWith, anthropicModelURN)
	assertProjectedLink(t, state, anthropicSettingURN, relationBelongsTo, anthropicOrgURN)
}

func TestProjectAIUsageAndCostMetricEdges(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	occurred := time.Date(2026, time.June, 18, 12, 45, 0, 0, time.UTC)

	events := []*cerebrov1.EventEnvelope{
		{
			Id:         "openai-usage-completion",
			TenantId:   "writer",
			SourceId:   "openai",
			Kind:       "openai.usage_completion",
			OccurredAt: timestamppb.New(occurred),
			Attributes: map[string]string{
				"api_key_id":         "fixture_123",
				"end_time":           "2026-06-18T13:00:00Z",
				"family":             "usage_completion",
				"id":                 "usage_123",
				"input_tokens":       "1200",
				"model":              "gpt-4o",
				"num_model_requests": "5",
				"output_tokens":      "320",
				"project_id":         "proj_123",
				"start_time":         "2026-06-18T12:00:00Z",
				"user_id":            "user_123",
			},
		},
		{
			Id:         "anthropic-cost-report",
			TenantId:   "writer",
			SourceId:   "anthropic",
			Kind:       "anthropic.cost_report",
			OccurredAt: timestamppb.New(occurred),
			Attributes: map[string]string{
				"api_key_id":      "fixture_456",
				"cost_usd":        "42.50",
				"end_time":        "2026-06-18T13:00:00Z",
				"family":          "cost_report",
				"id":              "cost_123",
				"model":           "claude-sonnet-4-20250514",
				"organization_id": "org_123",
				"start_time":      "2026-06-18T12:00:00Z",
				"user_id":         "user_456",
				"workspace_id":    "ws_123",
			},
		},
	}
	for _, event := range events {
		if _, err := service.Project(context.Background(), event); err != nil {
			t.Fatalf("Project(%q) error = %v", event.GetId(), err)
		}
	}

	openAIMetricURN := "urn:cerebro:writer:openai_usage_completion:usage_123"
	openAIOrgURN := "urn:cerebro:writer:openai_org:openai"
	openAIProjectURN := "urn:cerebro:writer:openai_project:proj_123"
	openAIUserURN := "urn:cerebro:writer:openai_user:user_123"
	openAICredentialURN := "urn:cerebro:writer:openai_credential:fixture_123" // #nosec G101 -- test credential URN fixture, not credential material.
	openAIModelURN := "urn:cerebro:writer:openai_model:gpt-4o"
	anthropicMetricURN := "urn:cerebro:writer:anthropic_cost_report:cost_123"
	anthropicOrgURN := "urn:cerebro:writer:anthropic_org:org_123"
	anthropicWorkspaceURN := "urn:cerebro:writer:anthropic_workspace:ws_123"
	anthropicUserURN := "urn:cerebro:writer:anthropic_user:user_456"
	anthropicCredentialURN := "urn:cerebro:writer:anthropic_credential:fixture_456" // #nosec G101 -- test credential URN fixture, not credential material.
	anthropicModelURN := "urn:cerebro:writer:anthropic_model:claude-sonnet-4-20250514"

	if entity := state.entities[openAIMetricURN]; entity == nil || entity.EntityType != "openai.usage_completion" || entity.Attributes["metric_type"] != "usage" {
		t.Fatalf("openai usage metric entity missing or wrong: %#v", entity)
	}
	if entity := state.entities[anthropicMetricURN]; entity == nil || entity.EntityType != "anthropic.cost_report" || entity.Attributes["metric_type"] != "cost" {
		t.Fatalf("anthropic cost metric entity missing or wrong: %#v", entity)
	}
	assertProjectedLink(t, state, openAIMetricURN, relationBelongsTo, openAIOrgURN)
	assertProjectedLink(t, state, openAIMetricURN, relationObservedOn, openAIProjectURN)
	assertProjectedLink(t, state, openAIMetricURN, relationObservedOn, openAIUserURN)
	assertProjectedLink(t, state, openAIMetricURN, relationObservedOn, openAICredentialURN)
	assertProjectedLink(t, state, openAIMetricURN, relationAssociatedWith, openAIModelURN)
	assertProjectedLink(t, state, anthropicMetricURN, relationBelongsTo, anthropicOrgURN)
	assertProjectedLink(t, state, anthropicMetricURN, relationObservedOn, anthropicWorkspaceURN)
	assertProjectedLink(t, state, anthropicMetricURN, relationObservedOn, anthropicUserURN)
	assertProjectedLink(t, state, anthropicMetricURN, relationObservedOn, anthropicCredentialURN)
	assertProjectedLink(t, state, anthropicMetricURN, relationAssociatedWith, anthropicModelURN)
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
			Id:         "anthropic-compliance-role-permission-sparse",
			TenantId:   "writer",
			SourceId:   "anthropic",
			Kind:       "anthropic.compliance_role_permission",
			OccurredAt: timestamppb.New(occurred),
			Attributes: map[string]string{
				"family":            "compliance_role_permission",
				"organization_uuid": "org-uuid-1",
				"role_id":           "rbac_role_123",
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
	sparseEntitlementURN := "urn:cerebro:writer:anthropic_entitlement:role_permission:rbac_role_123:anthropic-compliance-role-permission-sparse"
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
	if entity := state.entities[sparseEntitlementURN]; entity != nil {
		t.Fatalf("sparse role permission projected unstable entitlement: %#v", entity)
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

func TestProjectAnthropicInventoryEntitiesDeterministic(t *testing.T) {
	occurred := time.Date(2026, time.June, 18, 12, 0, 0, 0, time.UTC)

	t.Run("user", func(t *testing.T) {
		state := projectAnthropicInventoryEvent(t, &cerebrov1.EventEnvelope{
			Id:         "anthropic-user",
			TenantId:   "writer",
			SourceId:   "anthropic",
			Kind:       "anthropic.user",
			OccurredAt: timestamppb.New(occurred),
			Attributes: map[string]string{
				"family":  "user",
				"user_id": "user_123",
				"email":   "alice@example.com",
				"name":    "Alice Example",
				"role":    "admin",
				"status":  "active",
			},
		})
		userURN := "urn:cerebro:writer:anthropic_user:user_123"
		entity := state.entities[userURN]
		if entity == nil || entity.EntityType != "anthropic.user" || entity.Attributes["user_id"] != "user_123" || entity.Attributes["is_admin"] != "true" {
			t.Fatalf("anthropic user entity missing or wrong: %#v", entity)
		}
		assertProjectedLink(t, state, userURN, relationRepresentsIdentity, "urn:cerebro:writer:identity:email:alice@example.com")
	})

	t.Run("workspace", func(t *testing.T) {
		state := projectAnthropicInventoryEvent(t, &cerebrov1.EventEnvelope{
			Id:         "anthropic-workspace",
			TenantId:   "writer",
			SourceId:   "anthropic",
			Kind:       "anthropic.workspace",
			OccurredAt: timestamppb.New(occurred),
			Attributes: map[string]string{
				"family":          "workspace",
				"workspace_id":    "ws_123",
				"name":            "Research",
				"organization_id": "org_123",
			},
		})
		workspaceURN := "urn:cerebro:writer:anthropic_workspace:ws_123"
		entity := state.entities[workspaceURN]
		if entity == nil || entity.EntityType != "anthropic.workspace" || entity.Attributes["workspace_id"] != "ws_123" {
			t.Fatalf("anthropic workspace entity missing or wrong: %#v", entity)
		}
		assertProjectedLink(t, state, workspaceURN, relationBelongsTo, "urn:cerebro:writer:anthropic_org:org_123")
	})

	t.Run("api_key", func(t *testing.T) {
		inventoryID := "fixture-key-id"
		state := projectAnthropicInventoryEvent(t, &cerebrov1.EventEnvelope{
			Id:         "anthropic-api-key",
			TenantId:   "writer",
			SourceId:   "anthropic",
			Kind:       "anthropic.api_key",
			OccurredAt: timestamppb.New(occurred),
			Attributes: map[string]string{
				"family":        "api_key",
				"api_key_id":    inventoryID,
				"name":          "prod-key",
				"status":        "active",
				"owner_user_id": "user_123",
			},
		})
		authMethodURN := "urn:cerebro:writer:anthropic_credential:" + inventoryID
		userURN := "urn:cerebro:writer:anthropic_user:user_123"
		entity := state.entities[authMethodURN]
		if entity == nil || entity.EntityType != "anthropic.credential" || entity.Attributes["api_key_id"] != inventoryID || entity.Attributes["status"] != "active" {
			t.Fatalf("anthropic api key entity missing or wrong: %#v", entity)
		}
		assertProjectedLink(t, state, userURN, relationAssignedTo, authMethodURN)
	})
}

func TestProjectAnthropicRemainingRuntimeFamilies(t *testing.T) {
	occurred := time.Date(2026, time.June, 18, 12, 0, 0, 0, time.UTC)

	cases := []struct {
		name       string
		event      *cerebrov1.EventEnvelope
		entityType string
		attrKey    string
		attrValue  string
	}{
		{
			name: "organization",
			event: &cerebrov1.EventEnvelope{
				Id:         "anthropic-organization",
				TenantId:   "writer",
				SourceId:   "anthropic",
				Kind:       "anthropic.organization",
				OccurredAt: timestamppb.New(occurred),
				Attributes: map[string]string{
					"family":          "organization",
					"organization_id": "org_123",
					"name":            "Writer",
				},
			},
			entityType: "anthropic.org",
			attrKey:    "organization_id",
			attrValue:  "org_123",
		},
		{
			name: "external_key",
			event: &cerebrov1.EventEnvelope{
				Id:         "anthropic-external-key",
				TenantId:   "writer",
				SourceId:   "anthropic",
				Kind:       "anthropic.external_key",
				OccurredAt: timestamppb.New(occurred),
				Attributes: map[string]string{
					"external_key_id": "extkey_123",
					"family":          "external_key",
					"name":            "production key",
					"provider":        "aws",
					"status":          "active",
				},
			},
			entityType: "anthropic.credential",
			attrKey:    "external_key_id",
			attrValue:  "extkey_123",
		},
		{
			name: "service_account",
			event: &cerebrov1.EventEnvelope{
				Id:         "anthropic-service-account",
				TenantId:   "writer",
				SourceId:   "anthropic",
				Kind:       "anthropic.service_account",
				OccurredAt: timestamppb.New(occurred),
				Attributes: map[string]string{
					"family":             "service_account",
					"name":               "Deploy worker",
					"role":               "developer",
					"service_account_id": "svac_123",
					"status":             "active",
				},
			},
			entityType: "anthropic.service_account",
			attrKey:    "service_account_id",
			attrValue:  "svac_123",
		},
		{
			name: "federation_issuer",
			event: &cerebrov1.EventEnvelope{
				Id:         "anthropic-federation-issuer",
				TenantId:   "writer",
				SourceId:   "anthropic",
				Kind:       "anthropic.federation_issuer",
				OccurredAt: timestamppb.New(occurred),
				Attributes: map[string]string{
					"family":               "federation_issuer",
					"federation_issuer_id": "fdis_123",
					"issuer":               "https://issuer.example.com",
					"name":                 "Production IdP",
					"organization_id":      "org_123",
					"status":               "active",
				},
			},
			entityType: "anthropic.federation_issuer",
			attrKey:    "federation_issuer_id",
			attrValue:  "fdis_123",
		},
		{
			name: "usage_report_message",
			event: &cerebrov1.EventEnvelope{
				Id:         "anthropic-usage-report-message",
				TenantId:   "writer",
				SourceId:   "anthropic",
				Kind:       "anthropic.usage_report_message",
				OccurredAt: timestamppb.New(occurred),
				Attributes: map[string]string{
					"family":     "usage_report_message",
					"id":         "usage_msg_123",
					"model":      "claude-sonnet-4-20250514",
					"start_time": "2026-06-18T12:00:00Z",
				},
			},
			entityType: "anthropic.usage_report_message",
			attrKey:    "metric_id",
			attrValue:  "usage_msg_123",
		},
		{
			name: "usage_report_claude_code",
			event: &cerebrov1.EventEnvelope{
				Id:         "anthropic-usage-report-claude-code",
				TenantId:   "writer",
				SourceId:   "anthropic",
				Kind:       "anthropic.usage_report_claude_code",
				OccurredAt: timestamppb.New(occurred),
				Attributes: map[string]string{
					"family":     "usage_report_claude_code",
					"id":         "usage_code_123",
					"start_time": "2026-06-18T12:00:00Z",
					"user_id":    "user_123",
				},
			},
			entityType: "anthropic.usage_report_claude_code",
			attrKey:    "metric_id",
			attrValue:  "usage_code_123",
		},
		{
			name: "analytics_cost",
			event: &cerebrov1.EventEnvelope{
				Id:         "anthropic-analytics-cost",
				TenantId:   "writer",
				SourceId:   "anthropic",
				Kind:       "anthropic.analytics_cost",
				OccurredAt: timestamppb.New(occurred),
				Attributes: map[string]string{
					"cost_usd":   "8.75",
					"family":     "analytics_cost",
					"id":         "analytics_cost_123",
					"model":      "claude-sonnet-4-20250514",
					"start_time": "2026-06-18T12:00:00Z",
				},
			},
			entityType: "anthropic.analytics_cost",
			attrKey:    "metric_type",
			attrValue:  "cost",
		},
		{
			name: "rate_limit",
			event: &cerebrov1.EventEnvelope{
				Id:         "anthropic-rate-limit",
				TenantId:   "writer",
				SourceId:   "anthropic",
				Kind:       "anthropic.rate_limit",
				OccurredAt: timestamppb.New(occurred),
				Attributes: map[string]string{
					"family":        "rate_limit",
					"group_type":    "model",
					"model":         "claude-sonnet-4-20250514",
					"name":          "Messages",
					"rate_limit_id": "rl_123",
				},
			},
			entityType: "anthropic.rate_limit",
			attrKey:    "control_type",
			attrValue:  "rate_limit",
		},
		{
			name: "spend_limit",
			event: &cerebrov1.EventEnvelope{
				Id:         "anthropic-spend-limit",
				TenantId:   "writer",
				SourceId:   "anthropic",
				Kind:       "anthropic.spend_limit",
				OccurredAt: timestamppb.New(occurred),
				Attributes: map[string]string{
					"amount":         "2500",
					"family":         "spend_limit",
					"period":         "monthly",
					"spend_limit_id": "spend_123",
					"user_id":        "user_123",
				},
			},
			entityType: "anthropic.spend_limit",
			attrKey:    "control_type",
			attrValue:  "spend_limit",
		},
		{
			name: "spend_limit_increase_request",
			event: &cerebrov1.EventEnvelope{
				Id:         "anthropic-spend-limit-increase-request",
				TenantId:   "writer",
				SourceId:   "anthropic",
				Kind:       "anthropic.spend_limit_increase_request",
				OccurredAt: timestamppb.New(occurred),
				Attributes: map[string]string{
					"amount":     "5000",
					"family":     "spend_limit_increase_request",
					"period":     "monthly",
					"request_id": "req_123",
					"status":     "pending",
					"user_id":    "user_123",
				},
			},
			entityType: "anthropic.spend_limit_increase_request",
			attrKey:    "control_type",
			attrValue:  "spend_limit_increase_request",
		},
		{
			name: "compliance_organization",
			event: &cerebrov1.EventEnvelope{
				Id:         "anthropic-compliance-organization",
				TenantId:   "writer",
				SourceId:   "anthropic",
				Kind:       "anthropic.compliance_organization",
				OccurredAt: timestamppb.New(occurred),
				Attributes: map[string]string{
					"family":            "compliance_organization",
					"name":              "Writer",
					"organization_uuid": "org-uuid-1",
				},
			},
			entityType: "anthropic.org",
			attrKey:    "organization_uuid",
			attrValue:  "org-uuid-1",
		},
		{
			name: "compliance_organization_user",
			event: &cerebrov1.EventEnvelope{
				Id:         "anthropic-compliance-organization-user",
				TenantId:   "writer",
				SourceId:   "anthropic",
				Kind:       "anthropic.compliance_organization_user",
				OccurredAt: timestamppb.New(occurred),
				Attributes: map[string]string{
					"email":             "carol@example.com",
					"family":            "compliance_organization_user",
					"name":              "Carol Example",
					"organization_uuid": "org-uuid-1",
					"role":              "admin",
					"user_id":           "user_789",
				},
			},
			entityType: "anthropic.user",
			attrKey:    "user_id",
			attrValue:  "user_789",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			state := projectAnthropicInventoryEvent(t, tc.event)
			if entity := findProjectedEntityByAttribute(state, tc.entityType, tc.attrKey, tc.attrValue); entity == nil {
				t.Fatalf("projected %s entity with %s=%q missing in %#v", tc.entityType, tc.attrKey, tc.attrValue, state.entities)
			}
		})
	}
}

func projectAnthropicInventoryEvent(t *testing.T, event *cerebrov1.EventEnvelope) *projectionRecorder {
	t.Helper()
	state := &projectionRecorder{}
	service := New(state, nil)
	if _, err := service.Project(context.Background(), event); err != nil {
		t.Fatalf("Project(%q) error = %v", event.GetId(), err)
	}
	if _, err := service.Project(context.Background(), event); err != nil {
		t.Fatalf("Project(%q) replay error = %v", event.GetId(), err)
	}
	return state
}

func findProjectedEntityByAttribute(state *projectionRecorder, entityType string, attrKey string, attrValue string) *ports.ProjectedEntity {
	if state == nil {
		return nil
	}
	for _, entity := range state.entities {
		if entity == nil || entity.EntityType != entityType {
			continue
		}
		if entity.Attributes[attrKey] == attrValue {
			return entity
		}
	}
	return nil
}

func TestRegistryRoutesAnthropicDeclaredKinds(t *testing.T) {
	declared := []string{
		"anthropic.organization",
		"anthropic.user",
		"anthropic.invite",
		"anthropic.workspace",
		"anthropic.workspace_member",
		"anthropic.api_key",
		"anthropic.external_key",
		"anthropic.service_account",
		"anthropic.federation_issuer",
		"anthropic.federation_rule",
		"anthropic.usage_report_message",
		"anthropic.usage_report_claude_code",
		"anthropic.cost_report",
		"anthropic.analytics_cost",
		"anthropic.rate_limit",
		"anthropic.workspace_rate_limit",
		"anthropic.spend_limit",
		"anthropic.spend_limit_increase_request",
		"anthropic.compliance_activity",
		"anthropic.compliance_organization",
		"anthropic.compliance_organization_user",
		"anthropic.compliance_role",
		"anthropic.compliance_role_permission",
		"anthropic.compliance_group",
		"anthropic.compliance_group_member",
		"anthropic.compliance_project",
		"anthropic.compliance_project_collaborator",
		"anthropic.compliance_organization_setting",
	}
	registered := make(map[string]struct{})
	for _, kind := range BuiltinRegistry().Kinds() {
		registered[kind] = struct{}{}
	}
	for _, kind := range declared {
		if _, ok := registered[kind]; !ok {
			t.Fatalf("declared Anthropic kind %q is not routed in the projection registry", kind)
		}
	}
}
