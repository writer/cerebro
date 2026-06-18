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
	}
	for _, event := range events {
		if _, err := service.Project(context.Background(), event); err != nil {
			t.Fatalf("Project(%q) error = %v", event.GetId(), err)
		}
	}

	userURN := "urn:cerebro:writer:anthropic_user:user_789"
	groupURN := "urn:cerebro:writer:anthropic_group:rbac_group_123"
	orgURN := "urn:cerebro:writer:anthropic_org:org-uuid-1"
	identityURN := "urn:cerebro:writer:identity:email:carol@example.com"

	if entity := state.entities[groupURN]; entity == nil || entity.EntityType != "anthropic.group" {
		t.Fatalf("group entity missing or wrong: %#v", entity)
	}
	assertProjectedLink(t, state, groupURN, relationBelongsTo, orgURN)
	assertProjectedLink(t, state, userURN, relationRepresentsIdentity, identityURN)
	assertProjectedLink(t, state, userURN, relationMemberOf, groupURN)
}
