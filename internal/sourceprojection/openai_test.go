package sourceprojection

import (
	"context"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestProjectOpenAIKeyOwnershipAndPostureEnrichment(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	occurred := time.Date(2026, time.June, 18, 12, 0, 0, 0, time.UTC)

	events := []*cerebrov1.EventEnvelope{
		{
			Id:         "openai-owned-admin-key",
			TenantId:   "writer",
			SourceId:   "openai",
			Kind:       "openai.admin_api_key",
			OccurredAt: timestamppb.New(occurred),
			Attributes: map[string]string{
				"api_key_id":   "admin_owned",
				"family":       "admin_api_key",
				"key_class":    "admin",
				"name":         "owned-admin-key",
				"owner_id":     "user_123",
				"owner_name":   "Ada Lovelace",
				"owner_object": "organization.user",
				"owner_type":   "user",
				"privileged":   "true",
			},
		},
		{
			Id:         "openai-orphaned-admin-key",
			TenantId:   "writer",
			SourceId:   "openai",
			Kind:       "openai.admin_api_key",
			OccurredAt: timestamppb.New(occurred),
			Attributes: map[string]string{
				"api_key_id": "admin_orphaned",
				"family":     "admin_api_key",
				"key_class":  "admin",
				"name":       "orphaned-admin-key",
				"privileged": "true",
			},
		},
		{
			Id:         "openai-project-key",
			TenantId:   "writer",
			SourceId:   "openai",
			Kind:       "openai.project_api_key",
			OccurredAt: timestamppb.New(occurred),
			Attributes: map[string]string{
				"api_key_id":               "proj_key",
				"family":                   "project_api_key",
				"name":                     "prod-key",
				"owner_type":               "service_account",
				"owner_service_account_id": "sa_9",
				"project_id":               "proj_123",
			},
		},
	}
	for _, event := range events {
		if _, err := service.Project(context.Background(), event); err != nil {
			t.Fatalf("Project(%q) error = %v", event.GetId(), err)
		}
	}

	ownedURN := "urn:cerebro:writer:openai_credential:admin_owned"       // #nosec G101 -- test credential URN fixture, not credential material.
	orphanedURN := "urn:cerebro:writer:openai_credential:admin_orphaned" // #nosec G101 -- test credential URN fixture, not credential material.
	projKeyURN := "urn:cerebro:writer:openai_credential:proj_key"        // #nosec G101 -- test credential URN fixture, not credential material.
	userURN := "urn:cerebro:writer:openai_user:user_123"
	serviceAccountURN := "urn:cerebro:writer:openai_service_account:sa_9"
	orgURN := "urn:cerebro:writer:openai_org:openai"
	projectURN := "urn:cerebro:writer:openai_project:proj_123"

	owned := state.entities[ownedURN]
	if owned == nil || owned.EntityType != "openai.credential" {
		t.Fatalf("owned credential entity missing or wrong: %#v", owned)
	}
	for key, want := range map[string]string{"privileged": "true", "has_owner": "true", "orphaned_owner": "false", "owner_type": "user"} {
		if got := owned.Attributes[key]; got != want {
			t.Fatalf("owned credential attribute %q = %q, want %q", key, got, want)
		}
	}
	assertProjectedLink(t, state, userURN, relationAssignedTo, ownedURN)
	assertProjectedLink(t, state, ownedURN, relationCanPerform, orgURN)

	orphaned := state.entities[orphanedURN]
	if orphaned == nil {
		t.Fatalf("orphaned credential entity missing")
	}
	for key, want := range map[string]string{"privileged": "true", "has_owner": "false", "orphaned_owner": "true"} {
		if got := orphaned.Attributes[key]; got != want {
			t.Fatalf("orphaned credential attribute %q = %q, want %q", key, got, want)
		}
	}

	projKey := state.entities[projKeyURN]
	if projKey == nil {
		t.Fatalf("project credential entity missing")
	}
	if got := projKey.Attributes["has_owner"]; got != "true" {
		t.Fatalf("project credential has_owner = %q, want true", got)
	}
	assertProjectedLink(t, state, serviceAccountURN, relationAssignedTo, projKeyURN)
	assertProjectedLink(t, state, projKeyURN, relationCanPerform, projectURN)
}

func TestRegistryRoutesOpenAIDeclaredKinds(t *testing.T) {
	declared := []string{
		"openai.user",
		"openai.project",
		"openai.service_account",
		"openai.api_key",
		"openai.admin_api_key",
		"openai.audit_log",
		"openai.invite",
		"openai.role",
		"openai.user_role",
		"openai.group",
		"openai.group_user",
		"openai.group_role",
		"openai.data_retention",
		"openai.spend_alert",
		"openai.certificate",
		"openai.usage_audio_speech",
		"openai.usage_audio_transcription",
		"openai.usage_code_interpreter_session",
		"openai.usage_completion",
		"openai.usage_embedding",
		"openai.usage_image",
		"openai.usage_moderation",
		"openai.usage_vector_store",
		"openai.usage_file_search_call",
		"openai.usage_web_search_call",
		"openai.cost",
		"openai.project_user",
		"openai.project_user_role",
		"openai.project_service_account",
		"openai.project_api_key",
		"openai.project_rate_limit",
		"openai.project_model_permission",
		"openai.project_hosted_tool_permission",
		"openai.project_group",
		"openai.project_group_role",
		"openai.project_role",
		"openai.project_data_retention",
		"openai.project_spend_alert",
		"openai.project_certificate",
	}
	registered := make(map[string]struct{})
	for _, kind := range BuiltinRegistry().Kinds() {
		registered[kind] = struct{}{}
	}
	for _, kind := range declared {
		if _, ok := registered[kind]; !ok {
			t.Fatalf("declared OpenAI kind %q is not routed in the projection registry", kind)
		}
	}
}
