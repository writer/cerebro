package sourceprojection

import (
	"context"
	"strings"
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

func TestProjectOpenAIDeclaredKindsProduceGraphEntities(t *testing.T) {
	occurred := time.Date(2026, time.June, 18, 13, 30, 0, 0, time.UTC)
	cases := []struct {
		name   string
		family string
		kind   string
	}{
		{name: "user", family: "user", kind: "openai.user"},
		{name: "project", family: "project", kind: "openai.project"},
		{name: "service_account", family: "service_account", kind: "openai.service_account"},
		{name: "api_key", family: "api_key", kind: "openai.api_key"},
		{name: "admin_api_key", family: "admin_api_key", kind: "openai.admin_api_key"},
		{name: "audit_log", family: "audit_log", kind: "openai.audit_log"},
		{name: "invite", family: "invite", kind: "openai.invite"},
		{name: "role", family: "role", kind: "openai.role"},
		{name: "user_role", family: "user_role", kind: "openai.user_role"},
		{name: "group", family: "group", kind: "openai.group"},
		{name: "group_user", family: "group_user", kind: "openai.group_user"},
		{name: "group_role", family: "group_role", kind: "openai.group_role"},
		{name: "data_retention", family: "data_retention", kind: "openai.data_retention"},
		{name: "spend_alert", family: "spend_alert", kind: "openai.spend_alert"},
		{name: "certificate", family: "certificate", kind: "openai.certificate"},
		{name: "usage_audio_speech", family: "usage_audio_speech", kind: "openai.usage_audio_speech"},
		{name: "usage_audio_transcription", family: "usage_audio_transcription", kind: "openai.usage_audio_transcription"},
		{name: "usage_code_interpreter_session", family: "usage_code_interpreter_session", kind: "openai.usage_code_interpreter_session"},
		{name: "usage_completion", family: "usage_completion", kind: "openai.usage_completion"},
		{name: "usage_embedding", family: "usage_embedding", kind: "openai.usage_embedding"},
		{name: "usage_image", family: "usage_image", kind: "openai.usage_image"},
		{name: "usage_moderation", family: "usage_moderation", kind: "openai.usage_moderation"},
		{name: "usage_vector_store", family: "usage_vector_store", kind: "openai.usage_vector_store"},
		{name: "usage_file_search_call", family: "usage_file_search_call", kind: "openai.usage_file_search_call"},
		{name: "usage_web_search_call", family: "usage_web_search_call", kind: "openai.usage_web_search_call"},
		{name: "cost", family: "cost", kind: "openai.cost"},
		{name: "project_user", family: "project_user", kind: "openai.project_user"},
		{name: "project_user_role", family: "project_user_role", kind: "openai.project_user_role"},
		{name: "project_service_account", family: "project_service_account", kind: "openai.project_service_account"},
		{name: "project_api_key", family: "project_api_key", kind: "openai.project_api_key"},
		{name: "project_rate_limit", family: "project_rate_limit", kind: "openai.project_rate_limit"},
		{name: "project_model_permission", family: "project_model_permission", kind: "openai.project_model_permission"},
		{name: "project_hosted_tool_permission", family: "project_hosted_tool_permission", kind: "openai.project_hosted_tool_permission"},
		{name: "project_group", family: "project_group", kind: "openai.project_group"},
		{name: "project_group_role", family: "project_group_role", kind: "openai.project_group_role"},
		{name: "project_role", family: "project_role", kind: "openai.project_role"},
		{name: "project_data_retention", family: "project_data_retention", kind: "openai.project_data_retention"},
		{name: "project_spend_alert", family: "project_spend_alert", kind: "openai.project_spend_alert"},
		{name: "project_certificate", family: "project_certificate", kind: "openai.project_certificate"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			state := &projectionRecorder{}
			service := New(state, nil)
			attrs := openAIProjectionCoverageAttributes(tc.family)
			event := &cerebrov1.EventEnvelope{
				Id:         "openai-" + tc.name,
				TenantId:   "writer",
				SourceId:   "openai",
				Kind:       tc.kind,
				OccurredAt: timestamppb.New(occurred),
				Attributes: attrs,
			}

			result, err := service.Project(context.Background(), event)
			if err != nil {
				t.Fatalf("Project(%q) error = %v", tc.kind, err)
			}
			if result.EntitiesProjected == 0 {
				t.Fatalf("Project(%q) projected no entities", tc.kind)
			}
			if !hasOpenAIProviderEntity(state) {
				t.Fatalf("Project(%q) did not produce an OpenAI graph entity; projected types: %v", tc.kind, projectedEntityTypes(state))
			}
		})
	}
}

func openAIProjectionCoverageAttributes(family string) map[string]string {
	return map[string]string{
		"actor_email":               "admin@example.com",
		"actor_user_id":             "user_admin",
		"api_key_id":                "credential_coverage",
		"amount_currency":           "usd",
		"amount_value":              "12.34",
		"certificate_id":            "certificate_coverage",
		"code_interpreter_enabled":  "true",
		"email":                     "alice@example.com",
		"end_time":                  "2026-06-18T13:00:00Z",
		"event_type":                "role.assignment.created",
		"family":                    family,
		"file_search_enabled":       "true",
		"group_id":                  "group_coverage",
		"id":                        family + "_coverage",
		"image_generation_enabled":  "true",
		"input_tokens":              "100",
		"invite_id":                 "invite_coverage",
		"line_item":                 "usage",
		"max_requests_per_1_minute": "500",
		"mcp_enabled":               "true",
		"member_user_id":            "user_coverage",
		"model":                     "gpt-4o",
		"model_ids":                 "gpt-4o",
		"name":                      "Coverage Fixture",
		"num_model_requests":        "2",
		"object":                    "chat",
		"organization_id":           "org_coverage",
		"output_tokens":             "25",
		"owner_type":                "user",
		"owner_user_id":             "user_coverage",
		"principal_id":              "group_coverage",
		"principal_type":            "group",
		"project_id":                "project_coverage",
		"rate_limit_id":             "rate_limit_coverage",
		"resource_id":               "project_coverage",
		"resource_type":             "project",
		"retention_type":            "30d",
		"role":                      "owner",
		"role_id":                   "owner",
		"roles":                     "owner,member",
		"service_account_id":        "service_account_coverage",
		"spend_alert_id":            "spend_alert_coverage",
		"start_time":                "2026-06-18T12:00:00Z",
		"status":                    "active",
		"user_id":                   "user_coverage",
		"web_search_enabled":        "true",
	}
}

func hasOpenAIProviderEntity(state *projectionRecorder) bool {
	for _, entity := range state.entities {
		if entity != nil && entity.SourceID == "openai" && strings.HasPrefix(entity.EntityType, "openai.") {
			return true
		}
	}
	return false
}

func projectedEntityTypes(state *projectionRecorder) []string {
	types := make([]string, 0, len(state.entities))
	for _, entity := range state.entities {
		if entity == nil {
			continue
		}
		types = append(types, entity.EntityType)
	}
	return types
}
