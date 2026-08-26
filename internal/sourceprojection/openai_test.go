package sourceprojection

import (
	"errors"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestOpenAIGoProjectionFailsClosedForRustAuthoritativeFamilies(t *testing.T) {
	for _, kind := range []string{
		"openai.admin_api_key",
		"openai.api_key",
		"openai.audit_log",
		"openai.certificate",
		"openai.cost",
		"openai.data_retention",
		"openai.group",
		"openai.group_role",
		"openai.group_user",
		"openai.invite",
		"openai.project",
		"openai.project_api_key",
		"openai.project_certificate",
		"openai.project_data_retention",
		"openai.project_group",
		"openai.project_group_role",
		"openai.project_hosted_tool_permission",
		"openai.project_model_permission",
		"openai.project_rate_limit",
		"openai.project_role",
		"openai.project_service_account",
		"openai.project_spend_alert",
		"openai.project_user",
		"openai.project_user_role",
		"openai.role",
		"openai.service_account",
		"openai.spend_alert",
		"openai.usage_audio_speech",
		"openai.usage_audio_transcription",
		"openai.usage_code_interpreter_session",
		"openai.usage_completion",
		"openai.usage_embedding",
		"openai.usage_file_search_call",
		"openai.usage_image",
		"openai.usage_moderation",
		"openai.usage_vector_store",
		"openai.usage_web_search_call",
		"openai.user",
		"openai.user_role",
	} {
		t.Run(kind, func(t *testing.T) {
			entities, links, err := ProjectEvent(&cerebrov1.EventEnvelope{
				Id:       "event-1",
				TenantId: "tenant",
				SourceId: "openai",
				Kind:     kind,
			})
			if !errors.Is(err, errOpenAIRustProjectionRequired) {
				t.Fatalf("ProjectEvent() error = %v", err)
			}
			if len(entities) != 0 || len(links) != 0 {
				t.Fatalf("Go projection produced entities=%d links=%d", len(entities), len(links))
			}
		})
	}
}
