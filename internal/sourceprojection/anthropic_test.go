package sourceprojection

import (
	"errors"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestAnthropicGoProjectionFailsClosedForRustAuthoritativeFamilies(t *testing.T) {
	for _, kind := range []string{
		"anthropic.analytics_cost",
		"anthropic.api_key",
		"anthropic.compliance_activity",
		"anthropic.compliance_group",
		"anthropic.compliance_group_member",
		"anthropic.compliance_organization",
		"anthropic.compliance_organization_setting",
		"anthropic.compliance_organization_user",
		"anthropic.compliance_project",
		"anthropic.compliance_project_collaborator",
		"anthropic.compliance_role",
		"anthropic.compliance_role_permission",
		"anthropic.cost_report",
		"anthropic.external_key",
		"anthropic.federation_issuer",
		"anthropic.federation_rule",
		"anthropic.invite",
		"anthropic.organization",
		"anthropic.rate_limit",
		"anthropic.service_account",
		"anthropic.spend_limit",
		"anthropic.spend_limit_increase_request",
		"anthropic.usage_report_claude_code",
		"anthropic.usage_report_message",
		"anthropic.user",
		"anthropic.workspace",
		"anthropic.workspace_member",
		"anthropic.workspace_rate_limit",
	} {
		t.Run(kind, func(t *testing.T) {
			entities, links, err := ProjectEvent(&cerebrov1.EventEnvelope{
				Id:       "event-1",
				TenantId: "tenant",
				SourceId: "anthropic",
				Kind:     kind,
			})
			if !errors.Is(err, errAnthropicRustProjectionRequired) {
				t.Fatalf("ProjectEvent() error = %v", err)
			}
			if len(entities) != 0 || len(links) != 0 {
				t.Fatalf("Go projection produced entities=%d links=%d", len(entities), len(links))
			}
		})
	}
}
