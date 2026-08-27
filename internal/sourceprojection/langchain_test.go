package sourceprojection

import (
	"errors"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestLangChainGoProjectionFailsClosedForRustAuthoritativeFamilies(t *testing.T) {
	for _, kind := range []string{
		"langchain.api_key",
		"langchain.audit_log",
		"langchain.dataset",
		"langchain.feedback",
		"langchain.organization",
		"langchain.organization_member",
		"langchain.project",
		"langchain.role",
		"langchain.run",
		"langchain.service_account",
		"langchain.usage_limit",
		"langchain.workspace",
		"langchain.workspace_member",
	} {
		t.Run(kind, func(t *testing.T) {
			entities, links, err := ProjectEvent(&cerebrov1.EventEnvelope{
				Id:       "event-1",
				TenantId: "tenant",
				SourceId: "langchain",
				Kind:     kind,
			})
			if !errors.Is(err, errLangChainRustProjectionRequired) {
				t.Fatalf("ProjectEvent() error = %v", err)
			}
			if len(entities) != 0 || len(links) != 0 {
				t.Fatalf("Go projection produced entities=%d links=%d", len(entities), len(links))
			}
		})
	}
}
