package sourceprojection

import (
	"errors"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestElevenlabsGoProjectionFailsClosedForRustAuthoritativeFamilies(t *testing.T) {
	for _, kind := range []string{
		"elevenlabs.auth_connections",
		"elevenlabs.model_catalog",
		"elevenlabs.service_account_api_keys",
		"elevenlabs.service_accounts",
		"elevenlabs.voices",
		"elevenlabs.webhooks",
	} {
		t.Run(kind, func(t *testing.T) {
			entities, links, err := ProjectEvent(&cerebrov1.EventEnvelope{
				Id:       "event-1",
				TenantId: "tenant",
				SourceId: "elevenlabs",
				Kind:     kind,
			})
			if !errors.Is(err, errElevenlabsRustProjectionRequired) {
				t.Fatalf("ProjectEvent() error = %v", err)
			}
			if len(entities) != 0 || len(links) != 0 {
				t.Fatalf("Go projection produced entities=%d links=%d", len(entities), len(links))
			}
		})
	}
}
