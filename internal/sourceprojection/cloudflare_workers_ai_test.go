package sourceprojection

import (
	"errors"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestCloudflareWorkersAiGoProjectionFailsClosedForRustAuthoritativeFamilies(t *testing.T) {
	for _, kind := range []string{
		"cloudflare_workers_ai.ai_gateways",
		"cloudflare_workers_ai.gateway_evaluations",
		"cloudflare_workers_ai.gateway_logs",
		"cloudflare_workers_ai.gateway_provider_configs",
		"cloudflare_workers_ai.model_catalog",
		"cloudflare_workers_ai.vectorize_indexes",
	} {
		t.Run(kind, func(t *testing.T) {
			entities, links, err := ProjectEvent(&cerebrov1.EventEnvelope{
				Id:       "event-1",
				TenantId: "tenant",
				SourceId: "cloudflare_workers_ai",
				Kind:     kind,
			})
			if !errors.Is(err, errCloudflareWorkersAiRustProjectionRequired) {
				t.Fatalf("ProjectEvent() error = %v", err)
			}
			if len(entities) != 0 || len(links) != 0 {
				t.Fatalf("Go projection produced entities=%d links=%d", len(entities), len(links))
			}
		})
	}
}
