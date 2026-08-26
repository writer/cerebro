package sourceprojection

import (
	"errors"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestGoogleVertexAiGoProjectionFailsClosedForRustAuthoritativeFamilies(t *testing.T) {
	for _, kind := range []string{
		"google_vertex_ai.batch_prediction_jobs",
		"google_vertex_ai.custom_jobs",
		"google_vertex_ai.endpoints",
		"google_vertex_ai.indexes",
		"google_vertex_ai.models",
		"google_vertex_ai.reasoning_engines",
	} {
		t.Run(kind, func(t *testing.T) {
			entities, links, err := ProjectEvent(&cerebrov1.EventEnvelope{
				Id:       "event-1",
				TenantId: "tenant",
				SourceId: "google_vertex_ai",
				Kind:     kind,
			})
			if !errors.Is(err, errGoogleVertexAiRustProjectionRequired) {
				t.Fatalf("ProjectEvent() error = %v", err)
			}
			if len(entities) != 0 || len(links) != 0 {
				t.Fatalf("Go projection produced entities=%d links=%d", len(entities), len(links))
			}
		})
	}
}
