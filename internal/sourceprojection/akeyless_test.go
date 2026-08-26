package sourceprojection

import (
	"errors"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestAkeylessGoProjectionFailsClosedForRustAuthoritativeFamilies(t *testing.T) {
	for _, kind := range []string{"akeyless.items", "akeyless.auth_methods", "akeyless.roles", "akeyless.analytics"} {
		t.Run(kind, func(t *testing.T) {
			entities, links, err := ProjectEvent(&cerebrov1.EventEnvelope{
				Id:       "event-1",
				TenantId: "tenant",
				SourceId: "akeyless",
				Kind:     kind,
			})
			if !errors.Is(err, errAkeylessRustProjectionRequired) {
				t.Fatalf("ProjectEvent() error = %v", err)
			}
			if len(entities) != 0 || len(links) != 0 {
				t.Fatalf("Go projection produced entities=%d links=%d", len(entities), len(links))
			}
		})
	}
}
