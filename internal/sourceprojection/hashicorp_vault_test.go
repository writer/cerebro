package sourceprojection

import (
	"errors"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestHashicorpVaultGoProjectionFailsClosedForRustAuthoritativeFamilies(t *testing.T) {
	for _, kind := range []string{
		"hashicorp_vault.audit_events",
		"hashicorp_vault.secrets",
		"hashicorp_vault.users",
	} {
		t.Run(kind, func(t *testing.T) {
			entities, links, err := ProjectEvent(&cerebrov1.EventEnvelope{
				Id:       "event-1",
				TenantId: "tenant",
				SourceId: "hashicorp_vault",
				Kind:     kind,
			})
			if !errors.Is(err, errHashicorpVaultRustProjectionRequired) {
				t.Fatalf("ProjectEvent() error = %v", err)
			}
			if len(entities) != 0 || len(links) != 0 {
				t.Fatalf("Go projection produced entities=%d links=%d", len(entities), len(links))
			}
		})
	}
}
