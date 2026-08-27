package sourceprojection

import (
	"errors"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestCloudflareZeroTrustGoProjectionFailsClosedForRustAuthoritativeFamilies(t *testing.T) {
	for _, kind := range []string{
		"cloudflare_zero_trust.applications",
		"cloudflare_zero_trust.audit_events",
		"cloudflare_zero_trust.groups",
		"cloudflare_zero_trust.roles",
		"cloudflare_zero_trust.users",
	} {
		t.Run(kind, func(t *testing.T) {
			entities, links, err := ProjectEvent(&cerebrov1.EventEnvelope{
				Id:       "event-1",
				TenantId: "tenant",
				SourceId: "cloudflare_zero_trust",
				Kind:     kind,
			})
			if !errors.Is(err, errCloudflareZeroTrustRustProjectionRequired) {
				t.Fatalf("ProjectEvent() error = %v", err)
			}
			if len(entities) != 0 || len(links) != 0 {
				t.Fatalf("Go projection produced entities=%d links=%d", len(entities), len(links))
			}
		})
	}
}
