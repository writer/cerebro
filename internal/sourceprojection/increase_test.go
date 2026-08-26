package sourceprojection

import (
	"errors"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestIncreaseGoProjectionFailsClosedForRustAuthoritativeFamilies(t *testing.T) {
	for _, kind := range []string{
		"increase.account",
		"increase.account_number",
		"increase.account_statement",
		"increase.account_transfer",
		"increase.ach_prenotification",
		"increase.ach_transfer",
		"increase.card",
		"increase.digital_wallet_token",
		"increase.event",
		"increase.event_subscription",
		"increase.external_account",
		"increase.oauth_connection",
	} {
		t.Run(kind, func(t *testing.T) {
			entities, links, err := ProjectEvent(&cerebrov1.EventEnvelope{
				Id:       "event-1",
				TenantId: "tenant",
				SourceId: "increase",
				Kind:     kind,
			})
			if !errors.Is(err, errIncreaseRustProjectionRequired) {
				t.Fatalf("ProjectEvent() error = %v", err)
			}
			if len(entities) != 0 || len(links) != 0 {
				t.Fatalf("Go projection produced entities=%d links=%d", len(entities), len(links))
			}
		})
	}
}
