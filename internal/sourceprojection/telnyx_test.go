package sourceprojection

import (
	"errors"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestTelnyxGoProjectionFailsClosedForRustAuthoritativeFamilies(t *testing.T) {
	for _, kind := range []string{
		"telnyx.billing_group",
		"telnyx.call_control_application",
		"telnyx.call_event",
		"telnyx.credential_connection",
		"telnyx.detail_records_report",
		"telnyx.managed_account",
		"telnyx.notification_channel",
		"telnyx.notification_event",
		"telnyx.notification_event_condition",
		"telnyx.sim_card_group",
		"telnyx.sim_card_group_action",
		"telnyx.wireless_connectivity_log",
	} {
		t.Run(kind, func(t *testing.T) {
			entities, links, err := ProjectEvent(&cerebrov1.EventEnvelope{
				Id:       "event-1",
				TenantId: "tenant",
				SourceId: "telnyx",
				Kind:     kind,
			})
			if !errors.Is(err, errTelnyxRustProjectionRequired) {
				t.Fatalf("ProjectEvent() error = %v", err)
			}
			if len(entities) != 0 || len(links) != 0 {
				t.Fatalf("Go projection produced entities=%d links=%d", len(entities), len(links))
			}
		})
	}
}
