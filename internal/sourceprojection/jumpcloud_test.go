package sourceprojection

import (
	"errors"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestJumpCloudGoProjectionFailsClosedForRustAuthoritativeFamilies(t *testing.T) {
	for _, kind := range []string{
		"jumpcloud.users",
		"jumpcloud.groups",
		"jumpcloud.systems",
		"jumpcloud.applications",
		"jumpcloud.system_groups",
		"jumpcloud.group_members",
		"jumpcloud.audit_events",
	} {
		t.Run(kind, func(t *testing.T) {
			entities, links, err := ProjectEvent(&cerebrov1.EventEnvelope{
				Id:       "event-1",
				TenantId: "tenant",
				SourceId: "jumpcloud",
				Kind:     kind,
			})
			if !errors.Is(err, errJumpCloudRustProjectionRequired) {
				t.Fatalf("ProjectEvent() error = %v", err)
			}
			if len(entities) != 0 || len(links) != 0 {
				t.Fatalf("Go projection produced entities=%d links=%d", len(entities), len(links))
			}
		})
	}
}
