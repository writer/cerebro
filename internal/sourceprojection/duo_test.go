package sourceprojection

import (
	"errors"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestDuoGoProjectionFailsClosedForRustAuthoritativeFamilies(t *testing.T) {
	for _, kind := range []string{
		"duo.administrator",
		"duo.application",
		"duo.audit_event",
		"duo.authentication_log",
		"duo.endpoint",
		"duo.group",
		"duo.phone",
		"duo.role",
		"duo.token",
		"duo.user",
		"duo.web_authn_credential",
		"duo_security.applications",
		"duo_security.audit_events",
		"duo_security.groups",
		"duo_security.roles",
		"duo_security.users",
	} {
		t.Run(kind, func(t *testing.T) {
			entities, links, err := ProjectEvent(&cerebrov1.EventEnvelope{
				Id:       "event-1",
				TenantId: "tenant",
				SourceId: "duo",
				Kind:     kind,
			})
			if !errors.Is(err, errDuoRustProjectionRequired) {
				t.Fatalf("ProjectEvent() error = %v", err)
			}
			if len(entities) != 0 || len(links) != 0 {
				t.Fatalf("Go projection produced entities=%d links=%d", len(entities), len(links))
			}
		})
	}
}
