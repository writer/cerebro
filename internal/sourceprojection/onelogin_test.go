package sourceprojection

import (
	"errors"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestOneloginGoProjectionFailsClosedForRustAuthoritativeFamilies(t *testing.T) {
	for _, kind := range []string{
		"onelogin.app_rules",
		"onelogin.app_users",
		"onelogin.apps",
		"onelogin.audit_events",
		"onelogin.delegated_privileges",
		"onelogin.groups",
		"onelogin.mappings",
		"onelogin.mfa_devices",
		"onelogin.privilege_roles",
		"onelogin.privilege_users",
		"onelogin.privileges",
		"onelogin.role_admins",
		"onelogin.role_apps",
		"onelogin.role_users",
		"onelogin.roles",
		"onelogin.user_apps",
		"onelogin.user_privileges",
		"onelogin.users",
	} {
		t.Run(kind, func(t *testing.T) {
			entities, links, err := ProjectEvent(&cerebrov1.EventEnvelope{
				Id:       "event-1",
				TenantId: "tenant",
				SourceId: "onelogin",
				Kind:     kind,
			})
			if !errors.Is(err, errOneloginRustProjectionRequired) {
				t.Fatalf("ProjectEvent() error = %v", err)
			}
			if len(entities) != 0 || len(links) != 0 {
				t.Fatalf("Go projection produced entities=%d links=%d", len(entities), len(links))
			}
		})
	}
}
