package postgres

import (
	"strings"
	"testing"
)

func TestComplianceMonitorSchemaIsTenantScopedAndLeaseBacked(t *testing.T) {
	t.Parallel()
	joined := strings.Join(ensureComplianceMonitorStatements, "\n")
	for _, required := range []string{
		"PRIMARY KEY (tenant_id, id)",
		"PRIMARY KEY (tenant_id, plan_revision_id)",
		"claim_expires_at",
		"occurrence_key",
		"compliance_monitor_change_signals",
		"PRIMARY KEY (tenant_id, monitor_id, event_id)",
		"compliance_monitor_change_windows",
		"window_version",
		"FOREIGN KEY (tenant_id, monitor_id)",
	} {
		if !strings.Contains(joined, required) {
			t.Fatalf("schema/query contract missing %q", required)
		}
	}
}
