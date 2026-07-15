package postgres

import (
	"strings"
	"testing"
)

func TestGRCAuditPacketSchemaIsTenantScopedAndImmutable(t *testing.T) {
	schema := strings.Join(ensureGRCAuditPacketStatements, "\n")
	for _, required := range []string{
		"id TEXT PRIMARY KEY",
		"tenant_id TEXT NOT NULL",
		"finding_id TEXT NOT NULL",
		"digest TEXT NOT NULL",
		"packet_json JSONB NOT NULL",
		"grc_audit_packets_tenant_created_idx",
	} {
		if !strings.Contains(schema, required) {
			t.Fatalf("schema missing %q:\n%s", required, schema)
		}
	}
	if strings.Contains(strings.ToUpper(schema), " UPDATE ") {
		t.Fatalf("audit packet schema must not install an update path:\n%s", schema)
	}
}
