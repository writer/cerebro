package postgres

import (
	"strings"
	"testing"
)

func TestDecisionPacketSchemaIsTenantScopedImmutableAndRetained(t *testing.T) {
	schema := strings.Join(ensureDecisionPacketStatements, "\n")
	for _, required := range []string{
		"PRIMARY KEY (tenant_id, packet_id)",
		"schema_version TEXT NOT NULL",
		"packet_digest TEXT NOT NULL",
		"evidence_digest TEXT NOT NULL",
		"coverage_digest TEXT NOT NULL",
		"packet_json JSONB NOT NULL",
		"expires_at TIMESTAMPTZ",
		"decision_packet_receipts_expiry_idx",
	} {
		if !strings.Contains(schema, required) {
			t.Fatalf("schema missing %q:\n%s", required, schema)
		}
	}
	if strings.Contains(strings.ToUpper(schema), " DO UPDATE") {
		t.Fatalf("decision packet schema must not install an update path:\n%s", schema)
	}
}
