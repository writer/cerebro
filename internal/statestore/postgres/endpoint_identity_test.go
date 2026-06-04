package postgres

import (
	"strings"
	"testing"
)

func TestEndpointIdentitySchemaSupportsAliasResolution(t *testing.T) {
	joined := strings.Join(ensureEndpointIdentityStatements, "\n")
	for _, want := range []string{
		"CREATE TABLE IF NOT EXISTS endpoint_identity_aliases",
		"PRIMARY KEY (tenant_id, alias_type, alias_value_normalized, canonical_device_id)",
		"endpoint_identity_alias_lookup_idx",
		"endpoint_identity_alias_device_idx",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("endpoint identity schema missing %q:\n%s", want, joined)
		}
	}
}
