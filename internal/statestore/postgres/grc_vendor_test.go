package postgres

import (
	"strings"
	"testing"
)

func TestGRCVendorDiscoveryDecisionSchemaSerializesEvents(t *testing.T) {
	joined := strings.Join(ensureGRCVendorDiscoveryDecisionStatements, "\n")
	for _, fragment := range []string{
		"grc_vendor_discovery_decision_events_tenant_discovery_version_uidx",
		"(tenant_id, discovery_urn, version)",
	} {
		if !strings.Contains(joined, fragment) {
			t.Fatalf("vendor discovery decision schema missing %q:\n%s", fragment, joined)
		}
	}
}

func TestGRCVendorDiscoveryDecisionAdvisoryLockSerializesUpserts(t *testing.T) {
	query := grcVendorDiscoveryDecisionAdvisoryLockSQL()
	for _, fragment := range []string{
		"pg_advisory_xact_lock",
		"hashtext('grc_vendor_discovery_decision')",
		"hashtext($1)",
	} {
		if !strings.Contains(query, fragment) {
			t.Fatalf("vendor discovery decision advisory lock query missing %q:\n%s", fragment, query)
		}
	}
}
