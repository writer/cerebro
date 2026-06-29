package postgres

import (
	"strings"
	"testing"
)

func TestIdentityDirectorySchemaCreatesTenantScopedUsersAndOrganizations(t *testing.T) {
	joined := strings.Join(ensureIdentityDirectoryStatements, "\n")

	for _, want := range []string{
		"CREATE TABLE IF NOT EXISTS identity_organizations",
		"PRIMARY KEY (tenant_id, org_id)",
		"CREATE TABLE IF NOT EXISTS identity_users",
		"PRIMARY KEY (tenant_id, user_id)",
		"roles_json JSONB",
		"groups_json JSONB",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("identity directory schema missing %q", want)
		}
	}
}
