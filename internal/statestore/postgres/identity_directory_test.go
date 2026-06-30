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

func TestIdentitySourceClauseMatchesDisplayDefault(t *testing.T) {
	clauses := []string{"1=1"}
	args := []any{}

	addIdentitySourceClause(&clauses, &args, " Identity_Directory ")

	if len(args) != 1 || args[0] != "identity_directory" {
		t.Fatalf("args = %#v, want normalized identity_directory", args)
	}
	want := "LOWER(COALESCE(NULLIF(source, ''), 'identity_directory')) = $1"
	if len(clauses) != 2 || clauses[1] != want {
		t.Fatalf("clauses = %#v, want %q", clauses, want)
	}
}
