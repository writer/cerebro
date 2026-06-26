package postgres

import (
	"strings"
	"testing"
)

func TestUserPreferenceSchemaCreatesTenantUserPrimaryKey(t *testing.T) {
	joined := strings.Join(ensureUserPreferenceStatements, "\n")

	if !strings.Contains(joined, "CREATE TABLE IF NOT EXISTS user_preferences") {
		t.Fatal("user preference schema should create user_preferences table")
	}
	if !strings.Contains(joined, "PRIMARY KEY (tenant_id, user_id)") {
		t.Fatal("user preference schema should key rows by tenant and user")
	}
	if !strings.Contains(joined, "preferences_json JSONB") {
		t.Fatal("user preference schema should store preferences as jsonb")
	}
}
