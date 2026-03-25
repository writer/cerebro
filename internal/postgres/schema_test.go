package postgres

import (
	"strings"
	"testing"
)

func TestTableDDLsPresent(t *testing.T) {
	expectedTables := []string{
		"findings", "tickets", "access_reviews", "review_items",
		"attack_path_nodes", "attack_path_edges", "attack_paths",
		"agent_sessions", "agent_messages", "provider_syncs",
		"risk_engine_state", "policy_history", "audit_log",
		"webhooks", "webhook_deliveries", "cdc_events",
	}

	for _, table := range expectedTables {
		if _, ok := TableDDLs[table]; !ok {
			t.Errorf("expected table DDL for %q, but not found", table)
		}
	}
}

func TestTableDDLsNoSnowflakeTypes(t *testing.T) {
	snowflakeTypes := []string{
		"VARIANT",
		"TIMESTAMP_NTZ",
		"CURRENT_TIMESTAMP()",
	}

	for name, ddl := range TableDDLs {
		for _, sfType := range snowflakeTypes {
			if strings.Contains(ddl, sfType) {
				t.Errorf("table %q DDL contains Snowflake type %q", name, sfType)
			}
		}
	}
}

func TestTableDDLsUsePostgresTypes(t *testing.T) {
	// Check that at least some tables use JSONB
	foundJSONB := false
	for _, ddl := range TableDDLs {
		if strings.Contains(ddl, "JSONB") {
			foundJSONB = true
			break
		}
	}
	if !foundJSONB {
		t.Error("expected at least one table DDL to use JSONB type")
	}
}

func TestTableDDLsHaveSchemaPlaceholder(t *testing.T) {
	for name, ddl := range TableDDLs {
		if !strings.Contains(ddl, "%s.") {
			t.Errorf("table %q DDL should contain schema placeholder %%s.", name)
		}
	}
}

func TestSchemaNameConstant(t *testing.T) {
	if SchemaName != "cerebro" {
		t.Errorf("SchemaName = %q, want %q", SchemaName, "cerebro")
	}
}
