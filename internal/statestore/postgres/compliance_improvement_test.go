package postgres

import (
	"strings"
	"testing"
)

func TestComplianceImprovementSchemaIsTenantScopedAndDraftWorkflowReady(t *testing.T) {
	joined := strings.Join(ensureComplianceImprovementStatements, "\n")
	for _, table := range []string{
		"compliance_improvement_runs",
		"compliance_improvement_revisions",
		"compliance_improvement_team_outbox",
	} {
		if !strings.Contains(joined, "CREATE TABLE IF NOT EXISTS "+table) {
			t.Fatalf("schema is missing table %q", table)
		}
	}
	for _, statement := range ensureComplianceImprovementStatements {
		if !strings.HasPrefix(statement, "CREATE TABLE IF NOT EXISTS") {
			continue
		}
		if !strings.Contains(statement, "tenant_id TEXT NOT NULL") || !strings.Contains(statement, "PRIMARY KEY (tenant_id,") {
			t.Fatalf("table is not tenant scoped:\n%s", statement)
		}
	}
	for _, fragment := range []string{
		"UNIQUE (tenant_id, program_id, idempotency_key)",
		"UNIQUE (tenant_id, run_id, version)",
		"UNIQUE (tenant_id, idempotency_key)",
		"FOREIGN KEY (tenant_id, run_id)",
		"WHERE delivered_at IS NULL",
	} {
		if !strings.Contains(joined, fragment) {
			t.Fatalf("schema is missing %q", fragment)
		}
	}
}

func TestComplianceImprovementOutboxIDIsTenantScopedAndStable(t *testing.T) {
	first := complianceImprovementOutboxID("tenant-a", "proposal-a")
	if first == "" || first != complianceImprovementOutboxID("tenant-a", "proposal-a") {
		t.Fatalf("outbox id is not stable: %q", first)
	}
	if first == complianceImprovementOutboxID("tenant-b", "proposal-a") {
		t.Fatal("outbox id does not include tenant scope")
	}
}
