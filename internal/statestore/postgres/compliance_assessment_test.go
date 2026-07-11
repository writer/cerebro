package postgres

import (
	"strings"
	"testing"
)

func TestComplianceAssessmentSchemaPinsTenantRevisionAndChunkBoundaries(t *testing.T) {
	t.Parallel()
	joined := strings.Join(ensureComplianceAssessmentStatements, "\n")
	for _, required := range []string{
		"PRIMARY KEY (tenant_id, revision_id)",
		"UNIQUE (tenant_id, plan_id, revision_version)",
		"UNIQUE (tenant_id, idempotency_key)",
		"PRIMARY KEY (tenant_id, run_id, sequence)",
		"FOREIGN KEY (tenant_id, plan_revision_id)",
		"payload_digest TEXT NOT NULL",
	} {
		if !strings.Contains(joined, required) {
			t.Fatalf("assessment schema missing %q", required)
		}
	}
}
