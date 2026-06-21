package postgres

import (
	"strings"
	"testing"
)

func TestGRCFindingDispositionUpsertQuery(t *testing.T) {
	query, args := grcFindingDispositionUpsertQuery("writer", "risk_accepted", "alice", []string{"finding-1", "finding-2"})

	for _, fragment := range []string{
		"INSERT INTO grc_finding_dispositions (tenant_id, finding_id, disposition, updated_by)",
		"($1, $4, $2, $3)",
		"($1, $5, $2, $3)",
		"ON CONFLICT (tenant_id, finding_id) DO UPDATE",
		"SET disposition = EXCLUDED.disposition",
		"updated_at = NOW()",
		"RETURNING tenant_id, finding_id, disposition, updated_by, created_at, updated_at",
	} {
		if !strings.Contains(query, fragment) {
			t.Fatalf("upsert query missing %q:\n%s", fragment, query)
		}
	}

	if len(args) != 5 {
		t.Fatalf("args = %d, want 5", len(args))
	}
	if args[0] != "writer" || args[1] != "risk_accepted" || args[2] != "alice" {
		t.Fatalf("leading args = %v, want [writer risk_accepted alice]", args[:3])
	}
	if args[3] != "finding-1" || args[4] != "finding-2" {
		t.Fatalf("finding args = %v, want [finding-1 finding-2]", args[3:])
	}
}
