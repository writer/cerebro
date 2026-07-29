package postgres

import (
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/ports"
)

func TestGRCDashboardAggregateQueryCombinesFindingAndEvidenceCounts(t *testing.T) {
	query, args, err := grcDashboardAggregateQuery(ports.GRCDashboardAggregateRequest{
		FindingRequest: ports.ListFindingsRequest{
			TenantID:   "example",
			RuntimeIDs: []string{"tenant-runtime-a", "tenant-runtime-b"},
			Status:     "open",
		},
		EvidenceRequest: ports.ListFindingEvidenceRequest{
			RuntimeIDs: []string{"tenant-runtime-a", "tenant-runtime-b"},
		},
	})
	if err != nil {
		t.Fatalf("grcDashboardAggregateQuery() error = %v", err)
	}
	for _, fragment := range []string{
		"WITH finding_scope AS",
		"SELECT id, status,",
		"COUNT(*) FILTER (WHERE LOWER(status) = 'open') AS open_findings",
		"JOIN finding_control_refs AS ref ON ref.finding_id = finding.id",
		"jsonb_build_object('framework_name', framework_name, 'control_id', control_id)",
		"evidence_summary AS",
		"jsonb_object_agg(finding_id, evidence_count)",
		"GROUP BY finding_id",
		"FROM finding_evidence",
		"runtime_id IN ($5, $6)",
		"finding_id IN (SELECT id FROM finding_scope)",
	} {
		if !strings.Contains(query, fragment) {
			t.Fatalf("aggregate query missing %q:\n%s", fragment, query)
		}
	}
	// The dashboard evidence total must follow finding_scope (all open findings),
	// not a windowed preview finding-id list, so no positional finding_id filter.
	for _, forbidden := range []string{`E'\x00'`, `|| E'`, "control_key", "finding_id IN ($7", "jsonb_array_elements"} {
		if strings.Contains(query, forbidden) {
			t.Fatalf("aggregate query must not contain %q:\n%s", forbidden, query)
		}
	}
	if len(args) != 6 {
		t.Fatalf("aggregate query args len = %d, want 6 (%v)", len(args), args)
	}
}

func TestFindingControlReferenceProjectionStaysInSync(t *testing.T) {
	statements := strings.Join(ensureFindingStatements, "\n")
	for _, fragment := range []string{
		"CREATE TABLE IF NOT EXISTS finding_control_refs",
		"PRIMARY KEY (finding_id, framework_name, control_id)",
		"CREATE INDEX IF NOT EXISTS finding_control_refs_control_idx",
		"CREATE OR REPLACE FUNCTION sync_finding_control_refs()",
		"AFTER INSERT OR UPDATE OF control_refs_json ON findings",
		"WHERE NOT EXISTS",
	} {
		if !strings.Contains(statements, fragment) {
			t.Fatalf("finding control-reference projection missing %q", fragment)
		}
	}
}

func TestDecodeGRCDashboardControlKeysBuildsKeysInGo(t *testing.T) {
	got, err := decodeGRCDashboardControlKeys(`[
		{"framework_name":" SOC 2 ","control_id":" CC6.1 "},
		{"framework_name":"SOC 2","control_id":"CC6.1"},
		{"framework_name":"","control_id":""}
	]`)
	if err != nil {
		t.Fatalf("decodeGRCDashboardControlKeys() error = %v", err)
	}
	want := []string{"SOC 2\x00CC6.1", "Unmapped\x00Needs mapping"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("decodeGRCDashboardControlKeys() = %#v, want %#v", got, want)
	}
}

func TestDecodeGRCDashboardEvidenceCounts(t *testing.T) {
	got, err := decodeGRCDashboardEvidenceCounts(`{"finding-1":2,"":5}`)
	if err != nil {
		t.Fatalf("decodeGRCDashboardEvidenceCounts() error = %v", err)
	}
	if len(got) != 1 || got["finding-1"] != 2 {
		t.Fatalf("decodeGRCDashboardEvidenceCounts() = %#v, want finding-1=2 only", got)
	}
}

func TestRebasePostgresPlaceholders(t *testing.T) {
	got := rebasePostgresPlaceholders("runtime_id IN ($1, $2) AND finding_id = $3", 4)
	want := "runtime_id IN ($5, $6) AND finding_id = $7"
	if got != want {
		t.Fatalf("rebasePostgresPlaceholders() = %q, want %q", got, want)
	}
}
