package postgres

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/ports"
)

func TestGRCDashboardAggregateQueryCombinesFindingAndEvidenceCounts(t *testing.T) {
	query, args, err := grcDashboardAggregateQuery(ports.GRCDashboardAggregateRequest{
		FindingRequest: ports.ListFindingsRequest{
			TenantID: "example",
			Status:   "open",
		},
		PreviewFindingIDs: []string{"finding-a", "finding-b"},
		RuntimeScope: &ports.SourceRuntimeFilter{
			TenantID:               "example",
			ApplicationWorkspaceID: "workspace-a",
		},
	})
	if err != nil {
		t.Fatalf("grcDashboardAggregateQuery() error = %v", err)
	}
	for _, fragment := range []string{
		"runtime_scope AS",
		"FROM source_runtimes",
		"tenant_id = $1",
		"application_workspace_id = $2",
		"finding_scope AS",
		"SELECT id, runtime_id, status,",
		"runtime_id = ANY(ARRAY(SELECT id FROM runtime_scope))",
		"COUNT(*) FILTER (WHERE LOWER(status) = 'open') AS open_findings",
		"JOIN finding_control_refs AS ref ON ref.finding_id = finding.id",
		"jsonb_build_object('framework_name', framework_name, 'control_id', control_id)",
		"evidence_summary AS",
		"preview_evidence_counts AS",
		"jsonb_object_agg(finding.id, counts.evidence_count)",
		"JOIN finding_evidence_counts AS counts",
		"counts.runtime_id = finding.runtime_id",
		"finding.id IN ($4, $5)",
	} {
		if !strings.Contains(query, fragment) {
			t.Fatalf("aggregate query missing %q:\n%s", fragment, query)
		}
	}
	// The dashboard evidence total must follow finding_scope (all open findings),
	// not a windowed preview finding-id list, so no positional finding_id filter.
	for _, forbidden := range []string{`E'\x00'`, `|| E'`, "control_key", "FROM finding_evidence\n", "GROUP BY finding_id", "jsonb_array_elements"} {
		if strings.Contains(query, forbidden) {
			t.Fatalf("aggregate query must not contain %q:\n%s", forbidden, query)
		}
	}
	if len(args) != 5 {
		t.Fatalf("aggregate query args len = %d, want 5 (%v)", len(args), args)
	}
	if args[0] != "example" || args[1] != "workspace-a" || args[2] != "open" {
		t.Fatalf("aggregate query scope args = %#v, want tenant/workspace/status first", args)
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

func TestGRCDashboardAggregatePlanUsesMaterializedEvidenceCountsPostgresIntegration(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("CEREBRO_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("set CEREBRO_POSTGRES_DSN to run dashboard aggregate plan integration test")
	}
	store, err := Open(config.StateStoreConfig{Driver: config.StateStoreDriverPostgres, PostgresDSN: dsn})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	ctx := context.Background()
	if err := store.PrepareGRCReadModels(ctx); err != nil {
		t.Fatalf("PrepareGRCReadModels() error = %v", err)
	}
	query, args, err := grcDashboardAggregateQuery(ports.GRCDashboardAggregateRequest{
		FindingRequest: ports.ListFindingsRequest{
			TenantID: "dashboard-plan-tenant",
			Status:   "open",
		},
		PreviewFindingIDs: []string{"dashboard-plan-finding"},
		RuntimeScope: &ports.SourceRuntimeFilter{
			TenantID:               "dashboard-plan-tenant",
			ApplicationWorkspaceID: "dashboard-plan-workspace",
		},
	})
	if err != nil {
		t.Fatalf("grcDashboardAggregateQuery() error = %v", err)
	}
	var plan string
	if err := store.db.QueryRowContext(ctx, "EXPLAIN (FORMAT JSON) "+query, args...).Scan(&plan); err != nil {
		t.Fatalf("EXPLAIN dashboard aggregate: %v", err)
	}
	if !strings.Contains(plan, `"Relation Name": "finding_evidence_counts"`) {
		t.Fatalf("dashboard aggregate plan does not read the materialized count table: %s", plan)
	}
	if strings.Contains(plan, `"Relation Name": "finding_evidence"`) {
		t.Fatalf("dashboard aggregate plan scans raw finding evidence: %s", plan)
	}
	if !strings.Contains(plan, `"Relation Name": "source_runtimes"`) {
		t.Fatalf("dashboard aggregate plan does not resolve normalized runtime scope: %s", plan)
	}
}

func TestGRCDashboardAggregateScopeRejectsTenantWorkspaceMismatch(t *testing.T) {
	_, _, err := grcDashboardAggregateQuery(ports.GRCDashboardAggregateRequest{
		FindingRequest: ports.ListFindingsRequest{TenantID: "tenant-a", Status: "open"},
		RuntimeScope:   &ports.SourceRuntimeFilter{TenantID: "tenant-b", ApplicationWorkspaceID: "workspace-a"},
	})
	if err == nil {
		t.Fatal("grcDashboardAggregateQuery() error = nil, want tenant mismatch")
	}
}
