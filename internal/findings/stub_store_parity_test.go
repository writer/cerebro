package findings_test

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/statestore/postgres"
)

// TestStubFindingStoreFilterParity proves the fast tests' stub finding store
// filters the same way the Postgres store does.
//
// The fast suite runs against stubFindingStore, so any filter the stub drops
// makes tests pass that production would fail. That is exactly how application
// workspace scoping regressed: the stub ignored ApplicationWorkspaceID, the
// filter matched none of the durable findings written by Go event rules, and
// nothing but the nightly Integration job could see it.
//
// Run with: CEREBRO_POSTGRES_DSN=... go test ./internal/findings -run TestStubFindingStoreFilterParity -count=1
func TestStubFindingStoreFilterParity(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("CEREBRO_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("set CEREBRO_POSTGRES_DSN to run the stub/postgres finding filter parity test")
	}
	store, err := postgres.Open(config.StateStoreConfig{
		Driver:      config.StateStoreDriverPostgres,
		PostgresDSN: dsn,
	})
	if err != nil {
		t.Fatalf("open postgres store: %v", err)
	}
	rawDB, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open raw db: %v", err)
	}
	ctx := context.Background()

	nonce := time.Now().UTC().UnixNano()
	tenantID := fmt.Sprintf("tenant-filter-parity-%d", nonce)
	ruleID := fmt.Sprintf("rule-filter-parity-%d", nonce)
	otherRuleID := ruleID + "-other"
	runtimeA := fmt.Sprintf("runtime-parity-a-%d", nonce)
	runtimeB := fmt.Sprintf("runtime-parity-b-%d", nonce)
	workspace := "tenant-only:" + tenantID

	t.Cleanup(func() {
		_, _ = rawDB.ExecContext(context.Background(), `DELETE FROM findings WHERE tenant_id = $1`, tenantID)
		_ = rawDB.Close()
		_ = store.Close()
	})

	base := time.Now().UTC().Add(-30 * 24 * time.Hour).Truncate(time.Microsecond)
	records := []*ports.FindingRecord{
		parityFinding("a-open-legacy", tenantID, "", runtimeA, ruleID, "HIGH", "open", base, base.Add(time.Hour)),
		parityFinding("b-open-scoped", tenantID, workspace, runtimeB, ruleID, "MEDIUM", "open", base.Add(24*time.Hour), base.Add(25*time.Hour)),
		parityFinding("c-resolved", tenantID, workspace, runtimeA, ruleID, "LOW", "resolved", base.Add(48*time.Hour), base.Add(49*time.Hour)),
		// Same rule, different workspace: this is what makes the workspace-scope
		// case discriminating rather than vacuous.
		parityFinding("d-other-workspace", tenantID, "other-workspace", runtimeB, ruleID, "HIGH", "open", base.Add(72*time.Hour), base.Add(73*time.Hour)),
		parityFinding("e-other-rule", tenantID, workspace, runtimeB, otherRuleID, "HIGH", "open", base.Add(96*time.Hour), base.Add(97*time.Hour)),
	}
	records[0].ResourceURNs = []string{"urn:parity:one", "urn:parity:shared"}
	records[1].ResourceURNs = []string{"urn:parity:two", "urn:parity:shared"}
	records[2].ResourceURNs = []string{"urn:parity:three"}
	records[3].ResourceURNs = []string{"urn:parity:four"}
	records[4].ResourceURNs = []string{"urn:parity:five"}
	records[0].ControlRefs = []ports.FindingControlRef{{FrameworkName: "SOC 2", ControlID: "CC6.6"}}
	records[1].ControlRefs = []ports.FindingControlRef{{FrameworkName: "ISO 27001:2022", ControlID: "A.8.20"}}
	records[0].EventIDs = []string{"parity-event-1"}
	records[1].EventIDs = []string{"parity-event-2"}
	records[0].PolicyID = "policy-parity-1"
	// UpsertFinding normalises the effective severity into the severity column,
	// so a stored row never has the two disagreeing. The stub still mirrors
	// findingEffectiveSeveritySQL because tests hand it records directly, without
	// that normalisation; this case only pins the shared post-persist behaviour.
	records[1].Attributes = map[string]string{findings.FindingEffectiveSeverityAttribute: "CRITICAL"}

	for _, record := range records {
		if _, err := store.UpsertFinding(ctx, record); err != nil {
			t.Fatalf("seed %q: %v", record.ID, err)
		}
	}

	// Read the rows back so both sides filter over exactly what Postgres stored,
	// rather than over the in-memory records we happened to send.
	stored := make([]*ports.FindingRecord, 0, len(records))
	for _, record := range records {
		persisted, err := store.GetFinding(ctx, record.ID)
		if err != nil {
			t.Fatalf("read back %q: %v", record.ID, err)
		}
		stored = append(stored, persisted)
	}

	cases := []struct {
		name    string
		request ports.ListFindingsRequest
	}{
		{"rule only", ports.ListFindingsRequest{RuleID: ruleID}},
		{"status open", ports.ListFindingsRequest{RuleID: ruleID, Status: "open"}},
		{"workspace scope", ports.ListFindingsRequest{RuleID: ruleID, ApplicationWorkspaceID: workspace}},
		{"single runtime", ports.ListFindingsRequest{RuleID: ruleID, RuntimeID: runtimeA}},
		{"runtime set", ports.ListFindingsRequest{RuleID: ruleID, RuntimeIDs: []string{runtimeA, runtimeB}}},
		{"severity after effective-severity normalisation", ports.ListFindingsRequest{RuleID: ruleID, Severity: "CRITICAL"}},
		{"severity lowercase", ports.ListFindingsRequest{RuleID: ruleID, Severity: "high"}},
		{"single resource urn", ports.ListFindingsRequest{RuleID: ruleID, ResourceURN: "urn:parity:one"}},
		{"resource urn set", ports.ListFindingsRequest{RuleID: ruleID, ResourceURNs: []string{"urn:parity:two", "urn:parity:three"}}},
		{"shared resource urn", ports.ListFindingsRequest{RuleID: ruleID, ResourceURN: "urn:parity:shared"}},
		{"event id", ports.ListFindingsRequest{RuleID: ruleID, EventID: "parity-event-2"}},
		{"policy id", ports.ListFindingsRequest{RuleID: ruleID, PolicyID: "policy-parity-1"}},
		{"framework", ports.ListFindingsRequest{RuleID: ruleID, Framework: "soc 2"}},
		{"first observed from", ports.ListFindingsRequest{RuleID: ruleID, FirstObservedFrom: base.Add(24 * time.Hour)}},
		{"first observed before", ports.ListFindingsRequest{RuleID: ruleID, FirstObservedBefore: base.Add(48 * time.Hour)}},
		{"last observed before", ports.ListFindingsRequest{RuleID: ruleID, LastObservedBefore: base.Add(25 * time.Hour)}},
		{"finding id", ports.ListFindingsRequest{RuleID: ruleID, FindingID: records[0].ID}},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			request := testCase.request
			request.TenantID = tenantID

			actual, err := store.ListFindings(ctx, request)
			if err != nil {
				t.Fatalf("postgres ListFindings: %v", err)
			}
			fromStore := make([]string, 0, len(actual))
			for _, finding := range actual {
				fromStore = append(fromStore, strings.TrimSpace(finding.ID))
			}

			fromStub := []string{}
			for _, finding := range stored {
				if findings.FindingMatchesForParity(request, finding) {
					fromStub = append(fromStub, strings.TrimSpace(finding.ID))
				}
			}

			sort.Strings(fromStore)
			sort.Strings(fromStub)
			if strings.Join(fromStore, ",") != strings.Join(fromStub, ",") {
				t.Fatalf("stub and postgres disagree\n  postgres: %v\n      stub: %v", fromStore, fromStub)
			}
			if len(fromStore) == 0 {
				t.Fatalf("case matched nothing in either store; it proves no parity")
			}
		})
	}
}

func parityFinding(
	suffix string,
	tenantID string,
	workspace string,
	runtimeID string,
	ruleID string,
	severity string,
	status string,
	firstObserved time.Time,
	lastObserved time.Time,
) *ports.FindingRecord {
	record := &ports.FindingRecord{
		ID:              fmt.Sprintf("finding-parity-%s-%d", suffix, firstObserved.UnixNano()),
		Fingerprint:     fmt.Sprintf("fp-parity-%s-%d", suffix, firstObserved.UnixNano()),
		TenantID:        tenantID,
		RuntimeID:       runtimeID,
		RuleID:          ruleID,
		Title:           "Filter parity finding",
		Severity:        severity,
		Status:          status,
		Summary:         "summary",
		FirstObservedAt: firstObserved,
		LastObservedAt:  lastObserved,
	}
	record.ApplicationWorkspaceID = workspace
	return record
}
