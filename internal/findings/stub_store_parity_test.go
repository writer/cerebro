package findings_test

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"reflect"
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
// lists findings the same way the Postgres store does: same rows, same order,
// same limit.
//
// The fast suite runs against stubFindingStore, so any filter the stub drops
// makes tests pass that production would fail. That is exactly how application
// workspace scoping regressed: the stub ignored ApplicationWorkspaceID, the
// filter matched none of the durable findings written by Go event rules, and
// nothing but the nightly Integration job could see it.
//
// TestStubFindingStoreFilterParityCoversRequest (below, no Postgres needed)
// fails when a ports.ListFindingsRequest field has no case here, so a new
// filter cannot be added without a parity case.
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

	fixture := newParityFixture(time.Now().UTC())

	t.Cleanup(func() {
		_, _ = rawDB.ExecContext(context.Background(), `DELETE FROM findings WHERE tenant_id = $1`, fixture.tenantID)
		_ = rawDB.Close()
		_ = store.Close()
	})

	for _, record := range fixture.records {
		if _, err := store.UpsertFinding(ctx, record); err != nil {
			t.Fatalf("seed %q: %v", record.ID, err)
		}
	}

	// Read the rows back so both sides filter over exactly what Postgres stored,
	// rather than over the in-memory records we happened to send.
	stored := make([]*ports.FindingRecord, 0, len(fixture.records))
	for _, record := range fixture.records {
		persisted, err := store.GetFinding(ctx, record.ID)
		if err != nil {
			t.Fatalf("read back %q: %v", record.ID, err)
		}
		stored = append(stored, persisted)
	}

	for _, testCase := range fixture.cases() {
		t.Run(testCase.name, func(t *testing.T) {
			actual, err := store.ListFindings(ctx, testCase.request)
			if err != nil {
				t.Fatalf("postgres ListFindings: %v", err)
			}
			listed, err := findings.ListFindingsForParity(testCase.request, stored)
			if err != nil {
				t.Fatalf("stub ListFindings: %v", err)
			}

			// Ordered on purpose: Limit, Order and PriorityOrder decide which rows
			// come back, so a set comparison would let them diverge unnoticed.
			fromStore := parityIDs(actual)
			fromStub := parityIDs(listed)
			if strings.Join(fromStore, ",") != strings.Join(fromStub, ",") {
				t.Fatalf("stub and postgres disagree\n  postgres: %v\n      stub: %v", fromStore, fromStub)
			}
			if len(fromStore) == 0 {
				t.Fatalf("case matched nothing in either store; it proves no parity")
			}
			if len(fromStore) == len(stored) && !testCase.matchesAll {
				t.Fatalf("case matched every seeded row; it discriminates nothing")
			}
		})
	}
}

// TestStubFindingStoreFilterParityCoversRequest enumerates every field of
// ports.ListFindingsRequest and fails when the parity cases never set one of
// them. This is the Postgres-free half of the parity guarantee: adding a filter
// to the request without a parity case fails the fast suite, so the filter
// cannot be silently ignored by the stub in the way ApplicationWorkspaceID was.
func TestStubFindingStoreFilterParityCoversRequest(t *testing.T) {
	fixture := newParityFixture(time.Date(2026, time.September, 1, 12, 0, 0, 0, time.UTC))
	cases := fixture.cases()

	exercised := map[string]struct{}{}
	for _, testCase := range cases {
		for _, name := range setListFindingsRequestFields(testCase.request) {
			exercised[name] = struct{}{}
		}
	}

	for _, name := range listFindingsRequestFields() {
		if _, ok := exercised[name]; !ok {
			t.Errorf(
				"ports.ListFindingsRequest.%s is never set by a TestStubFindingStoreFilterParity case; "+
					"add one so the stub finding store cannot silently ignore it",
				name,
			)
		}
	}

	seen := map[string]struct{}{}
	for _, testCase := range cases {
		if _, ok := seen[testCase.name]; ok {
			t.Errorf("duplicate parity case name %q", testCase.name)
		}
		seen[testCase.name] = struct{}{}
		if strings.TrimSpace(testCase.request.TenantID) == "" {
			t.Errorf("parity case %q has no tenant id", testCase.name)
		}
	}
}

// listFindingsRequestFields returns the leaf field names of
// ports.ListFindingsRequest, flattening embedded structs the way the stub's
// findingFilterSupport classification does.
func listFindingsRequestFields() []string {
	names := []string{}
	var walk func(reflect.Type)
	walk = func(current reflect.Type) {
		for i := range current.NumField() {
			field := current.Field(i)
			if field.Anonymous && field.Type.Kind() == reflect.Struct {
				walk(field.Type)
				continue
			}
			names = append(names, field.Name)
		}
	}
	walk(reflect.TypeOf(ports.ListFindingsRequest{}))
	return names
}

// setListFindingsRequestFields returns the leaf field names that are non-zero
// on the request.
func setListFindingsRequestFields(request ports.ListFindingsRequest) []string {
	names := []string{}
	var walk func(reflect.Value)
	walk = func(current reflect.Value) {
		currentType := current.Type()
		for i := range currentType.NumField() {
			field := currentType.Field(i)
			value := current.Field(i)
			if field.Anonymous && value.Kind() == reflect.Struct {
				walk(value)
				continue
			}
			if !value.IsZero() {
				names = append(names, field.Name)
			}
		}
	}
	walk(reflect.ValueOf(request))
	return names
}

type parityCase struct {
	name    string
	request ports.ListFindingsRequest
	// matchesAll marks the one case that is allowed to return every seeded row:
	// the unfiltered baseline that proves ordering alone.
	matchesAll bool
}

// parityFixture seeds five findings for one tenant that differ on every
// filterable axis, so each parity case selects a strict, non-empty subset.
type parityFixture struct {
	tenantID    string
	ruleID      string
	otherRuleID string
	runtimeA    string
	runtimeB    string
	workspace   string
	base        time.Time
	records     []*ports.FindingRecord
}

func newParityFixture(now time.Time) parityFixture {
	nonce := now.UnixNano()
	fixture := parityFixture{
		tenantID:    fmt.Sprintf("tenant-filter-parity-%d", nonce),
		ruleID:      fmt.Sprintf("rule-filter-parity-%d", nonce),
		runtimeA:    fmt.Sprintf("runtime-parity-a-%d", nonce),
		runtimeB:    fmt.Sprintf("runtime-parity-b-%d", nonce),
		otherRuleID: fmt.Sprintf("rule-filter-parity-%d-other", nonce),
	}
	fixture.workspace = "tenant-only:" + fixture.tenantID
	// Age filters are whole-day windows against NOW(); the half-day offset
	// keeps every first_observed_at well away from a day boundary so the
	// stub's clock and the database's NOW() cannot land on different sides.
	fixture.base = now.Add(-30*24*time.Hour - 12*time.Hour).Truncate(time.Microsecond)
	base := fixture.base
	const day = 24 * time.Hour

	a := parityFinding("a-open-legacy", fixture.tenantID, "", fixture.runtimeA, fixture.ruleID, "HIGH", "open", base, base.Add(time.Hour))
	a.ResourceURNs = []string{"urn:parity:one", "urn:parity:shared"}
	a.ControlRefs = []ports.FindingControlRef{{FrameworkName: "SOC 2", ControlID: "CC6.6"}}
	a.EventIDs = []string{"parity-event-1"}
	a.PolicyID = "policy-parity-1"
	a.StatusUpdatedAt = base.Add(2 * time.Hour)
	a.DueAt = now.Add(-day) // overdue
	a.RiskScore = 50

	b := parityFinding("b-open-scoped", fixture.tenantID, fixture.workspace, fixture.runtimeB, fixture.ruleID, "MEDIUM", "open", base.Add(day), base.Add(25*time.Hour))
	b.ResourceURNs = []string{"urn:parity:two", "urn:parity:shared"}
	b.ControlRefs = []ports.FindingControlRef{{FrameworkName: "ISO 27001:2022", ControlID: "A.8.20"}}
	b.EventIDs = []string{"parity-event-2"}
	b.StatusUpdatedAt = base.Add(26 * time.Hour)
	b.DueAt = now.Add(day) // due_soon
	// UpsertFinding normalises the effective severity into the severity column,
	// so a stored row never has the two disagreeing. The stub still mirrors
	// findingEffectiveSeveritySQL because tests hand it records directly, without
	// that normalisation; this case only pins the shared post-persist behaviour.
	b.Attributes = map[string]string{findings.FindingEffectiveSeverityAttribute: "CRITICAL"}

	c := parityFinding("c-resolved", fixture.tenantID, fixture.workspace, fixture.runtimeA, fixture.ruleID, "LOW", "resolved", base.Add(2*day), base.Add(49*time.Hour))
	c.ResourceURNs = []string{"urn:parity:three"}
	c.StatusUpdatedAt = base.Add(50 * time.Hour)
	c.RiskScore = 90

	// Same rule, different workspace: this is what makes the workspace-scope
	// case discriminating rather than vacuous.
	d := parityFinding("d-other-workspace", fixture.tenantID, "other-workspace", fixture.runtimeB, fixture.ruleID, "HIGH", "open", base.Add(3*day), base.Add(73*time.Hour))
	d.ResourceURNs = []string{"urn:parity:four"}
	d.StatusUpdatedAt = base.Add(74 * time.Hour)
	d.DueAt = now.Add(10 * day) // on_track

	// No due date and no status_updated_at: both persist as NULL, which the
	// SLA and status_updated_at cases rely on to discriminate.
	e := parityFinding("e-other-rule", fixture.tenantID, fixture.workspace, fixture.runtimeB, fixture.otherRuleID, "HIGH", "open", base.Add(4*day), base.Add(97*time.Hour))
	e.ResourceURNs = []string{"urn:parity:five"}

	fixture.records = []*ports.FindingRecord{a, b, c, d, e}
	return fixture
}

func (f parityFixture) cases() []parityCase {
	base := f.base
	bothRuntimes := []string{f.runtimeA, f.runtimeB}
	cases := []parityCase{
		{name: "rule only", request: ports.ListFindingsRequest{RuleID: f.ruleID}},
		{name: "both runtimes unfiltered", request: ports.ListFindingsRequest{RuntimeIDs: bothRuntimes}, matchesAll: true},
		{name: "status open", request: ports.ListFindingsRequest{RuleID: f.ruleID, Status: "open"}},
		{name: "workspace scope", request: ports.ListFindingsRequest{RuleID: f.ruleID, ApplicationWorkspaceID: f.workspace}},
		{name: "single runtime", request: ports.ListFindingsRequest{RuleID: f.ruleID, RuntimeID: f.runtimeA}},
		{name: "runtime set", request: ports.ListFindingsRequest{RuleID: f.ruleID, RuntimeIDs: bothRuntimes}},
		{name: "severity after effective-severity normalisation", request: ports.ListFindingsRequest{RuleID: f.ruleID, Severity: "CRITICAL"}},
		{name: "severity lowercase", request: ports.ListFindingsRequest{RuleID: f.ruleID, Severity: "high"}},
		{name: "single resource urn", request: ports.ListFindingsRequest{RuleID: f.ruleID, ResourceURN: "urn:parity:one"}},
		{name: "resource urn set", request: ports.ListFindingsRequest{RuleID: f.ruleID, ResourceURNs: []string{"urn:parity:two", "urn:parity:three"}}},
		{name: "shared resource urn", request: ports.ListFindingsRequest{RuleID: f.ruleID, ResourceURN: "urn:parity:shared"}},
		{name: "event id", request: ports.ListFindingsRequest{RuleID: f.ruleID, EventID: "parity-event-2"}},
		{name: "policy id", request: ports.ListFindingsRequest{RuleID: f.ruleID, PolicyID: "policy-parity-1"}},
		{name: "framework", request: ports.ListFindingsRequest{RuleID: f.ruleID, Framework: "soc 2"}},
		{name: "first observed from", request: ports.ListFindingsRequest{RuleID: f.ruleID, FirstObservedFrom: base.Add(24 * time.Hour)}},
		{name: "first observed before", request: ports.ListFindingsRequest{RuleID: f.ruleID, FirstObservedBefore: base.Add(48 * time.Hour)}},
		{name: "status updated from", request: ports.ListFindingsRequest{RuleID: f.ruleID, StatusUpdatedFrom: base.Add(50 * time.Hour)}},
		// Includes the row whose status_updated_at is NULL, which neither bound
		// may admit.
		{name: "status updated before", request: ports.ListFindingsRequest{RuntimeIDs: bothRuntimes, StatusUpdatedBefore: base.Add(50 * time.Hour)}},
		{name: "last observed before", request: ports.ListFindingsRequest{RuleID: f.ruleID, LastObservedBefore: base.Add(25 * time.Hour)}},
		{name: "finding id", request: ports.ListFindingsRequest{RuleID: f.ruleID, FindingID: f.records[0].ID}},

		// Profile predicate: rule IDs OR control refs, case-insensitive on refs.
		{name: "profile rule ids", request: ports.ListFindingsRequest{RuntimeIDs: bothRuntimes, ProfilePredicate: ports.FindingProfilePredicate{RuleIDs: []string{f.otherRuleID}}}},
		{name: "profile control refs", request: ports.ListFindingsRequest{RuleID: f.ruleID, ProfilePredicate: ports.FindingProfilePredicate{ControlRefs: []ports.FindingControlRef{{FrameworkName: "soc 2", ControlID: "cc6.6"}}}}},
		{name: "profile union", request: ports.ListFindingsRequest{RuntimeIDs: bothRuntimes, ProfilePredicate: ports.FindingProfilePredicate{
			RuleIDs:     []string{f.otherRuleID},
			ControlRefs: []ports.FindingControlRef{{FrameworkName: "ISO 27001:2022", ControlID: "A.8.20"}},
		}}},

		// Age in whole days from first_observed_at against NOW().
		{name: "min age days", request: ports.ListFindingsRequest{RuleID: f.ruleID, FindingAgeRange: ports.FindingAgeRange{MinAgeDays: 28}}},
		{name: "max age days", request: ports.ListFindingsRequest{RuleID: f.ruleID, FindingAgeRange: ports.FindingAgeRange{MaxAgeDays: 28}}},
		{name: "age window", request: ports.ListFindingsRequest{RuleID: f.ruleID, FindingAgeRange: ports.FindingAgeRange{MinAgeDays: 28, MaxAgeDays: 28}}},

		// SLA status against NOW() and a nullable due_at.
		{name: "sla overdue", request: ports.ListFindingsRequest{RuleID: f.ruleID, SLAStatus: "overdue"}},
		{name: "sla due soon", request: ports.ListFindingsRequest{RuleID: f.ruleID, SLAStatus: "due_soon"}},
		{name: "sla on track", request: ports.ListFindingsRequest{RuleID: f.ruleID, SLAStatus: "on_track"}},
		{name: "sla no due date", request: ports.ListFindingsRequest{RuntimeIDs: bothRuntimes, SLAStatus: "no_due_date"}},
		{name: "sla closed", request: ports.ListFindingsRequest{RuleID: f.ruleID, SLAStatus: "closed"}},
		{name: "sla explicit status", request: ports.ListFindingsRequest{RuleID: f.ruleID, SLAStatus: "Resolved"}},

		// Ordering and paging decide which rows come back once a limit applies.
		{name: "limit", request: ports.ListFindingsRequest{RuleID: f.ruleID, Limit: 2}},
		{name: "priority order", request: ports.ListFindingsRequest{RuleID: f.ruleID, PriorityOrder: true, Limit: 2}},
		{name: "order priority", request: ports.ListFindingsRequest{RuleID: f.ruleID, Order: ports.FindingOrderPriority}},
		{name: "order risk score", request: ports.ListFindingsRequest{RuleID: f.ruleID, Order: ports.FindingOrderRiskScore, Limit: 3}},
	}
	for i := range cases {
		cases[i].request.TenantID = f.tenantID
	}
	return cases
}

func parityIDs(records []*ports.FindingRecord) []string {
	ids := make([]string, 0, len(records))
	for _, record := range records {
		ids = append(ids, strings.TrimSpace(record.ID))
	}
	return ids
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
