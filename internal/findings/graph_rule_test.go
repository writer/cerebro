package findings

import (
	"context"
	"errors"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

type stubGraphRule struct {
	spec     *cerebrov1.RuleSpec
	sourceID string
	query    ports.CypherQueryRequest
	rows     []ports.CypherRow
	emit     []*ports.FindingRecord
	emitErr  error
}

func (r *stubGraphRule) Spec() *cerebrov1.RuleSpec {
	if r == nil {
		return nil
	}
	return r.spec
}

func (r *stubGraphRule) SupportsRuntime(runtime *cerebrov1.SourceRuntime) bool {
	if r == nil || runtime == nil {
		return false
	}
	return runtime.GetSourceId() == r.sourceID
}

func (r *stubGraphRule) Evaluate(_ context.Context, _ *cerebrov1.SourceRuntime, _ *cerebrov1.EventEnvelope) ([]*ports.FindingRecord, error) {
	return nil, nil
}

func (r *stubGraphRule) QueryFor(_ *cerebrov1.SourceRuntime) ports.CypherQueryRequest {
	if r == nil {
		return ports.CypherQueryRequest{}
	}
	return r.query
}

func (r *stubGraphRule) EvaluateRows(_ context.Context, _ *cerebrov1.SourceRuntime, rows []ports.CypherRow) ([]*ports.FindingRecord, error) {
	if r == nil {
		return nil, nil
	}
	if r.emitErr != nil {
		return nil, r.emitErr
	}
	r.rows = append(r.rows, rows...)
	return r.emit, nil
}

// scopedStubGraphRule opts into ScopedStaleResolver with an injectable scope
// attribute and incomplete-scope set, so service tests can drive cap-aware stale
// resolution without re-deriving scopes from rows.
type scopedStubGraphRule struct {
	stubGraphRule
	scopeAttribute   string
	incompleteScopes map[string]struct{}
}

func (r *scopedStubGraphRule) StaleResolutionScopeAttribute() string {
	return r.scopeAttribute
}

func (r *scopedStubGraphRule) IncompleteStaleResolutionScopes(_ []ports.CypherRow) map[string]struct{} {
	return r.incompleteScopes
}

func TestEvaluateSourceRuntimeGraphRulesExcludesNamedRules(t *testing.T) {
	runtime := &cerebrov1.SourceRuntime{Id: "runtime-okta", SourceId: "okta", TenantId: "writer"}
	store := &stubFindingStore{}
	graphStore := &stubGraphStore{}
	ruleA := &stubGraphRule{spec: &cerebrov1.RuleSpec{Id: "rule-a"}, sourceID: "okta", query: ports.CypherQueryRequest{Query: "MATCH (n) RETURN n"}}
	ruleB := &stubGraphRule{spec: &cerebrov1.RuleSpec{Id: "rule-b"}, sourceID: "okta", query: ports.CypherQueryRequest{Query: "MATCH (n) RETURN n"}}
	registry, err := NewRegistry(ruleA, ruleB)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	service := NewWithRegistry(newGraphRuleStubRuntimeStore(runtime), &stubReplayer{}, store, store, store, store, registry).WithGraphQueryStore(graphStore)

	// Excluding rule-a leaves only rule-b (coverage for the other rule is kept).
	result, err := service.EvaluateSourceRuntimeGraphRules(context.Background(), EvaluateGraphRulesRequest{RuntimeID: "runtime-okta", ExcludeRuleIDs: []string{"rule-a"}})
	if err != nil {
		t.Fatalf("EvaluateSourceRuntimeGraphRules() error = %v", err)
	}
	if got := len(result.Evaluations); got != 1 {
		t.Fatalf("len(Evaluations) = %d, want 1", got)
	}
	if got := result.Evaluations[0].Rule.GetId(); got != "rule-b" {
		t.Fatalf("evaluated rule = %q, want rule-b", got)
	}

	// Excluding every supported rule evaluates nothing, without error: the
	// tenant already ran them this cycle.
	empty, err := service.EvaluateSourceRuntimeGraphRules(context.Background(), EvaluateGraphRulesRequest{RuntimeID: "runtime-okta", ExcludeRuleIDs: []string{"rule-a", "rule-b"}})
	if err != nil {
		t.Fatalf("EvaluateSourceRuntimeGraphRules() error = %v", err)
	}
	if got := len(empty.Evaluations); got != 0 {
		t.Fatalf("len(Evaluations) = %d, want 0 when all rules excluded", got)
	}
}

func TestAsGraphRuleNarrows(t *testing.T) {
	if _, ok := asGraphRule(nil); ok {
		t.Fatalf("asGraphRule(nil) should be false")
	}
	regular := &stubRule{spec: &cerebrov1.RuleSpec{Id: "regular"}}
	if _, ok := asGraphRule(regular); ok {
		t.Fatalf("asGraphRule(regular) should be false")
	}
	graph := &stubGraphRule{spec: &cerebrov1.RuleSpec{Id: "graph"}}
	if _, ok := asGraphRule(graph); !ok {
		t.Fatalf("asGraphRule(graph) should be true")
	}
}

func newGraphRuleStubRuntimeStore(runtime *cerebrov1.SourceRuntime) *stubRuntimeStore {
	return &stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{runtime.GetId(): runtime}}
}

func TestEvaluateSourceRuntimeGraphRulesEmitsAndPersistsFindings(t *testing.T) {
	runtime := &cerebrov1.SourceRuntime{Id: "runtime-okta", SourceId: "okta", TenantId: "writer"}
	store := &stubFindingStore{}
	graphStore := &stubGraphStore{
		cypherRows: []ports.CypherRow{
			{Values: map[string]any{"label": "alice@writer.com"}},
		},
	}
	rule := &stubGraphRule{
		spec:     &cerebrov1.RuleSpec{Id: "test-graph-rule"},
		sourceID: "okta",
		query: ports.CypherQueryRequest{
			Query:  "MATCH (n) RETURN n LIMIT 1",
			Params: map[string]any{"tenant_id": "writer"},
		},
		emit: []*ports.FindingRecord{
			{
				ID:           "finding-graph-1",
				Fingerprint:  "fp-graph-1",
				TenantID:     "writer",
				RuntimeID:    "runtime-okta",
				RuleID:       "test-graph-rule",
				Title:        "Test graph finding",
				Severity:     "CRITICAL",
				Status:       findingStatusOpen,
				Summary:      "graph rule fired",
				ResourceURNs: []string{"urn:cerebro:writer:identity:email:alice@writer.com"},
				GraphEvidenceRows: []*cerebrov1.GraphEvidenceRow{
					newGraphEvidenceRow("identity_path", map[string]string{"label": "alice@writer.com"}, newGraphEvidencePath(
						"urn:cerebro:writer:okta_user:alice",
						"alice@writer.com",
						"okta.user",
						"represents_identity",
						"urn:cerebro:writer:identity:email:alice@writer.com",
						"alice@writer.com",
						"identity.email",
						map[string]string{"match_type": "exact_email"},
					)),
				},
			},
		},
	}
	registry, err := NewRegistry(rule)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	service := NewWithRegistry(newGraphRuleStubRuntimeStore(runtime), &stubReplayer{}, store, store, store, store, registry).WithGraphQueryStore(graphStore)
	result, err := service.EvaluateSourceRuntimeGraphRules(context.Background(), EvaluateGraphRulesRequest{RuntimeID: "runtime-okta"})
	if err != nil {
		t.Fatalf("EvaluateSourceRuntimeGraphRules() error = %v", err)
	}
	if got := len(result.Evaluations); got != 1 {
		t.Fatalf("len(Evaluations) = %d, want 1", got)
	}
	evaluation := result.Evaluations[0]
	if got := evaluation.Rule.GetId(); got != "test-graph-rule" {
		t.Fatalf("Rule.Id = %q, want %q", got, "test-graph-rule")
	}
	if got := evaluation.RowsRead; got != 1 {
		t.Fatalf("RowsRead = %d, want 1", got)
	}
	if evaluation.Truncated {
		t.Fatalf("Truncated = true, want false (rows below cap)")
	}
	if got := len(evaluation.Findings); got != 1 {
		t.Fatalf("len(Findings) = %d, want 1", got)
	}
	if got := evaluation.Findings[0].ID; got != "finding-graph-1" {
		t.Fatalf("Findings[0].ID = %q, want %q", got, "finding-graph-1")
	}
	if got := evaluation.Run.GetStatus(); got != "completed" {
		t.Fatalf("Run.Status = %q, want completed", got)
	}
	if got := evaluation.Run.GetEventsEvaluated(); got != 0 {
		t.Fatalf("Run.EventsEvaluated = %d, want 0 (graph rules read graph rows, not events)", got)
	}
	if store.findings == nil || store.findings["finding-graph-1"] == nil {
		t.Fatalf("finding store should contain persisted finding")
	}
	if got := len(evaluation.Evidence); got != 1 {
		t.Fatalf("len(Evidence) = %d, want 1", got)
	}
	if got := len(evaluation.Evidence[0].GetGraphRows()); got != 1 {
		t.Fatalf("len(Evidence[0].GraphRows) = %d, want 1", got)
	}
	if got := evaluation.Evidence[0].GetAttributes()["primary_resource_urn"]; got != "" {
		t.Fatalf("Evidence[0].Attributes[primary_resource_urn] = %q, want empty for fixture without finding attributes", got)
	}
	if len(evaluation.Evidence[0].GetGraphPathUrns()) != 2 {
		t.Fatalf("Evidence[0].GraphPathUrns = %#v, want two endpoint urns", evaluation.Evidence[0].GetGraphPathUrns())
	}
	if got := evaluation.Evidence[0].GetGraphRows()[0].GetPaths()[0].GetRelation(); got != "represents_identity" {
		t.Fatalf("graph evidence relation = %q, want represents_identity", got)
	}
}

func TestEvaluateSourceRuntimeGraphRulesTruncatedSkipsStaleResolution(t *testing.T) {
	// When the cypher result hits the row cap we cannot tell a graph that has cap rows from a
	// graph that has cap+1: an offender may have fallen past the cutoff. Auto-resolving open
	// findings on that incomplete view would close still-active findings.
	const rowLimit = 2
	runtime := &cerebrov1.SourceRuntime{Id: "runtime-okta", SourceId: "okta", TenantId: "writer"}
	staleFinding := &ports.FindingRecord{
		ID:          "finding-stale",
		Fingerprint: "fp-stale",
		TenantID:    "writer",
		RuntimeID:   "runtime-okta",
		RuleID:      "truncating-rule",
		Status:      findingStatusOpen,
	}
	store := &stubFindingStore{findings: map[string]*ports.FindingRecord{staleFinding.ID: cloneFinding(staleFinding)}}
	graphStore := &stubGraphStore{
		cypherRows: []ports.CypherRow{
			{Values: map[string]any{"label": "row-1"}},
			{Values: map[string]any{"label": "row-2"}},
		},
	}
	rule := &stubGraphRule{
		spec:     &cerebrov1.RuleSpec{Id: "truncating-rule"},
		sourceID: "okta",
		query: ports.CypherQueryRequest{
			Query:    "MATCH (n) RETURN n LIMIT $row_limit",
			Params:   map[string]any{"row_limit": int64(rowLimit)},
			RowLimit: rowLimit,
		},
	}
	registry, err := NewRegistry(rule)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	service := NewWithRegistry(newGraphRuleStubRuntimeStore(runtime), &stubReplayer{}, store, store, store, store, registry).WithGraphQueryStore(graphStore)
	result, err := service.EvaluateSourceRuntimeGraphRules(context.Background(), EvaluateGraphRulesRequest{RuntimeID: "runtime-okta"})
	if err != nil {
		t.Fatalf("EvaluateSourceRuntimeGraphRules() error = %v", err)
	}
	if got := len(result.Evaluations); got != 1 {
		t.Fatalf("len(Evaluations) = %d, want 1", got)
	}
	evaluation := result.Evaluations[0]
	if !evaluation.Truncated {
		t.Fatalf("Truncated = false, want true (rows hit cap)")
	}
	persisted, ok := store.findings[staleFinding.ID]
	if !ok {
		t.Fatalf("stale finding %q missing after evaluation", staleFinding.ID)
	}
	if got := persisted.Status; got != findingStatusOpen {
		t.Fatalf("stale finding status = %q, want still %q (truncated cypher view must not auto-resolve)", got, findingStatusOpen)
	}
}

func TestEvaluateSourceRuntimeGraphRulesCapSignalSkipsStaleResolution(t *testing.T) {
	// A rule can drop matching data internally (e.g. a per-account cap) while the
	// total row count stays under the row limit. When that happens the query sets
	// graph_rule_truncated=true so the evaluation is treated as truncated and
	// stale-finding auto-resolution is skipped; otherwise still-active findings for
	// the dropped rows would be wrongly closed as no-longer-matching.
	for _, tc := range []struct {
		name          string
		signal        any
		wantTruncated bool
	}{
		{name: "capped signals truncation", signal: true, wantTruncated: true},
		{name: "capped string signals truncation", signal: "true", wantTruncated: true},
		{name: "not capped allows resolution", signal: false, wantTruncated: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runtime := &cerebrov1.SourceRuntime{Id: "runtime-okta", SourceId: "okta", TenantId: "writer"}
			staleFinding := &ports.FindingRecord{
				ID:          "finding-stale",
				Fingerprint: "fp-stale",
				TenantID:    "writer",
				RuntimeID:   "runtime-okta",
				RuleID:      "capping-rule",
				Status:      findingStatusOpen,
			}
			store := &stubFindingStore{findings: map[string]*ports.FindingRecord{staleFinding.ID: cloneFinding(staleFinding)}}
			graphStore := &stubGraphStore{
				cypherRows: []ports.CypherRow{
					{Values: map[string]any{"label": "row-1", graphRuleTruncationColumn: tc.signal}},
				},
			}
			rule := &stubGraphRule{
				spec:     &cerebrov1.RuleSpec{Id: "capping-rule"},
				sourceID: "okta",
				query: ports.CypherQueryRequest{
					Query:    "MATCH (n) RETURN n LIMIT $row_limit",
					Params:   map[string]any{"row_limit": int64(250)},
					RowLimit: 250,
				},
			}
			registry, err := NewRegistry(rule)
			if err != nil {
				t.Fatalf("NewRegistry() error = %v", err)
			}
			service := NewWithRegistry(newGraphRuleStubRuntimeStore(runtime), &stubReplayer{}, store, store, store, store, registry).WithGraphQueryStore(graphStore)
			result, err := service.EvaluateSourceRuntimeGraphRules(context.Background(), EvaluateGraphRulesRequest{RuntimeID: "runtime-okta"})
			if err != nil {
				t.Fatalf("EvaluateSourceRuntimeGraphRules() error = %v", err)
			}
			if got := len(result.Evaluations); got != 1 {
				t.Fatalf("len(Evaluations) = %d, want 1", got)
			}
			if got := result.Evaluations[0].Truncated; got != tc.wantTruncated {
				t.Fatalf("Truncated = %v, want %v (1 row below the row limit, signal=%v)", got, tc.wantTruncated, tc.signal)
			}
			persisted, ok := store.findings[staleFinding.ID]
			if !ok {
				t.Fatalf("stale finding %q missing after evaluation", staleFinding.ID)
			}
			if tc.wantTruncated {
				if got := persisted.Status; got != findingStatusOpen {
					t.Fatalf("stale finding status = %q, want still %q (cap signal must skip stale resolution)", got, findingStatusOpen)
				}
				return
			}
			if got := persisted.StatusReason; got != "graph_rule_no_longer_matches" {
				t.Fatalf("stale finding StatusReason = %q, want graph_rule_no_longer_matches (no cap signal must auto-resolve)", got)
			}
		})
	}
}

func TestEvaluateSourceRuntimeGraphRulesCapAwareStaleResolutionResolvesCompleteScopes(t *testing.T) {
	// A per-scope-capped rule (ScopedStaleResolver) drops data for SOME scopes while
	// leaving others fully represented. When only the internal cap fired (the global
	// row limit was not hit) stale resolution must run scope-by-scope: keep capped
	// scopes open, resolve scopes that came back complete, resolve scopes that no
	// longer match at all, and leave findings with no scope key untouched.
	const scopeAttr = "cloud_account_urn"
	cappedAccount := "urn:cerebro:writer:cloud_account:capped"
	completeAccount := "urn:cerebro:writer:cloud_account:complete"
	absentAccount := "urn:cerebro:writer:cloud_account:absent"
	runtime := &cerebrov1.SourceRuntime{Id: "runtime-aws", SourceId: "aws", TenantId: "writer"}
	openFinding := func(id, account string) *ports.FindingRecord {
		finding := &ports.FindingRecord{
			ID:          id,
			Fingerprint: id,
			TenantID:    "writer",
			RuntimeID:   "runtime-aws",
			RuleID:      "scoped-rule",
			Status:      findingStatusOpen,
		}
		if account != "" {
			finding.Attributes = map[string]string{scopeAttr: account}
		}
		return finding
	}
	store := &stubFindingStore{findings: map[string]*ports.FindingRecord{
		"stale-capped":   openFinding("stale-capped", cappedAccount),
		"stale-complete": openFinding("stale-complete", completeAccount),
		"stale-absent":   openFinding("stale-absent", absentAccount),
		"stale-noscope":  openFinding("stale-noscope", ""),
	}}
	graphStore := &stubGraphStore{cypherRows: []ports.CypherRow{
		{Values: map[string]any{"account_urn": cappedAccount, graphRuleTruncationColumn: true}},
		{Values: map[string]any{"account_urn": completeAccount, graphRuleTruncationColumn: false}},
	}}
	rule := &scopedStubGraphRule{
		stubGraphRule: stubGraphRule{
			spec:     &cerebrov1.RuleSpec{Id: "scoped-rule"},
			sourceID: "aws",
			query: ports.CypherQueryRequest{
				Query:    "MATCH (n) RETURN n LIMIT $row_limit",
				Params:   map[string]any{"row_limit": int64(250)},
				RowLimit: 250,
			},
		},
		scopeAttribute:   scopeAttr,
		incompleteScopes: map[string]struct{}{cappedAccount: {}},
	}
	registry, err := NewRegistry(rule)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	service := NewWithRegistry(newGraphRuleStubRuntimeStore(runtime), &stubReplayer{}, store, store, store, store, registry).WithGraphQueryStore(graphStore)
	result, err := service.EvaluateSourceRuntimeGraphRules(context.Background(), EvaluateGraphRulesRequest{RuntimeID: "runtime-aws"})
	if err != nil {
		t.Fatalf("EvaluateSourceRuntimeGraphRules() error = %v", err)
	}
	if got := len(result.Evaluations); got != 1 {
		t.Fatalf("len(Evaluations) = %d, want 1", got)
	}
	if !result.Evaluations[0].Truncated {
		t.Fatalf("Truncated = false, want true (a capped row signals truncation)")
	}
	wantStatus := map[string]string{
		"stale-capped":   findingStatusOpen,     // capped scope: a still-matching row may have been dropped
		"stale-complete": findingStatusResolved, // fully-represented scope: safe to auto-resolve
		"stale-absent":   findingStatusResolved, // scope no longer matches; cap cannot drop a whole scope
		"stale-noscope":  findingStatusOpen,     // no scope key: cannot prove the scope was complete
	}
	for id, want := range wantStatus {
		finding, ok := store.findings[id]
		if !ok {
			t.Fatalf("finding %q missing after evaluation", id)
		}
		if got := finding.Status; got != want {
			t.Fatalf("finding %q status = %q, want %q", id, got, want)
		}
	}
}

func TestEvaluateSourceRuntimeGraphRulesCapAwareResolutionSkippedOnRowLimit(t *testing.T) {
	// When the GLOBAL row limit is hit, entire scopes can fall past the cutoff, so even a
	// ScopedStaleResolver must keep the conservative global skip and resolve nothing: an
	// absent scope here is indistinguishable from one whose rows were simply truncated.
	const (
		scopeAttr = "cloud_account_urn"
		rowLimit  = 2
	)
	cappedAccount := "urn:cerebro:writer:cloud_account:capped"
	completeAccount := "urn:cerebro:writer:cloud_account:complete"
	runtime := &cerebrov1.SourceRuntime{Id: "runtime-aws", SourceId: "aws", TenantId: "writer"}
	staleComplete := &ports.FindingRecord{
		ID:          "stale-complete",
		Fingerprint: "stale-complete",
		TenantID:    "writer",
		RuntimeID:   "runtime-aws",
		RuleID:      "scoped-rule",
		Status:      findingStatusOpen,
		Attributes:  map[string]string{scopeAttr: completeAccount},
	}
	store := &stubFindingStore{findings: map[string]*ports.FindingRecord{staleComplete.ID: cloneFinding(staleComplete)}}
	graphStore := &stubGraphStore{cypherRows: []ports.CypherRow{
		{Values: map[string]any{"account_urn": cappedAccount, graphRuleTruncationColumn: true}},
		{Values: map[string]any{"account_urn": completeAccount, graphRuleTruncationColumn: false}},
	}}
	rule := &scopedStubGraphRule{
		stubGraphRule: stubGraphRule{
			spec:     &cerebrov1.RuleSpec{Id: "scoped-rule"},
			sourceID: "aws",
			query: ports.CypherQueryRequest{
				Query:    "MATCH (n) RETURN n LIMIT $row_limit",
				Params:   map[string]any{"row_limit": int64(rowLimit)},
				RowLimit: rowLimit,
			},
		},
		scopeAttribute:   scopeAttr,
		incompleteScopes: map[string]struct{}{cappedAccount: {}},
	}
	registry, err := NewRegistry(rule)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	service := NewWithRegistry(newGraphRuleStubRuntimeStore(runtime), &stubReplayer{}, store, store, store, store, registry).WithGraphQueryStore(graphStore)
	result, err := service.EvaluateSourceRuntimeGraphRules(context.Background(), EvaluateGraphRulesRequest{RuntimeID: "runtime-aws"})
	if err != nil {
		t.Fatalf("EvaluateSourceRuntimeGraphRules() error = %v", err)
	}
	if !result.Evaluations[0].Truncated {
		t.Fatalf("Truncated = false, want true (rows hit the row limit)")
	}
	if got := store.findings[staleComplete.ID].Status; got != findingStatusOpen {
		t.Fatalf("stale finding status = %q, want still %q (row-limit truncation must skip scoped resolution)", got, findingStatusOpen)
	}
}

func TestEvaluateSourceRuntimeGraphRulesRequiresGraphQuery(t *testing.T) {
	runtime := &cerebrov1.SourceRuntime{Id: "runtime-okta", SourceId: "okta", TenantId: "writer"}
	store := &stubFindingStore{}
	registry, err := NewRegistry(&stubGraphRule{spec: &cerebrov1.RuleSpec{Id: "graph-rule"}, sourceID: "okta"})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	service := NewWithRegistry(newGraphRuleStubRuntimeStore(runtime), &stubReplayer{}, store, store, store, store, registry)
	if _, err := service.EvaluateSourceRuntimeGraphRules(context.Background(), EvaluateGraphRulesRequest{RuntimeID: "runtime-okta"}); !errors.Is(err, ErrRuntimeUnavailable) {
		t.Fatalf("EvaluateSourceRuntimeGraphRules() error = %v, want ErrRuntimeUnavailable", err)
	}
}

func TestEvaluateSourceRuntimeGraphRulesPropagatesCypherFailure(t *testing.T) {
	runtime := &cerebrov1.SourceRuntime{Id: "runtime-okta", SourceId: "okta", TenantId: "writer"}
	store := &stubFindingStore{}
	graphStore := &stubGraphStore{cypherErr: errors.New("boom")}
	rule := &stubGraphRule{
		spec:     &cerebrov1.RuleSpec{Id: "graph-rule"},
		sourceID: "okta",
		query:    ports.CypherQueryRequest{Query: "MATCH (n) RETURN n"},
	}
	registry, err := NewRegistry(rule)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	service := NewWithRegistry(newGraphRuleStubRuntimeStore(runtime), &stubReplayer{}, store, store, store, store, registry).WithGraphQueryStore(graphStore)
	result, err := service.EvaluateSourceRuntimeGraphRules(context.Background(), EvaluateGraphRulesRequest{RuntimeID: "runtime-okta"})
	if err == nil {
		t.Fatalf("EvaluateSourceRuntimeGraphRules() expected error")
	}
	if result == nil || len(result.Evaluations) != 1 {
		t.Fatalf("partial result expected with one evaluation, got %#v", result)
	}
	evaluation := result.Evaluations[0]
	if got := evaluation.Run.GetStatus(); got != "failed" {
		t.Fatalf("Run.Status = %q, want failed", got)
	}
}

func TestEvaluateSourceRuntimeGraphRulesContinuesAfterRuleFailure(t *testing.T) {
	runtime := &cerebrov1.SourceRuntime{Id: "runtime-okta", SourceId: "okta", TenantId: "writer"}
	store := &stubFindingStore{}
	graphStore := &stubGraphStore{
		cypherRows: []ports.CypherRow{
			{Values: map[string]any{"label": "alice@writer.com"}},
		},
	}
	failing := &stubGraphRule{
		spec:     &cerebrov1.RuleSpec{Id: "failing-rule"},
		sourceID: "okta",
		query:    ports.CypherQueryRequest{Query: "MATCH (n) RETURN n"},
		emitErr:  errors.New("evaluate failure"),
	}
	healthy := &stubGraphRule{
		spec:     &cerebrov1.RuleSpec{Id: "healthy-rule"},
		sourceID: "okta",
		query:    ports.CypherQueryRequest{Query: "MATCH (n) RETURN n"},
	}
	registry, err := NewRegistry(failing, healthy)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	service := NewWithRegistry(newGraphRuleStubRuntimeStore(runtime), &stubReplayer{}, store, store, store, store, registry).WithGraphQueryStore(graphStore)
	result, err := service.EvaluateSourceRuntimeGraphRules(context.Background(), EvaluateGraphRulesRequest{RuntimeID: "runtime-okta"})
	if err == nil {
		t.Fatalf("EvaluateSourceRuntimeGraphRules() expected error from failing rule")
	}
	if result == nil {
		t.Fatalf("result = nil, want partial result with both rule evaluations")
	}
	if got := len(result.Evaluations); got != 2 {
		t.Fatalf("len(Evaluations) = %d, want 2 (both rules should run)", got)
	}
	var failingRun, healthyRun *cerebrov1.FindingEvaluationRun
	for _, evaluation := range result.Evaluations {
		switch evaluation.Rule.GetId() {
		case "failing-rule":
			failingRun = evaluation.Run
		case "healthy-rule":
			healthyRun = evaluation.Run
		}
	}
	if failingRun == nil || failingRun.GetStatus() != "failed" {
		t.Fatalf("failing rule run status = %v, want failed", failingRun)
	}
	if healthyRun == nil || healthyRun.GetStatus() != "completed" {
		t.Fatalf("healthy rule run status = %v, want completed (failures of one rule must not abort others)", healthyRun)
	}
}

func TestEvaluateSourceRuntimeGraphRulesSelectsByRuleID(t *testing.T) {
	runtime := &cerebrov1.SourceRuntime{Id: "runtime-okta", SourceId: "okta", TenantId: "writer"}
	store := &stubFindingStore{}
	graphStore := &stubGraphStore{}
	emitting := &stubGraphRule{
		spec:     &cerebrov1.RuleSpec{Id: "selected"},
		sourceID: "okta",
		query:    ports.CypherQueryRequest{Query: "MATCH (n) RETURN n"},
	}
	other := &stubGraphRule{
		spec:     &cerebrov1.RuleSpec{Id: "other"},
		sourceID: "okta",
		query:    ports.CypherQueryRequest{Query: "MATCH (n) RETURN n"},
	}
	registry, err := NewRegistry(emitting, other)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	service := NewWithRegistry(newGraphRuleStubRuntimeStore(runtime), &stubReplayer{}, store, store, store, store, registry).WithGraphQueryStore(graphStore)
	result, err := service.EvaluateSourceRuntimeGraphRules(context.Background(), EvaluateGraphRulesRequest{RuntimeID: "runtime-okta", RuleIDs: []string{"selected"}})
	if err != nil {
		t.Fatalf("EvaluateSourceRuntimeGraphRules() error = %v", err)
	}
	if got := len(result.Evaluations); got != 1 {
		t.Fatalf("len(Evaluations) = %d, want 1", got)
	}
	if got := result.Evaluations[0].Rule.GetId(); got != "selected" {
		t.Fatalf("Rule.Id = %q, want selected", got)
	}
}

// Graph rules satisfy Rule only to fit the registry contract; their Evaluate() is a no-op
// because they need a cypher boundary the replay path doesn't supply. Letting the event
// replay path pick them up creates empty completed evaluation runs and duplicates run
// records per orchestrator iteration. The replay path must filter them out instead.
func TestEvaluateSourceRuntimeRulesExcludesGraphRules(t *testing.T) {
	runtime := &cerebrov1.SourceRuntime{Id: "runtime-okta", SourceId: "okta", TenantId: "writer"}
	store := &stubFindingStore{}
	graphRule := &stubGraphRule{
		spec:     &cerebrov1.RuleSpec{Id: "okta-graph-only"},
		sourceID: "okta",
		query:    ports.CypherQueryRequest{Query: "MATCH (n) RETURN n"},
	}
	registry, err := NewRegistry(graphRule)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	service := NewWithRegistry(newGraphRuleStubRuntimeStore(runtime), &stubReplayer{}, store, store, store, store, registry)
	if _, err := service.EvaluateSourceRuntimeRules(context.Background(), EvaluateRulesRequest{RuntimeID: "runtime-okta"}); !errors.Is(err, ErrRuleUnavailable) {
		t.Fatalf("EvaluateSourceRuntimeRules() error = %v, want ErrRuleUnavailable (graph rule should not be picked up by replay path)", err)
	}
}

// ListRules powers `GET /finding-rules` and the rule selection UI. Because all public
// evaluation endpoints reject graph rules, advertising them in the catalog would surface
// rule ids that no client can run. Graph rules execute exclusively from the orchestrator
// hook and must be hidden from the public list.
func TestListRulesHidesGraphRulesFromCatalog(t *testing.T) {
	store := &stubFindingStore{}
	eventRule := &stubRule{spec: &cerebrov1.RuleSpec{Id: "event-only-rule"}}
	graphRule := &stubGraphRule{spec: &cerebrov1.RuleSpec{Id: "graph-only-rule"}, sourceID: "okta"}
	registry, err := NewRegistry(eventRule, graphRule)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	service := NewWithRegistry(&stubRuntimeStore{}, &stubReplayer{}, store, store, store, store, registry)
	listed := service.ListRules().GetRules()
	for _, spec := range listed {
		if spec.GetId() == "graph-only-rule" {
			t.Fatalf("ListRules() advertised graph-only-rule via public catalog; clients have no way to execute it")
		}
	}
	var foundEvent bool
	for _, spec := range listed {
		if spec.GetId() == "event-only-rule" {
			foundEvent = true
		}
	}
	if !foundEvent {
		t.Fatalf("ListRules() dropped event-only-rule along with graph rules; got %v", listed)
	}
}

// When the caller asks for a graph rule by ID through the replay endpoint we must reject
// rather than create a useless empty evaluation run.
func TestEvaluateSourceRuntimeRulesRejectsExplicitGraphRuleID(t *testing.T) {
	runtime := &cerebrov1.SourceRuntime{Id: "runtime-okta", SourceId: "okta", TenantId: "writer"}
	store := &stubFindingStore{}
	graphRule := &stubGraphRule{
		spec:     &cerebrov1.RuleSpec{Id: "okta-graph-only"},
		sourceID: "okta",
		query:    ports.CypherQueryRequest{Query: "MATCH (n) RETURN n"},
	}
	registry, err := NewRegistry(graphRule)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	service := NewWithRegistry(newGraphRuleStubRuntimeStore(runtime), &stubReplayer{}, store, store, store, store, registry)
	if _, err := service.EvaluateSourceRuntimeRules(context.Background(), EvaluateRulesRequest{RuntimeID: "runtime-okta", RuleIDs: []string{"okta-graph-only"}}); !errors.Is(err, ErrRuleUnsupported) {
		t.Fatalf("EvaluateSourceRuntimeRules() error = %v, want ErrRuleUnsupported (explicit graph rule id must be rejected by replay path)", err)
	}
}

// multiSourceStubGraphRule matches every runtime whose source_id is in supportedSources, so a
// single graph rule can be triggered by an okta evaluation and then by a github evaluation
// (mirroring the deprovisioned-Okta-active-in-GitHub topology).
type multiSourceStubGraphRule struct {
	stubGraphRule
	supportedSources []string
}

func (r *multiSourceStubGraphRule) SupportsRuntime(runtime *cerebrov1.SourceRuntime) bool {
	if r == nil || runtime == nil {
		return false
	}
	for _, source := range r.supportedSources {
		if runtime.GetSourceId() == source {
			return true
		}
	}
	return false
}

// Cross-runtime graph-rule reevaluations must keep the finding pinned to the first triggering
// runtime (so runtime_id stays addressable through the real source-runtime APIs) AND record
// each subsequent evaluation's evidence under the runtime that performed it (so
// `/source-runtimes/{runtime}/finding-evidence?run_id=<runtime-run>` actually returns rows
// for the runtime that produced the run, instead of leaving the run listed in evaluation
// listings without any matching evidence rows).
func TestEvaluateSourceRuntimeGraphRulesPinsFindingButRecordsEvidencePerRuntime(t *testing.T) {
	oktaRuntime := &cerebrov1.SourceRuntime{Id: "runtime-okta", SourceId: "okta", TenantId: "writer"}
	githubRuntime := &cerebrov1.SourceRuntime{Id: "runtime-github", SourceId: "github", TenantId: "writer"}
	runtimeStore := &stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
		oktaRuntime.GetId():   oktaRuntime,
		githubRuntime.GetId(): githubRuntime,
	}}
	store := &stubFindingStore{}
	graphStore := &stubGraphStore{
		cypherRows: []ports.CypherRow{{Values: map[string]any{"label": "alice@writer.com"}}},
	}
	// The same fingerprint is emitted from both okta and github triggers; that's the contract
	// graph rules establish (tenant-scoped offender). UpsertFinding's ON CONFLICT clause
	// pins runtime_id on first insert; evidence ownership is taken from the run.
	emitFinding := func(triggeringRuntimeID string) []*ports.FindingRecord {
		return []*ports.FindingRecord{{
			ID:           "finding-cross-runtime",
			Fingerprint:  "fp-cross-runtime",
			TenantID:     "writer",
			RuntimeID:    triggeringRuntimeID,
			RuleID:       "cross-runtime-graph-rule",
			Title:        "Cross runtime graph finding",
			Severity:     "CRITICAL",
			Status:       findingStatusOpen,
			Summary:      "graph rule fired",
			ResourceURNs: []string{"urn:cerebro:writer:identity:email:alice@writer.com"},
		}}
	}
	rule := &multiSourceStubGraphRule{
		stubGraphRule: stubGraphRule{
			spec:  &cerebrov1.RuleSpec{Id: "cross-runtime-graph-rule"},
			query: ports.CypherQueryRequest{Query: "MATCH (n) RETURN n LIMIT 1"},
			emit:  emitFinding(oktaRuntime.GetId()),
		},
		supportedSources: []string{"okta", "github"},
	}
	registry, err := NewRegistry(rule)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	service := NewWithRegistry(runtimeStore, &stubReplayer{}, store, store, store, store, registry).WithGraphQueryStore(graphStore)

	oktaResult, err := service.EvaluateSourceRuntimeGraphRules(context.Background(), EvaluateGraphRulesRequest{RuntimeID: oktaRuntime.GetId()})
	if err != nil {
		t.Fatalf("EvaluateSourceRuntimeGraphRules(okta) error = %v", err)
	}
	if got := len(oktaResult.Evaluations); got != 1 {
		t.Fatalf("len(okta.Evaluations) = %d, want 1", got)
	}
	oktaEvaluation := oktaResult.Evaluations[0]
	if got := len(oktaEvaluation.Evidence); got != 1 {
		t.Fatalf("len(okta.Evidence) = %d, want 1", got)
	}
	if got := oktaEvaluation.Evidence[0].GetRuntimeId(); got != oktaRuntime.GetId() {
		t.Fatalf("okta evidence RuntimeId = %q, want %q", got, oktaRuntime.GetId())
	}
	if got := oktaEvaluation.Evidence[0].GetRunId(); got != oktaEvaluation.Run.GetId() {
		t.Fatalf("okta evidence RunId = %q, want %q (the okta run)", got, oktaEvaluation.Run.GetId())
	}

	rule.emit = emitFinding(githubRuntime.GetId())
	githubResult, err := service.EvaluateSourceRuntimeGraphRules(context.Background(), EvaluateGraphRulesRequest{RuntimeID: githubRuntime.GetId()})
	if err != nil {
		t.Fatalf("EvaluateSourceRuntimeGraphRules(github) error = %v", err)
	}
	if got := len(githubResult.Evaluations); got != 1 {
		t.Fatalf("len(github.Evaluations) = %d, want 1", got)
	}
	githubEvaluation := githubResult.Evaluations[0]
	if got := len(githubEvaluation.Findings); got != 1 {
		t.Fatalf("len(github.Findings) = %d, want 1", got)
	}
	if got := githubEvaluation.Findings[0].RuntimeID; got != oktaRuntime.GetId() {
		t.Fatalf("github reevaluation finding RuntimeID = %q, want %q (pinned to first observer)", got, oktaRuntime.GetId())
	}
	if got := len(githubEvaluation.Evidence); got != 1 {
		t.Fatalf("len(github.Evidence) = %d, want 1", got)
	}
	if got := githubEvaluation.Evidence[0].GetRuntimeId(); got != githubRuntime.GetId() {
		t.Fatalf("github evidence RuntimeId = %q, want %q (evidence is owned by the evaluating runtime so /source-runtimes/{github}/finding-evidence stays consistent with the run)", got, githubRuntime.GetId())
	}
	if got := githubEvaluation.Evidence[0].GetRunId(); got != githubEvaluation.Run.GetId() {
		t.Fatalf("github evidence RunId = %q, want %q", got, githubEvaluation.Run.GetId())
	}
	if got := githubEvaluation.Run.GetRuntimeId(); got != githubRuntime.GetId() {
		t.Fatalf("github Run RuntimeId = %q, want %q (run is recorded under the evaluating runtime)", got, githubRuntime.GetId())
	}
	if oktaEvaluation.Evidence[0].GetId() == githubEvaluation.Evidence[0].GetId() {
		t.Fatalf("evidence ids collided across runtimes (%q); evidence id must be runtime-scoped so each runtime's listing is non-empty", oktaEvaluation.Evidence[0].GetId())
	}
}

// Graph-rule runs evaluate cypher rows over the projected graph, not events from
// the replay log, so the per-event `EventLimit` field is meaningless for them.
// `newFindingEvaluationRun` normalizes 0 to the default replay cap (100), which
// would make Get/ListFindingEvaluationRun advertise a fictional "100-event"
// pass for every graph evaluation. We therefore use a dedicated constructor
// that leaves EventLimit at the proto default (0), which the API surfaces as
// "n/a for graph rule".
func TestEvaluateSourceRuntimeGraphRulesPersistsRunWithoutEventLimit(t *testing.T) {
	runtime := &cerebrov1.SourceRuntime{Id: "runtime-okta", SourceId: "okta", TenantId: "writer"}
	runtimeStore := &stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
		runtime.GetId(): runtime,
	}}
	store := &stubFindingStore{}
	graphStore := &stubGraphStore{
		cypherRows: []ports.CypherRow{{Values: map[string]any{"label": "alice@writer.com"}}},
	}
	rule := &stubGraphRule{
		spec:     &cerebrov1.RuleSpec{Id: "graph-rule-no-event-limit"},
		sourceID: "okta",
		query:    ports.CypherQueryRequest{Query: "MATCH (n) RETURN n LIMIT 1"},
	}
	registry, err := NewRegistry(rule)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	service := NewWithRegistry(runtimeStore, &stubReplayer{}, store, store, store, store, registry).WithGraphQueryStore(graphStore)
	result, err := service.EvaluateSourceRuntimeGraphRules(context.Background(), EvaluateGraphRulesRequest{RuntimeID: runtime.GetId()})
	if err != nil {
		t.Fatalf("EvaluateSourceRuntimeGraphRules() error = %v", err)
	}
	if got := len(result.Evaluations); got != 1 {
		t.Fatalf("len(Evaluations) = %d, want 1", got)
	}
	run := result.Evaluations[0].Run
	if run == nil {
		t.Fatal("Run is nil")
	}
	if got := run.GetEventLimit(); got != 0 {
		t.Fatalf("Run.EventLimit = %d, want 0; graph runs have no event-limit input and must not advertise the replay default", got)
	}
}

// TestEvaluateSourceRuntimeGraphRulesRecordsGraphTelemetry asserts the
// graph-rule discriminator and rows-read counter both surface on the persisted
// run. These two fields let operators triage graph rules separately from event
// rules without having to join the run record back to the rule catalog.
func TestEvaluateSourceRuntimeGraphRulesRecordsGraphTelemetry(t *testing.T) {
	runtime := &cerebrov1.SourceRuntime{Id: "runtime-okta", SourceId: "okta", TenantId: "writer"}
	store := &stubFindingStore{}
	graphStore := &stubGraphStore{cypherRows: []ports.CypherRow{
		{Values: map[string]any{"label": "alice@writer.com"}},
		{Values: map[string]any{"label": "bob@writer.com"}},
		{Values: map[string]any{"label": "carol@writer.com"}},
	}}
	rule := &stubGraphRule{
		spec:     &cerebrov1.RuleSpec{Id: "graph-rule-telemetry"},
		sourceID: "okta",
		query:    ports.CypherQueryRequest{Query: "MATCH (n) RETURN n LIMIT 10"},
	}
	registry, err := NewRegistry(rule)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	service := NewWithRegistry(newGraphRuleStubRuntimeStore(runtime), &stubReplayer{}, store, store, store, store, registry).WithGraphQueryStore(graphStore)
	result, err := service.EvaluateSourceRuntimeGraphRules(context.Background(), EvaluateGraphRulesRequest{RuntimeID: runtime.GetId()})
	if err != nil {
		t.Fatalf("EvaluateSourceRuntimeGraphRules() error = %v", err)
	}
	if got := len(result.Evaluations); got != 1 {
		t.Fatalf("len(Evaluations) = %d, want 1", got)
	}
	run := result.Evaluations[0].Run
	if got := run.GetGraphRule(); !got {
		t.Fatalf("Run.GraphRule = false, want true on graph rule run")
	}
	if got := run.GetGraphRowsRead(); got != 3 {
		t.Fatalf("Run.GraphRowsRead = %d, want 3 (cypher returned three rows)", got)
	}
	if got := run.GetEventsEvaluated(); got != 0 {
		t.Fatalf("Run.EventsEvaluated = %d, want 0 (graph rules do not replay events)", got)
	}
	if got := run.GetEventsMatched(); got != 0 {
		t.Fatalf("Run.EventsMatched = %d, want 0 (events_matched is the event-rule counter)", got)
	}
}

// TestEvaluateSourceRuntimeGraphRulesEmptyQueryPersistsGraphRuleFlag verifies
// graph rules whose generated cypher is empty (a soft no-op) still leave a run
// row that announces itself as a graph rule. Operators must not read the empty
// counters as "missing telemetry from an event rule".
func TestEvaluateSourceRuntimeGraphRulesEmptyQueryPersistsGraphRuleFlag(t *testing.T) {
	runtime := &cerebrov1.SourceRuntime{Id: "runtime-okta", SourceId: "okta", TenantId: "writer"}
	store := &stubFindingStore{}
	graphStore := &stubGraphStore{}
	rule := &stubGraphRule{
		spec:     &cerebrov1.RuleSpec{Id: "graph-rule-empty-query"},
		sourceID: "okta",
		query:    ports.CypherQueryRequest{Query: "   "},
	}
	registry, err := NewRegistry(rule)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	service := NewWithRegistry(newGraphRuleStubRuntimeStore(runtime), &stubReplayer{}, store, store, store, store, registry).WithGraphQueryStore(graphStore)
	if _, err := service.EvaluateSourceRuntimeGraphRules(context.Background(), EvaluateGraphRulesRequest{RuntimeID: runtime.GetId()}); err != nil {
		t.Fatalf("EvaluateSourceRuntimeGraphRules() error = %v", err)
	}
	if got := len(store.runs); got != 1 {
		t.Fatalf("len(store.runs) = %d, want 1", got)
	}
	for _, run := range store.runs {
		if got := run.GetGraphRule(); !got {
			t.Fatalf("Run.GraphRule = false, want true even for empty-query graph runs")
		}
		if got := run.GetGraphRowsRead(); got != 0 {
			t.Fatalf("Run.GraphRowsRead = %d, want 0", got)
		}
		if got := run.GetStatus(); got != "completed" {
			t.Fatalf("Run.Status = %q, want completed", got)
		}
	}
}

func TestEvaluateSourceRuntimeGraphRulesRetiredEmptyQueryResolvesOpenFindings(t *testing.T) {
	runtime := &cerebrov1.SourceRuntime{Id: "runtime-graph", SourceId: "graph", TenantId: "writer"}
	store := &stubFindingStore{findings: map[string]*ports.FindingRecord{
		"stale-meta": {
			ID:             "stale-meta",
			TenantID:       "writer",
			RuntimeID:      "runtime-old",
			RuleID:         "graph-resource-multiple-open-findings",
			Status:         findingStatusOpen,
			LastObservedAt: time.Now().UTC().Add(-time.Hour),
		},
	}}
	registry, err := NewRegistry(newResourceMultipleOpenFindingsRule())
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	service := NewWithRegistry(newGraphRuleStubRuntimeStore(runtime), &stubReplayer{}, store, store, store, store, registry).WithGraphQueryStore(&stubGraphStore{})
	result, err := service.EvaluateSourceRuntimeGraphRules(context.Background(), EvaluateGraphRulesRequest{RuntimeID: runtime.GetId()})
	if err != nil {
		t.Fatalf("EvaluateSourceRuntimeGraphRules() error = %v", err)
	}
	if len(result.Evaluations) != 1 {
		t.Fatalf("len(Evaluations) = %d, want 1", len(result.Evaluations))
	}
	if got := store.findings["stale-meta"].Status; got != findingStatusResolved {
		t.Fatalf("retired graph finding status = %q, want resolved", got)
	}
	if got := store.findings["stale-meta"].StatusReason; got != "graph_rule_no_longer_matches" {
		t.Fatalf("retired graph finding status reason = %q", got)
	}
	if len(store.updateStatusCalls) != 1 {
		t.Fatalf("len(updateStatusCalls) = %d, want 1", len(store.updateStatusCalls))
	}
}

// TestEvaluateSourceRuntimeGraphRulesFailedRunPreservesGraphTelemetry confirms
// that even when the cypher query fails the persisted failed run still marks
// itself as a graph rule, so the rule-class discriminator survives failures
// and operators can sort failed runs by event-rule vs graph-rule causes.
func TestEvaluateSourceRuntimeGraphRulesFailedRunPreservesGraphTelemetry(t *testing.T) {
	runtime := &cerebrov1.SourceRuntime{Id: "runtime-okta", SourceId: "okta", TenantId: "writer"}
	store := &stubFindingStore{}
	graphStore := &stubGraphStore{cypherErr: errors.New("graph store unavailable")}
	rule := &stubGraphRule{
		spec:     &cerebrov1.RuleSpec{Id: "graph-rule-failure"},
		sourceID: "okta",
		query:    ports.CypherQueryRequest{Query: "MATCH (n) RETURN n LIMIT 1"},
	}
	registry, err := NewRegistry(rule)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	service := NewWithRegistry(newGraphRuleStubRuntimeStore(runtime), &stubReplayer{}, store, store, store, store, registry).WithGraphQueryStore(graphStore)
	if _, err := service.EvaluateSourceRuntimeGraphRules(context.Background(), EvaluateGraphRulesRequest{RuntimeID: runtime.GetId()}); err == nil {
		t.Fatal("EvaluateSourceRuntimeGraphRules() error = nil, want failure")
	}
	if got := len(store.runs); got != 1 {
		t.Fatalf("len(store.runs) = %d, want 1", got)
	}
	for _, run := range store.runs {
		if got := run.GetStatus(); got != "failed" {
			t.Fatalf("Run.Status = %q, want failed", got)
		}
		if got := run.GetGraphRule(); !got {
			t.Fatalf("Run.GraphRule = false on failed graph run, want true (discriminator must survive failures)")
		}
		if got := run.GetGraphRowsRead(); got != 0 {
			t.Fatalf("Run.GraphRowsRead = %d, want 0 (failure happened during cypher execution before any rows arrived)", got)
		}
	}
}

func TestNewGraphFindingEvaluationRunSetsGraphRuleFlagAtConstruction(t *testing.T) {
	t.Parallel()
	run := newGraphFindingEvaluationRun("writer-okta-audit", "graph-rule-a", time.Now())
	if got := run.GetGraphRule(); !got {
		t.Fatalf("Run.GraphRule = false, want true (graph rule discriminator must be present at construction time)")
	}
	if got := run.GetStatus(); got != "running" {
		t.Fatalf("Run.Status = %q, want running", got)
	}
	if got := run.GetEventLimit(); got != 0 {
		t.Fatalf("Run.EventLimit = %d, want 0 (graph rules do not replay events)", got)
	}
}

func TestNewFindingEvaluationRunLeavesGraphRuleFlagFalse(t *testing.T) {
	t.Parallel()
	run := newFindingEvaluationRun("writer-okta-audit", "event-rule-a", 25, time.Now())
	if got := run.GetGraphRule(); got {
		t.Fatalf("Run.GraphRule = true, want false for event-rule run (discriminator must not leak across rule classes)")
	}
	if got := run.GetEventLimit(); got != 25 {
		t.Fatalf("Run.EventLimit = %d, want 25", got)
	}
}
