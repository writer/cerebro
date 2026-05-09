package findings

import (
	"context"
	"errors"
	"testing"

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
