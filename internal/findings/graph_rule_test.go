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
