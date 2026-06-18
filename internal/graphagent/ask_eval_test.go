package graphagent

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/ports"
)

type askEvalCase struct {
	Name                  string            `json:"name"`
	Question              string            `json:"question"`
	ScopeURN              string            `json:"scope_urn"`
	DraftPlan             AskQueryPlan      `json:"draft_plan"`
	Rows                  []map[string]any  `json:"rows"`
	RecoveryRows          []map[string]any  `json:"recovery_rows"`
	Summary               string            `json:"summary"`
	ExpectedIntent        string            `json:"expected_intent"`
	ExpectedMinRows       int               `json:"expected_min_rows"`
	ExpectedURNs          []string          `json:"expected_urns"`
	ExpectQualityPass     *bool             `json:"expect_quality_pass"`
	ExpectRecovery        bool              `json:"expect_recovery"`
	ExpectCitationsOK     bool              `json:"expect_citations_ok"`
	ExpectUnsupportedCode string            `json:"expect_unsupported_code"`
	Filters               map[string]string `json:"-"`
}

func TestAskTrajectoryGoldenEvals(t *testing.T) {
	raw, err := os.ReadFile("testdata/ask_evals/core.json")
	if err != nil {
		t.Fatalf("read eval fixture: %v", err)
	}
	var cases []askEvalCase
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatalf("decode eval fixture: %v", err)
	}
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			store := &askEvalStore{
				rows:         rowsFromMaps(tc.Rows),
				recoveryRows: rowsFromMaps(tc.RecoveryRows),
			}
			llm := &StubLLMClient{
				DraftResponse: &DraftResponse{
					Rationale: "eval route",
					Plan:      &tc.DraftPlan,
				},
				Summary: tc.Summary,
			}
			service := NewServiceWithOptions(store, llm, ValidatorOptions{}, ServiceOptions{
				EnableGraphProbes: true,
				EnableRecovery:    true,
				EnableMapReduce:   true,
			})
			var events []Event
			err := service.Stream(context.Background(), AskRequest{
				TenantID: "writer",
				Question: tc.Question,
				ScopeURN: tc.ScopeURN,
			}, func(event Event) error {
				events = append(events, event)
				return nil
			})
			if err != nil {
				t.Fatalf("Stream() error = %v", err)
			}
			plan := eventData[QueryPlanEvent](t, events, EventQueryPlan)
			if plan.Plan.Intent != tc.ExpectedIntent {
				t.Fatalf("intent = %q, want %q", plan.Plan.Intent, tc.ExpectedIntent)
			}
			if eventData[GraphProbeEvent](t, events, EventGraphProbe).Probe.FindingCount == 0 {
				t.Fatalf("probe did not report fixture finding count")
			}
			summary := eventData[SummaryEvent](t, events, EventSummary)
			score := ScoreAskEvents(events)
			if tc.ExpectQualityPass != nil && score.Passed != *tc.ExpectQualityPass {
				t.Fatalf("quality score = %+v, want passed %v", score, *tc.ExpectQualityPass)
			}
			if tc.ExpectUnsupportedCode != "" {
				if summary.UnsupportedQuery == nil || summary.UnsupportedQuery.Code != tc.ExpectUnsupportedCode {
					t.Fatalf("unsupported query = %#v, want code %q", summary.UnsupportedQuery, tc.ExpectUnsupportedCode)
				}
				return
			}
			rows := eventData[RowsEvent](t, events, EventRows)
			if len(rows.Rows) < tc.ExpectedMinRows {
				t.Fatalf("rows = %#v, want at least %d", rows.Rows, tc.ExpectedMinRows)
			}
			if tc.ExpectRecovery && countEvents(events, EventRecovery) == 0 {
				t.Fatalf("expected recovery event, got %#v", events)
			}
			for _, urn := range tc.ExpectedURNs {
				if !strings.Contains(summary.Markdown, urn) {
					t.Fatalf("summary %q missing expected URN %q", summary.Markdown, urn)
				}
			}
			if tc.ExpectCitationsOK && (summary.CitationValidation == nil || !summary.CitationValidation.OK) {
				t.Fatalf("citation validation = %#v, want ok", summary.CitationValidation)
			}
		})
	}
}

func TestAskMapReduceSummarizesLargeRowSets(t *testing.T) {
	var rows []ports.CypherRow
	for i := 0; i < 5; i++ {
		rows = append(rows, ports.CypherRow{Values: map[string]any{
			"entity_urn":  "urn:cerebro:example:asset:" + string(rune('a'+i)),
			"entity_type": "asset",
			"label":       "asset",
		}})
	}
	store := &askStore{rows: rows}
	llm := &StubLLMClient{
		DraftResponse: &DraftResponse{
			Rationale: "large rows",
			Cypher: `MATCH (e:Entity {tenant_id: $tenant_id})
RETURN e.urn AS entity_urn, e.entity_type AS entity_type, e.label AS label
LIMIT 25`,
		},
		SummaryResponses: []string{
			"chunk one",
			"chunk two",
			"chunk three",
			"Final answer cites `urn:cerebro:example:asset:a`.",
		},
	}
	service := NewServiceWithOptions(store, llm, ValidatorOptions{}, ServiceOptions{
		EnableMapReduce:       true,
		MapReduceRowThreshold: 2,
	})
	var events []Event
	if err := service.Stream(context.Background(), AskRequest{TenantID: "example", Question: "summarize everything"}, func(event Event) error {
		events = append(events, event)
		return nil
	}); err != nil {
		t.Fatalf("Stream() error = %v", err)
	}
	if len(llm.SummaryRequests) != 4 {
		t.Fatalf("summary request count = %d, want 4", len(llm.SummaryRequests))
	}
	if len(llm.SummaryRequests[3].Rows) != 3 {
		t.Fatalf("reduce rows = %#v, want one row per chunk", llm.SummaryRequests[3].Rows)
	}
	summary := eventData[SummaryEvent](t, events, EventSummary)
	if summary.CitationValidation == nil || !summary.CitationValidation.OK {
		t.Fatalf("citation validation = %#v, want ok", summary.CitationValidation)
	}
}

func TestAskTrajectoryPersistenceIsNonFatal(t *testing.T) {
	store := &askStore{rows: []ports.CypherRow{{Values: map[string]any{"entity_urn": "urn:cerebro:example:asset:alpha"}}}}
	trajectoryStore := &recordingTrajectoryStore{errOnAppend: true}
	service := NewServiceWithOptions(store, &StubLLMClient{
		DraftResponse: &DraftResponse{
			Rationale: "trace",
			Cypher: `MATCH (e:Entity {tenant_id: $tenant_id})
RETURN e.urn AS entity_urn
LIMIT 25`,
		},
		Summary: "`urn:cerebro:example:asset:alpha` is present.",
	}, ValidatorOptions{}, ServiceOptions{TrajectoryStore: trajectoryStore})
	if err := service.Stream(context.Background(), AskRequest{TenantID: "example", Question: "trace it"}, func(Event) error {
		return nil
	}); err != nil {
		t.Fatalf("Stream() error = %v", err)
	}
	if trajectoryStore.run.TraceID == "" {
		t.Fatalf("trajectory run was not recorded")
	}
	if trajectoryStore.finish.TraceID != trajectoryStore.run.TraceID || trajectoryStore.finish.Status != "success" {
		t.Fatalf("trajectory finish = %#v, run = %#v", trajectoryStore.finish, trajectoryStore.run)
	}
}

func TestAskRecoveryRefusesSaturatedCandidateWindow(t *testing.T) {
	recoveryRows := make([]ports.CypherRow, 0, postProcessingCandidateRowLimit)
	for i := 0; i < postProcessingCandidateRowLimit; i++ {
		recoveryRows = append(recoveryRows, ports.CypherRow{Values: map[string]any{
			"finding_urn":                       "urn:cerebro:writer:finding:" + string(rune('a'+i%26)),
			"resource_urn":                      "urn:cerebro:writer:repo:alpha",
			"relation_attributes_json_internal": `{"risk_score":42}`,
			"finding_attributes_json_internal":  `{"severity":"HIGH"}`,
		}})
	}
	store := &askEvalStore{rows: nil, recoveryRows: recoveryRows}
	service := NewServiceWithOptions(store, &StubLLMClient{DraftResponse: &DraftResponse{
		Rationale: "recover top risk",
		Plan:      &AskQueryPlan{Intent: IntentTopRiskFindings, Filters: map[string]string{"severity": "critical"}, Limit: 10},
	}}, ValidatorOptions{}, ServiceOptions{EnableRecovery: true})
	var events []Event
	if err := service.Stream(context.Background(), AskRequest{TenantID: "writer", Question: "show critical risk findings"}, func(event Event) error {
		events = append(events, event)
		return nil
	}); err != nil {
		t.Fatalf("Stream() error = %v", err)
	}
	summary := eventData[SummaryEvent](t, events, EventSummary)
	if summary.UnsupportedQuery == nil || summary.UnsupportedQuery.Code != "post_processing_candidate_limit" {
		t.Fatalf("unsupported query = %#v, want post_processing_candidate_limit", summary.UnsupportedQuery)
	}
	if countEvents(events, EventRows) != 0 {
		t.Fatalf("recovery emitted rows after saturated candidate window: %#v", events)
	}
}

func TestScoreAskEventsRequiresGroundingAndCitations(t *testing.T) {
	score := ScoreAskEvents([]Event{
		{Name: EventQueryPlan, Data: QueryPlanEvent{Plan: AskQueryPlan{Intent: IntentTopRiskFindings}}},
		{Name: EventRows, Data: RowsEvent{Rows: []map[string]any{{"finding_urn": "urn:cerebro:writer:finding:alpha"}}}},
		{Name: EventSummary, Data: SummaryEvent{CitationValidation: &CitationValidation{OK: true, RowURNCount: 1, ReferencedURNCount: 1}}},
	})
	if !score.Passed || score.QueryPlanStatus != "pass" || score.GroundingStatus != "pass" || score.CitationStatus != "pass" {
		t.Fatalf("score = %+v, want passed with query plan, grounding, and citations", score)
	}

	ungrounded := ScoreAskEvents([]Event{
		{Name: EventQueryPlan, Data: QueryPlanEvent{Plan: AskQueryPlan{Intent: IntentTopRiskFindings}}},
		{Name: EventSummary, Data: SummaryEvent{Markdown: "alpha is risky"}},
	})
	if ungrounded.Passed || len(ungrounded.Failures) == 0 {
		t.Fatalf("ungrounded score = %+v, want failures", ungrounded)
	}
}

func TestScoreAskEventsAcceptsSafeRefusal(t *testing.T) {
	score := ScoreAskEvents([]Event{
		{Name: EventQueryPlan, Data: QueryPlanEvent{Plan: AskQueryPlan{Intent: IntentTopRiskFindings}}},
		{Name: EventSummary, Data: SummaryEvent{UnsupportedQuery: &UnsupportedQuery{Code: "unsupported_filter"}}},
	})
	if !score.Passed || score.UnsupportedStatus != "safe_refusal" || score.CitationStatus != "not_required" {
		t.Fatalf("score = %+v, want safe refusal pass", score)
	}
}

type askEvalStore struct {
	rows         []ports.CypherRow
	recoveryRows []ports.CypherRow
	executions   int
}

type recordingTrajectoryStore struct {
	run         ports.AskTrajectoryRun
	events      []ports.AskTrajectoryEvent
	finish      ports.AskTrajectoryFinish
	errOnAppend bool
}

func (s *recordingTrajectoryStore) PutAskTrajectoryRun(_ context.Context, run ports.AskTrajectoryRun) error {
	s.run = run
	return nil
}

func (s *recordingTrajectoryStore) AppendAskTrajectoryEvent(_ context.Context, event ports.AskTrajectoryEvent) error {
	if s.errOnAppend {
		return os.ErrPermission
	}
	s.events = append(s.events, event)
	return nil
}

func (s *recordingTrajectoryStore) FinishAskTrajectoryRun(_ context.Context, finish ports.AskTrajectoryFinish) error {
	s.finish = finish
	return nil
}

func (s *askEvalStore) Ping(context.Context) error { return nil }

func (s *askEvalStore) GetEntityNeighborhood(context.Context, string, int) (*ports.EntityNeighborhood, error) {
	return &ports.EntityNeighborhood{
		Root: &ports.NeighborhoodNode{URN: "urn:cerebro:writer:scope", EntityType: "asset", Label: "scope"},
	}, nil
}

func (s *askEvalStore) ExecuteReadCypher(_ context.Context, request ports.CypherQueryRequest) ([]ports.CypherRow, error) {
	switch {
	case strings.Contains(request.Query, "RETURN n.entity_type AS name"):
		return []ports.CypherRow{{Values: map[string]any{"name": "finding", "count": int64(3)}}, {Values: map[string]any{"name": "source", "count": int64(1)}}}, nil
	case strings.Contains(request.Query, "RETURN r.relation AS name"):
		return []ports.CypherRow{{Values: map[string]any{"name": "has_finding", "count": int64(2)}}}, nil
	case strings.HasPrefix(request.Query, "EXPLAIN "):
		return nil, nil
	}
	if s.executions == 0 {
		s.executions++
		return s.rows, nil
	}
	s.executions++
	return s.recoveryRows, nil
}

func rowsFromMaps(rows []map[string]any) []ports.CypherRow {
	out := make([]ports.CypherRow, 0, len(rows))
	for _, row := range rows {
		out = append(out, ports.CypherRow{Values: row})
	}
	return out
}

func eventData[T any](t *testing.T, events []Event, name string) T {
	t.Helper()
	for _, event := range events {
		if event.Name != name {
			continue
		}
		data, ok := event.Data.(T)
		if !ok {
			t.Fatalf("event %s data = %T", name, event.Data)
		}
		return data
	}
	var zero T
	t.Fatalf("event %s not found in %#v", name, events)
	return zero
}

func countEvents(events []Event, name string) int {
	count := 0
	for _, event := range events {
		if event.Name == name {
			count++
		}
	}
	return count
}
