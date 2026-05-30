package graphagent

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/ports"
)

func TestServiceStreamsSuccessfulAskSequence(t *testing.T) {
	store := &askStore{
		rows: []ports.CypherRow{{
			Values: map[string]any{
				"entity_urn":  "urn:cerebro:example:asset:alpha",
				"entity_type": "asset",
				"label":       "alpha",
			},
		}},
		graph: &ports.EntityNeighborhood{
			Root: &ports.NeighborhoodNode{URN: "urn:cerebro:example:asset:alpha", EntityType: "asset", Label: "alpha"},
		},
	}
	llm := &StubLLMClient{
		DraftResponse: &DraftResponse{
			Rationale: "Counting risky entities.",
			Cypher: `MATCH (e:Entity {tenant_id: $tenant_id})
RETURN e.urn AS entity_urn, e.entity_type AS entity_type, e.label AS label
LIMIT 25`,
		},
		Summary: "Review `urn:cerebro:example:asset:alpha` first.",
	}
	service := NewService(store, llm, ValidatorOptions{})

	var events []Event
	err := service.Stream(context.Background(), AskRequest{
		TenantID: "example",
		Question: "Which entities are risky?",
		ScopeURN: "urn:cerebro:example:asset:alpha",
	}, func(event Event) error {
		events = append(events, event)
		return nil
	})
	if err != nil {
		t.Fatalf("Stream() error = %v", err)
	}
	assertEventNames(t, events, []string{EventProgress, EventRationale, EventQueryPlan, EventProgress, EventCypher, EventProgress, EventRows, EventProgress, EventSummary, EventDone})
	progressEvent, ok := events[0].Data.(ProgressEvent)
	if !ok {
		t.Fatalf("progress event data = %T", events[0].Data)
	}
	if progressEvent.Stage != "drafting_query" {
		t.Fatalf("first progress stage = %q, want drafting_query", progressEvent.Stage)
	}
	rowsEvent, ok := events[6].Data.(RowsEvent)
	if !ok {
		t.Fatalf("rows event data = %T", events[6].Data)
	}
	if len(rowsEvent.Rows) != 1 || rowsEvent.Rows[0]["entity_urn"] != "urn:cerebro:example:asset:alpha" {
		t.Fatalf("rows = %#v", rowsEvent.Rows)
	}
	if rowsEvent.Graph == nil || rowsEvent.Graph.Root == nil {
		t.Fatalf("graph neighborhood missing")
	}
	summaryEvent, ok := events[8].Data.(SummaryEvent)
	if !ok {
		t.Fatalf("summary event data = %T", events[8].Data)
	}
	if len(summaryEvent.Citations) != 1 || summaryEvent.Citations[0].URN != "urn:cerebro:example:asset:alpha" {
		t.Fatalf("citations = %#v", summaryEvent.Citations)
	}
	if len(store.requests) != 1 || store.requests[0].Params["tenant_id"] != "example" {
		t.Fatalf("store requests = %#v", store.requests)
	}
}

func TestServiceRefusesValidatorRejectedCypher(t *testing.T) {
	store := &askStore{}
	llm := &StubLLMClient{DraftResponse: &DraftResponse{
		Rationale: "Attempting a write query.",
		Cypher:    `MATCH (e:Entity {tenant_id: $tenant_id}) DELETE e LIMIT 25`,
	}}
	service := NewService(store, llm, ValidatorOptions{})

	var events []Event
	err := service.Stream(context.Background(), AskRequest{TenantID: "example", Question: "delete risky nodes"}, func(event Event) error {
		events = append(events, event)
		return nil
	})
	if err != nil {
		t.Fatalf("Stream() error = %v", err)
	}
	assertEventNames(t, events, []string{EventProgress, EventRationale, EventQueryPlan, EventProgress, EventCypher, EventSummary, EventDone})
	cypherEvent := events[4].Data.(CypherEvent)
	if cypherEvent.Validator.OK {
		t.Fatalf("validator ok = true, want false")
	}
	done := events[6].Data.(DoneEvent)
	if !done.CypherRefused {
		t.Fatalf("done.CypherRefused = false, want true")
	}
	if len(store.requests) != 0 {
		t.Fatalf("store executed rejected query: %#v", store.requests)
	}
}

func TestServiceRefusesUnsupportedPlanOnlyDraftAsConversionFailure(t *testing.T) {
	store := &askStore{}
	llm := &StubLLMClient{DraftResponse: &DraftResponse{
		Rationale: "Planning filtered high-risk findings.",
		Plan:      &AskQueryPlan{Intent: IntentTopRiskFindings, Filters: map[string]string{"severity": "HIGH"}},
	}}
	service := NewService(store, llm, ValidatorOptions{})

	var events []Event
	err := service.Stream(context.Background(), AskRequest{TenantID: "example", Question: "show HIGH risk findings"}, func(event Event) error {
		events = append(events, event)
		return nil
	})
	if err != nil {
		t.Fatalf("Stream() error = %v", err)
	}
	assertEventNames(t, events, []string{EventProgress, EventRationale, EventQueryPlan, EventCypher, EventSummary, EventDone})
	planEvent := events[2].Data.(QueryPlanEvent)
	if planEvent.Source != "conversion_refusal" || len(planEvent.Diagnostics) == 0 || planEvent.Diagnostics[0].Code != "query_plan_conversion_failed" {
		t.Fatalf("query plan event = %#v, want conversion refusal diagnostic", planEvent)
	}
	cypherEvent := events[3].Data.(CypherEvent)
	if cypherEvent.Validator.OK || strings.Contains(cypherEvent.Validator.Reason, "LLM refused") {
		t.Fatalf("cypher validator = %#v, want backend conversion refusal", cypherEvent.Validator)
	}
	if !strings.Contains(cypherEvent.Validator.Reason, "could not be converted") {
		t.Fatalf("refusal reason = %q, want conversion failure", cypherEvent.Validator.Reason)
	}
	if len(store.requests) != 0 {
		t.Fatalf("store executed conversion-refused query: %#v", store.requests)
	}
}

func TestServiceConvertsFindingSourceAggregationDraft(t *testing.T) {
	store := &askStore{
		rows: []ports.CypherRow{{
			Values: map[string]any{
				"source_family": "okta",
				"finding_count": int64(3),
			},
		}},
	}
	llm := &StubLLMClient{
		DraftResponse: &DraftResponse{
			Rationale: "Counting findings by source family.",
			Cypher: `MATCH (f:Entity {tenant_id: $tenant_id})
WHERE f.entity_type = 'Finding'
OPTIONAL MATCH (f)-[r:RELATION]->(src:Entity {tenant_id: $tenant_id})
WHERE r.relation = 'HAS_SOURCE' OR r.relation = 'BELONGS_TO_SOURCE'
WITH f, src,
     coalesce(src.label,
              apoc.convert.fromJsonMap(f.attributes_json).source_family,
              apoc.convert.fromJsonMap(f.attributes_json).sourceFamily,
              'Unknown') AS source_family
RETURN source_family, count(f) AS finding_count
ORDER BY finding_count DESC
LIMIT 10`,
		},
		Summary: "okta has the most findings.",
	}
	service := NewService(store, llm, ValidatorOptions{})

	var events []Event
	err := service.Stream(context.Background(), AskRequest{TenantID: "writer", Question: "top finding sources"}, func(event Event) error {
		events = append(events, event)
		return nil
	})
	if err != nil {
		t.Fatalf("Stream() error = %v", err)
	}
	assertEventNames(t, events, []string{EventProgress, EventRationale, EventQueryPlan, EventProgress, EventCypher, EventProgress, EventRows, EventProgress, EventSummary, EventDone})
	planEvent := events[2].Data.(QueryPlanEvent)
	if planEvent.Plan.Intent != IntentAggregateFindingsBySource || !planEvent.Deterministic || !planEvent.Corrected {
		t.Fatalf("query plan event = %#v, want deterministic corrected source aggregation", planEvent)
	}
	cypher := events[4].Data.(CypherEvent)
	if !cypher.Validator.OK {
		t.Fatalf("validator = %#v, want ok", cypher.Validator)
	}
	if strings.Contains(cypher.Cypher, "apoc.") || strings.Contains(cypher.Cypher, "HAS_SOURCE") || strings.Contains(cypher.Cypher, "entity_type = 'Finding'") {
		t.Fatalf("cypher was not canonicalized:\n%s", cypher.Cypher)
	}
	if len(store.requests) != 1 || !strings.Contains(store.requests[0].Query, "entity_type: 'finding'") || !strings.Contains(store.requests[0].Query, "count(DISTINCT f)") {
		t.Fatalf("store request = %#v", store.requests)
	}
}

func TestServiceSanitizesInternalFindingAttributes(t *testing.T) {
	store := &askStore{
		rows: []ports.CypherRow{{
			Values: map[string]any{
				"finding_urn":                      "urn:cerebro:writer:finding:quoted-summary",
				"finding_label":                    "Quoted finding",
				"summary":                          "",
				"status":                           "",
				"severity":                         "",
				"finding_attributes_json_internal": `{"summary":"Okta policy rule \"Admins\" is INACTIVE","status":"open","severity":"HIGH","risk_score":"47"}`,
			},
		}},
	}
	llm := &StubLLMClient{
		DraftResponse: &DraftResponse{
			Rationale: "Explaining the scoped finding.",
			Plan:      &AskQueryPlan{Intent: IntentExplainFinding, Limit: 25},
		},
		Summary: "Quoted finding should be reviewed.",
	}
	service := NewService(store, llm, ValidatorOptions{})

	var events []Event
	err := service.Stream(context.Background(), AskRequest{
		TenantID: "writer",
		Question: "Explain this finding",
		ScopeURN: "urn:cerebro:writer:finding:quoted-summary",
	}, func(event Event) error {
		events = append(events, event)
		return nil
	})
	if err != nil {
		t.Fatalf("Stream() error = %v", err)
	}
	rowsEvent := events[6].Data.(RowsEvent)
	row := rowsEvent.Rows[0]
	if _, exists := row["finding_attributes_json_internal"]; exists {
		t.Fatalf("internal attributes leaked in row: %#v", row)
	}
	if got := row["summary"]; got != `Okta policy rule "Admins" is INACTIVE` {
		t.Fatalf("summary = %q, want full quoted summary", got)
	}
	if got := row["severity"]; got != "HIGH" {
		t.Fatalf("severity = %q, want HIGH", got)
	}
}

func TestServiceRequiresTenantID(t *testing.T) {
	service := NewService(&askStore{}, NewStubLLMClient(), ValidatorOptions{})
	err := service.Stream(context.Background(), AskRequest{Question: "hello"}, func(Event) error { return nil })
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Stream() error = %v, want tenant_id validation", err)
	}
}

func assertEventNames(t *testing.T, events []Event, want []string) {
	t.Helper()
	if len(events) != len(want) {
		t.Fatalf("events len = %d, want %d (%#v)", len(events), len(want), events)
	}
	for i, name := range want {
		if events[i].Name != name {
			t.Fatalf("event[%d] = %q, want %q", i, events[i].Name, name)
		}
	}
}

type askStore struct {
	requests []ports.CypherQueryRequest
	rows     []ports.CypherRow
	graph    *ports.EntityNeighborhood
}

func (s *askStore) Ping(context.Context) error { return nil }

func (s *askStore) GetEntityNeighborhood(context.Context, string, int) (*ports.EntityNeighborhood, error) {
	if s.graph != nil {
		return s.graph, nil
	}
	return nil, ports.ErrGraphEntityNotFound
}

func (s *askStore) ExecuteReadCypher(_ context.Context, request ports.CypherQueryRequest) ([]ports.CypherRow, error) {
	s.requests = append(s.requests, request)
	if len(request.Query) >= len("EXPLAIN ") && request.Query[:len("EXPLAIN ")] == "EXPLAIN " {
		return nil, nil
	}
	return s.rows, nil
}

var _ ports.GraphQueryStore = (*askStore)(nil)
