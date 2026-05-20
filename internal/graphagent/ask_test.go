package graphagent

import (
	"context"
	"errors"
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
	assertEventNames(t, events, []string{EventRationale, EventCypher, EventRows, EventSummary, EventDone})
	rowsEvent, ok := events[2].Data.(RowsEvent)
	if !ok {
		t.Fatalf("rows event data = %T", events[2].Data)
	}
	if len(rowsEvent.Rows) != 1 || rowsEvent.Rows[0]["entity_urn"] != "urn:cerebro:example:asset:alpha" {
		t.Fatalf("rows = %#v", rowsEvent.Rows)
	}
	if rowsEvent.Graph == nil || rowsEvent.Graph.Root == nil {
		t.Fatalf("graph neighborhood missing")
	}
	summaryEvent, ok := events[3].Data.(SummaryEvent)
	if !ok {
		t.Fatalf("summary event data = %T", events[3].Data)
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
	assertEventNames(t, events, []string{EventRationale, EventCypher, EventSummary, EventDone})
	cypherEvent := events[1].Data.(CypherEvent)
	if cypherEvent.Validator.OK {
		t.Fatalf("validator ok = true, want false")
	}
	done := events[3].Data.(DoneEvent)
	if !done.CypherRefused {
		t.Fatalf("done.CypherRefused = false, want true")
	}
	if len(store.requests) != 0 {
		t.Fatalf("store executed rejected query: %#v", store.requests)
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
