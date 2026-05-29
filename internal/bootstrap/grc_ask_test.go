package bootstrap

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/graphagent"
	"github.com/writer/cerebro/internal/ports"
)

func TestGRCAskStreamsSSE(t *testing.T) {
	graphStore := &stubGraphStore{
		cypherRows: [][]ports.CypherRow{{
			{Values: map[string]any{
				"entity_urn":  "urn:cerebro:example:asset:alpha",
				"entity_type": "asset",
				"label":       "alpha",
			}},
		}},
		neighborhood: &ports.EntityNeighborhood{
			Root: &ports.NeighborhoodNode{URN: "urn:cerebro:example:asset:alpha", EntityType: "asset", Label: "alpha"},
		},
	}
	llm := &graphagent.StubLLMClient{
		DraftResponse: &graphagent.DraftResponse{
			Rationale: "Finding scoped graph rows.",
			Cypher: `MATCH (e:Entity {tenant_id: $tenant_id})
RETURN e.urn AS entity_urn, e.entity_type AS entity_type, e.label AS label
LIMIT 25`,
		},
		Summary: "Review `urn:cerebro:example:asset:alpha` first.",
	}
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{GraphStore: graphStore, GraphAgentLLM: llm}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	body := []byte(`{"tenant_id":"example","question":"What is risky?","scope_urn":"urn:cerebro:example:asset:alpha"}`)
	resp, err := server.Client().Post(server.URL+"/grc/ask", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /grc/ask error = %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /grc/ask status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if got := resp.Header.Get("Content-Type"); !strings.Contains(got, "text/event-stream") {
		t.Fatalf("content-type = %q, want text/event-stream", got)
	}
	events := readSSEEvents(t, resp)
	want := []string{"progress", "rationale", "progress", "cypher", "progress", "rows", "progress", "summary", "done"}
	if len(events) != len(want) {
		t.Fatalf("events = %#v, want names %v", events, want)
	}
	for i, name := range want {
		if events[i].Name != name {
			t.Fatalf("event[%d] = %q, want %q", i, events[i].Name, name)
		}
	}
	if len(graphStore.cypherRequests) != 2 {
		t.Fatalf("cypher request count = %d, want EXPLAIN + execute", len(graphStore.cypherRequests))
	}
	if !strings.HasPrefix(graphStore.cypherRequests[0].Query, "EXPLAIN ") {
		t.Fatalf("first cypher request = %q, want EXPLAIN", graphStore.cypherRequests[0].Query)
	}
}

func TestGRCAskMissingTenantReturnsBadRequest(t *testing.T) {
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{GraphStore: &stubGraphStore{}, GraphAgentLLM: graphagent.NewStubLLMClient()}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	resp, err := server.Client().Post(server.URL+"/grc/ask", "application/json", strings.NewReader(`{"question":"hello"}`))
	if err != nil {
		t.Fatalf("POST /grc/ask error = %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

func TestGRCAskMissingStartupLLMReturnsUnavailable(t *testing.T) {
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{GraphStore: &stubGraphStore{}}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	resp, err := server.Client().Post(server.URL+"/grc/ask", "application/json", strings.NewReader(`{"tenant_id":"example","question":"hello"}`))
	if err != nil {
		t.Fatalf("POST /grc/ask error = %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusServiceUnavailable)
	}
}

func TestGRCAskDraftFailureReturnsServiceUnavailable(t *testing.T) {
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{
		GraphStore:    &stubGraphStore{},
		GraphAgentLLM: &graphagent.StubLLMClient{DraftErr: errors.New("bedrock unavailable")},
	}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	resp, err := server.Client().Post(server.URL+"/grc/ask", "application/json", strings.NewReader(`{"tenant_id":"example","question":"hello"}`))
	if err != nil {
		t.Fatalf("POST /grc/ask error = %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d with streamed error event", resp.StatusCode, http.StatusOK)
	}
	events := readSSEEvents(t, resp)
	assertSSEEventNames(t, events, []string{"progress", "error"})
	if !strings.Contains(string(events[1].Data), "draft cypher") {
		t.Fatalf("error event = %s, want draft failure", events[1].Data)
	}
}

func TestGRCAskExplainFailureReturnsServiceUnavailable(t *testing.T) {
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{
		GraphStore:    &stubGraphStore{err: errors.New("neo4j unavailable")},
		GraphAgentLLM: graphagent.NewStubLLMClient(),
	}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	resp, err := server.Client().Post(server.URL+"/grc/ask", "application/json", strings.NewReader(`{"tenant_id":"example","question":"hello"}`))
	if err != nil {
		t.Fatalf("POST /grc/ask error = %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d with streamed error event", resp.StatusCode, http.StatusOK)
	}
	events := readSSEEvents(t, resp)
	assertSSEEventNames(t, events, []string{"progress", "rationale", "progress", "error"})
	if !strings.Contains(string(events[3].Data), "explain cypher") {
		t.Fatalf("error event = %s, want explain failure", events[3].Data)
	}
}

type sseRecord struct {
	Name string
	Data json.RawMessage
}

func readSSEEvents(t *testing.T, resp *http.Response) []sseRecord {
	t.Helper()
	var events []sseRecord
	var current sseRecord
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			if current.Name != "" {
				events = append(events, current)
				current = sseRecord{}
			}
			continue
		}
		if value, ok := strings.CutPrefix(line, "event: "); ok {
			current.Name = value
		}
		if value, ok := strings.CutPrefix(line, "data: "); ok {
			current.Data = json.RawMessage(value)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan SSE: %v", err)
	}
	return events
}

func assertSSEEventNames(t *testing.T, events []sseRecord, want []string) {
	t.Helper()
	if len(events) != len(want) {
		t.Fatalf("events = %#v, want names %v", events, want)
	}
	for i, name := range want {
		if events[i].Name != name {
			t.Fatalf("event[%d] = %q, want %q", i, events[i].Name, name)
		}
	}
}
