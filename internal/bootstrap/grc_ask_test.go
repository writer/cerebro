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
	want := []string{"progress", "rationale", "query_plan", "progress", "cypher", "progress", "rows", "progress", "summary", "done"}
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

func TestGRCAskTelemetryIncludesQueryPlanDiagnostics(t *testing.T) {
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{
		GraphStore: &stubGraphStore{},
		GraphAgentLLM: &graphagent.StubLLMClient{DraftResponse: &graphagent.DraftResponse{
			Rationale: "Planning filtered high-risk findings.",
			Plan:      &graphagent.AskQueryPlan{Intent: graphagent.IntentTopRiskFindings, Filters: map[string]string{"severity": "HIGH"}},
		}},
	}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	var events []sseRecord
	stderr := captureBootstrapStderr(t, func() {
		resp, err := server.Client().Post(server.URL+"/grc/ask", "application/json", strings.NewReader(`{"tenant_id":"example","question":"show HIGH risk findings"}`))
		if err != nil {
			t.Fatalf("POST /grc/ask error = %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("POST /grc/ask status = %d, want %d", resp.StatusCode, http.StatusOK)
		}
		events = readSSEEvents(t, resp)
	})
	assertSSEEventNames(t, events, []string{"progress", "rationale", "query_plan", "cypher", "summary", "done"})

	payload := decodeBootstrapTelemetryPayload(t, stderr)
	for key, want := range map[string]any{
		"name":                         "cerebro.grc.ask",
		"operation":                    "grc.ask",
		"outcome":                      "success",
		"status":                       float64(http.StatusOK),
		"tenant_id":                    "example",
		"sse_events":                   float64(6),
		"query_plan.intent":            graphagent.IntentTopRiskFindings,
		"query_plan.source":            "conversion_refusal",
		"query_plan.deterministic":     false,
		"query_plan.corrected":         false,
		"query_plan.diagnostics_count": float64(1),
		"query_plan.diagnostic_codes":  "query_plan_conversion_failed",
		"terminal_event":               "done",
		"cypher_refused":               true,
		"validator.ok":                 false,
		"row_count":                    float64(0),
		"citation_count":               float64(0),
	} {
		if got := payload[key]; got != want {
			t.Fatalf("telemetry %s = %#v, want %#v; payload=%#v", key, got, want, payload)
		}
	}
	if traceID, ok := payload["ask_trace_id"].(string); !ok || traceID == "" {
		t.Fatalf("ask_trace_id = %#v, want non-empty string; payload=%#v", payload["ask_trace_id"], payload)
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

	var events []sseRecord
	stderr := captureBootstrapStderr(t, func() {
		resp, err := server.Client().Post(server.URL+"/grc/ask", "application/json", strings.NewReader(`{"tenant_id":"example","question":"hello"}`))
		if err != nil {
			t.Fatalf("POST /grc/ask error = %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want %d with streamed error event", resp.StatusCode, http.StatusOK)
		}
		events = readSSEEvents(t, resp)
	})
	assertSSEEventNames(t, events, []string{"progress", "error"})
	if !strings.Contains(string(events[1].Data), "draft cypher") {
		t.Fatalf("error event = %s, want draft failure", events[1].Data)
	}
	var errorEvent graphagent.ErrorEvent
	if err := json.Unmarshal(events[1].Data, &errorEvent); err != nil {
		t.Fatalf("unmarshal error event: %v", err)
	}
	if errorEvent.TraceID == "" {
		t.Fatalf("error trace_id is empty: %#v", errorEvent)
	}
	payload := decodeBootstrapTelemetryPayload(t, stderr)
	if got := payload["runtime_error.code"]; got != "ask_failed" {
		t.Fatalf("runtime_error.code = %#v, want ask_failed; payload=%#v", got, payload)
	}
	if _, exists := payload["validator.code"]; exists {
		t.Fatalf("validator.code recorded runtime error: payload=%#v", payload)
	}
	if got := payload["ask_trace_id"]; got != errorEvent.TraceID {
		t.Fatalf("ask_trace_id = %#v, want error trace %q; payload=%#v", got, errorEvent.TraceID, payload)
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
	assertSSEEventNames(t, events, []string{"progress", "rationale", "query_plan", "progress", "error"})
	if !strings.Contains(string(events[4].Data), "explain cypher") {
		t.Fatalf("error event = %s, want explain failure", events[4].Data)
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
