package graph

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/neptunedata"
	"github.com/aws/smithy-go"
)

type fakeNeptuneExecutor struct {
	calls          []fakeNeptuneCall
	results        map[string]any
	explainCalls   []fakeNeptuneExplainCall
	explainResults map[string][]byte
	handler        func(query string, params map[string]any) (any, error)
	err            error
}

type fakeNeptuneCall struct {
	query  string
	params map[string]any
}

type fakeNeptuneExplainCall struct {
	query  string
	mode   NeptuneExplainMode
	params map[string]any
}

func (f *fakeNeptuneExecutor) ExecuteOpenCypher(_ context.Context, query string, params map[string]any) (any, error) {
	if f.err != nil {
		return nil, f.err
	}
	trimmed := strings.TrimSpace(query)
	f.calls = append(f.calls, fakeNeptuneCall{query: trimmed, params: params})
	if f.handler != nil {
		return f.handler(trimmed, params)
	}
	if f.results == nil {
		return nil, nil
	}
	return f.results[trimmed], nil
}

func (f *fakeNeptuneExecutor) ExecuteOpenCypherExplain(_ context.Context, query string, mode NeptuneExplainMode, params map[string]any) ([]byte, error) {
	if f.err != nil {
		return nil, f.err
	}
	trimmed := strings.TrimSpace(query)
	f.explainCalls = append(f.explainCalls, fakeNeptuneExplainCall{query: trimmed, mode: mode, params: params})
	if f.explainResults == nil {
		return nil, nil
	}
	return f.explainResults[fmt.Sprintf("%s|%s", mode, trimmed)], nil
}

type fakeNeptuneDataClient struct {
	queryCalls    int
	queryInputs   []*neptunedata.ExecuteOpenCypherQueryInput
	queryOutputs  []*neptunedata.ExecuteOpenCypherQueryOutput
	queryErrors   []error
	explainCalls  int
	explainInputs []*neptunedata.ExecuteOpenCypherExplainQueryInput
	explainOuts   []*neptunedata.ExecuteOpenCypherExplainQueryOutput
	explainErrors []error
}

func (f *fakeNeptuneDataClient) ExecuteOpenCypherQuery(_ context.Context, params *neptunedata.ExecuteOpenCypherQueryInput, _ ...func(*neptunedata.Options)) (*neptunedata.ExecuteOpenCypherQueryOutput, error) {
	f.queryCalls++
	f.queryInputs = append(f.queryInputs, params)
	idx := f.queryCalls - 1
	var output *neptunedata.ExecuteOpenCypherQueryOutput
	if idx < len(f.queryOutputs) {
		output = f.queryOutputs[idx]
	}
	if idx < len(f.queryErrors) {
		return output, f.queryErrors[idx]
	}
	return output, nil
}

func (f *fakeNeptuneDataClient) ExecuteOpenCypherExplainQuery(_ context.Context, params *neptunedata.ExecuteOpenCypherExplainQueryInput, _ ...func(*neptunedata.Options)) (*neptunedata.ExecuteOpenCypherExplainQueryOutput, error) {
	f.explainCalls++
	f.explainInputs = append(f.explainInputs, params)
	idx := f.explainCalls - 1
	var output *neptunedata.ExecuteOpenCypherExplainQueryOutput
	if idx < len(f.explainOuts) {
		output = f.explainOuts[idx]
	}
	if idx < len(f.explainErrors) {
		return output, f.explainErrors[idx]
	}
	return output, nil
}

func newNeptuneDocumentTestClient(t *testing.T, responseBody string) (neptuneDataClient, func()) {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(responseBody))
	}))
	client := neptunedata.NewFromConfig(aws.Config{
		Region:      "us-east-1",
		Credentials: aws.AnonymousCredentials{},
		HTTPClient:  server.Client(),
	}, func(options *neptunedata.Options) {
		options.BaseEndpoint = aws.String(server.URL)
	})
	return client, server.Close
}

type timeoutNetError struct{}

func (timeoutNetError) Error() string   { return "i/o timeout" }
func (timeoutNetError) Timeout() bool   { return true }
func (timeoutNetError) Temporary() bool { return true }

var _ net.Error = timeoutNetError{}

func TestNeptuneDataExecutorExecuteOpenCypherRetriesTransientErrors(t *testing.T) {
	client := &fakeNeptuneDataClient{
		queryErrors: []error{
			&smithy.GenericAPIError{Code: "ThrottlingException", Message: "slow down"},
			timeoutNetError{},
			nil,
		},
		queryOutputs: []*neptunedata.ExecuteOpenCypherQueryOutput{
			nil,
			nil,
			{},
		},
	}
	var sleeps []time.Duration
	exec := &neptuneDataExecutor{
		client: client,
		retry:  neptuneRetryOptions{Attempts: 3, BaseDelay: 10 * time.Millisecond, MaxDelay: 25 * time.Millisecond},
		sleep: func(_ context.Context, d time.Duration) error {
			sleeps = append(sleeps, d)
			return nil
		},
	}

	if _, err := exec.ExecuteOpenCypher(context.Background(), "MATCH (n) RETURN n", map[string]any{"tenant_id": "tenant-a"}); err != nil {
		t.Fatalf("ExecuteOpenCypher() error = %v", err)
	}
	if client.queryCalls != 3 {
		t.Fatalf("query attempts = %d, want 3", client.queryCalls)
	}
	if !reflect.DeepEqual(sleeps, []time.Duration{10 * time.Millisecond, 20 * time.Millisecond}) {
		t.Fatalf("sleep backoff = %#v", sleeps)
	}
	if len(client.queryInputs) != 3 || client.queryInputs[0].Parameters == nil || *client.queryInputs[0].Parameters != `{"tenant_id":"tenant-a"}` {
		t.Fatalf("expected marshaled parameters on retry input, got %#v", client.queryInputs)
	}
}

func TestNeptuneDataExecutorExecuteOpenCypherDoesNotRetryPermanentErrors(t *testing.T) {
	client := &fakeNeptuneDataClient{
		queryErrors: []error{errors.New("syntax error at line 1")},
	}
	sleepCalls := 0
	exec := &neptuneDataExecutor{
		client: client,
		retry:  neptuneRetryOptions{Attempts: 4, BaseDelay: time.Millisecond, MaxDelay: 5 * time.Millisecond},
		sleep: func(_ context.Context, _ time.Duration) error {
			sleepCalls++
			return nil
		},
	}

	if _, err := exec.ExecuteOpenCypher(context.Background(), "MATCH (n", nil); err == nil {
		t.Fatal("expected permanent error")
	}
	if client.queryCalls != 1 {
		t.Fatalf("query attempts = %d, want 1", client.queryCalls)
	}
	if sleepCalls != 0 {
		t.Fatalf("sleep calls = %d, want 0", sleepCalls)
	}
}

func TestNeptuneDataExecutorExecuteOpenCypherStopsAtMaxAttempts(t *testing.T) {
	client := &fakeNeptuneDataClient{
		queryErrors: []error{
			errors.New("connection reset by peer"),
			errors.New("connection reset by peer"),
			errors.New("connection reset by peer"),
		},
	}
	var sleeps []time.Duration
	exec := &neptuneDataExecutor{
		client: client,
		retry:  neptuneRetryOptions{Attempts: 3, BaseDelay: 10 * time.Millisecond, MaxDelay: 15 * time.Millisecond},
		sleep: func(_ context.Context, d time.Duration) error {
			sleeps = append(sleeps, d)
			return nil
		},
	}

	if _, err := exec.ExecuteOpenCypher(context.Background(), "MATCH (n) RETURN n", nil); err == nil {
		t.Fatal("expected retry exhaustion error")
	}
	if client.queryCalls != 3 {
		t.Fatalf("query attempts = %d, want 3", client.queryCalls)
	}
	if !reflect.DeepEqual(sleeps, []time.Duration{10 * time.Millisecond, 15 * time.Millisecond}) {
		t.Fatalf("sleep backoff = %#v", sleeps)
	}
}

func TestNeptuneGraphStoreCountNodesDecodesSmithyDocumentResults(t *testing.T) {
	client, cleanup := newNeptuneDocumentTestClient(t, `{"results":[{"total":2}]}`)
	defer cleanup()

	store := NewNeptuneGraphStore(NewNeptuneDataExecutor(client))
	got, err := store.CountNodes(context.Background())
	if err != nil {
		t.Fatalf("CountNodes() error = %v", err)
	}
	if got != 2 {
		t.Fatalf("CountNodes() = %d, want 2", got)
	}
}

func TestNeptuneDataExecutorExecuteOpenCypherExplainRetriesTransientErrors(t *testing.T) {
	client := &fakeNeptuneDataClient{
		explainErrors: []error{
			errors.New("read tcp 10.0.0.1:443: connection reset by peer"),
			nil,
		},
		explainOuts: []*neptunedata.ExecuteOpenCypherExplainQueryOutput{
			nil,
			{Results: []byte("plan")},
		},
	}
	var sleeps []time.Duration
	exec := &neptuneDataExecutor{
		client: client,
		retry:  neptuneRetryOptions{Attempts: 2, BaseDelay: 5 * time.Millisecond, MaxDelay: 20 * time.Millisecond},
		sleep: func(_ context.Context, d time.Duration) error {
			sleeps = append(sleeps, d)
			return nil
		},
	}

	got, err := exec.ExecuteOpenCypherExplain(context.Background(), "MATCH (n) RETURN n", NeptuneExplainModeDetails, nil)
	if err != nil {
		t.Fatalf("ExecuteOpenCypherExplain() error = %v", err)
	}
	if string(got) != "plan" {
		t.Fatalf("ExecuteOpenCypherExplain() = %q, want plan", got)
	}
	if client.explainCalls != 2 {
		t.Fatalf("explain attempts = %d, want 2", client.explainCalls)
	}
	if !reflect.DeepEqual(sleeps, []time.Duration{5 * time.Millisecond}) {
		t.Fatalf("sleep backoff = %#v", sleeps)
	}
}

func TestNeptuneTenantScopedReadQueriesIncludeTenantPredicates(t *testing.T) {
	t.Run("node queries", func(t *testing.T) {
		for name, query := range map[string]string{
			"lookup node":          neptuneLookupNodeQuery,
			"lookup nodes by kind": neptuneLookupNodesByKindQuery,
			"count nodes":          neptuneCountNodesQuery,
			"snapshot nodes":       neptuneSnapshotNodesQuery,
		} {
			if !strings.Contains(query, "tenant_scope_disabled") {
				t.Fatalf("%s query missing tenant scope guard:\n%s", name, query)
			}
			if !strings.Contains(query, "tenant_id IN $tenant_ids") {
				t.Fatalf("%s query missing tenant_id filter:\n%s", name, query)
			}
		}
	})

	t.Run("edge queries", func(t *testing.T) {
		for name, query := range map[string]string{
			"lookup edge":            neptuneLookupEdgeQuery,
			"lookup out edges":       neptuneLookupOutEdgesQuery,
			"lookup in edges":        neptuneLookupInEdgesQuery,
			"lookup out edges bt":    neptuneLookupOutEdgesBitemporalQuery,
			"lookup in edges bt":     neptuneLookupInEdgesBitemporalQuery,
			"lookup out edges range": neptuneLookupOutEdgesBetweenQuery,
			"lookup in edges range":  neptuneLookupInEdgesBetweenQuery,
			"count edges":            neptuneCountEdgesQuery,
			"snapshot edges":         neptuneSnapshotEdgesQuery,
			"traversal edges":        neptuneTraversalEdgesQuery(neptuneTraversalDirectionBoth, 2),
			"traversal nodes":        neptuneTraversalNodesQuery(neptuneTraversalDirectionBoth, 2),
			"bitemporal trav nodes":  neptuneTemporalBitemporalTraversalNodeQuery(neptuneTraversalDirectionBoth, 2),
			"bitemporal trav edges":  neptuneTemporalBitemporalTraversalEdgeQuery(neptuneTraversalDirectionBoth, 2),
			"range traversal nodes":  neptuneTemporalRangeTraversalNodeQuery(neptuneTraversalDirectionBoth, 2),
			"range traversal edges":  neptuneTemporalRangeTraversalEdgeQuery(neptuneTraversalDirectionBoth, 2),
		} {
			if !strings.Contains(query, "tenant_scope_disabled") {
				t.Fatalf("%s query missing tenant scope guard:\n%s", name, query)
			}
			if !strings.Contains(query, "tenant_id IN $tenant_ids") {
				t.Fatalf("%s query missing tenant_id filter:\n%s", name, query)
			}
		}
	})
}

func TestNeptuneGraphStoreReadQueriesApplyTenantScopeFromContext(t *testing.T) {
	t.Run("count nodes", func(t *testing.T) {
		exec := &fakeNeptuneExecutor{
			results: map[string]any{
				strings.TrimSpace(neptuneCountNodesQuery): []any{map[string]any{"total": int64(2)}},
			},
		}
		store := NewNeptuneGraphStore(exec)

		got, err := store.CountNodes(WithTenantScope(context.Background(), " tenant-a "))
		if err != nil {
			t.Fatalf("CountNodes() error = %v", err)
		}
		if got != 2 {
			t.Fatalf("CountNodes() = %d, want 2", got)
		}
		if len(exec.calls) != 1 {
			t.Fatalf("expected one Neptune call, got %d", len(exec.calls))
		}
		call := exec.calls[0]
		if got := call.params["tenant_scope_disabled"]; got != false {
			t.Fatalf("tenant_scope_disabled = %#v, want false", got)
		}
		if got := call.params["tenant_ids"]; !reflect.DeepEqual(got, []string{"tenant-a"}) {
			t.Fatalf("tenant_ids = %#v, want [tenant-a]", got)
		}
	})

	t.Run("lookup nodes by kind cross tenant", func(t *testing.T) {
		exec := &fakeNeptuneExecutor{
			results: map[string]any{
				strings.TrimSpace(neptuneLookupNodesByKindQuery): nil,
			},
		}
		store := NewNeptuneGraphStore(exec)

		_, err := store.LookupNodesByKind(WithCrossTenantScope(context.Background(), "cursor[bot]", "investigate", "tenant-b", " tenant-a ", "tenant-b"), NodeKindService)
		if err != nil {
			t.Fatalf("LookupNodesByKind() error = %v", err)
		}
		if len(exec.calls) != 1 {
			t.Fatalf("expected one Neptune call, got %d", len(exec.calls))
		}
		call := exec.calls[0]
		if got := call.params["tenant_scope_disabled"]; got != false {
			t.Fatalf("tenant_scope_disabled = %#v, want false", got)
		}
		if got := call.params["tenant_ids"]; !reflect.DeepEqual(got, []string{"tenant-a", "tenant-b"}) {
			t.Fatalf("tenant_ids = %#v, want [tenant-a tenant-b]", got)
		}
	})

	t.Run("snapshot", func(t *testing.T) {
		exec := &fakeNeptuneExecutor{
			results: map[string]any{
				strings.TrimSpace(neptuneSnapshotNodesQuery): []any{
					map[string]any{"node": map[string]any{
						"id":         "service:tenant-a",
						"kind":       "service",
						"tenant_id":  "tenant-a",
						"created_at": "2026-03-20T12:00:00Z",
						"updated_at": "2026-03-20T12:01:00Z",
						"version":    int64(1),
					}},
				},
				strings.TrimSpace(neptuneSnapshotEdgesQuery): []any{
					map[string]any{"edge": map[string]any{
						"id":         "edge:tenant-a",
						"source":     "service:tenant-a",
						"target":     "service:shared",
						"kind":       "depends_on",
						"effect":     "allow",
						"priority":   int64(50),
						"created_at": "2026-03-20T12:02:00Z",
						"version":    int64(1),
					}},
				},
			},
		}
		store := NewNeptuneGraphStore(exec)

		snapshot, err := store.Snapshot(WithTenantScope(context.Background(), "tenant-a"))
		if err != nil {
			t.Fatalf("Snapshot() error = %v", err)
		}
		if snapshot == nil || len(snapshot.Nodes) != 1 || len(snapshot.Edges) != 1 {
			t.Fatalf("Snapshot() = %#v, want 1 node and 1 edge", snapshot)
		}
		if len(exec.calls) != 2 {
			t.Fatalf("expected two Neptune calls, got %d", len(exec.calls))
		}
		for _, call := range exec.calls {
			if got := call.params["tenant_scope_disabled"]; got != false {
				t.Fatalf("tenant_scope_disabled = %#v, want false", got)
			}
			if got := call.params["tenant_ids"]; !reflect.DeepEqual(got, []string{"tenant-a"}) {
				t.Fatalf("tenant_ids = %#v, want [tenant-a]", got)
			}
		}
	})
}

func TestNeptuneGraphStoreUpsertNodeBuildsOpenCypherPayload(t *testing.T) {
	exec := &fakeNeptuneExecutor{}
	store := NewNeptuneGraphStore(exec)

	node := &Node{
		ID:         "service:payments",
		Kind:       NodeKindApplication,
		Name:       "Payments",
		TenantID:   "tenant-a",
		Properties: map[string]any{"critical": true},
		Tags:       map[string]string{"env": "prod"},
		Findings:   []string{"finding-1"},
		CreatedAt:  time.Date(2026, time.March, 20, 12, 0, 0, 0, time.UTC),
		UpdatedAt:  time.Date(2026, time.March, 20, 12, 1, 0, 0, time.UTC),
		Version:    3,
	}
	if err := store.UpsertNode(context.Background(), node); err != nil {
		t.Fatalf("UpsertNode() error = %v", err)
	}
	if len(exec.calls) != 1 {
		t.Fatalf("expected one Neptune call, got %d", len(exec.calls))
	}
	call := exec.calls[0]
	if call.query != strings.TrimSpace(neptuneUpsertNodeQuery) {
		t.Fatalf("unexpected Neptune query:\n%s", call.query)
	}
	if got := call.params["id"]; got != node.ID {
		t.Fatalf("upsert node id = %#v, want %q", got, node.ID)
	}
	if got := call.params["tenant_id"]; got != node.TenantID {
		t.Fatalf("upsert tenant_id = %#v, want %q", got, node.TenantID)
	}
	if got := call.params["properties_json"]; got != `{"critical":true,"tenant_id":"tenant-a"}` {
		t.Fatalf("upsert properties_json = %#v", got)
	}
	if got := call.params["tags_json"]; got != `{"env":"prod"}` {
		t.Fatalf("upsert tags_json = %#v", got)
	}
}

func TestNeptuneGraphStoreBatchUpsertsUseSingleUNWINDQuery(t *testing.T) {
	t.Run("nodes", func(t *testing.T) {
		exec := &fakeNeptuneExecutor{}
		store := NewNeptuneGraphStore(exec)

		err := store.UpsertNodesBatch(context.Background(), []*Node{
			{
				ID:         "service:payments",
				Kind:       NodeKindApplication,
				Name:       "Payments",
				TenantID:   "tenant-a",
				Properties: map[string]any{"critical": true},
				Tags:       map[string]string{"env": "prod"},
				Findings:   []string{"finding-1"},
				CreatedAt:  time.Date(2026, time.March, 20, 12, 0, 0, 0, time.UTC),
				UpdatedAt:  time.Date(2026, time.March, 20, 12, 1, 0, 0, time.UTC),
				Version:    3,
			},
			nil,
			{ID: "   "},
			{
				ID:        "service:billing",
				Kind:      NodeKindApplication,
				Name:      "Billing",
				CreatedAt: time.Date(2026, time.March, 21, 8, 0, 0, 0, time.UTC),
				UpdatedAt: time.Date(2026, time.March, 21, 8, 5, 0, 0, time.UTC),
				Version:   1,
			},
		})
		if err != nil {
			t.Fatalf("UpsertNodesBatch() error = %v", err)
		}
		if len(exec.calls) != 1 {
			t.Fatalf("expected one Neptune call, got %d", len(exec.calls))
		}
		call := exec.calls[0]
		if call.query != strings.TrimSpace(neptuneUpsertNodesBatchQuery) {
			t.Fatalf("unexpected Neptune batch node query:\n%s", call.query)
		}
		rows, ok := call.params["rows"].([]map[string]any)
		if !ok {
			t.Fatalf("expected rows param, got %#v", call.params["rows"])
		}
		if len(rows) != 2 {
			t.Fatalf("expected 2 valid node rows, got %#v", rows)
		}
		if got := rows[0]["id"]; got != "service:payments" {
			t.Fatalf("first batch node id = %#v", got)
		}
		if got := rows[0]["properties_json"]; got != `{"critical":true,"tenant_id":"tenant-a"}` {
			t.Fatalf("first batch node properties_json = %#v", got)
		}
		if got := rows[1]["id"]; got != "service:billing" {
			t.Fatalf("second batch node id = %#v", got)
		}
	})

	t.Run("edges", func(t *testing.T) {
		exec := &fakeNeptuneExecutor{
			handler: func(query string, params map[string]any) (any, error) {
				switch query {
				case strings.TrimSpace(neptuneLookupNodeQuery):
					id, _ := params["id"].(string)
					switch id {
					case "service:payments", "service:billing":
						return []any{map[string]any{"node": map[string]any{
							"id":   id,
							"kind": string(NodeKindApplication),
							"name": id,
						}}}, nil
					case "database:payments", "queue:jobs":
						return []any{map[string]any{"node": map[string]any{
							"id":   id,
							"kind": string(NodeKindDatabase),
							"name": id,
						}}}, nil
					}
				case strings.TrimSpace(neptuneLookupOutEdgesQuery), strings.TrimSpace(neptuneLookupInEdgesQuery):
					return []any{}, nil
				}
				return nil, nil
			},
		}
		store := NewNeptuneGraphStore(exec)

		err := store.UpsertEdgesBatch(context.Background(), []*Edge{
			{
				ID:        "access:payments:db",
				Source:    "service:payments",
				Target:    "database:payments",
				Kind:      EdgeKindCalls,
				Effect:    EdgeEffectAllow,
				Priority:  50,
				CreatedAt: time.Date(2026, time.March, 20, 12, 2, 0, 0, time.UTC),
				Version:   4,
				Properties: map[string]any{
					"path": "/query",
				},
			},
			nil,
			{ID: "skip-missing-target", Source: "service:payments"},
			{
				ID:        "access:billing:queue",
				Source:    "service:billing",
				Target:    "queue:jobs",
				Kind:      EdgeKindDependsOn,
				Effect:    EdgeEffectAllow,
				Priority:  50,
				CreatedAt: time.Date(2026, time.March, 21, 9, 0, 0, 0, time.UTC),
				Version:   1,
			},
		})
		if err != nil {
			t.Fatalf("UpsertEdgesBatch() error = %v", err)
		}
		call, ok := findNeptuneCall(exec.calls, strings.TrimSpace(neptuneUpsertEdgesBatchQuery))
		if !ok {
			t.Fatalf("expected Neptune batch edge mutation query, got %#v", neptuneCallQueries(exec.calls))
		}
		if call.query != strings.TrimSpace(neptuneUpsertEdgesBatchQuery) {
			t.Fatalf("unexpected Neptune batch edge query:\n%s", call.query)
		}
		rows, ok := call.params["rows"].([]map[string]any)
		if !ok {
			t.Fatalf("expected rows param, got %#v", call.params["rows"])
		}
		if len(rows) != 2 {
			t.Fatalf("expected 2 valid edge rows, got %#v", rows)
		}
		if got := rows[0]["id"]; got != "access:payments:db" {
			t.Fatalf("first batch edge id = %#v", got)
		}
		if got := rows[0]["properties_json"]; got != `{"path":"/query"}` {
			t.Fatalf("first batch edge properties_json = %#v", got)
		}
		if got := rows[1]["id"]; got != "access:billing:queue" {
			t.Fatalf("second batch edge id = %#v", got)
		}
	})
}

func TestNeptuneGraphStoreUpsertNodeRejectsSchemaViolations(t *testing.T) {
	customKind := NodeKind("test_neptune_required_node_kind_v1")
	if _, err := RegisterNodeKindDefinition(NodeKindDefinition{
		Kind:       customKind,
		Categories: []NodeKindCategory{NodeCategoryBusiness},
		Properties: map[string]string{
			"owner":    "string",
			"priority": "integer",
		},
		RequiredProperties: []string{"owner"},
	}); err != nil {
		t.Fatalf("register node kind: %v", err)
	}

	exec := &fakeNeptuneExecutor{}
	store := NewNeptuneGraphStore(exec)

	err := store.UpsertNode(context.Background(), &Node{
		ID:         "node:invalid",
		Kind:       customKind,
		Properties: map[string]any{"priority": "high"},
	})
	if err == nil {
		t.Fatal("UpsertNode() error = nil, want schema validation error")
	}
	var validationErr *SchemaValidationError
	if !errors.As(err, &validationErr) {
		t.Fatalf("UpsertNode() error = %T, want *SchemaValidationError", err)
	}
	if len(validationErr.Issues) < 2 {
		t.Fatalf("expected multiple validation issues, got %#v", validationErr.Issues)
	}
	if len(exec.calls) != 0 {
		t.Fatalf("expected no Neptune mutation call, got %#v", exec.calls)
	}
}

func TestNeptuneGraphStoreUpsertEdgeRejectsOntologyAndCardinalityViolations(t *testing.T) {
	sourceKind := NodeKind("test_neptune_cardinality_source_v1")
	targetKind := NodeKind("test_neptune_cardinality_target_v1")
	if _, err := RegisterNodeKindDefinition(NodeKindDefinition{
		Kind:          sourceKind,
		Categories:    []NodeKindCategory{NodeCategoryBusiness},
		Relationships: []EdgeKind{EdgeKindMemberOf},
		RelationshipCardinality: map[EdgeKind]RelationshipCardinality{
			EdgeKindMemberOf: {MaxOutgoing: 1},
		},
	}); err != nil {
		t.Fatalf("register source kind: %v", err)
	}
	if _, err := RegisterNodeKindDefinition(NodeKindDefinition{
		Kind:       targetKind,
		Categories: []NodeKindCategory{NodeCategoryBusiness},
	}); err != nil {
		t.Fatalf("register target kind: %v", err)
	}

	exec := &fakeNeptuneExecutor{
		handler: func(query string, params map[string]any) (any, error) {
			switch query {
			case strings.TrimSpace(neptuneLookupNodeQuery):
				id, _ := params["id"].(string)
				switch id {
				case "person:alice":
					return []any{map[string]any{"node": map[string]any{
						"id":   id,
						"kind": string(sourceKind),
						"name": "Alice",
					}}}, nil
				case "department:eng", "department:ops":
					return []any{map[string]any{"node": map[string]any{
						"id":   id,
						"kind": string(targetKind),
						"name": id,
					}}}, nil
				}
				return []any{}, nil
			case strings.TrimSpace(neptuneLookupOutEdgesQuery):
				return []any{map[string]any{"edge": map[string]any{
					"id":      "edge:existing",
					"source":  "person:alice",
					"target":  "department:eng",
					"kind":    string(EdgeKindMemberOf),
					"effect":  string(EdgeEffectAllow),
					"version": int64(1),
				}}}, nil
			case strings.TrimSpace(neptuneLookupInEdgesQuery):
				return []any{}, nil
			}
			return nil, nil
		},
	}
	store := NewNeptuneGraphStore(exec)

	err := store.UpsertEdge(context.Background(), &Edge{
		ID:     "edge:new",
		Source: "person:alice",
		Target: "department:ops",
		Kind:   EdgeKindMemberOf,
		Effect: EdgeEffectAllow,
	})
	if err == nil {
		t.Fatal("UpsertEdge() error = nil, want schema validation error")
	}
	var validationErr *SchemaValidationError
	if !errors.As(err, &validationErr) {
		t.Fatalf("UpsertEdge() error = %T, want *SchemaValidationError", err)
	}
	if !containsSchemaIssueCode(validationErr.Issues, SchemaIssueCardinalityExceeded) {
		t.Fatalf("expected cardinality issue, got %#v", validationErr.Issues)
	}
	if _, ok := findNeptuneCall(exec.calls, strings.TrimSpace(neptuneUpsertEdgeQuery)); ok {
		t.Fatalf("unexpected Neptune mutation call: %#v", exec.calls)
	}
}

func TestNeptuneGraphStoreUpsertEdgesBatchEnforcesCardinalityAcrossBatch(t *testing.T) {
	sourceKind := NodeKind("test_neptune_batch_card_source_v1")
	targetKind := NodeKind("test_neptune_batch_card_target_v1")
	if _, err := RegisterNodeKindDefinition(NodeKindDefinition{
		Kind:          sourceKind,
		Categories:    []NodeKindCategory{NodeCategoryBusiness},
		Relationships: []EdgeKind{EdgeKindMemberOf},
		RelationshipCardinality: map[EdgeKind]RelationshipCardinality{
			EdgeKindMemberOf: {MaxOutgoing: 1},
		},
	}); err != nil {
		t.Fatalf("register source kind: %v", err)
	}
	if _, err := RegisterNodeKindDefinition(NodeKindDefinition{
		Kind:       targetKind,
		Categories: []NodeKindCategory{NodeCategoryBusiness},
	}); err != nil {
		t.Fatalf("register target kind: %v", err)
	}

	exec := &fakeNeptuneExecutor{
		handler: func(query string, params map[string]any) (any, error) {
			switch query {
			case strings.TrimSpace(neptuneLookupNodeQuery):
				id, _ := params["id"].(string)
				switch id {
				case "batch:person":
					return []any{map[string]any{"node": map[string]any{
						"id":   id,
						"kind": string(sourceKind),
						"name": "BatchPerson",
					}}}, nil
				case "batch:dept-a", "batch:dept-b":
					return []any{map[string]any{"node": map[string]any{
						"id":   id,
						"kind": string(targetKind),
						"name": id,
					}}}, nil
				}
				return []any{}, nil
			case strings.TrimSpace(neptuneLookupOutEdgesQuery):
				// DB currently has 0 outgoing edges of this kind.
				return []any{}, nil
			case strings.TrimSpace(neptuneLookupInEdgesQuery):
				return []any{}, nil
			}
			return nil, nil
		},
	}
	store := NewNeptuneGraphStore(exec)

	// Batch with two edges from the same source with MaxOutgoing=1
	// and DB count=0. Without batch-aware counting the second edge
	// would also pass validation.
	err := store.UpsertEdgesBatch(context.Background(), []*Edge{
		{
			ID:     "edge:batch-a",
			Source: "batch:person",
			Target: "batch:dept-a",
			Kind:   EdgeKindMemberOf,
			Effect: EdgeEffectAllow,
		},
		{
			ID:     "edge:batch-b",
			Source: "batch:person",
			Target: "batch:dept-b",
			Kind:   EdgeKindMemberOf,
			Effect: EdgeEffectAllow,
		},
	})
	if err == nil {
		t.Fatal("UpsertEdgesBatch() error = nil, want schema validation error for second edge")
	}
	var validationErr *SchemaValidationError
	if !errors.As(err, &validationErr) {
		t.Fatalf("UpsertEdgesBatch() error = %T, want *SchemaValidationError", err)
	}
	if !containsSchemaIssueCode(validationErr.Issues, SchemaIssueCardinalityExceeded) {
		t.Fatalf("expected cardinality issue, got %#v", validationErr.Issues)
	}
	if _, ok := findNeptuneCall(exec.calls, strings.TrimSpace(neptuneUpsertEdgesBatchQuery)); ok {
		t.Fatal("unexpected Neptune batch mutation call after cardinality rejection")
	}
}

func TestNeptuneGraphStoreDecodesLookupAndSnapshotResults(t *testing.T) {
	exec := &fakeNeptuneExecutor{
		results: map[string]any{
			strings.TrimSpace(neptuneLookupNodeQuery): []any{
				map[string]any{
					"node": map[string]any{
						"id":              "service:payments",
						"kind":            "service",
						"name":            "Payments",
						"tenant_id":       "tenant-a",
						"properties_json": `{"critical":true}`,
						"tags_json":       `{"env":"prod"}`,
						"findings_json":   `["finding-1"]`,
						"created_at":      "2026-03-20T12:00:00Z",
						"updated_at":      "2026-03-20T12:01:00Z",
						"version":         int64(2),
					},
				},
			},
			strings.TrimSpace(neptuneLookupEdgeQuery): []any{
				map[string]any{
					"edge": map[string]any{
						"id":              "edge:payments-db",
						"source":          "service:payments",
						"target":          "database:payments",
						"kind":            "calls",
						"effect":          "allow",
						"priority":        int64(50),
						"properties_json": `{"path":"/query"}`,
						"created_at":      "2026-03-20T12:02:00Z",
						"version":         int64(4),
					},
				},
			},
			strings.TrimSpace(neptuneCountNodesQuery): []any{
				map[string]any{"total": int64(2)},
			},
			strings.TrimSpace(neptuneCountEdgesQuery): []any{
				map[string]any{"total": int64(1)},
			},
			strings.TrimSpace(neptuneSnapshotNodesQuery): []any{
				map[string]any{"node": map[string]any{
					"id":         "service:payments",
					"kind":       "service",
					"name":       "Payments",
					"created_at": "2026-03-20T12:00:00Z",
					"updated_at": "2026-03-20T12:01:00Z",
					"version":    int64(2),
				}},
				map[string]any{"node": map[string]any{
					"id":         "database:payments",
					"kind":       "database",
					"name":       "Payments DB",
					"created_at": "2026-03-20T12:00:30Z",
					"updated_at": "2026-03-20T12:01:30Z",
					"version":    int64(1),
				}},
			},
			strings.TrimSpace(neptuneSnapshotEdgesQuery): []any{
				map[string]any{"edge": map[string]any{
					"id":         "edge:payments-db",
					"source":     "service:payments",
					"target":     "database:payments",
					"kind":       "calls",
					"effect":     "allow",
					"priority":   int64(50),
					"created_at": "2026-03-20T12:02:00Z",
					"version":    int64(4),
				}},
			},
		},
	}
	store := NewNeptuneGraphStore(exec)

	node, ok, err := store.LookupNode(context.Background(), "service:payments")
	if err != nil {
		t.Fatalf("LookupNode() error = %v", err)
	}
	if !ok || node == nil || node.Kind != NodeKindService {
		t.Fatalf("LookupNode() = (%#v, %v), want service node", node, ok)
	}
	if node.TenantID != "tenant-a" {
		t.Fatalf("LookupNode() tenant_id = %q, want tenant-a", node.TenantID)
	}

	edge, ok, err := store.LookupEdge(context.Background(), "edge:payments-db")
	if err != nil {
		t.Fatalf("LookupEdge() error = %v", err)
	}
	if !ok || edge == nil || edge.Target != "database:payments" {
		t.Fatalf("LookupEdge() = (%#v, %v), want database edge", edge, ok)
	}

	nodeCount, err := store.CountNodes(context.Background())
	if err != nil || nodeCount != 2 {
		t.Fatalf("CountNodes() = (%d, %v), want (2, nil)", nodeCount, err)
	}
	edgeCount, err := store.CountEdges(context.Background())
	if err != nil || edgeCount != 1 {
		t.Fatalf("CountEdges() = (%d, %v), want (1, nil)", edgeCount, err)
	}

	snapshot, err := store.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("Snapshot() error = %v", err)
	}
	if snapshot == nil || len(snapshot.Nodes) != 2 || len(snapshot.Edges) != 1 {
		t.Fatalf("Snapshot() = %#v, want 2 nodes and 1 edge", snapshot)
	}
}

func TestNeptuneGraphStoreSnapshotFiltersDeletedRecordsServerSide(t *testing.T) {
	expectedNodesQuery := strings.TrimSpace(neptuneSnapshotNodesQuery)
	expectedEdgesQuery := strings.TrimSpace(neptuneSnapshotEdgesQuery)

	exec := &fakeNeptuneExecutor{
		results: map[string]any{
			expectedNodesQuery: []any{
				map[string]any{"node": map[string]any{
					"id":         "service:payments",
					"kind":       "service",
					"name":       "Payments",
					"created_at": "2026-03-20T12:00:00Z",
					"updated_at": "2026-03-20T12:01:00Z",
					"version":    int64(2),
				}},
			},
			expectedEdgesQuery: []any{
				map[string]any{"edge": map[string]any{
					"id":         "edge:payments-db",
					"source":     "service:payments",
					"target":     "database:payments",
					"kind":       "calls",
					"effect":     "allow",
					"priority":   int64(50),
					"created_at": "2026-03-20T12:02:00Z",
					"version":    int64(4),
				}},
			},
		},
	}
	store := NewNeptuneGraphStore(exec)

	snapshot, err := store.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("Snapshot() error = %v", err)
	}
	if snapshot == nil || len(snapshot.Nodes) != 1 || len(snapshot.Edges) != 1 {
		t.Fatalf("Snapshot() = %#v, want 1 active node and 1 active edge", snapshot)
	}
	if len(exec.calls) != 2 {
		t.Fatalf("expected 2 Neptune calls, got %d", len(exec.calls))
	}
	if exec.calls[0].query != expectedNodesQuery {
		t.Fatalf("snapshot nodes query = %q", exec.calls[0].query)
	}
	if exec.calls[1].query != expectedEdgesQuery {
		t.Fatalf("snapshot edges query = %q", exec.calls[1].query)
	}
}

func TestNeptuneGraphStoreTraversalMethodsUseBoundedTraversalQueries(t *testing.T) {
	base := setupTestGraph()

	t.Run("blast radius", func(t *testing.T) {
		exec := newTraversalOnlyNeptuneExecutor(base)
		store := NewNeptuneGraphStore(exec)

		got, err := store.BlastRadius(context.Background(), "user:alice", 3)
		if err != nil {
			t.Fatalf("BlastRadius() error = %v", err)
		}
		want := BlastRadius(base, "user:alice", 3)

		assertNoSnapshotQueries(t, exec.calls)
		if got.PrincipalID != want.PrincipalID || got.TotalCount != want.TotalCount || got.CrossAccountRisk != want.CrossAccountRisk || got.AccountsReached != want.AccountsReached || !reflect.DeepEqual(got.RiskSummary, want.RiskSummary) {
			t.Fatalf("BlastRadius() = %#v, want %#v", got, want)
		}
		if !reflect.DeepEqual(sortedReachableNodeIDs(got.ReachableNodes), sortedReachableNodeIDs(want.ReachableNodes)) {
			t.Fatalf("BlastRadius() reachable nodes = %#v, want %#v", sortedReachableNodeIDs(got.ReachableNodes), sortedReachableNodeIDs(want.ReachableNodes))
		}
		if !reflect.DeepEqual(sortedStrings(got.ForeignAccounts), sortedStrings(want.ForeignAccounts)) {
			t.Fatalf("BlastRadius() foreign accounts = %#v, want %#v", got.ForeignAccounts, want.ForeignAccounts)
		}
	})

	t.Run("reverse access", func(t *testing.T) {
		exec := newTraversalOnlyNeptuneExecutor(base)
		store := NewNeptuneGraphStore(exec)

		got, err := store.ReverseAccess(context.Background(), "bucket:sensitive", 2)
		if err != nil {
			t.Fatalf("ReverseAccess() error = %v", err)
		}
		want := ReverseAccess(base, "bucket:sensitive", 2)

		assertNoSnapshotQueries(t, exec.calls)
		if got.ResourceID != want.ResourceID || got.TotalCount != want.TotalCount {
			t.Fatalf("ReverseAccess() = %#v, want %#v", got, want)
		}
		if !reflect.DeepEqual(sortedAccessorNodeIDs(got.AccessibleBy), sortedAccessorNodeIDs(want.AccessibleBy)) {
			t.Fatalf("ReverseAccess() accessors = %#v, want %#v", sortedAccessorNodeIDs(got.AccessibleBy), sortedAccessorNodeIDs(want.AccessibleBy))
		}
	})

	t.Run("effective access", func(t *testing.T) {
		exec := newTraversalOnlyNeptuneExecutor(base)
		store := NewNeptuneGraphStore(exec)

		got, err := store.EffectiveAccess(context.Background(), "user:alice", "db:production", 3)
		if err != nil {
			t.Fatalf("EffectiveAccess() error = %v", err)
		}
		want := EffectiveAccess(base, "user:alice", "db:production", 3)

		assertNoSnapshotQueries(t, exec.calls)
		if got.PrincipalID != want.PrincipalID || got.ResourceID != want.ResourceID || got.Allowed != want.Allowed {
			t.Fatalf("EffectiveAccess() = %#v, want %#v", got, want)
		}
		if !reflect.DeepEqual(sortedEdgeIDs(got.AllowedBy), sortedEdgeIDs(want.AllowedBy)) {
			t.Fatalf("EffectiveAccess() allowed_by = %#v, want %#v", sortedEdgeIDs(got.AllowedBy), sortedEdgeIDs(want.AllowedBy))
		}
		if !reflect.DeepEqual(sortedEdgeIDs(got.DeniedBy), sortedEdgeIDs(want.DeniedBy)) {
			t.Fatalf("EffectiveAccess() denied_by = %#v, want %#v", sortedEdgeIDs(got.DeniedBy), sortedEdgeIDs(want.DeniedBy))
		}
	})

	t.Run("cascading blast radius", func(t *testing.T) {
		exec := newTraversalOnlyNeptuneExecutor(base)
		store := NewNeptuneGraphStore(exec)

		got, err := store.CascadingBlastRadius(context.Background(), "user:alice", 3)
		if err != nil {
			t.Fatalf("CascadingBlastRadius() error = %v", err)
		}
		want := CascadingBlastRadius(base, "user:alice", 3)

		assertNoSnapshotQueries(t, exec.calls)
		if got.SourceID != want.SourceID || got.TotalImpact != want.TotalImpact || got.MaxCascadeDepth != want.MaxCascadeDepth || got.CriticalPathCount != want.CriticalPathCount {
			t.Fatalf("CascadingBlastRadius() = %#v, want %#v", got, want)
		}
		if !reflect.DeepEqual(sortedCompromisedNodeIDsByDepth(got.TimeToCompromise), sortedCompromisedNodeIDsByDepth(want.TimeToCompromise)) {
			t.Fatalf("CascadingBlastRadius() compromised nodes = %#v, want %#v", sortedCompromisedNodeIDsByDepth(got.TimeToCompromise), sortedCompromisedNodeIDsByDepth(want.TimeToCompromise))
		}
		if !reflect.DeepEqual(sortedBoundaryCrossings(got.AccountBoundaries), sortedBoundaryCrossings(want.AccountBoundaries)) {
			t.Fatalf("CascadingBlastRadius() boundaries = %#v, want %#v", sortedBoundaryCrossings(got.AccountBoundaries), sortedBoundaryCrossings(want.AccountBoundaries))
		}
	})

	t.Run("extract subgraph", func(t *testing.T) {
		exec := newTraversalOnlyNeptuneExecutor(base)
		store := NewNeptuneGraphStore(exec)

		got, err := store.ExtractSubgraph(context.Background(), "role:admin", ExtractSubgraphOptions{
			MaxDepth:  2,
			Direction: ExtractSubgraphDirectionBoth,
		})
		if err != nil {
			t.Fatalf("ExtractSubgraph() error = %v", err)
		}
		want := ExtractSubgraph(base, "role:admin", ExtractSubgraphOptions{
			MaxDepth:  2,
			Direction: ExtractSubgraphDirectionBoth,
		})

		assertNoSnapshotQueries(t, exec.calls)
		if !reflect.DeepEqual(sortedNodeIDs(got.GetAllNodes()), sortedNodeIDs(want.GetAllNodes())) {
			t.Fatalf("ExtractSubgraph() nodes = %#v, want %#v", sortedNodeIDs(got.GetAllNodes()), sortedNodeIDs(want.GetAllNodes()))
		}
		if !reflect.DeepEqual(sortedGraphEdgeIDs(got), sortedGraphEdgeIDs(want)) {
			t.Fatalf("ExtractSubgraph() edges = %#v, want %#v", sortedGraphEdgeIDs(got), sortedGraphEdgeIDs(want))
		}
	})
}

func TestNeptuneGraphStoreEnsureIndexesIsNoOp(t *testing.T) {
	exec := &fakeNeptuneExecutor{}
	store := NewNeptuneGraphStore(exec)

	if err := store.EnsureIndexes(context.Background()); err != nil {
		t.Fatalf("EnsureIndexes() error = %v", err)
	}

	if len(exec.calls) != 0 {
		t.Fatalf("EnsureIndexes() executed %d statements, want 0", len(exec.calls))
	}
}

func TestNeptuneGraphStoreUpsertEdgeProjectsTemporalFields(t *testing.T) {
	exec := &fakeNeptuneExecutor{
		handler: func(query string, params map[string]any) (any, error) {
			switch query {
			case strings.TrimSpace(neptuneLookupNodeQuery):
				id, _ := params["id"].(string)
				kind := NodeKindApplication
				if id == "database:payments" {
					kind = NodeKindDatabase
				}
				return []any{map[string]any{"node": map[string]any{
					"id":   id,
					"kind": string(kind),
					"name": id,
				}}}, nil
			case strings.TrimSpace(neptuneLookupOutEdgesQuery), strings.TrimSpace(neptuneLookupInEdgesQuery):
				return []any{}, nil
			}
			return nil, nil
		},
	}
	store := NewNeptuneGraphStore(exec)

	edge := &Edge{
		ID:        "edge:service-db",
		Source:    "service:payments",
		Target:    "database:payments",
		Kind:      EdgeKindCalls,
		Effect:    EdgeEffectAllow,
		CreatedAt: time.Date(2026, time.March, 1, 0, 0, 0, 0, time.UTC),
		Properties: map[string]any{
			"observed_at":      "2026-03-01T01:00:00Z",
			"valid_from":       "2026-03-01T02:00:00Z",
			"valid_to":         "2026-03-03T04:05:06Z",
			"expires_at":       "2026-03-04T05:06:07Z",
			"recorded_at":      "2026-03-01T06:07:08Z",
			"transaction_from": "2026-03-01T07:08:09Z",
			"transaction_to":   "2026-03-05T08:09:10Z",
		},
	}

	if err := store.UpsertEdge(context.Background(), edge); err != nil {
		t.Fatalf("UpsertEdge() error = %v", err)
	}

	call, ok := findNeptuneCall(exec.calls, strings.TrimSpace(neptuneUpsertEdgeQuery))
	if !ok {
		t.Fatalf("expected Neptune edge mutation query, got %#v", neptuneCallQueries(exec.calls))
	}
	for _, setter := range []string{
		"r.observed_at = $observed_at",
		"r.valid_from = $valid_from",
		"r.valid_to = $valid_to",
		"r.expires_at = $expires_at",
		"r.recorded_at = $recorded_at",
		"r.transaction_from = $transaction_from",
		"r.transaction_to = $transaction_to",
	} {
		if !strings.Contains(call.query, setter) {
			t.Fatalf("upsert query missing temporal setter %q:\n%s", setter, call.query)
		}
	}
	if got := call.params["observed_at"]; got != "2026-03-01T01:00:00Z" {
		t.Fatalf("observed_at param = %#v", got)
	}
	if got := call.params["valid_from"]; got != "2026-03-01T02:00:00Z" {
		t.Fatalf("valid_from param = %#v", got)
	}
	if got := call.params["valid_to"]; got != "2026-03-03T04:05:06Z" {
		t.Fatalf("valid_to param = %#v", got)
	}
	if got := call.params["expires_at"]; got != "2026-03-04T05:06:07Z" {
		t.Fatalf("expires_at param = %#v", got)
	}
	if got := call.params["recorded_at"]; got != "2026-03-01T06:07:08Z" {
		t.Fatalf("recorded_at param = %#v", got)
	}
	if got := call.params["transaction_from"]; got != "2026-03-01T07:08:09Z" {
		t.Fatalf("transaction_from param = %#v", got)
	}
	if got := call.params["transaction_to"]; got != "2026-03-05T08:09:10Z" {
		t.Fatalf("transaction_to param = %#v", got)
	}
}

func TestNeptuneGraphStoreTemporalQueriesUseBoundedTimeFilteredTraversal(t *testing.T) {
	base := newTemporalTraversalTestGraph()
	exec := newTemporalTraversalNeptuneExecutor(base)
	store := NewNeptuneGraphStore(exec)

	validAt := time.Date(2026, time.March, 2, 12, 0, 0, 0, time.UTC)
	recordedAt := time.Date(2026, time.March, 2, 12, 0, 0, 0, time.UTC)
	edges, err := store.LookupOutEdgesBitemporal(context.Background(), "service:payments", validAt, recordedAt)
	if err != nil {
		t.Fatalf("LookupOutEdgesBitemporal() error = %v", err)
	}
	if got := sortedEdgeIDs(edges); !reflect.DeepEqual(got, []string{"edge:current"}) {
		t.Fatalf("LookupOutEdgesBitemporal() = %#v, want current edge only", got)
	}

	view, err := store.ExtractSubgraphBetween(context.Background(), "service:payments", ExtractSubgraphOptions{
		MaxDepth:  1,
		Direction: ExtractSubgraphDirectionOutgoing,
	}, time.Date(2026, time.March, 3, 0, 0, 0, 0, time.UTC), time.Date(2026, time.March, 4, 23, 59, 59, 0, time.UTC))
	if err != nil {
		t.Fatalf("ExtractSubgraphBetween() error = %v", err)
	}

	assertNoSnapshotQueries(t, exec.calls)
	if got := sortedNodeIDs(view.GetAllNodes()); !reflect.DeepEqual(got, []string{"database:future", "database:late-recorded", "service:payments"}) {
		t.Fatalf("ExtractSubgraphBetween() nodes = %#v", got)
	}
	if got := sortedGraphEdgeIDs(view); !reflect.DeepEqual(got, []string{"edge:future", "edge:late-recorded"}) {
		t.Fatalf("ExtractSubgraphBetween() edges = %#v", got)
	}
}

func TestAnalyzeNeptuneExplainOutputParsesPlanHotspotsAndRecommendations(t *testing.T) {
	analysis, err := AnalyzeNeptuneExplainOutput([]byte(sampleNeptuneExplainOutput()), NeptuneExplainModeDetails)
	if err != nil {
		t.Fatalf("AnalyzeNeptuneExplainOutput() error = %v", err)
	}
	if analysis.Query != "MATCH (n:Service)-[:CALLS]->(m) RETURN n, m ORDER BY n.name" {
		t.Fatalf("analysis.Query = %q", analysis.Query)
	}
	if analysis.Mode != NeptuneExplainModeDetails {
		t.Fatalf("analysis.Mode = %q", analysis.Mode)
	}
	if got := len(analysis.Operators); got != 5 {
		t.Fatalf("len(analysis.Operators) = %d, want 5", got)
	}
	if got := len(analysis.PlanRoots); got != 1 || analysis.PlanRoots[0].ID != 0 {
		t.Fatalf("analysis.PlanRoots = %#v, want root operator 0", analysis.PlanRoots)
	}
	if got := analysis.PlanRoots[0].Children[0].Name; got != "DFEPipelineScan" {
		t.Fatalf("root child = %q, want DFEPipelineScan", got)
	}
	if analysis.TotalTimeMillis <= 0 {
		t.Fatalf("analysis.TotalTimeMillis = %f, want positive", analysis.TotalTimeMillis)
	}
	hotspots := hotspotOperatorsByID(analysis.Hotspots)
	for _, operatorID := range []int{1, 2, 3} {
		if _, ok := hotspots[operatorID]; !ok {
			t.Fatalf("expected hotspot for operator %d, got %#v", operatorID, analysis.Hotspots)
		}
	}
	if !containsStringWith(analysis.Recommendations, "selective MATCH/WHERE predicates") {
		t.Fatalf("missing scan recommendation in %#v", analysis.Recommendations)
	}
	if !containsStringWith(analysis.Recommendations, "Constrain relationship expansions and joins earlier") {
		t.Fatalf("missing join recommendation in %#v", analysis.Recommendations)
	}
	if !containsStringWith(analysis.Recommendations, "Push down filters, projections, or LIMIT") {
		t.Fatalf("missing blocking recommendation in %#v", analysis.Recommendations)
	}
}

func TestAnalyzeNeptuneExplainOutputRejectsMissingPlanTable(t *testing.T) {
	if _, err := AnalyzeNeptuneExplainOutput([]byte("Query:\nMATCH (n) RETURN n"), NeptuneExplainModeDynamic); err == nil {
		t.Fatal("expected error for explain output without a plan table")
	}
}

func TestNeptuneGraphStoreProfileQueryExecutesExplainEndpointAndReturnsAnalysis(t *testing.T) {
	exec := &fakeNeptuneExecutor{
		explainResults: map[string][]byte{
			fmt.Sprintf("%s|%s", NeptuneExplainModeDetails, "MATCH (n:Service)-[:CALLS]->(m) RETURN n, m ORDER BY n.name"): []byte(sampleNeptuneExplainOutput()),
		},
	}
	store := NewNeptuneGraphStore(exec)

	analysis, err := store.ProfileQuery(context.Background(), "MATCH (n:Service)-[:CALLS]->(m) RETURN n, m ORDER BY n.name", map[string]any{"tenant_id": "tenant-a"})
	if err != nil {
		t.Fatalf("ProfileQuery() error = %v", err)
	}
	if analysis == nil || len(analysis.Operators) != 5 {
		t.Fatalf("ProfileQuery() analysis = %#v", analysis)
	}
	if len(exec.explainCalls) != 1 {
		t.Fatalf("expected one explain call, got %d", len(exec.explainCalls))
	}
	call := exec.explainCalls[0]
	if call.mode != NeptuneExplainModeDetails {
		t.Fatalf("explain mode = %q, want %q", call.mode, NeptuneExplainModeDetails)
	}
	if call.query != "MATCH (n:Service)-[:CALLS]->(m) RETURN n, m ORDER BY n.name" {
		t.Fatalf("explain query = %q", call.query)
	}
	if got := call.params["tenant_id"]; got != "tenant-a" {
		t.Fatalf("explain params[tenant_id] = %#v", got)
	}
}

type traversalOnlyNeptuneExecutor struct {
	graph *Graph
	calls []fakeNeptuneCall
}

func newTraversalOnlyNeptuneExecutor(graph *Graph) *traversalOnlyNeptuneExecutor {
	return &traversalOnlyNeptuneExecutor{graph: graph}
}

func (f *traversalOnlyNeptuneExecutor) ExecuteOpenCypher(_ context.Context, query string, params map[string]any) (any, error) {
	trimmed := strings.TrimSpace(query)
	f.calls = append(f.calls, fakeNeptuneCall{query: trimmed, params: params})

	switch trimmed {
	case strings.TrimSpace(neptuneSnapshotNodesQuery), strings.TrimSpace(neptuneSnapshotEdgesQuery):
		return nil, fmt.Errorf("unexpected full snapshot query: %s", trimmed)
	}

	view, err := f.subgraphForQuery(trimmed, params)
	if err != nil {
		return nil, err
	}
	switch {
	case strings.Contains(trimmed, "UNWIND nodes(p) AS n"):
		return traversalNodeRows(view), nil
	case strings.Contains(trimmed, "UNWIND relationships(p) AS r"):
		return traversalEdgeRows(view), nil
	default:
		return nil, fmt.Errorf("unexpected traversal query: %s", trimmed)
	}
}

func (f *traversalOnlyNeptuneExecutor) subgraphForQuery(query string, params map[string]any) (*Graph, error) {
	rootID, _ := params["root_id"].(string)
	if strings.TrimSpace(rootID) == "" {
		return New(), nil
	}
	maxDepth, err := traversalDepthFromQuery(query)
	if err != nil {
		return nil, err
	}
	direction, err := traversalDirectionFromQuery(query)
	if err != nil {
		return nil, err
	}
	return ExtractSubgraph(f.graph, rootID, ExtractSubgraphOptions{
		MaxDepth:  maxDepth,
		Direction: direction,
	}), nil
}

func traversalNodeRows(g *Graph) []any {
	nodes := append([]*Node(nil), g.GetAllNodes()...)
	sort.Slice(nodes, func(i, j int) bool {
		return nodes[i].ID < nodes[j].ID
	})
	rows := make([]any, 0, len(nodes))
	for _, node := range nodes {
		rows = append(rows, map[string]any{"node": neptuneNodeRecordForTest(node)})
	}
	return rows
}

func traversalEdgeRows(g *Graph) []any {
	edges := make([]*Edge, 0)
	for _, edgeList := range g.GetAllEdges() {
		edges = append(edges, edgeList...)
	}
	sort.Slice(edges, func(i, j int) bool {
		return edges[i].ID < edges[j].ID
	})
	rows := make([]any, 0, len(edges))
	for _, edge := range edges {
		rows = append(rows, map[string]any{"edge": neptuneEdgeRecordForTest(edge)})
	}
	return rows
}

func neptuneNodeRecordForTest(node *Node) map[string]any {
	params := neptuneNodeParams(cloneNode(node))
	return map[string]any{
		"id":                       params["id"],
		"kind":                     params["kind"],
		"name":                     params["name"],
		"tenant_id":                params["tenant_id"],
		"provider":                 params["provider"],
		"account":                  params["account"],
		"region":                   params["region"],
		"properties_json":          params["properties_json"],
		"tags_json":                params["tags_json"],
		"risk":                     params["risk"],
		"findings_json":            params["findings_json"],
		"created_at":               params["created_at"],
		"updated_at":               params["updated_at"],
		"deleted_at":               params["deleted_at"],
		"version":                  params["version"],
		"previous_properties_json": params["previous_properties_json"],
		"property_history_json":    params["property_history_json"],
	}
}

func neptuneEdgeRecordForTest(edge *Edge) map[string]any {
	params := neptuneEdgeParams(cloneEdge(edge))
	return map[string]any{
		"id":              params["id"],
		"source":          params["source"],
		"target":          params["target"],
		"kind":            params["kind"],
		"effect":          params["effect"],
		"priority":        params["priority"],
		"properties_json": params["properties_json"],
		"risk":            params["risk"],
		"created_at":      params["created_at"],
		"deleted_at":      params["deleted_at"],
		"version":         params["version"],
	}
}

var traversalDepthPattern = regexp.MustCompile(`\*0\.\.(\d+)`)

func traversalDepthFromQuery(query string) (int, error) {
	matches := traversalDepthPattern.FindStringSubmatch(query)
	if len(matches) != 2 {
		return 0, fmt.Errorf("missing traversal depth in query: %s", query)
	}
	var depth int
	if _, err := fmt.Sscanf(matches[1], "%d", &depth); err != nil {
		return 0, fmt.Errorf("parse traversal depth %q: %w", matches[1], err)
	}
	return depth, nil
}

func traversalDirectionFromQuery(query string) (ExtractSubgraphDirection, error) {
	switch {
	case strings.Contains(query, "<-[:"+neptuneEdgeType+"*0.."):
		return ExtractSubgraphDirectionIncoming, nil
	case strings.Contains(query, "-[:"+neptuneEdgeType+"*0..") && strings.Contains(query, "]->"):
		return ExtractSubgraphDirectionOutgoing, nil
	case strings.Contains(query, "-[:"+neptuneEdgeType+"*0..") && strings.Contains(query, "]-("):
		return ExtractSubgraphDirectionBoth, nil
	default:
		return 0, fmt.Errorf("unknown traversal direction for query: %s", query)
	}
}

func assertNoSnapshotQueries(t *testing.T, calls []fakeNeptuneCall) {
	t.Helper()
	for _, call := range calls {
		if call.query == strings.TrimSpace(neptuneSnapshotNodesQuery) || call.query == strings.TrimSpace(neptuneSnapshotEdgesQuery) {
			t.Fatalf("unexpected snapshot query: %s", call.query)
		}
	}
}

type temporalTraversalNeptuneExecutor struct {
	graph *Graph
	calls []fakeNeptuneCall
}

func newTemporalTraversalNeptuneExecutor(graph *Graph) *temporalTraversalNeptuneExecutor {
	return &temporalTraversalNeptuneExecutor{graph: graph}
}

func (f *temporalTraversalNeptuneExecutor) ExecuteOpenCypher(_ context.Context, query string, params map[string]any) (any, error) {
	trimmed := strings.TrimSpace(query)
	f.calls = append(f.calls, fakeNeptuneCall{query: trimmed, params: params})

	switch trimmed {
	case strings.TrimSpace(neptuneSnapshotNodesQuery), strings.TrimSpace(neptuneSnapshotEdgesQuery):
		return nil, fmt.Errorf("unexpected full snapshot query: %s", trimmed)
	}

	switch {
	case strings.Contains(trimmed, "UNWIND nodes(p) AS n"):
		view, err := f.temporalSubgraphForQuery(trimmed, params)
		if err != nil {
			return nil, err
		}
		return traversalNodeRows(view), nil
	case strings.Contains(trimmed, "UNWIND relationships(p) AS r"):
		view, err := f.temporalSubgraphForQuery(trimmed, params)
		if err != nil {
			return nil, err
		}
		return traversalEdgeRows(view), nil
	case strings.Contains(trimmed, "AS edge"):
		edges, err := f.temporalEdgesForQuery(trimmed, params)
		if err != nil {
			return nil, err
		}
		rows := make([]any, 0, len(edges))
		for _, edge := range edges {
			rows = append(rows, map[string]any{"edge": neptuneEdgeRecordForTest(edge)})
		}
		return rows, nil
	default:
		return nil, fmt.Errorf("unexpected temporal Neptune query: %s", trimmed)
	}
}

func (f *temporalTraversalNeptuneExecutor) temporalSubgraphForQuery(query string, params map[string]any) (*Graph, error) {
	view, err := f.temporalViewForParams(params)
	if err != nil {
		return nil, err
	}
	rootID, _ := params["root_id"].(string)
	maxDepth, err := traversalDepthFromQuery(query)
	if err != nil {
		return nil, err
	}
	direction, err := traversalDirectionFromQuery(query)
	if err != nil {
		return nil, err
	}
	return ExtractSubgraph(view, rootID, ExtractSubgraphOptions{
		MaxDepth:  maxDepth,
		Direction: direction,
	}), nil
}

func (f *temporalTraversalNeptuneExecutor) temporalEdgesForQuery(query string, params map[string]any) ([]*Edge, error) {
	view, err := f.temporalViewForParams(params)
	if err != nil {
		return nil, err
	}
	nodeID, _ := params["node_id"].(string)
	if strings.Contains(query, "-[r:"+neptuneEdgeType+"]->(dst:"+neptuneNodeLabel+" {id: $node_id})") {
		return view.GetInEdges(nodeID), nil
	}
	return view.GetOutEdges(nodeID), nil
}

func (f *temporalTraversalNeptuneExecutor) temporalViewForParams(params map[string]any) (*Graph, error) {
	switch {
	case params["valid_at"] != nil || params["recorded_at"] != nil:
		validAt, err := timeParamFromTestValue(params["valid_at"])
		if err != nil {
			return nil, err
		}
		recordedAt, err := timeParamFromTestValue(params["recorded_at"])
		if err != nil {
			return nil, err
		}
		return f.graph.SubgraphBitemporal(validAt, recordedAt), nil
	case params["from"] != nil || params["to"] != nil:
		from, err := timeParamFromTestValue(params["from"])
		if err != nil {
			return nil, err
		}
		to, err := timeParamFromTestValue(params["to"])
		if err != nil {
			return nil, err
		}
		return f.graph.SubgraphBetween(from, to), nil
	default:
		return f.graph, nil
	}
}

func timeParamFromTestValue(value any) (time.Time, error) {
	switch typed := value.(type) {
	case nil:
		return time.Time{}, nil
	case time.Time:
		return typed.UTC(), nil
	case string:
		parsed := parseStoreTime(typed)
		if parsed.IsZero() {
			return time.Time{}, fmt.Errorf("parse time parameter %q", typed)
		}
		return parsed, nil
	default:
		return time.Time{}, fmt.Errorf("unsupported time parameter type %T", value)
	}
}

func newTemporalTraversalTestGraph() *Graph {
	g := New()
	for _, node := range []*Node{
		{
			ID:        "service:payments",
			Kind:      NodeKindService,
			Name:      "Payments",
			CreatedAt: time.Date(2026, time.March, 1, 0, 0, 0, 0, time.UTC),
		},
		{
			ID:        "database:current",
			Kind:      NodeKindDatabase,
			Name:      "Current",
			CreatedAt: time.Date(2026, time.March, 1, 0, 0, 0, 0, time.UTC),
		},
		{
			ID:        "database:future",
			Kind:      NodeKindDatabase,
			Name:      "Future",
			CreatedAt: time.Date(2026, time.March, 1, 0, 0, 0, 0, time.UTC),
		},
		{
			ID:        "database:late-recorded",
			Kind:      NodeKindDatabase,
			Name:      "Late Recorded",
			CreatedAt: time.Date(2026, time.March, 1, 0, 0, 0, 0, time.UTC),
		},
	} {
		g.AddNode(node)
	}
	for _, edge := range []*Edge{
		{
			ID:        "edge:current",
			Source:    "service:payments",
			Target:    "database:current",
			Kind:      EdgeKindCalls,
			Effect:    EdgeEffectAllow,
			CreatedAt: time.Date(2026, time.March, 1, 0, 0, 0, 0, time.UTC),
			Properties: map[string]any{
				"valid_from":       "2026-03-01T00:00:00Z",
				"valid_to":         "2026-03-02T23:59:59Z",
				"recorded_at":      "2026-03-01T00:00:00Z",
				"transaction_from": "2026-03-01T00:00:00Z",
			},
		},
		{
			ID:        "edge:future",
			Source:    "service:payments",
			Target:    "database:future",
			Kind:      EdgeKindCalls,
			Effect:    EdgeEffectAllow,
			CreatedAt: time.Date(2026, time.March, 1, 0, 0, 0, 0, time.UTC),
			Properties: map[string]any{
				"valid_from":       "2026-03-03T00:00:00Z",
				"valid_to":         "2026-03-04T23:59:59Z",
				"recorded_at":      "2026-03-01T00:00:00Z",
				"transaction_from": "2026-03-01T00:00:00Z",
			},
		},
		{
			ID:        "edge:late-recorded",
			Source:    "service:payments",
			Target:    "database:late-recorded",
			Kind:      EdgeKindCalls,
			Effect:    EdgeEffectAllow,
			CreatedAt: time.Date(2026, time.March, 1, 0, 0, 0, 0, time.UTC),
			Properties: map[string]any{
				"valid_from":       "2026-03-03T00:00:00Z",
				"valid_to":         "2026-03-04T23:59:59Z",
				"recorded_at":      "2026-03-05T00:00:00Z",
				"transaction_from": "2026-03-05T00:00:00Z",
			},
		},
	} {
		g.AddEdge(edge)
	}
	return g
}

func neptuneCallQueries(calls []fakeNeptuneCall) []string {
	out := make([]string, 0, len(calls))
	for _, call := range calls {
		out = append(out, call.query)
	}
	return out
}

func findNeptuneCall(calls []fakeNeptuneCall, query string) (fakeNeptuneCall, bool) {
	for _, call := range calls {
		if call.query == query {
			return call, true
		}
	}
	return fakeNeptuneCall{}, false
}

func containsSchemaIssueCode(issues []SchemaValidationIssue, code SchemaValidationIssueCode) bool {
	for _, issue := range issues {
		if issue.Code == code {
			return true
		}
	}
	return false
}

func sortedReachableNodeIDs(nodes []*ReachableNode) []string {
	values := make([]string, 0, len(nodes))
	for _, node := range nodes {
		if node != nil && node.Node != nil {
			values = append(values, node.Node.ID)
		}
	}
	return sortedStrings(values)
}

func sortedAccessorNodeIDs(nodes []*AccessorNode) []string {
	values := make([]string, 0, len(nodes))
	for _, node := range nodes {
		if node != nil && node.Node != nil {
			values = append(values, node.Node.ID)
		}
	}
	return sortedStrings(values)
}

func sortedEdgeIDs(edges []*Edge) []string {
	values := make([]string, 0, len(edges))
	for _, edge := range edges {
		if edge != nil && edge.ID != "" {
			values = append(values, edge.ID)
		}
	}
	return sortedStrings(values)
}

func sortedCompromisedNodeIDsByDepth(values map[int][]*CompromisedNode) map[int][]string {
	out := make(map[int][]string, len(values))
	for depth, nodes := range values {
		ids := make([]string, 0, len(nodes))
		for _, node := range nodes {
			if node != nil && node.Node != nil {
				ids = append(ids, node.Node.ID)
			}
		}
		out[depth] = sortedStrings(ids)
	}
	return out
}

func sortedBoundaryCrossings(values []*AccountBoundaryCross) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == nil {
			continue
		}
		out = append(out, fmt.Sprintf("%s>%s@%s:%d:%s", value.FromAccount, value.ToAccount, value.CrossingAt, value.Depth, value.EdgeKind))
	}
	return sortedStrings(out)
}

func sortedNodeIDs(nodes []*Node) []string {
	values := make([]string, 0, len(nodes))
	for _, node := range nodes {
		if node != nil && node.ID != "" {
			values = append(values, node.ID)
		}
	}
	return sortedStrings(values)
}

func sortedGraphEdgeIDs(g *Graph) []string {
	values := make([]string, 0)
	for _, edgeList := range g.GetAllEdges() {
		for _, edge := range edgeList {
			if edge != nil && edge.ID != "" {
				values = append(values, edge.ID)
			}
		}
	}
	return sortedStrings(values)
}

func sortedStrings(values []string) []string {
	out := append([]string(nil), values...)
	sort.Strings(out)
	return out
}

func hotspotOperatorsByID(hotspots []NeptuneQueryHotspot) map[int]NeptuneQueryHotspot {
	out := make(map[int]NeptuneQueryHotspot, len(hotspots))
	for _, hotspot := range hotspots {
		out[hotspot.OperatorID] = hotspot
	}
	return out
}

func containsStringWith(values []string, fragment string) bool {
	for _, value := range values {
		if strings.Contains(value, fragment) {
			return true
		}
	}
	return false
}

func sampleNeptuneExplainOutput() string {
	return strings.TrimSpace(`
Query:
MATCH (n:Service)-[:CALLS]->(m) RETURN n, m ORDER BY n.name
╔════╤═══════╤═══════╤═══════════════════╤══════════════════════╤═════════════════════╤══════════╤═══════════╤═══════╤═══════════╗
║ ID │ Out #1│ Out #2│ Name              │ Arguments            │ Mode                │ Units In │ Units Out │ Ratio │ Time (ms) ║
╠════╪═══════╪═══════╪═══════════════════╪══════════════════════╪═════════════════════╪══════════╪═══════════╪═══════╪═══════════╣
║ 0  │ 1     │ -     │ SolutionInjection │ -                    │ -                   │ 0        │ 1         │ -     │ 0.02      ║
║ 1  │ 2     │ -     │ DFEPipelineScan   │ (n:Service)          │ -                   │ 1        │ 1500      │ 1500  │ 12.50     ║
║ 2  │ 3     │ -     │ DFEPipelineJoin   │ [:CALLS]             │ -                   │ 1500     │ 22000     │ 14.67 │ 35.00     ║
║ 3  │ 4     │ -     │ DFESort           │ n.name               │ -                   │ 22000    │ 22000     │ 1     │ 14.00     ║
║ 4  │ -     │ -     │ TermResolution    │ -                    │ id2value_opencypher │ 22000    │ 22000     │ 1     │ 4.50      ║
╚════╧═══════╧═══════╧═══════════════════╧══════════════════════╧═════════════════════╧══════════╧═══════════╧═══════╧═══════════╝`)
}
