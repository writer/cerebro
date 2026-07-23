package organizationalgraph

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/ports"
	cerebrourn "github.com/writer/cerebro/internal/urn"
)

type queryStoreStub struct {
	neighborhood *ports.EntityNeighborhood
	err          error
}

type assertionQueryStoreStub struct {
	queryStoreStub
	coverageTenant    string
	coverageRelations []string
	migrationRequest  ports.ProjectionAssertionMigrationRequest
}

func (s queryStoreStub) Ping(context.Context) error { return s.err }

func (s queryStoreStub) GetEntityNeighborhood(context.Context, string, int) (*ports.EntityNeighborhood, error) {
	return s.neighborhood, nil
}

func (s queryStoreStub) ExecuteReadCypher(context.Context, ports.CypherQueryRequest) ([]ports.CypherRow, error) {
	return []ports.CypherRow{{Values: map[string]any{"authority": "go"}}}, nil
}

func (s *assertionQueryStoreStub) CountProjectedLinksMissingAssertions(_ context.Context, tenantID string, relations []string) (uint32, error) {
	s.coverageTenant = tenantID
	s.coverageRelations = append([]string(nil), relations...)
	return 7, nil
}

func (s *assertionQueryStoreStub) MigrateProjectedLinkAssertions(_ context.Context, request ports.ProjectionAssertionMigrationRequest) (ports.ProjectionAssertionMigrationResult, error) {
	s.migrationRequest = request
	return ports.ProjectionAssertionMigrationResult{LinksMatched: 7, LinksMigrated: 6, LinksQuarantined: 1}, nil
}

func TestQueryStoreReturnsRustNeighborhoodAndDelegatesRawCypher(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/graph/expand" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		var request expandRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if request.TenantID != "tenant-a" || request.RootKey != "urn:cerebro:tenant-a:runtime_file:asset-1" || request.Depth != 1 {
			t.Fatalf("request = %#v", request)
		}
		_ = json.NewEncoder(w).Encode(rustNeighborhood{
			TenantID: "tenant-a",
			Root: rustEntity{
				EntityID: "entity-1", AgentKey: "urn:cerebro:tenant-a:runtime_file:asset-1",
				EntityKind: "resource", Label: "One",
			},
			Entities: []rustEntity{{
				EntityID:   "entity-2",
				AgentKey:   "urn:cerebro:tenant-a:repository:asset-2",
				EntityKind: "repository",
				Label:      "Two",
				Properties: map[string]string{"resource_urn": "urn:cerebro:tenant-a:repository:asset-2"},
			}},
			Edges: []rustEdge{{
				From:            "entity-1",
				Relation:        "contains",
				To:              "entity-2",
				SourceRuntimeID: "box-prod",
			}},
		})
	}))
	defer server.Close()

	rootURN := "urn:cerebro:tenant-a:runtime_file:asset-1"
	store, err := NewQueryStore(queryStoreStub{}, server.URL, time.Second)
	if err != nil {
		t.Fatalf("NewQueryStore() error = %v", err)
	}
	got, err := store.GetEntityNeighborhood(context.Background(), rootURN, 10)
	if err != nil {
		t.Fatalf("GetEntityNeighborhood() error = %v", err)
	}
	if got.Root == nil || got.Root.URN != rootURN || got.Root.Label != "One" {
		t.Fatalf("root = %#v", got.Root)
	}
	if len(got.Neighbors) != 1 || got.Neighbors[0].URN != "urn:cerebro:tenant-a:repository:asset-2" {
		t.Fatalf("neighbors = %#v", got.Neighbors)
	}
	if len(got.Relations) != 1 || got.Relations[0].FromURN != rootURN || got.Relations[0].Attributes["source_runtime_id"] != "box-prod" {
		t.Fatalf("relations = %#v", got.Relations)
	}

	rows, err := store.ExecuteReadCypher(context.Background(), ports.CypherQueryRequest{Query: "RETURN 1"})
	if err != nil || len(rows) != 1 || rows[0].Values["authority"] != "go" {
		t.Fatalf("ExecuteReadCypher() = %#v, %v", rows, err)
	}
}

func TestQueryStoreFailsClosedWhenRustIsUnavailable(t *testing.T) {
	store, err := NewQueryStore(queryStoreStub{}, "http://127.0.0.1:1", 10*time.Millisecond)
	if err != nil {
		t.Fatalf("NewQueryStore() error = %v", err)
	}
	_, err = store.GetEntityNeighborhood(context.Background(), "urn:cerebro:tenant-a:runtime_file:asset-1", 10)
	if err == nil {
		t.Fatal("GetEntityNeighborhood() error = nil")
	}
	if errors.Is(err, ports.ErrGraphEntityNotFound) {
		t.Fatalf("GetEntityNeighborhood() error = %v, want unavailable", err)
	}
}

func TestQueryStoreHealthRequiresCompatibilityAndRustAuthorities(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.Path != "/healthz" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	store, err := NewQueryStore(queryStoreStub{}, server.URL, time.Second)
	if err != nil {
		t.Fatalf("NewQueryStore() error = %v", err)
	}
	if err := store.Ping(context.Background()); err != nil {
		t.Fatalf("Ping() error = %v", err)
	}
	if requests != 1 {
		t.Fatalf("health requests = %d, want 1", requests)
	}

	store, err = NewQueryStore(
		queryStoreStub{err: errors.New("compatibility unavailable")},
		server.URL,
		time.Second,
	)
	if err != nil {
		t.Fatalf("NewQueryStore(failing compatibility) error = %v", err)
	}
	if err := store.Ping(context.Background()); err == nil {
		t.Fatal("Ping(failing compatibility) error = nil")
	}
	if requests != 1 {
		t.Fatalf("health requests after compatibility failure = %d, want 1", requests)
	}

	compatibility := queryStoreStub{}
	if got := ReadinessStore(compatibility, nil); got != compatibility {
		t.Fatalf("ReadinessStore(compatibility, nil) = %#v", got)
	}
	if got := ReadinessStore(compatibility, store); got != store {
		t.Fatalf("ReadinessStore(compatibility, authority) = %#v", got)
	}
}

func TestQueryStorePreservesProjectionAssertionCapabilities(t *testing.T) {
	compatibility := &assertionQueryStoreStub{}
	store, err := NewQueryStore(compatibility, "http://127.0.0.1:1", time.Second)
	if err != nil {
		t.Fatalf("NewQueryStore() error = %v", err)
	}
	missing, err := store.CountProjectedLinksMissingAssertions(context.Background(), "tenant-a", []string{"owns", "runs_in"})
	if err != nil || missing != 7 {
		t.Fatalf("CountProjectedLinksMissingAssertions() = %d, %v", missing, err)
	}
	if compatibility.coverageTenant != "tenant-a" || len(compatibility.coverageRelations) != 2 {
		t.Fatalf("coverage delegation = %q, %#v", compatibility.coverageTenant, compatibility.coverageRelations)
	}
	request := ports.ProjectionAssertionMigrationRequest{
		TenantID:  "tenant-a",
		Relations: []string{"owns"},
		Limit:     100,
		DryRun:    true,
	}
	result, err := store.MigrateProjectedLinkAssertions(context.Background(), request)
	if err != nil || result.LinksMatched != 7 || result.LinksMigrated != 6 || result.LinksQuarantined != 1 {
		t.Fatalf("MigrateProjectedLinkAssertions() = %#v, %v", result, err)
	}
	if compatibility.migrationRequest.TenantID != request.TenantID || !compatibility.migrationRequest.DryRun {
		t.Fatalf("migration delegation = %#v", compatibility.migrationRequest)
	}
}

func TestQueryStoreFailsClosedWithoutProjectionAssertionCapabilities(t *testing.T) {
	store, err := NewQueryStore(queryStoreStub{}, "http://127.0.0.1:1", time.Second)
	if err != nil {
		t.Fatalf("NewQueryStore() error = %v", err)
	}
	if _, err := store.CountProjectedLinksMissingAssertions(context.Background(), "tenant-a", nil); err == nil {
		t.Fatal("CountProjectedLinksMissingAssertions() error = nil")
	}
	if _, err := store.MigrateProjectedLinkAssertions(context.Background(), ports.ProjectionAssertionMigrationRequest{TenantID: "tenant-a"}); err == nil {
		t.Fatal("MigrateProjectedLinkAssertions() error = nil")
	}
}

func TestQueryStoreBatchesTenantRootsInOneRustRequest(t *testing.T) {
	rootOne := "urn:cerebro:tenant-a:runtime_file:asset-1"
	rootTwo := "urn:cerebro:tenant-a:runtime_file:asset-2"
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.Path != "/v1/graph/expand-batch" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		var request expandBatchRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if request.TenantID != "tenant-a" || len(request.RootKeys) != 2 {
			t.Fatalf("request = %#v", request)
		}
		_ = json.NewEncoder(w).Encode(expandBatchResponse{Neighborhoods: map[string]rustNeighborhood{
			rootOne: {
				TenantID: "tenant-a",
				Root: rustEntity{
					EntityID: "entity-1", AgentKey: rootOne, EntityKind: "resource", Label: "One",
				},
			},
			rootTwo: {
				TenantID: "tenant-a",
				Root: rustEntity{
					EntityID: "entity-2", AgentKey: rootTwo, EntityKind: "resource", Label: "Two",
				},
			},
		}})
	}))
	defer server.Close()

	store, err := NewQueryStore(queryStoreStub{}, server.URL, time.Second)
	if err != nil {
		t.Fatalf("NewQueryStore() error = %v", err)
	}
	got, err := store.GetEntityNeighborhoods(context.Background(), []string{rootOne, rootTwo, rootOne}, 10)
	if err != nil {
		t.Fatalf("GetEntityNeighborhoods() error = %v", err)
	}
	if requests != 1 || len(got) != 2 || got[rootOne].Root.URN != rootOne || got[rootTwo].Root.URN != rootTwo {
		t.Fatalf("requests = %d, neighborhoods = %#v", requests, got)
	}
}

func TestQueryStoreRejectsUnrequestedBatchRoot(t *testing.T) {
	rootURN := "urn:cerebro:tenant-a:runtime_file:asset-1"
	extraURN := "urn:cerebro:tenant-a:runtime_file:asset-2"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(expandBatchResponse{Neighborhoods: map[string]rustNeighborhood{
			extraURN: {
				TenantID: "tenant-a",
				Root: rustEntity{
					EntityID: "entity-2", AgentKey: extraURN, EntityKind: "resource", Label: "Two",
				},
			},
		}})
	}))
	defer server.Close()

	store, err := NewQueryStore(queryStoreStub{}, server.URL, time.Second)
	if err != nil {
		t.Fatalf("NewQueryStore() error = %v", err)
	}
	if _, err := store.GetEntityNeighborhoods(context.Background(), []string{rootURN}, 10); err == nil {
		t.Fatal("GetEntityNeighborhoods() error = nil")
	}
}

func TestQueryStoreAgainstLiveRustGraph(t *testing.T) {
	baseURL := os.Getenv("CEREBRO_TEST_ORGANIZATIONAL_GRAPH_URL")
	rootURN := os.Getenv("CEREBRO_TEST_ORGANIZATIONAL_GRAPH_ROOT")
	if baseURL == "" || rootURN == "" {
		t.Skip("requires a disposable live Rust organizational graph")
	}
	store, err := NewQueryStore(queryStoreStub{}, baseURL, 5*time.Second)
	if err != nil {
		t.Fatalf("NewQueryStore() error = %v", err)
	}
	if err := store.Ping(context.Background()); err != nil {
		t.Fatalf("Ping() error = %v", err)
	}
	got, err := store.GetEntityNeighborhood(context.Background(), rootURN, 10)
	if err != nil {
		t.Fatalf("GetEntityNeighborhood() error = %v", err)
	}
	if got.Root == nil || got.Root.URN != rootURN {
		t.Fatalf("root = %#v", got.Root)
	}
	for _, node := range got.Neighbors {
		if node == nil || cerebrourn.TenantID(node.URN) != cerebrourn.TenantID(rootURN) {
			t.Fatalf("neighbor is not round-trippable: %#v", node)
		}
	}
}
