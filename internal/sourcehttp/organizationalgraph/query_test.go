package organizationalgraph

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	cerebrographv1 "github.com/writer/cerebro/gen/cerebro/graph/v1"
	"github.com/writer/cerebro/gen/cerebro/graph/v1/cerebrographv1connect"
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

type graphServiceStub struct {
	cerebrographv1connect.UnimplementedOrganizationalGraphServiceHandler
	expand      func(context.Context, *connect.Request[cerebrographv1.ExpandRequest]) (*connect.Response[cerebrographv1.ExpandResponse], error)
	expandBatch func(context.Context, *connect.Request[cerebrographv1.ExpandBatchRequest]) (*connect.Response[cerebrographv1.ExpandBatchResponse], error)
}

func (s graphServiceStub) Expand(ctx context.Context, request *connect.Request[cerebrographv1.ExpandRequest]) (*connect.Response[cerebrographv1.ExpandResponse], error) {
	return s.expand(ctx, request)
}

func (s graphServiceStub) ExpandBatch(ctx context.Context, request *connect.Request[cerebrographv1.ExpandBatchRequest]) (*connect.Response[cerebrographv1.ExpandBatchResponse], error) {
	return s.expandBatch(ctx, request)
}

func newGraphTestServer(t *testing.T, service graphServiceStub) *httptest.Server {
	t.Helper()
	path, handler := cerebrographv1connect.NewOrganizationalGraphServiceHandler(service)
	mux := http.NewServeMux()
	mux.Handle(path, handler)
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	return httptest.NewServer(mux)
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
	server := newGraphTestServer(t, graphServiceStub{
		expand: func(_ context.Context, request *connect.Request[cerebrographv1.ExpandRequest]) (*connect.Response[cerebrographv1.ExpandResponse], error) {
			if request.Header().Get(tenantAuthHeader) != "tenant-a" || !strings.HasPrefix(request.Header().Get("Authorization"), "Bearer ") {
				t.Fatalf("tenant authentication headers are missing")
			}
			if request.Msg.GetTenantId() != "tenant-a" || request.Msg.GetRootKey() != "urn:cerebro:tenant-a:runtime_file:asset-1" || request.Msg.GetDepth() != 1 {
				t.Fatalf("request = %#v", request.Msg)
			}
			return connect.NewResponse(&cerebrographv1.ExpandResponse{
				TenantId: "tenant-a",
				Root: &cerebrographv1.GraphEntity{
					EntityId: "entity-1", AgentKey: "urn:cerebro:tenant-a:runtime_file:asset-1",
					EntityKind: "resource", Label: "One",
				},
				Entities: []*cerebrographv1.GraphEntity{{
					EntityId:   "entity-2",
					AgentKey:   "urn:cerebro:tenant-a:repository:asset-2",
					EntityKind: "repository",
					Label:      "Two",
					Properties: map[string]string{"resource_urn": "urn:cerebro:tenant-a:repository:asset-2"},
				}},
				Edges: []*cerebrographv1.GraphEdge{
					{
						AssertionId:     "assertion-1",
						FromEntityId:    "entity-1",
						Relation:        "contains",
						ToEntityId:      "entity-2",
						SourceRuntimeId: "box-prod",
					},
					{
						AssertionId:     "assertion-2",
						FromEntityId:    "entity-1",
						Relation:        "contains",
						ToEntityId:      "entity-2",
						SourceRuntimeId: "box-prod",
					},
				},
			}), nil
		},
	})
	defer server.Close()

	rootURN := "urn:cerebro:tenant-a:runtime_file:asset-1"
	store, err := NewQueryStore(queryStoreStub{}, server.URL, testSharedSecret, time.Second)
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
	store, err := NewQueryStore(queryStoreStub{}, "http://127.0.0.1:1", testSharedSecret, 10*time.Millisecond)
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

func TestShadowQueryStoreReturnsLegacyWhenRustIsUnavailable(t *testing.T) {
	rootURN := "urn:cerebro:tenant-a:runtime_file:asset-1"
	legacy := &ports.EntityNeighborhood{
		Root: &ports.NeighborhoodNode{URN: rootURN, Label: "Legacy"},
	}
	store, err := NewShadowQueryStore(
		queryStoreStub{neighborhood: legacy},
		"http://127.0.0.1:1",
		testSharedSecret,
		10*time.Millisecond,
		100,
	)
	if err != nil {
		t.Fatalf("NewShadowQueryStore() error = %v", err)
	}
	got, err := store.GetEntityNeighborhood(context.Background(), rootURN, 10)
	if err != nil {
		t.Fatalf("GetEntityNeighborhood() error = %v", err)
	}
	if got != legacy {
		t.Fatalf("GetEntityNeighborhood() = %#v, want legacy response", got)
	}
	if err := store.Ping(context.Background()); err != nil {
		t.Fatalf("Ping() error = %v, shadow readiness must use legacy authority", err)
	}
}

func TestShadowQueryStoreRequiresCompatibilityAndBoundedSampling(t *testing.T) {
	if _, err := NewShadowQueryStore(nil, "http://127.0.0.1:1", testSharedSecret, time.Second, 100); err == nil {
		t.Fatal("NewShadowQueryStore(nil) error = nil")
	}
	if _, err := NewShadowQueryStore(queryStoreStub{}, "http://127.0.0.1:1", testSharedSecret, time.Second, 0); err == nil {
		t.Fatal("NewShadowQueryStore(0%) error = nil")
	}
	if _, err := NewShadowQueryStore(queryStoreStub{}, "http://127.0.0.1:1", testSharedSecret, time.Second, 101); err == nil {
		t.Fatal("NewShadowQueryStore(101%) error = nil")
	}
}

func TestCanaryQueryStoreUsesStableSingleAuthorityAndFailsClosed(t *testing.T) {
	requests := 0
	server := newGraphTestServer(t, graphServiceStub{
		expand: func(_ context.Context, request *connect.Request[cerebrographv1.ExpandRequest]) (*connect.Response[cerebrographv1.ExpandResponse], error) {
			requests++
			return connect.NewResponse(&cerebrographv1.ExpandResponse{
				TenantId: request.Msg.GetTenantId(),
				Root: &cerebrographv1.GraphEntity{
					EntityId:   "rust-root",
					AgentKey:   request.Msg.GetRootKey(),
					EntityKind: "resource",
					Label:      "Rust",
				},
			}), nil
		},
	})
	defer server.Close()

	legacy := &ports.EntityNeighborhood{
		Root: &ports.NeighborhoodNode{URN: "legacy", Label: "Legacy"},
	}
	store, err := NewCanaryQueryStore(
		queryStoreStub{neighborhood: legacy},
		server.URL,
		testSharedSecret,
		time.Second,
		50,
	)
	if err != nil {
		t.Fatalf("NewCanaryQueryStore() error = %v", err)
	}
	rustRoot := canaryRoot(t, store, true)
	legacyRoot := canaryRoot(t, store, false)

	rust, err := store.GetEntityNeighborhood(context.Background(), rustRoot, 10)
	if err != nil {
		t.Fatalf("GetEntityNeighborhood(Rust) error = %v", err)
	}
	if rust.Root == nil || rust.Root.Label != "Rust" || requests != 1 {
		t.Fatalf("Rust response = %#v, requests = %d", rust, requests)
	}
	secondRustRoot := strings.Replace(rustRoot, ":asset", ":asset-2", 1)
	if _, err := store.GetEntityNeighborhood(context.Background(), secondRustRoot, 10); err != nil {
		t.Fatalf("GetEntityNeighborhood(second Rust root) error = %v", err)
	}
	if requests != 2 {
		t.Fatalf("same Rust tenant changed authority, requests = %d", requests)
	}
	gotLegacy, err := store.GetEntityNeighborhood(context.Background(), legacyRoot, 10)
	if err != nil {
		t.Fatalf("GetEntityNeighborhood(legacy) error = %v", err)
	}
	if gotLegacy != legacy || requests != 2 {
		t.Fatalf("legacy response = %#v, requests = %d", gotLegacy, requests)
	}
	if _, err := store.GetEntityNeighborhoods(
		context.Background(),
		[]string{rustRoot, legacyRoot},
		10,
	); err == nil {
		t.Fatal("mixed-tenant canary batch error = nil")
	}

	failing, err := NewCanaryQueryStore(
		queryStoreStub{neighborhood: legacy},
		"http://127.0.0.1:1",
		testSharedSecret,
		10*time.Millisecond,
		50,
	)
	if err != nil {
		t.Fatalf("NewCanaryQueryStore(failing) error = %v", err)
	}
	if _, err := failing.GetEntityNeighborhood(
		context.Background(),
		canaryRoot(t, failing, true),
		10,
	); err == nil {
		t.Fatal("sampled Rust failure fell back to Go")
	}
}

func TestCanaryQueryStoreRequiresCompatibilityAndBoundedSampling(t *testing.T) {
	if _, err := NewCanaryQueryStore(nil, "http://127.0.0.1:1", testSharedSecret, time.Second, 10); err == nil {
		t.Fatal("NewCanaryQueryStore(nil) error = nil")
	}
	for _, percent := range []int{0, 100, 101} {
		if _, err := NewCanaryQueryStore(queryStoreStub{}, "http://127.0.0.1:1", testSharedSecret, time.Second, percent); err == nil {
			t.Fatalf("NewCanaryQueryStore(%d) error = nil", percent)
		}
	}
}

func TestCanaryQueryStoreReadinessUsesCompatibilityAuthority(t *testing.T) {
	store, err := NewCanaryQueryStore(
		queryStoreStub{},
		"http://127.0.0.1:1",
		testSharedSecret,
		10*time.Millisecond,
		50,
	)
	if err != nil {
		t.Fatalf("NewCanaryQueryStore() error = %v", err)
	}
	if err := store.Ping(context.Background()); err != nil {
		t.Fatalf("Ping() error = %v, canary readiness must keep the compatibility cohort available", err)
	}

	store, err = NewCanaryQueryStore(
		queryStoreStub{err: errors.New("compatibility unavailable")},
		"http://127.0.0.1:1",
		testSharedSecret,
		10*time.Millisecond,
		50,
	)
	if err != nil {
		t.Fatalf("NewCanaryQueryStore(failing compatibility) error = %v", err)
	}
	if err := store.Ping(context.Background()); err == nil {
		t.Fatal("Ping(failing compatibility) error = nil")
	}
}

func canaryRoot(t *testing.T, store *QueryStore, wantRust bool) string {
	t.Helper()
	for index := 0; index < 10_000; index++ {
		tenantID := fmt.Sprintf("tenant-%d", index)
		root := fmt.Sprintf("urn:cerebro:%s:runtime_file:asset", tenantID)
		if store.sample(tenantID) == wantRust {
			return root
		}
	}
	t.Fatalf("no canary root found for wantRust=%t", wantRust)
	return ""
}

func TestQueryStoreHealthRequiresRustAndChecksCompatibilityWhenPresent(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.Path != "/readyz" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	store, err := NewQueryStore(queryStoreStub{}, server.URL, testSharedSecret, time.Second)
	if err != nil {
		t.Fatalf("NewQueryStore() error = %v", err)
	}
	if err := store.Ping(context.Background()); err != nil {
		t.Fatalf("Ping() error = %v", err)
	}
	if requests != 1 {
		t.Fatalf("health requests = %d, want 1", requests)
	}

	strictStore, err := NewQueryStore(nil, server.URL, testSharedSecret, time.Second)
	if err != nil {
		t.Fatalf("NewQueryStore(strict) error = %v", err)
	}
	if err := strictStore.Ping(context.Background()); err != nil {
		t.Fatalf("Ping(strict) error = %v", err)
	}
	if requests != 2 {
		t.Fatalf("health requests after strict ping = %d, want 2", requests)
	}

	store, err = NewQueryStore(
		queryStoreStub{err: errors.New("compatibility unavailable")},
		server.URL,
		testSharedSecret,
		time.Second,
	)
	if err != nil {
		t.Fatalf("NewQueryStore(failing compatibility) error = %v", err)
	}
	if err := store.Ping(context.Background()); err == nil {
		t.Fatal("Ping(failing compatibility) error = nil")
	}
	if requests != 2 {
		t.Fatalf("health requests after compatibility failure = %d, want 2", requests)
	}

	compatibility := queryStoreStub{}
	if got := ReadinessStore(compatibility, nil); got != compatibility {
		t.Fatalf("ReadinessStore(compatibility, nil) = %#v", got)
	}
	if got := ReadinessStore(compatibility, store); got != store {
		t.Fatalf("ReadinessStore(compatibility, authority) = %#v", got)
	}
}

func TestQueryStoreStrictReplacementRejectsUntypedCompatibilityCalls(t *testing.T) {
	store, err := NewQueryStore(nil, "http://127.0.0.1:1", testSharedSecret, time.Second)
	if err != nil {
		t.Fatalf("NewQueryStore() error = %v", err)
	}
	if _, err := store.ExecuteReadCypher(context.Background(), ports.CypherQueryRequest{Query: "RETURN 1"}); !errors.Is(err, ports.ErrGraphTypedOperationRequired) {
		t.Fatalf("ExecuteReadCypher() error = %v", err)
	}
	if _, err := store.CountProjectedLinksMissingAssertions(context.Background(), "tenant-a", nil); !errors.Is(err, ports.ErrGraphTypedOperationRequired) {
		t.Fatalf("CountProjectedLinksMissingAssertions() error = %v", err)
	}
	if _, err := store.MigrateProjectedLinkAssertions(context.Background(), ports.ProjectionAssertionMigrationRequest{TenantID: "tenant-a"}); !errors.Is(err, ports.ErrGraphTypedOperationRequired) {
		t.Fatalf("MigrateProjectedLinkAssertions() error = %v", err)
	}
}

func TestQueryStorePreservesProjectionAssertionCapabilities(t *testing.T) {
	compatibility := &assertionQueryStoreStub{}
	store, err := NewQueryStore(compatibility, "http://127.0.0.1:1", testSharedSecret, time.Second)
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
	store, err := NewQueryStore(queryStoreStub{}, "http://127.0.0.1:1", testSharedSecret, time.Second)
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
	server := newGraphTestServer(t, graphServiceStub{
		expandBatch: func(_ context.Context, request *connect.Request[cerebrographv1.ExpandBatchRequest]) (*connect.Response[cerebrographv1.ExpandBatchResponse], error) {
			requests++
			if request.Msg.GetTenantId() != "tenant-a" || len(request.Msg.GetRootKeys()) != 2 {
				t.Fatalf("request = %#v", request.Msg)
			}
			return connect.NewResponse(&cerebrographv1.ExpandBatchResponse{Neighborhoods: map[string]*cerebrographv1.ExpandResponse{
				rootOne: {
					TenantId: "tenant-a",
					Root: &cerebrographv1.GraphEntity{
						EntityId: "entity-1", AgentKey: rootOne, EntityKind: "resource", Label: "One",
					},
				},
				rootTwo: {
					TenantId: "tenant-a",
					Root: &cerebrographv1.GraphEntity{
						EntityId: "entity-2", AgentKey: rootTwo, EntityKind: "resource", Label: "Two",
					},
				},
			}}), nil
		},
	})
	defer server.Close()

	store, err := NewQueryStore(queryStoreStub{}, server.URL, testSharedSecret, time.Second)
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
	server := newGraphTestServer(t, graphServiceStub{
		expandBatch: func(_ context.Context, _ *connect.Request[cerebrographv1.ExpandBatchRequest]) (*connect.Response[cerebrographv1.ExpandBatchResponse], error) {
			return connect.NewResponse(&cerebrographv1.ExpandBatchResponse{Neighborhoods: map[string]*cerebrographv1.ExpandResponse{
				extraURN: {
					TenantId: "tenant-a",
					Root: &cerebrographv1.GraphEntity{
						EntityId: "entity-2", AgentKey: extraURN, EntityKind: "resource", Label: "Two",
					},
				},
			}}), nil
		},
	})
	defer server.Close()

	store, err := NewQueryStore(queryStoreStub{}, server.URL, testSharedSecret, time.Second)
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
	sharedSecret := os.Getenv("CEREBRO_TEST_ORGANIZATIONAL_GRAPH_SHARED_SECRET")
	if sharedSecret == "" {
		sharedSecret = testSharedSecret
	}
	store, err := NewQueryStore(nil, baseURL, sharedSecret, 5*time.Second)
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
	relationKeys := make(map[string]struct{}, len(got.Relations))
	for _, relation := range got.Relations {
		key := relation.FromURN + "\x00" + relation.Relation + "\x00" + relation.ToURN
		if _, exists := relationKeys[key]; exists {
			t.Fatalf("duplicate product relation: %#v", relation)
		}
		relationKeys[key] = struct{}{}
	}
	if _, err := store.ExecuteReadCypher(context.Background(), ports.CypherQueryRequest{Query: "RETURN 1"}); !errors.Is(err, ports.ErrGraphTypedOperationRequired) {
		t.Fatalf("ExecuteReadCypher() error = %v", err)
	}
}
