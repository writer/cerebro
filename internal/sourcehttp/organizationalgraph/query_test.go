package organizationalgraph

import (
	"context"
	"errors"
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

type rawCypherOnlyStub struct {
	rows []ports.CypherRow
}

type assertionQueryStoreStub struct {
	queryStoreStub
	coverageTenant    string
	coverageRelations []string
	migrationRequest  ports.ProjectionAssertionMigrationRequest
}

type graphServiceStub struct {
	cerebrographv1connect.UnimplementedOrganizationalGraphServiceHandler
	expand            func(context.Context, *connect.Request[cerebrographv1.ExpandRequest]) (*connect.Response[cerebrographv1.ExpandResponse], error)
	expandBatch       func(context.Context, *connect.Request[cerebrographv1.ExpandBatchRequest]) (*connect.Response[cerebrographv1.ExpandBatchResponse], error)
	listEntities      func(context.Context, *connect.Request[cerebrographv1.ListEntitiesRequest]) (*connect.Response[cerebrographv1.ListEntitiesResponse], error)
	countRelations    func(context.Context, *connect.Request[cerebrographv1.CountRelationsRequest]) (*connect.Response[cerebrographv1.CountRelationsResponse], error)
	personAccess      func(context.Context, *connect.Request[cerebrographv1.ListPersonAccessPathsRequest]) (*connect.Response[cerebrographv1.ListPersonAccessPathsResponse], error)
	vendorRegister    func(context.Context, *connect.Request[cerebrographv1.ListVendorRegisterRequest]) (*connect.Response[cerebrographv1.ListVendorRegisterResponse], error)
	vendorDiscoveries func(context.Context, *connect.Request[cerebrographv1.ListVendorDiscoveriesRequest]) (*connect.Response[cerebrographv1.ListVendorDiscoveriesResponse], error)
}

func (s graphServiceStub) ListEntities(ctx context.Context, request *connect.Request[cerebrographv1.ListEntitiesRequest]) (*connect.Response[cerebrographv1.ListEntitiesResponse], error) {
	return s.listEntities(ctx, request)
}

func (s graphServiceStub) Expand(ctx context.Context, request *connect.Request[cerebrographv1.ExpandRequest]) (*connect.Response[cerebrographv1.ExpandResponse], error) {
	return s.expand(ctx, request)
}

func (s graphServiceStub) ExpandBatch(ctx context.Context, request *connect.Request[cerebrographv1.ExpandBatchRequest]) (*connect.Response[cerebrographv1.ExpandBatchResponse], error) {
	return s.expandBatch(ctx, request)
}

func (s graphServiceStub) CountRelations(ctx context.Context, request *connect.Request[cerebrographv1.CountRelationsRequest]) (*connect.Response[cerebrographv1.CountRelationsResponse], error) {
	return s.countRelations(ctx, request)
}

func (s graphServiceStub) ListPersonAccessPaths(ctx context.Context, request *connect.Request[cerebrographv1.ListPersonAccessPathsRequest]) (*connect.Response[cerebrographv1.ListPersonAccessPathsResponse], error) {
	return s.personAccess(ctx, request)
}

func (s graphServiceStub) ListVendorDiscoveries(ctx context.Context, request *connect.Request[cerebrographv1.ListVendorDiscoveriesRequest]) (*connect.Response[cerebrographv1.ListVendorDiscoveriesResponse], error) {
	return s.vendorDiscoveries(ctx, request)
}

func (s graphServiceStub) ListVendorRegister(ctx context.Context, request *connect.Request[cerebrographv1.ListVendorRegisterRequest]) (*connect.Response[cerebrographv1.ListVendorRegisterResponse], error) {
	return s.vendorRegister(ctx, request)
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

func (s rawCypherOnlyStub) Ping(context.Context) error { return nil }

func (s rawCypherOnlyStub) ExecuteReadCypher(context.Context, ports.CypherQueryRequest) ([]ports.CypherRow, error) {
	return s.rows, nil
}

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

func TestProductExposureCoverageEnforcesTenantBoundsAndCompleteness(t *testing.T) {
	entity := func(tenant, kind, id string) *cerebrographv1.GraphEntity {
		return &cerebrographv1.GraphEntity{AgentKey: "urn:cerebro:" + tenant + ":" + strings.ReplaceAll(kind, ".", "_") + ":" + id, EntityKind: kind, Label: id}
	}
	valid := func() *cerebrographv1.CompareExposureCoverageResponse {
		return &cerebrographv1.CompareExposureCoverageResponse{
			TenantId: "tenant-a", GraphRevision: 17,
			Counts:       &cerebrographv1.ExposureCoverageCounts{PrimaryEntities: 3},
			Completeness: &cerebrographv1.ExposureCoverageCompleteness{OverlapsTruncated: true},
			Overlaps: []*cerebrographv1.ExposureCoverageOverlap{{
				Primary: entity("tenant-a", "aws.load.balancer", "alb"), Indicator: entity("tenant-a", "internet.host", "app"), Corroborating: entity("tenant-a", "external.asset", "app"),
			}},
		}
	}

	result, err := productExposureCoverage("tenant-a", 1, valid())
	if err != nil {
		t.Fatalf("productExposureCoverage() error = %v", err)
	}
	if result.GraphRevision != 17 || result.Counts.PrimaryEntities != 3 || !result.Completeness.OverlapsTruncated || len(result.Overlaps) != 1 {
		t.Fatalf("result = %#v", result)
	}

	for name, mutate := range map[string]func(*cerebrographv1.CompareExposureCoverageResponse){
		"omitted completeness": func(response *cerebrographv1.CompareExposureCoverageResponse) { response.Completeness = nil },
		"wrong tenant":         func(response *cerebrographv1.CompareExposureCoverageResponse) { response.TenantId = "tenant-b" },
		"cross tenant entity": func(response *cerebrographv1.CompareExposureCoverageResponse) {
			response.Overlaps[0].Indicator = entity("tenant-b", "internet.host", "app")
		},
		"over bound": func(response *cerebrographv1.CompareExposureCoverageResponse) {
			response.Overlaps = append(response.Overlaps, response.Overlaps[0])
		},
	} {
		t.Run(name, func(t *testing.T) {
			response := valid()
			mutate(response)
			if _, err := productExposureCoverage("tenant-a", 1, response); err == nil {
				t.Fatal("productExposureCoverage() error = nil, want fail-closed rejection")
			}
		})
	}
}

func TestQueryStoreVendorDiscoveriesPreservesRustAuthorityAndVisibleFields(t *testing.T) {
	server := newGraphTestServer(t, graphServiceStub{
		vendorDiscoveries: func(_ context.Context, request *connect.Request[cerebrographv1.ListVendorDiscoveriesRequest]) (*connect.Response[cerebrographv1.ListVendorDiscoveriesResponse], error) {
			if request.Header().Get(tenantAuthHeader) != "tenant-a" || request.Msg.GetFilter().GetTenantId() != "tenant-a" || request.Msg.GetFilter().GetSourceStatus() != "discovered" || request.Msg.GetLimit() != 25 {
				t.Fatalf("vendor discovery authority or bounds missing: headers=%v request=%#v", request.Header(), request.Msg)
			}
			return connect.NewResponse(&cerebrographv1.ListVendorDiscoveriesResponse{
				TenantId: "tenant-a", GraphRevision: 23, DataAuthority: "rust_graph", GeneratedAt: "2026-08-24T00:00:00Z",
				Discoveries:     []*cerebrographv1.VendorDiscoveryRow{{Urn: "urn:cerebro:tenant-a:vendor_discovery:grc:acme", DiscoveryId: "acme", Name: "Acme", SourceId: "grc", RuntimeId: "grc-prod", Provider: "grc", SourceStatus: "discovered", DecisionState: "discovered", SourceIds: []string{"grc"}, ConfidenceScore: 0.91, DiscoveryReason: "Observed in the provider account", FirstObservedAt: "2026-08-20T00:00:00Z", LastObservedAt: "2026-08-24T00:00:00Z", Signals: []*cerebrographv1.VendorDiscoverySignal{{Id: "signal-1", Label: "Provider account", SourceId: "grc", EntityUrn: "urn:cerebro:tenant-a:vendor_discovery:grc:acme", ConfidenceScore: 0.91}}}},
				Summary:         &cerebrographv1.VendorDiscoverySummary{TotalDiscoveries: 1, Discovered: 1, SourceCount: 1, EvidenceSignals: 1},
				SourceSummaries: []*cerebrographv1.VendorDiscoverySourceSummary{{SourceId: "grc", Provider: "grc", RuntimeId: "grc-prod", Status: "ready", Total: 1, Discovered: 1}},
			}), nil
		},
	})
	defer server.Close()
	store, err := NewQueryStore(nil, server.URL, testSharedSecret, time.Second)
	if err != nil {
		t.Fatalf("NewQueryStore() error = %v", err)
	}
	page, err := store.ListVendorDiscoveries(context.Background(), ports.VendorDiscoveryFilter{TenantID: "tenant-a", SourceStatus: "discovered", Limit: 25})
	if err != nil {
		t.Fatalf("ListVendorDiscoveries() error = %v", err)
	}
	if page.GraphRevision != 23 || page.DataAuthority != "rust_graph" || page.Summary.EvidenceSignals != 1 || len(page.SourceSummaries) != 1 || len(page.Discoveries) != 1 || len(page.Discoveries[0].Signals) != 1 {
		t.Fatalf("page = %#v", page)
	}
}

func TestQueryStoreEntityCatalogPreservesTenantSearchAndRelationCountContract(t *testing.T) {
	server := newGraphTestServer(t, graphServiceStub{
		listEntities: func(_ context.Context, request *connect.Request[cerebrographv1.ListEntitiesRequest]) (*connect.Response[cerebrographv1.ListEntitiesResponse], error) {
			if request.Header().Get(tenantAuthHeader) != "tenant-a" || request.Msg.GetFilter().GetTenantId() != "tenant-a" || request.Msg.GetFilter().GetApplicationWorkspaceId() != "workspace-a" {
				t.Fatalf("tenant authority missing: headers=%v request=%#v", request.Header(), request.Msg)
			}
			if request.Msg.GetFilter().GetQueryAttributes() {
				t.Fatal("attribute search widened without caller opt-in")
			}
			counts := request.Msg.GetFilter().GetRelationCounts()
			if counts == nil || len(counts.GetDirections()) != 1 || counts.GetRelations()[0] != "associated_with" || counts.GetNeighborKinds()[0] != "contract" {
				t.Fatalf("relation count filter = %#v", counts)
			}
			return connect.NewResponse(&cerebrographv1.ListEntitiesResponse{TenantId: "tenant-a", GraphRevision: 9, Entities: []*cerebrographv1.GraphEntity{{AgentKey: "urn:cerebro:tenant-a:vendor:one", EntityKind: "vendor", Label: "One"}}, RelationCounts: []*cerebrographv1.EntityRelationCount{{AgentKey: "urn:cerebro:tenant-a:vendor:one", Direction: cerebrographv1.EntityRelationDirection_ENTITY_RELATION_DIRECTION_INCOMING, Relation: "associated_with", NeighborKind: "contract", Count: 2}}}), nil
		},
		countRelations: func(_ context.Context, request *connect.Request[cerebrographv1.CountRelationsRequest]) (*connect.Response[cerebrographv1.CountRelationsResponse], error) {
			if request.Header().Get(tenantAuthHeader) != "tenant-a" || request.Msg.GetTenantId() != "tenant-a" || request.Msg.GetLimit() != 10 {
				t.Fatalf("relation count request missing tenant/bounds: headers=%v request=%#v", request.Header(), request.Msg)
			}
			return connect.NewResponse(&cerebrographv1.CountRelationsResponse{TenantId: "tenant-a", GraphRevision: 9, Counts: []*cerebrographv1.RelationCount{{Relation: "has_finding", Count: 4}}}), nil
		},
		personAccess: func(_ context.Context, request *connect.Request[cerebrographv1.ListPersonAccessPathsRequest]) (*connect.Response[cerebrographv1.ListPersonAccessPathsResponse], error) {
			if request.Header().Get(tenantAuthHeader) != "tenant-a" || request.Msg.GetTenantId() != "tenant-a" || request.Msg.GetLimit() != 10 || request.Msg.GetMaxDepth() != 3 {
				t.Fatalf("person access request missing tenant/bounds: headers=%v request=%#v", request.Header(), request.Msg)
			}
			entity := func(kind, urn, label string) *cerebrographv1.GraphEntity {
				return &cerebrographv1.GraphEntity{AgentKey: urn, EntityKind: kind, Label: label}
			}
			return connect.NewResponse(&cerebrographv1.ListPersonAccessPathsResponse{
				TenantId:      "tenant-a",
				GraphRevision: 9,
				Paths: []*cerebrographv1.PersonAccessPath{{
					Person:        entity("person", "urn:cerebro:tenant-a:person:one", "One"),
					Identity:      entity("identity.email", "urn:cerebro:tenant-a:identity:one", "one@example.com"),
					Principal:     entity("okta.user", "urn:cerebro:tenant-a:okta_user:one", "One"),
					AccessTarget:  entity("aws.role", "urn:cerebro:tenant-a:aws_role:reader", "Reader"),
					RelationChain: []string{"assigned_to"},
				}},
			}), nil
		},
	})
	defer server.Close()
	store, err := NewQueryStore(queryStoreStub{}, server.URL, testSharedSecret, time.Second)
	if err != nil {
		t.Fatalf("NewQueryStore() error = %v", err)
	}
	page, err := store.ListEntities(context.Background(), ports.EntityCatalogPageRequest{Filter: ports.EntityCatalogFilter{TenantID: "tenant-a", ApplicationWorkspaceID: " workspace-a ", IncludeKinds: []string{"vendor"}, Query: "one", RelationCounts: &ports.EntityRelationCountFilter{Directions: []ports.EntityRelationDirection{ports.EntityRelationIncoming}, Relations: []string{"associated_with"}, NeighborKinds: []string{"contract"}}}, Limit: 10})
	if err != nil {
		t.Fatalf("ListEntities() error = %v", err)
	}
	if page.GraphRevision != 9 || len(page.Entities) != 1 || len(page.RelationCounts) != 1 || page.RelationCounts[0].Count != 2 {
		t.Fatalf("page = %#v", page)
	}
	relations, err := store.CountRelations(context.Background(), ports.RelationCountRequest{TenantID: "tenant-a", Limit: 10})
	if err != nil {
		t.Fatalf("CountRelations() error = %v", err)
	}
	if relations.GraphRevision != 9 || len(relations.Counts) != 1 || relations.Counts[0].Relation != "has_finding" || relations.Counts[0].Count != 4 {
		t.Fatalf("relations = %#v", relations)
	}
	access, err := store.ListPersonAccessPaths(context.Background(), ports.PersonAccessPathRequest{TenantID: "tenant-a", PersonQuery: "One", Limit: 10, Depth: 3})
	if err != nil {
		t.Fatalf("ListPersonAccessPaths() error = %v", err)
	}
	if access.GraphRevision != 9 || len(access.Paths) != 1 || access.Paths[0].AccessTarget.EntityType != "aws.role" {
		t.Fatalf("access = %#v", access)
	}
}

func TestQueryStoreVendorRegisterForwardsApplicationWorkspace(t *testing.T) {
	server := newGraphTestServer(t, graphServiceStub{
		vendorRegister: func(_ context.Context, request *connect.Request[cerebrographv1.ListVendorRegisterRequest]) (*connect.Response[cerebrographv1.ListVendorRegisterResponse], error) {
			filter := request.Msg.GetFilter()
			if request.Header().Get(tenantAuthHeader) != "tenant-a" || filter.GetTenantId() != "tenant-a" || filter.GetApplicationWorkspaceId() != "workspace-a" || request.Msg.GetLimit() != 25 {
				t.Fatalf("vendor register scope or bounds missing: headers=%v request=%#v", request.Header(), request.Msg)
			}
			return connect.NewResponse(&cerebrographv1.ListVendorRegisterResponse{
				TenantId: "tenant-a", DataAuthority: "rust_graph", Summary: &cerebrographv1.VendorRegisterSummary{},
			}), nil
		},
	})
	defer server.Close()
	store, err := NewQueryStore(nil, server.URL, testSharedSecret, time.Second)
	if err != nil {
		t.Fatalf("NewQueryStore() error = %v", err)
	}
	page, err := store.ListVendorRegister(context.Background(), ports.VendorRegisterFilter{TenantID: "tenant-a", ApplicationWorkspaceID: " workspace-a ", Limit: 25})
	if err != nil {
		t.Fatalf("ListVendorRegister() error = %v", err)
	}
	if page.TenantID != "tenant-a" || page.DataAuthority != "rust_graph" {
		t.Fatalf("page = %#v", page)
	}
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

func TestAuthorityKeepsRawCypherWithoutGoTypedReads(t *testing.T) {
	server := newGraphTestServer(t, graphServiceStub{
		expand: func(_ context.Context, request *connect.Request[cerebrographv1.ExpandRequest]) (*connect.Response[cerebrographv1.ExpandResponse], error) {
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

	raw := rawCypherOnlyStub{rows: []ports.CypherRow{{Values: map[string]any{"compatibility": "go"}}}}
	store, err := NewConfiguredQueryStoreWithCompatibility(
		raw,
		server.URL,
		testSharedSecret,
		time.Second,
		"authority",
	)
	if err != nil {
		t.Fatalf("NewConfiguredQueryStoreWithCompatibility() error = %v", err)
	}
	root := "urn:cerebro:tenant-a:resource:one"
	neighborhood, err := store.GetEntityNeighborhood(context.Background(), root, 10)
	if err != nil {
		t.Fatalf("GetEntityNeighborhood() error = %v", err)
	}
	if neighborhood.Root == nil || neighborhood.Root.URN != root || neighborhood.Root.Label != "Rust" {
		t.Fatalf("GetEntityNeighborhood() = %#v", neighborhood)
	}
	rows, err := store.ExecuteReadCypher(context.Background(), ports.CypherQueryRequest{Query: "RETURN 1"})
	if err != nil || len(rows) != 1 || rows[0].Values["compatibility"] != "go" {
		t.Fatalf("ExecuteReadCypher() = %#v, %v", rows, err)
	}

	if _, err := NewConfiguredQueryStoreWithCompatibility(
		raw,
		server.URL,
		testSharedSecret,
		time.Second,
		"legacy",
	); err == nil {
		t.Fatal("legacy mode error = nil")
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

func TestConfiguredQueryStoreRejectsRemovedReadModes(t *testing.T) {
	for _, mode := range []string{"legacy", "shadow", "canary"} {
		t.Run(mode, func(t *testing.T) {
			if _, err := NewConfiguredQueryStore(queryStoreStub{}, "http://127.0.0.1:1", testSharedSecret, time.Second, mode); err == nil {
				t.Fatalf("NewConfiguredQueryStore(%s) error = nil", mode)
			}
			if _, err := NewConfiguredQueryStoreWithCompatibility(queryStoreStub{}, "http://127.0.0.1:1", testSharedSecret, time.Second, mode); err == nil {
				t.Fatalf("NewConfiguredQueryStoreWithCompatibility(%s) error = nil", mode)
			}
		})
	}
}

func TestAuthorityHealthRequiresOnlyRust(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.Path != "/readyz" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	store, err := NewQueryStore(queryStoreStub{}, server.URL, testSharedSecret, 5*time.Second)
	if err != nil {
		t.Fatalf("NewQueryStore() error = %v", err)
	}
	if err := store.Ping(context.Background()); err != nil {
		t.Fatalf("Ping() error = %v", err)
	}
	if requests != 1 {
		t.Fatalf("health requests = %d, want 1", requests)
	}

	strictStore, err := NewQueryStore(nil, server.URL, testSharedSecret, 5*time.Second)
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
	if err := store.Ping(context.Background()); err != nil {
		t.Fatalf("Ping(failing compatibility) error = %v, Rust authority must not depend on Go health", err)
	}
	if requests != 3 {
		t.Fatalf("health requests after compatibility failure = %d, want 3", requests)
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

func TestAuthorityReportsUnavailableRustRuntime(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	store, err := NewQueryStore(nil, server.URL, testSharedSecret, time.Second)
	if err != nil {
		t.Fatalf("NewQueryStore() error = %v", err)
	}
	if _, err := store.GetEntityNeighborhood(context.Background(), "urn:cerebro:tenant-a:resource:one", 10); !errors.Is(err, ports.ErrGraphRuntimeUnavailable) {
		t.Fatalf("GetEntityNeighborhood() error = %v, want %v", err, ports.ErrGraphRuntimeUnavailable)
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

func TestQueryStoreRejectsIncompleteBatchResponse(t *testing.T) {
	rootOne := "urn:cerebro:tenant-a:runtime_file:asset-1"
	rootTwo := "urn:cerebro:tenant-a:runtime_file:asset-2"
	server := newGraphTestServer(t, graphServiceStub{
		expandBatch: func(_ context.Context, request *connect.Request[cerebrographv1.ExpandBatchRequest]) (*connect.Response[cerebrographv1.ExpandBatchResponse], error) {
			return connect.NewResponse(&cerebrographv1.ExpandBatchResponse{
				Neighborhoods: map[string]*cerebrographv1.ExpandResponse{
					rootOne: {
						TenantId: request.Msg.GetTenantId(),
						Root: &cerebrographv1.GraphEntity{
							EntityId:   "root-1",
							AgentKey:   rootOne,
							EntityKind: "resource",
						},
					},
				},
			}), nil
		},
	})
	defer server.Close()

	store, err := NewQueryStore(queryStoreStub{}, server.URL, testSharedSecret, time.Second)
	if err != nil {
		t.Fatalf("NewQueryStore() error = %v", err)
	}
	if _, err := store.GetEntityNeighborhoods(context.Background(), []string{rootOne, rootTwo}, 10); !errors.Is(err, errRustGraphOmittedRoot) {
		t.Fatalf("GetEntityNeighborhoods() error = %v, want omitted-root rejection", err)
	}
}

func TestProductNeighborhoodRejectsAmbiguousRustIdentity(t *testing.T) {
	root := "urn:cerebro:tenant-a:runtime_file:asset-1"
	tests := []struct {
		name     string
		root     *cerebrographv1.GraphEntity
		entities []*cerebrographv1.GraphEntity
		want     error
	}{
		{
			name: "different root",
			root: &cerebrographv1.GraphEntity{
				EntityId: "root-1",
				AgentKey: "urn:cerebro:tenant-a:runtime_file:other",
			},
			want: errRustGraphDifferentRoot,
		},
		{
			name: "missing root ID",
			root: &cerebrographv1.GraphEntity{
				AgentKey: root,
			},
			want: errRustGraphMissingRootID,
		},
		{
			name: "duplicate entity ID",
			root: &cerebrographv1.GraphEntity{
				EntityId: "same-id",
				AgentKey: root,
			},
			entities: []*cerebrographv1.GraphEntity{{
				EntityId: "same-id",
				AgentKey: "urn:cerebro:tenant-a:repository:repo-1",
			}},
			want: errRustGraphDuplicateEntityID,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := productNeighborhood(root, &cerebrographv1.ExpandResponse{
				TenantId: "tenant-a",
				Root:     test.root,
				Entities: test.entities,
			})
			if !errors.Is(err, test.want) {
				t.Fatalf("productNeighborhood() error = %v, want %v", err, test.want)
			}
		})
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
