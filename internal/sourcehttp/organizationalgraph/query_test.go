package organizationalgraph

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
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

type countingQueryStoreStub struct {
	queryStoreStub
	requests atomic.Int64
	mu       sync.RWMutex
}

type blockingQueryStoreStub struct {
	queryStoreStub
	started chan struct{}
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

func (s rawCypherOnlyStub) Ping(context.Context) error { return nil }

func (s rawCypherOnlyStub) ExecuteReadCypher(context.Context, ports.CypherQueryRequest) ([]ports.CypherRow, error) {
	return s.rows, nil
}

func (s queryStoreStub) GetEntityNeighborhood(context.Context, string, int) (*ports.EntityNeighborhood, error) {
	return s.neighborhood, nil
}

func (s *countingQueryStoreStub) GetEntityNeighborhood(context.Context, string, int) (*ports.EntityNeighborhood, error) {
	s.requests.Add(1)
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.neighborhood, s.err
}

func (s *countingQueryStoreStub) requestCount() int {
	return int(s.requests.Load())
}

func (s *countingQueryStoreStub) setError(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.err = err
}

func (s *blockingQueryStoreStub) GetEntityNeighborhood(ctx context.Context, _ string, _ int) (*ports.EntityNeighborhood, error) {
	select {
	case s.started <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return nil, ctx.Err()
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
		nil,
		raw,
		server.URL,
		testSharedSecret,
		time.Second,
		"authority",
		0,
		0,
		0,
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
		nil,
		raw,
		server.URL,
		testSharedSecret,
		time.Second,
		"legacy",
		0,
		0,
		0,
	); err == nil {
		t.Fatal("legacy mode without Go typed reads error = nil")
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

func TestShadowComparisonDoesNotDelayLegacyResponse(t *testing.T) {
	rustStarted := make(chan struct{}, 1)
	rustCanceled := make(chan struct{}, 1)
	server := newGraphTestServer(t, graphServiceStub{
		expand: func(ctx context.Context, _ *connect.Request[cerebrographv1.ExpandRequest]) (*connect.Response[cerebrographv1.ExpandResponse], error) {
			rustStarted <- struct{}{}
			<-ctx.Done()
			rustCanceled <- struct{}{}
			return nil, connect.NewError(connect.CodeCanceled, ctx.Err())
		},
	})
	defer server.Close()

	legacy := &ports.EntityNeighborhood{Root: &ports.NeighborhoodNode{URN: "legacy"}}
	store, err := NewShadowQueryStore(
		queryStoreStub{neighborhood: legacy},
		server.URL,
		testSharedSecret,
		500*time.Millisecond,
		100,
	)
	if err != nil {
		t.Fatalf("NewShadowQueryStore() error = %v", err)
	}

	started := time.Now()
	got, err := store.GetEntityNeighborhood(
		context.Background(),
		"urn:cerebro:tenant-a:runtime_file:asset-1",
		10,
	)
	if err != nil {
		t.Fatalf("GetEntityNeighborhood() error = %v", err)
	}
	if got != legacy {
		t.Fatalf("GetEntityNeighborhood() = %#v, want legacy", got)
	}
	if elapsed := time.Since(started); elapsed >= 250*time.Millisecond {
		t.Fatalf("legacy response waited %s for a 500ms Rust timeout", elapsed)
	}
	select {
	case <-rustStarted:
	case <-time.After(time.Second):
		t.Fatal("background Rust comparison did not start")
	}
	select {
	case <-rustCanceled:
	case <-time.After(time.Second):
		t.Fatal("background Rust comparison did not respect its timeout")
	}
}

func TestShadowComparisonConcurrencyIsBounded(t *testing.T) {
	server := newGraphTestServer(t, graphServiceStub{
		expand: func(ctx context.Context, _ *connect.Request[cerebrographv1.ExpandRequest]) (*connect.Response[cerebrographv1.ExpandResponse], error) {
			<-ctx.Done()
			return nil, connect.NewError(connect.CodeCanceled, ctx.Err())
		},
	})
	defer server.Close()

	store, err := NewShadowQueryStore(
		queryStoreStub{neighborhood: &ports.EntityNeighborhood{}},
		server.URL,
		testSharedSecret,
		time.Second,
		100,
	)
	if err != nil {
		t.Fatalf("NewShadowQueryStore() error = %v", err)
	}

	started := time.Now()
	for index := 0; index < maxConcurrentComparisons+64; index++ {
		root := fmt.Sprintf("urn:cerebro:tenant-a:runtime_file:asset-%d", index)
		if _, err := store.GetEntityNeighborhood(context.Background(), root, 10); err != nil {
			t.Fatalf("GetEntityNeighborhood(%d) error = %v", index, err)
		}
	}
	if elapsed := time.Since(started); elapsed >= 500*time.Millisecond {
		t.Fatalf("bounded shadow scheduling delayed legacy traffic by %s", elapsed)
	}
	if got := len(store.comparisons); got != maxConcurrentComparisons {
		t.Fatalf("in-flight comparisons = %d, want %d", got, maxConcurrentComparisons)
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

func TestCanaryQueryStoreRoutesConfiguredTrafficPercentages(t *testing.T) {
	rustRequests := 0
	server := newGraphTestServer(t, graphServiceStub{
		expand: func(_ context.Context, request *connect.Request[cerebrographv1.ExpandRequest]) (*connect.Response[cerebrographv1.ExpandResponse], error) {
			rustRequests++
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

	const tenants = 1_000
	for _, percent := range []int{1, 10, 25, 50, 99} {
		t.Run(fmt.Sprintf("%d-percent", percent), func(t *testing.T) {
			rustRequests = 0
			legacy := &countingQueryStoreStub{queryStoreStub: queryStoreStub{
				neighborhood: &ports.EntityNeighborhood{
					Root: &ports.NeighborhoodNode{URN: "legacy", Label: "Go"},
				},
			}}
			store, err := NewCanaryQueryStore(legacy, server.URL, testSharedSecret, time.Second, percent)
			if err != nil {
				t.Fatalf("NewCanaryQueryStore() error = %v", err)
			}

			expectedRust := 0
			for index := 0; index < tenants; index++ {
				tenantID := fmt.Sprintf("traffic-tenant-%d", index)
				root := fmt.Sprintf("urn:cerebro:%s:runtime_file:asset", tenantID)
				wantRust := store.sample(tenantID)
				if wantRust {
					expectedRust++
				}
				got, err := store.GetEntityNeighborhood(context.Background(), root, 10)
				if err != nil {
					t.Fatalf("GetEntityNeighborhood(%q) error = %v", root, err)
				}
				wantLabel := "Go"
				if wantRust {
					wantLabel = "Rust"
				}
				if got == nil || got.Root == nil || got.Root.Label != wantLabel {
					t.Fatalf("GetEntityNeighborhood(%q) label = %#v, want %q", root, got, wantLabel)
				}
			}

			if expectedRust == 0 || expectedRust == tenants {
				t.Fatalf("expected Rust requests = %d, want a partial cohort", expectedRust)
			}
			if rustRequests != expectedRust {
				t.Fatalf("Rust requests = %d, want %d", rustRequests, expectedRust)
			}
			if legacy.requestCount() != tenants-expectedRust {
				t.Fatalf("Go requests = %d, want %d", legacy.requestCount(), tenants-expectedRust)
			}
		})
	}
}

func TestVerifiedCanaryQueryStoreComparesRustAuthorityWithoutChangingResponse(t *testing.T) {
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

	legacy := &countingQueryStoreStub{queryStoreStub: queryStoreStub{
		neighborhood: &ports.EntityNeighborhood{
			Root: &ports.NeighborhoodNode{URN: "legacy", Label: "Go"},
		},
	}}
	store, err := NewVerifiedCanaryQueryStore(
		legacy,
		server.URL,
		testSharedSecret,
		time.Second,
		50,
		100,
	)
	if err != nil {
		t.Fatalf("NewVerifiedCanaryQueryStore() error = %v", err)
	}
	root := canaryRoot(t, store, true)
	got, err := store.GetEntityNeighborhood(context.Background(), root, 10)
	if err != nil {
		t.Fatalf("GetEntityNeighborhood() error = %v", err)
	}
	if got == nil || got.Root == nil || got.Root.Label != "Rust" {
		t.Fatalf("GetEntityNeighborhood() = %#v, want Rust authority", got)
	}
	waitForRequestCount(t, legacy, 1)
	if legacy.requestCount() != 1 {
		t.Fatalf("verification requests = %d, want 1", legacy.requestCount())
	}

	legacy.setError(errors.New("legacy unavailable"))
	got, err = store.GetEntityNeighborhood(context.Background(), root, 10)
	if err != nil {
		t.Fatalf("GetEntityNeighborhood(legacy error) error = %v", err)
	}
	if got == nil || got.Root == nil || got.Root.Label != "Rust" {
		t.Fatalf("GetEntityNeighborhood(legacy error) = %#v, want Rust authority", got)
	}
	waitForRequestCount(t, legacy, 2)
	if legacy.requestCount() != 2 {
		t.Fatalf("verification requests = %d, want 2", legacy.requestCount())
	}

	unverified, err := NewVerifiedCanaryQueryStore(
		legacy,
		server.URL,
		testSharedSecret,
		time.Second,
		50,
		0,
	)
	if err != nil {
		t.Fatalf("NewVerifiedCanaryQueryStore(unverified) error = %v", err)
	}
	unverifiedRoot := canaryRoot(t, unverified, true)
	if _, err := unverified.GetEntityNeighborhood(context.Background(), unverifiedRoot, 10); err != nil {
		t.Fatalf("GetEntityNeighborhood(unverified) error = %v", err)
	}
	if legacy.requestCount() != 2 {
		t.Fatalf("disabled verification requests = %d, want 2", legacy.requestCount())
	}
}

func TestCanaryVerificationDoesNotDelayRustAuthority(t *testing.T) {
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

	legacy := &blockingQueryStoreStub{started: make(chan struct{}, 1)}
	store, err := NewVerifiedCanaryQueryStore(
		legacy,
		server.URL,
		testSharedSecret,
		500*time.Millisecond,
		50,
		100,
	)
	if err != nil {
		t.Fatalf("NewVerifiedCanaryQueryStore() error = %v", err)
	}
	root := canaryRoot(t, store, true)
	started := time.Now()
	got, err := store.GetEntityNeighborhood(context.Background(), root, 10)
	if err != nil {
		t.Fatalf("GetEntityNeighborhood() error = %v", err)
	}
	if got == nil || got.Root == nil || got.Root.Label != "Rust" {
		t.Fatalf("GetEntityNeighborhood() = %#v, want Rust authority", got)
	}
	if elapsed := time.Since(started); elapsed >= 250*time.Millisecond {
		t.Fatalf("Rust response waited %s for a 500ms Go verification timeout", elapsed)
	}
	select {
	case <-legacy.started:
	case <-time.After(time.Second):
		t.Fatal("background Go verification did not start")
	}
}

func TestCanarySamplingIsStableNestedAndTracksConfiguredPercent(t *testing.T) {
	const tenants = 100_000
	previous := make([]bool, tenants)
	for percentIndex, percent := range []int{1, 5, 10, 25, 50, 75, 99} {
		store, err := NewCanaryQueryStore(
			queryStoreStub{},
			"http://127.0.0.1:1",
			testSharedSecret,
			time.Second,
			percent,
		)
		if err != nil {
			t.Fatalf("NewCanaryQueryStore(%d%%) error = %v", percent, err)
		}

		selected := 0
		for index := 0; index < tenants; index++ {
			tenantID := fmt.Sprintf("distribution-tenant-%d", index)
			current := store.sample(tenantID)
			if current != store.sample(tenantID) {
				t.Fatalf("tenant %q changed cohort at %d%%", tenantID, percent)
			}
			if percentIndex > 0 && previous[index] && !current {
				t.Fatalf("tenant %q left the Rust cohort when allocation increased to %d%%", tenantID, percent)
			}
			previous[index] = current
			if current {
				selected++
			}
		}

		scaledDelta := selected*100 - percent*tenants
		if scaledDelta < 0 {
			scaledDelta = -scaledDelta
		}
		if scaledDelta > tenants/4 {
			t.Fatalf("selected %d of %d tenants at %d%%, outside 0.25 percentage points", selected, tenants, percent)
		}
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
	for _, percent := range []int{-1, 101} {
		if _, err := NewVerifiedCanaryQueryStore(queryStoreStub{}, "http://127.0.0.1:1", testSharedSecret, time.Second, 10, percent); err == nil {
			t.Fatalf("NewVerifiedCanaryQueryStore(verify=%d) error = nil", percent)
		}
	}
}

func TestCanaryQueryStoreReadinessRequiresBothAuthorities(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	store, err := NewCanaryQueryStore(
		queryStoreStub{},
		server.URL,
		testSharedSecret,
		time.Second,
		50,
	)
	if err != nil {
		t.Fatalf("NewCanaryQueryStore() error = %v", err)
	}
	if err := store.Ping(context.Background()); err != nil {
		t.Fatalf("Ping() error = %v, canary readiness requires both cohorts", err)
	}

	store, err = NewCanaryQueryStore(
		queryStoreStub{err: errors.New("compatibility unavailable")},
		server.URL,
		testSharedSecret,
		time.Second,
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

func waitForRequestCount(t *testing.T, store *countingQueryStoreStub, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for store.requestCount() < want && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
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

func TestLegacyModeIsExplicitGoAuthorityAndDoesNotCallRust(t *testing.T) {
	rustRequests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		rustRequests++
		http.Error(w, "must not be called", http.StatusInternalServerError)
	}))
	defer server.Close()

	legacy := &countingQueryStoreStub{
		queryStoreStub: queryStoreStub{
			neighborhood: &ports.EntityNeighborhood{Root: &ports.NeighborhoodNode{URN: "legacy"}},
		},
	}
	store, err := NewConfiguredQueryStore(
		legacy,
		server.URL,
		testSharedSecret,
		time.Second,
		"legacy",
		0,
		0,
		0,
	)
	if err != nil {
		t.Fatalf("NewConfiguredQueryStore(legacy) error = %v", err)
	}
	if err := store.Ping(context.Background()); err != nil {
		t.Fatalf("Ping(legacy) error = %v", err)
	}
	got, err := store.GetEntityNeighborhood(context.Background(), "urn:cerebro:tenant-a:resource:one", 10)
	if err != nil {
		t.Fatalf("GetEntityNeighborhood(legacy) error = %v", err)
	}
	if got == nil || got.Root == nil || got.Root.URN != "legacy" {
		t.Fatalf("GetEntityNeighborhood(legacy) = %#v", got)
	}
	if legacy.requestCount() != 1 || rustRequests != 0 {
		t.Fatalf("legacy requests = %d, Rust requests = %d", legacy.requestCount(), rustRequests)
	}
}

func TestCanaryHealthFailsClosedWhenEitherAuthorityIsUnavailable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	store, err := NewCanaryQueryStore(queryStoreStub{}, server.URL, testSharedSecret, time.Second, 10)
	if err != nil {
		t.Fatalf("NewCanaryQueryStore() error = %v", err)
	}
	if err := store.Ping(context.Background()); err == nil {
		t.Fatal("Ping(canary with Rust unavailable) error = nil")
	}

	store, err = NewCanaryQueryStore(
		queryStoreStub{err: errors.New("compatibility unavailable")},
		server.URL,
		testSharedSecret,
		time.Second,
		10,
	)
	if err != nil {
		t.Fatalf("NewCanaryQueryStore(failing compatibility) error = %v", err)
	}
	if err := store.Ping(context.Background()); err == nil {
		t.Fatal("Ping(canary with compatibility unavailable) error = nil")
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

func TestVerifiedCanaryQueryStoreComparesBatchWithoutChangingAuthority(t *testing.T) {
	server := newGraphTestServer(t, graphServiceStub{
		expandBatch: func(_ context.Context, request *connect.Request[cerebrographv1.ExpandBatchRequest]) (*connect.Response[cerebrographv1.ExpandBatchResponse], error) {
			neighborhoods := make(map[string]*cerebrographv1.ExpandResponse, len(request.Msg.GetRootKeys()))
			for index, root := range request.Msg.GetRootKeys() {
				neighborhoods[root] = &cerebrographv1.ExpandResponse{
					TenantId: request.Msg.GetTenantId(),
					Root: &cerebrographv1.GraphEntity{
						EntityId:   fmt.Sprintf("rust-root-%d", index),
						AgentKey:   root,
						EntityKind: "resource",
						Label:      "Rust",
					},
				}
			}
			return connect.NewResponse(&cerebrographv1.ExpandBatchResponse{
				Neighborhoods: neighborhoods,
			}), nil
		},
	})
	defer server.Close()

	legacy := &countingQueryStoreStub{queryStoreStub: queryStoreStub{
		neighborhood: &ports.EntityNeighborhood{
			Root: &ports.NeighborhoodNode{URN: "legacy", Label: "Go"},
		},
	}}
	store, err := NewVerifiedCanaryQueryStore(
		legacy,
		server.URL,
		testSharedSecret,
		time.Second,
		50,
		100,
	)
	if err != nil {
		t.Fatalf("NewVerifiedCanaryQueryStore() error = %v", err)
	}
	first := canaryRoot(t, store, true)
	second := strings.Replace(first, ":asset", ":asset-2", 1)
	got, err := store.GetEntityNeighborhoods(context.Background(), []string{first, second}, 10)
	if err != nil {
		t.Fatalf("GetEntityNeighborhoods() error = %v", err)
	}
	if len(got) != 2 || got[first].Root.Label != "Rust" || got[second].Root.Label != "Rust" {
		t.Fatalf("GetEntityNeighborhoods() = %#v, want Rust authority", got)
	}
	waitForRequestCount(t, legacy, 2)
	if legacy.requestCount() != 2 {
		t.Fatalf("batch verification requests = %d, want 2", legacy.requestCount())
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

func TestComparisonIgnoresSetOrderingButDetectsContentChanges(t *testing.T) {
	root := &ports.NeighborhoodNode{URN: "urn:cerebro:tenant-a:resource:root"}
	nodeOne := &ports.NeighborhoodNode{URN: "urn:cerebro:tenant-a:resource:one", Label: "One"}
	nodeTwo := &ports.NeighborhoodNode{URN: "urn:cerebro:tenant-a:resource:two", Label: "Two"}
	relationOne := &ports.NeighborhoodRelation{FromURN: root.URN, Relation: "contains", ToURN: nodeOne.URN}
	relationTwo := &ports.NeighborhoodRelation{FromURN: root.URN, Relation: "contains", ToURN: nodeTwo.URN}
	legacy := &ports.EntityNeighborhood{
		Root:      root,
		Neighbors: []*ports.NeighborhoodNode{nodeOne, nodeTwo},
		Relations: []*ports.NeighborhoodRelation{relationOne, relationTwo},
	}
	rust := &ports.EntityNeighborhood{
		Root:      root,
		Neighbors: []*ports.NeighborhoodNode{nodeTwo, nodeOne},
		Relations: []*ports.NeighborhoodRelation{relationTwo, relationOne},
	}
	if status := comparisonStatus(legacy, nil, rust, nil); status != "match" {
		t.Fatalf("comparisonStatus(reordered) = %q, want match", status)
	}
	legacyDigest, _ := comparisonReceipt(legacy)
	rustDigest, _ := comparisonReceipt(rust)
	if legacyDigest != rustDigest {
		t.Fatalf("reordered digests differ: %s != %s", legacyDigest, rustDigest)
	}
	rust.Neighbors[0] = &ports.NeighborhoodNode{URN: nodeTwo.URN, Label: "Changed"}
	if status := comparisonStatus(legacy, nil, rust, nil); status != "mismatch" {
		t.Fatalf("comparisonStatus(changed) = %q, want mismatch", status)
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
