package organizationalgraph

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	cerebrographv1 "github.com/writer/cerebro/gen/cerebro/graph/v1"
	"github.com/writer/cerebro/gen/cerebro/graph/v1/cerebrographv1connect"
	"github.com/writer/cerebro/internal/compliance"
	"github.com/writer/cerebro/internal/complianceintegration"
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
	expand              func(context.Context, *connect.Request[cerebrographv1.ExpandRequest]) (*connect.Response[cerebrographv1.ExpandResponse], error)
	expandBatch         func(context.Context, *connect.Request[cerebrographv1.ExpandBatchRequest]) (*connect.Response[cerebrographv1.ExpandBatchResponse], error)
	listEntities        func(context.Context, *connect.Request[cerebrographv1.ListEntitiesRequest]) (*connect.Response[cerebrographv1.ListEntitiesResponse], error)
	listEntityRelations func(context.Context, *connect.Request[cerebrographv1.ListEntityRelationsRequest]) (*connect.Response[cerebrographv1.ListEntityRelationsResponse], error)
	countRelations      func(context.Context, *connect.Request[cerebrographv1.CountRelationsRequest]) (*connect.Response[cerebrographv1.CountRelationsResponse], error)
	impactFact          func(context.Context, *connect.Request[cerebrographv1.GetComplianceImpactFactRequest]) (*connect.Response[cerebrographv1.GetComplianceImpactFactResponse], error)
	impactDependents    func(context.Context, *connect.Request[cerebrographv1.ListComplianceImpactDependentsRequest]) (*connect.Response[cerebrographv1.ListComplianceImpactDependentsResponse], error)
	personAccess        func(context.Context, *connect.Request[cerebrographv1.ListPersonAccessPathsRequest]) (*connect.Response[cerebrographv1.ListPersonAccessPathsResponse], error)
	cloudAttackPaths    func(context.Context, *connect.Request[cerebrographv1.ListCloudAttackPathsRequest]) (*connect.Response[cerebrographv1.ListCloudAttackPathsResponse], error)
	vendorRegister      func(context.Context, *connect.Request[cerebrographv1.ListVendorRegisterRequest]) (*connect.Response[cerebrographv1.ListVendorRegisterResponse], error)
	vendorDiscoveries   func(context.Context, *connect.Request[cerebrographv1.ListVendorDiscoveriesRequest]) (*connect.Response[cerebrographv1.ListVendorDiscoveriesResponse], error)
}

func (s graphServiceStub) ListEntities(ctx context.Context, request *connect.Request[cerebrographv1.ListEntitiesRequest]) (*connect.Response[cerebrographv1.ListEntitiesResponse], error) {
	return s.listEntities(ctx, request)
}

func (s graphServiceStub) ListEntityRelations(ctx context.Context, request *connect.Request[cerebrographv1.ListEntityRelationsRequest]) (*connect.Response[cerebrographv1.ListEntityRelationsResponse], error) {
	return s.listEntityRelations(ctx, request)
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

func (s graphServiceStub) GetComplianceImpactFact(ctx context.Context, request *connect.Request[cerebrographv1.GetComplianceImpactFactRequest]) (*connect.Response[cerebrographv1.GetComplianceImpactFactResponse], error) {
	return s.impactFact(ctx, request)
}

func (s graphServiceStub) ListComplianceImpactDependents(ctx context.Context, request *connect.Request[cerebrographv1.ListComplianceImpactDependentsRequest]) (*connect.Response[cerebrographv1.ListComplianceImpactDependentsResponse], error) {
	return s.impactDependents(ctx, request)
}

func (s graphServiceStub) ListPersonAccessPaths(ctx context.Context, request *connect.Request[cerebrographv1.ListPersonAccessPathsRequest]) (*connect.Response[cerebrographv1.ListPersonAccessPathsResponse], error) {
	return s.personAccess(ctx, request)
}

func (s graphServiceStub) ListCloudAttackPaths(ctx context.Context, request *connect.Request[cerebrographv1.ListCloudAttackPathsRequest]) (*connect.Response[cerebrographv1.ListCloudAttackPathsResponse], error) {
	return s.cloudAttackPaths(ctx, request)
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

func newComplianceImpactQueryStore(t *testing.T, service graphServiceStub) *QueryStore {
	t.Helper()
	server := newGraphTestServer(t, service)
	t.Cleanup(server.Close)
	store, err := NewQueryStore(nil, server.URL, testSharedSecret, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return store
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

func TestComplianceImpactTypedReadsPreserveTenantFactAndKeysetContract(t *testing.T) {
	root := canonicalComplianceRevision(t, "tenant-a", complianceintegration.FactAssessmentPlan, "plan-1", "plan-1-revision", 1, "a", time.Date(2026, time.August, 25, 12, 0, 0, 0, time.UTC))
	dependency := canonicalComplianceRevision(t, "tenant-a", complianceintegration.FactPolicy, "policy-1", "policy-1-revision", 1, "b", time.Date(2026, time.August, 25, 12, 1, 0, 0, time.UTC))
	dependent := canonicalComplianceRevision(t, "tenant-a", complianceintegration.FactAssessmentPlan, "plan-2", "plan-2-revision", 1, "c", time.Date(2026, time.August, 25, 12, 2, 0, 0, time.UTC))
	rootKey := complianceImpactKey(t, root)
	dependencyKey := complianceImpactKey(t, dependency)
	dependentKey := complianceImpactKey(t, dependent)
	server := newGraphTestServer(t, graphServiceStub{
		impactFact: func(_ context.Context, request *connect.Request[cerebrographv1.GetComplianceImpactFactRequest]) (*connect.Response[cerebrographv1.GetComplianceImpactFactResponse], error) {
			if request.Header().Get(tenantAuthHeader) != "tenant-a" || request.Msg.GetTenantId() != "tenant-a" || request.Msg.GetAgentKey() != rootKey {
				t.Fatalf("fact authority or key missing: headers=%v request=%#v", request.Header(), request.Msg)
			}
			return connect.NewResponse(&cerebrographv1.GetComplianceImpactFactResponse{
				TenantId: "tenant-a", GraphRevision: 41, Fact: complianceImpactEntity(t, root), DependencyCount: 1,
				Dependencies: []*cerebrographv1.ComplianceImpactDependency{{Entity: complianceImpactEntity(t, dependency), Relation: "policy_input"}},
			}), nil
		},
		impactDependents: func(_ context.Context, request *connect.Request[cerebrographv1.ListComplianceImpactDependentsRequest]) (*connect.Response[cerebrographv1.ListComplianceImpactDependentsResponse], error) {
			if request.Header().Get(tenantAuthHeader) != "tenant-a" || request.Msg.GetTenantId() != "tenant-a" || request.Msg.GetDependencyAgentKey() != dependencyKey || request.Msg.GetAfterAgentKey() != rootKey || request.Msg.GetLimit() != 1 {
				t.Fatalf("dependent authority, cursor, or bound missing: headers=%v request=%#v", request.Header(), request.Msg)
			}
			return connect.NewResponse(&cerebrographv1.ListComplianceImpactDependentsResponse{
				TenantId: "tenant-a", GraphRevision: 41, Dependents: []*cerebrographv1.GraphEntity{complianceImpactEntity(t, dependent)}, Truncated: true, NextAfterAgentKey: dependentKey,
			}), nil
		},
	})
	defer server.Close()
	store, err := NewQueryStore(nil, server.URL, testSharedSecret, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	fact, err := store.GetComplianceImpactFact(context.Background(), "tenant-a", complianceImpactPortRevision(t, root))
	if err != nil {
		t.Fatal(err)
	}
	if fact.Revision.AgentKey != rootKey || len(fact.Dependencies) != 1 || fact.Dependencies[0].Revision.AgentKey != dependencyKey || fact.Dependencies[0].Relation != "policy_input" {
		t.Fatalf("fact = %#v", fact)
	}
	page, err := store.ListComplianceImpactDependents(context.Background(), ports.ComplianceImpactDependentRequest{
		TenantID: "tenant-a", Dependency: complianceImpactPortRevision(t, dependency), AfterCursor: rootKey, Limit: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if page.Complete || page.NextCursor != dependentKey || len(page.Dependents) != 1 || page.Dependents[0].AgentKey != dependentKey {
		t.Fatalf("page = %#v", page)
	}
}

func TestComplianceImpactTypedReadsFailClosedOnMalformedResponses(t *testing.T) {
	root := canonicalComplianceRevision(t, "tenant-a", complianceintegration.FactAssessmentPlan, "plan-1", "plan-1-revision", 1, "a", time.Date(2026, time.August, 25, 12, 0, 0, 0, time.UTC))
	valid := func() *cerebrographv1.GetComplianceImpactFactResponse {
		return &cerebrographv1.GetComplianceImpactFactResponse{TenantId: "tenant-a", Fact: complianceImpactEntity(t, root)}
	}
	for name, mutate := range map[string]func(*cerebrographv1.GetComplianceImpactFactResponse){
		"wrong tenant":   func(response *cerebrographv1.GetComplianceImpactFactResponse) { response.TenantId = "tenant-b" },
		"count mismatch": func(response *cerebrographv1.GetComplianceImpactFactResponse) { response.DependencyCount = 1 },
		"missing edge attribute": func(response *cerebrographv1.GetComplianceImpactFactResponse) {
			response.DependencyCount = 1
			dependency := canonicalComplianceRevision(t, "tenant-a", complianceintegration.FactPolicy, "policy-1", "policy-1-revision", 1, "b", time.Date(2026, time.August, 25, 12, 1, 0, 0, time.UTC))
			response.Dependencies = []*cerebrographv1.ComplianceImpactDependency{{Entity: complianceImpactEntity(t, dependency)}}
		},
		"malformed properties": func(response *cerebrographv1.GetComplianceImpactFactResponse) {
			response.Fact.Properties["revision_version"] = "invalid"
		},
	} {
		t.Run(name, func(t *testing.T) {
			response := valid()
			mutate(response)
			server := newGraphTestServer(t, graphServiceStub{impactFact: func(context.Context, *connect.Request[cerebrographv1.GetComplianceImpactFactRequest]) (*connect.Response[cerebrographv1.GetComplianceImpactFactResponse], error) {
				return connect.NewResponse(response), nil
			}})
			defer server.Close()
			store, err := NewQueryStore(nil, server.URL, testSharedSecret, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.GetComplianceImpactFact(context.Background(), "tenant-a", complianceImpactPortRevision(t, root)); err == nil {
				t.Fatal("malformed response accepted")
			}
		})
	}
}

func canonicalComplianceRevision(t *testing.T, tenantID string, kind complianceintegration.FactKind, id, revisionID string, version uint64, digestByte string, lastModified time.Time) complianceintegration.RevisionRef {
	t.Helper()
	if len(digestByte) != 1 || !strings.Contains("0123456789abcdef", digestByte) {
		t.Fatalf("digest byte %q is not a lowercase hexadecimal digit", digestByte)
	}
	revision, err := complianceintegration.AdaptRevisionRef(tenantID, "grc", kind, compliance.RevisionRef{
		ID: id, RevisionID: revisionID, Version: version,
		ContentDigest: compliance.ContentDigest("sha256:" + strings.Repeat(digestByte, 64)), LastModified: lastModified,
	})
	if err != nil {
		t.Fatalf("canonical compliance revision: %v", err)
	}
	return revision
}

func complianceImpactKey(t *testing.T, revision complianceintegration.RevisionRef) string {
	t.Helper()
	key, err := revision.ImpactRevisionURN()
	if err != nil {
		t.Fatalf("canonical compliance impact key: %v", err)
	}
	return key
}

func complianceImpactPortRevision(t *testing.T, revision complianceintegration.RevisionRef) ports.ComplianceImpactRevisionRef {
	t.Helper()
	canonical := revision.Canonical()
	return ports.ComplianceImpactRevisionRef{
		AgentKey: complianceImpactKey(t, revision), TenantID: revision.TenantID(), Domain: revision.Domain(), Kind: string(revision.Kind()),
		ID: revision.ID(), RevisionID: revision.RevisionID(), Version: revision.Version(), ContentDigest: string(canonical.ContentDigest), LastModified: canonical.LastModified,
	}
}

func complianceImpactEntity(t *testing.T, revision complianceintegration.RevisionRef) *cerebrographv1.GraphEntity {
	t.Helper()
	key := complianceImpactKey(t, revision)
	canonical := revision.Canonical()
	return &cerebrographv1.GraphEntity{
		AgentKey: key, EntityKind: "compliance.impact_revision", Label: revision.ID() + "@" + revision.RevisionID(),
		Properties: map[string]string{
			"entity_urn": key, "entity_type": "compliance.impact_revision", "source_id": "compliance",
			"tenant_id": revision.TenantID(), "domain": revision.Domain(), "fact_kind": string(revision.Kind()), "stable_id": revision.ID(),
			"revision_id": revision.RevisionID(), "revision_version": strconv.FormatUint(revision.Version(), 10), "content_digest": string(canonical.ContentDigest),
			"last_modified": canonical.LastModified.Format(time.RFC3339Nano),
		},
	}
}

func TestComplianceImpactTypedReadsRejectNonCanonicalKeysAndMetadata(t *testing.T) {
	root := canonicalComplianceRevision(t, "tenant-a", complianceintegration.FactAssessmentPlan, "plan-1", "plan-1-revision", 1, "a", time.Date(2026, time.August, 25, 12, 0, 0, 0, time.UTC))
	rootKey := complianceImpactKey(t, root)
	rootRef := complianceImpactPortRevision(t, root)
	foreign := canonicalComplianceRevision(t, "tenant-b", complianceintegration.FactAssessmentPlan, "plan-foreign", "plan-foreign-revision", 1, "b", time.Date(2026, time.August, 25, 12, 1, 0, 0, time.UTC))
	foreignRef := complianceImpactPortRevision(t, foreign)

	t.Run("malformed fact key", func(t *testing.T) {
		calls := 0
		store := newComplianceImpactQueryStore(t, graphServiceStub{impactFact: func(context.Context, *connect.Request[cerebrographv1.GetComplianceImpactFactRequest]) (*connect.Response[cerebrographv1.GetComplianceImpactFactResponse], error) {
			calls++
			return connect.NewResponse(&cerebrographv1.GetComplianceImpactFactResponse{TenantId: "tenant-a", Fact: complianceImpactEntity(t, root)}), nil
		}})
		requested := rootRef
		requested.AgentKey = rootKey + ":tampered"
		if _, err := store.GetComplianceImpactFact(context.Background(), "tenant-a", requested); err == nil {
			t.Fatal("malformed fact key accepted")
		}
		if calls != 0 {
			t.Fatalf("malformed fact key reached Rust authority %d times", calls)
		}
	})

	t.Run("cross tenant fact key", func(t *testing.T) {
		calls := 0
		store := newComplianceImpactQueryStore(t, graphServiceStub{impactFact: func(context.Context, *connect.Request[cerebrographv1.GetComplianceImpactFactRequest]) (*connect.Response[cerebrographv1.GetComplianceImpactFactResponse], error) {
			calls++
			return connect.NewResponse(&cerebrographv1.GetComplianceImpactFactResponse{TenantId: "tenant-a", Fact: complianceImpactEntity(t, root)}), nil
		}})
		if _, err := store.GetComplianceImpactFact(context.Background(), "tenant-a", foreignRef); err == nil {
			t.Fatal("cross-tenant fact key accepted")
		}
		if calls != 0 {
			t.Fatalf("cross-tenant fact key reached Rust authority %d times", calls)
		}
	})

	dependency := canonicalComplianceRevision(t, "tenant-a", complianceintegration.FactPolicy, "policy-1", "policy-1-revision", 1, "c", time.Date(2026, time.August, 25, 12, 2, 0, 0, time.UTC))
	dependencyKey := complianceImpactKey(t, dependency)
	for name, request := range map[string]ports.ComplianceImpactDependentRequest{
		"malformed dependency key": {TenantID: "tenant-a", Dependency: func() ports.ComplianceImpactRevisionRef {
			ref := complianceImpactPortRevision(t, dependency)
			ref.AgentKey = dependencyKey + ":tampered"
			return ref
		}(), Limit: 1},
		"malformed after key":         {TenantID: "tenant-a", Dependency: complianceImpactPortRevision(t, dependency), AfterCursor: rootKey + ":tampered", Limit: 1},
		"cross tenant dependency key": {TenantID: "tenant-a", Dependency: foreignRef, Limit: 1},
	} {
		t.Run(name, func(t *testing.T) {
			calls := 0
			store := newComplianceImpactQueryStore(t, graphServiceStub{impactDependents: func(context.Context, *connect.Request[cerebrographv1.ListComplianceImpactDependentsRequest]) (*connect.Response[cerebrographv1.ListComplianceImpactDependentsResponse], error) {
				calls++
				return connect.NewResponse(&cerebrographv1.ListComplianceImpactDependentsResponse{TenantId: "tenant-a"}), nil
			}})
			if _, err := store.ListComplianceImpactDependents(context.Background(), request); err == nil {
				t.Fatal("malformed or cross-tenant cursor accepted")
			}
			if calls != 0 {
				t.Fatalf("invalid cursor reached Rust authority %d times", calls)
			}
		})
	}

	for name, mutate := range map[string]func(*cerebrographv1.GetComplianceImpactFactResponse){
		"wrong response tenant": func(response *cerebrographv1.GetComplianceImpactFactResponse) {
			response.TenantId = "tenant-b"
		},
		"wrong entity tenant": func(response *cerebrographv1.GetComplianceImpactFactResponse) {
			response.Fact.Properties["tenant_id"] = "tenant-b"
		},
		"wrong entity kind": func(response *cerebrographv1.GetComplianceImpactFactResponse) {
			response.Fact.EntityKind = "compliance.impact_revision_legacy"
		},
		"wrong revision metadata": func(response *cerebrographv1.GetComplianceImpactFactResponse) {
			response.Fact.Properties["stable_id"] = root.ID() + "-replacement"
		},
		"canonical key metadata mismatch": func(response *cerebrographv1.GetComplianceImpactFactResponse) {
			response.Fact.AgentKey = rootKey + ":tampered"
		},
		"missing revision attribute": func(response *cerebrographv1.GetComplianceImpactFactResponse) {
			delete(response.Fact.Properties, "revision_id")
		},
		"malformed revision version": func(response *cerebrographv1.GetComplianceImpactFactResponse) {
			response.Fact.Properties["revision_version"] = "not-a-number"
		},
		"non-canonical revision version": func(response *cerebrographv1.GetComplianceImpactFactResponse) {
			response.Fact.Properties["revision_version"] = "01"
		},
		"malformed content digest": func(response *cerebrographv1.GetComplianceImpactFactResponse) {
			response.Fact.Properties["content_digest"] = strings.TrimSuffix(string(root.Canonical().ContentDigest), "a")
		},
		"malformed last modified": func(response *cerebrographv1.GetComplianceImpactFactResponse) {
			response.Fact.Properties["last_modified"] = "not-a-timestamp"
		},
		"non-canonical last modified": func(response *cerebrographv1.GetComplianceImpactFactResponse) {
			response.Fact.Properties["last_modified"] = "2026-08-25T05:00:00-07:00"
		},
	} {
		t.Run(name, func(t *testing.T) {
			response := &cerebrographv1.GetComplianceImpactFactResponse{TenantId: "tenant-a", Fact: complianceImpactEntity(t, root)}
			mutate(response)
			store := newComplianceImpactQueryStore(t, graphServiceStub{impactFact: func(context.Context, *connect.Request[cerebrographv1.GetComplianceImpactFactRequest]) (*connect.Response[cerebrographv1.GetComplianceImpactFactResponse], error) {
				return connect.NewResponse(response), nil
			}})
			if _, err := store.GetComplianceImpactFact(context.Background(), "tenant-a", rootRef); err == nil {
				t.Fatal("non-canonical response accepted")
			}
		})
	}
}

func TestComplianceImpactTypedReadsClassifyInvalidLimits(t *testing.T) {
	dependency := canonicalComplianceRevision(t, "tenant-a", complianceintegration.FactPolicy, "policy-1", "policy-1-revision", 1, "a", time.Date(2026, time.August, 25, 12, 0, 0, 0, time.UTC))
	store := newComplianceImpactQueryStore(t, graphServiceStub{})
	for _, limit := range []uint32{0, ports.MaxCypherQueryRows} {
		_, err := store.ListComplianceImpactDependents(context.Background(), ports.ComplianceImpactDependentRequest{TenantID: "tenant-a", Dependency: complianceImpactPortRevision(t, dependency), Limit: limit})
		if !errors.Is(err, ports.ErrComplianceImpactInvalidProjection) {
			t.Fatalf("limit %d error = %v, want ErrComplianceImpactInvalidProjection", limit, err)
		}
	}
}

func TestComplianceImpactTypedReadsRejectDependencyCountListMismatch(t *testing.T) {
	root := canonicalComplianceRevision(t, "tenant-a", complianceintegration.FactAssessmentPlan, "plan-1", "plan-1-revision", 1, "a", time.Date(2026, time.August, 25, 12, 0, 0, 0, time.UTC))
	dependency := canonicalComplianceRevision(t, "tenant-a", complianceintegration.FactPolicy, "policy-1", "policy-1-revision", 1, "b", time.Date(2026, time.August, 25, 12, 1, 0, 0, time.UTC))
	for name, response := range map[string]*cerebrographv1.GetComplianceImpactFactResponse{
		"nonzero count with empty list": {
			TenantId: "tenant-a", Fact: complianceImpactEntity(t, root), DependencyCount: 1,
		},
		"zero count with nonempty list": {
			TenantId: "tenant-a", Fact: complianceImpactEntity(t, root), DependencyCount: 0,
			Dependencies: []*cerebrographv1.ComplianceImpactDependency{{Entity: complianceImpactEntity(t, dependency), Relation: "policy_input"}},
		},
		"count over maximum": {
			TenantId: "tenant-a", Fact: complianceImpactEntity(t, root), DependencyCount: 3000,
		},
	} {
		t.Run(name, func(t *testing.T) {
			store := newComplianceImpactQueryStore(t, graphServiceStub{impactFact: func(context.Context, *connect.Request[cerebrographv1.GetComplianceImpactFactRequest]) (*connect.Response[cerebrographv1.GetComplianceImpactFactResponse], error) {
				return connect.NewResponse(response), nil
			}})
			if _, err := store.GetComplianceImpactFact(context.Background(), "tenant-a", complianceImpactPortRevision(t, root)); err == nil {
				t.Fatal("dependency count/list mismatch accepted")
			}
		})
	}
}

func TestComplianceImpactTypedReadsPreserveExactOrderedDependencyRelations(t *testing.T) {
	root := canonicalComplianceRevision(t, "tenant-a", complianceintegration.FactAssessmentPlan, "plan-1", "plan-1-revision", 1, "a", time.Date(2026, time.August, 25, 12, 0, 0, 0, time.UTC))
	left := canonicalComplianceRevision(t, "tenant-a", complianceintegration.FactPolicy, "policy-left", "policy-left-revision", 1, "b", time.Date(2026, time.August, 25, 12, 1, 0, 0, time.UTC))
	right := canonicalComplianceRevision(t, "tenant-a", complianceintegration.FactProgram, "program-right", "program-right-revision", 1, "c", time.Date(2026, time.August, 25, 12, 2, 0, 0, time.UTC))
	type dependencyFixture struct {
		revision complianceintegration.RevisionRef
		relation string
		key      string
	}
	fixtures := []dependencyFixture{
		{revision: left, relation: "policy_input", key: complianceImpactKey(t, left)},
		{revision: right, relation: "program_control", key: complianceImpactKey(t, right)},
	}
	sort.Slice(fixtures, func(i, j int) bool {
		return fixtures[i].key+"\x00"+fixtures[i].relation < fixtures[j].key+"\x00"+fixtures[j].relation
	})
	store := newComplianceImpactQueryStore(t, graphServiceStub{impactFact: func(context.Context, *connect.Request[cerebrographv1.GetComplianceImpactFactRequest]) (*connect.Response[cerebrographv1.GetComplianceImpactFactResponse], error) {
		return connect.NewResponse(&cerebrographv1.GetComplianceImpactFactResponse{
			TenantId: "tenant-a", Fact: complianceImpactEntity(t, root), DependencyCount: 2,
			Dependencies: []*cerebrographv1.ComplianceImpactDependency{
				{Entity: complianceImpactEntity(t, fixtures[0].revision), Relation: fixtures[0].relation},
				{Entity: complianceImpactEntity(t, fixtures[1].revision), Relation: fixtures[1].relation},
			},
		}), nil
	}})
	fact, err := store.GetComplianceImpactFact(context.Background(), "tenant-a", complianceImpactPortRevision(t, root))
	if err != nil {
		t.Fatal(err)
	}
	if len(fact.Dependencies) != len(fixtures) {
		t.Fatalf("dependency count = %d, want %d", len(fact.Dependencies), len(fixtures))
	}
	for index, fixture := range fixtures {
		got := fact.Dependencies[index]
		if got.Revision.AgentKey != fixture.key || got.Relation != fixture.relation {
			t.Fatalf("dependency[%d] = %#v, want key %q relation %q", index, got, fixture.key, fixture.relation)
		}
		if got.Relation == "compliance_depends_on" {
			t.Fatalf("dependency[%d] returned the wrapper relation instead of the edge attribute", index)
		}
	}
}

func TestComplianceImpactTypedReadsRejectDuplicateDirectDependencies(t *testing.T) {
	root := canonicalComplianceRevision(t, "tenant-a", complianceintegration.FactAssessmentPlan, "plan-1", "plan-1-revision", 1, "a", time.Date(2026, time.August, 25, 12, 0, 0, 0, time.UTC))
	dependency := canonicalComplianceRevision(t, "tenant-a", complianceintegration.FactPolicy, "policy-1", "policy-1-revision", 1, "b", time.Date(2026, time.August, 25, 12, 1, 0, 0, time.UTC))
	store := newComplianceImpactQueryStore(t, graphServiceStub{impactFact: func(context.Context, *connect.Request[cerebrographv1.GetComplianceImpactFactRequest]) (*connect.Response[cerebrographv1.GetComplianceImpactFactResponse], error) {
		entity := complianceImpactEntity(t, dependency)
		return connect.NewResponse(&cerebrographv1.GetComplianceImpactFactResponse{
			TenantId: "tenant-a", Fact: complianceImpactEntity(t, root), DependencyCount: 2,
			Dependencies: []*cerebrographv1.ComplianceImpactDependency{
				{Entity: entity, Relation: "policy_input"},
				{Entity: entity, Relation: "policy_input"},
			},
		}), nil
	}})
	if _, err := store.GetComplianceImpactFact(context.Background(), "tenant-a", complianceImpactPortRevision(t, root)); err == nil {
		t.Fatal("duplicate direct dependency accepted")
	}
}

func TestComplianceImpactTypedReadsRejectMalformedDependentCursors(t *testing.T) {
	dependency := canonicalComplianceRevision(t, "tenant-a", complianceintegration.FactPolicy, "policy-1", "policy-1-revision", 1, "a", time.Date(2026, time.August, 25, 12, 0, 0, 0, time.UTC))
	first := canonicalComplianceRevision(t, "tenant-a", complianceintegration.FactAssessmentPlan, "plan-a", "plan-a-revision", 1, "b", time.Date(2026, time.August, 25, 12, 1, 0, 0, time.UTC))
	second := canonicalComplianceRevision(t, "tenant-a", complianceintegration.FactAssessmentPlan, "plan-b", "plan-b-revision", 2, "c", time.Date(2026, time.August, 25, 12, 2, 0, 0, time.UTC))
	firstKey := complianceImpactKey(t, first)
	secondKey := complianceImpactKey(t, second)
	if secondKey < firstKey {
		first, second = second, first
		firstKey, secondKey = secondKey, firstKey
	}

	for name, mutate := range map[string]func(*cerebrographv1.ListComplianceImpactDependentsResponse){
		"duplicate dependent identity": func(response *cerebrographv1.ListComplianceImpactDependentsResponse) {
			response.Dependents = []*cerebrographv1.GraphEntity{complianceImpactEntity(t, first), complianceImpactEntity(t, first)}
			response.Truncated = false
			response.NextAfterAgentKey = ""
		},
		"descending dependent keys": func(response *cerebrographv1.ListComplianceImpactDependentsResponse) {
			response.Dependents = []*cerebrographv1.GraphEntity{complianceImpactEntity(t, second), complianceImpactEntity(t, first)}
			response.Truncated = false
			response.NextAfterAgentKey = ""
		},
		"truncated without cursor": func(response *cerebrographv1.ListComplianceImpactDependentsResponse) {
			response.Dependents = []*cerebrographv1.GraphEntity{complianceImpactEntity(t, first)}
			response.Truncated = true
			response.NextAfterAgentKey = ""
		},
		"truncated cursor not last": func(response *cerebrographv1.ListComplianceImpactDependentsResponse) {
			response.Dependents = []*cerebrographv1.GraphEntity{complianceImpactEntity(t, first)}
			response.Truncated = true
			response.NextAfterAgentKey = secondKey
		},
		"complete page with cursor": func(response *cerebrographv1.ListComplianceImpactDependentsResponse) {
			response.Dependents = []*cerebrographv1.GraphEntity{complianceImpactEntity(t, first)}
			response.Truncated = false
			response.NextAfterAgentKey = firstKey
		},
		"response exceeds requested limit": func(response *cerebrographv1.ListComplianceImpactDependentsResponse) {
			response.Dependents = []*cerebrographv1.GraphEntity{complianceImpactEntity(t, first), complianceImpactEntity(t, second)}
			response.Truncated = false
			response.NextAfterAgentKey = ""
		},
		"dependent key metadata mismatch": func(response *cerebrographv1.ListComplianceImpactDependentsResponse) {
			entity := complianceImpactEntity(t, first)
			entity.AgentKey = firstKey + ":tampered"
			response.Dependents = []*cerebrographv1.GraphEntity{entity}
			response.Truncated = false
			response.NextAfterAgentKey = ""
		},
	} {
		t.Run(name, func(t *testing.T) {
			response := &cerebrographv1.ListComplianceImpactDependentsResponse{TenantId: "tenant-a"}
			mutate(response)
			limit := uint32(1)
			if len(response.Dependents) == 2 && name != "response exceeds requested limit" {
				limit = 2
			}
			store := newComplianceImpactQueryStore(t, graphServiceStub{impactDependents: func(context.Context, *connect.Request[cerebrographv1.ListComplianceImpactDependentsRequest]) (*connect.Response[cerebrographv1.ListComplianceImpactDependentsResponse], error) {
				return connect.NewResponse(response), nil
			}})
			if _, err := store.ListComplianceImpactDependents(context.Background(), ports.ComplianceImpactDependentRequest{TenantID: "tenant-a", Dependency: complianceImpactPortRevision(t, dependency), Limit: limit}); err == nil {
				t.Fatal("malformed dependent cursor response accepted")
			}
		})
	}
}

func TestComplianceImpactTypedReadsRoundTripTwoDependentLimitPlusOnePages(t *testing.T) {
	dependency := canonicalComplianceRevision(t, "tenant-a", complianceintegration.FactPolicy, "policy-1", "policy-1-revision", 1, "a", time.Date(2026, time.August, 25, 12, 0, 0, 0, time.UTC))
	first := canonicalComplianceRevision(t, "tenant-a", complianceintegration.FactAssessmentPlan, "plan-a", "plan-a-revision", 1, "b", time.Date(2026, time.August, 25, 12, 1, 0, 0, time.UTC))
	second := canonicalComplianceRevision(t, "tenant-a", complianceintegration.FactAssessmentPlan, "plan-b", "plan-b-revision", 1, "c", time.Date(2026, time.August, 25, 12, 2, 0, 0, time.UTC))
	firstKey := complianceImpactKey(t, first)
	secondKey := complianceImpactKey(t, second)
	if secondKey < firstKey {
		first, second = second, first
		firstKey, secondKey = secondKey, firstKey
	}
	dependencyKey := complianceImpactKey(t, dependency)
	calls := 0
	store := newComplianceImpactQueryStore(t, graphServiceStub{impactDependents: func(_ context.Context, request *connect.Request[cerebrographv1.ListComplianceImpactDependentsRequest]) (*connect.Response[cerebrographv1.ListComplianceImpactDependentsResponse], error) {
		if request.Header().Get(tenantAuthHeader) != "tenant-a" || request.Msg.GetTenantId() != "tenant-a" || request.Msg.GetDependencyAgentKey() != dependencyKey || request.Msg.GetLimit() != 1 {
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("unexpected dependent request"))
		}
		calls++
		switch request.Msg.GetAfterAgentKey() {
		case "":
			return connect.NewResponse(&cerebrographv1.ListComplianceImpactDependentsResponse{
				TenantId: "tenant-a", Dependents: []*cerebrographv1.GraphEntity{complianceImpactEntity(t, first)}, Truncated: true, NextAfterAgentKey: firstKey,
			}), nil
		case firstKey:
			return connect.NewResponse(&cerebrographv1.ListComplianceImpactDependentsResponse{
				TenantId: "tenant-a", Dependents: []*cerebrographv1.GraphEntity{complianceImpactEntity(t, second)}, Truncated: false,
			}), nil
		default:
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("unexpected dependent cursor"))
		}
	}})
	page1, err := store.ListComplianceImpactDependents(context.Background(), ports.ComplianceImpactDependentRequest{TenantID: "tenant-a", Dependency: complianceImpactPortRevision(t, dependency), Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if page1.Complete || page1.NextCursor != firstKey || len(page1.Dependents) != 1 || page1.Dependents[0].AgentKey != firstKey {
		t.Fatalf("first page = %#v", page1)
	}
	page2, err := store.ListComplianceImpactDependents(context.Background(), ports.ComplianceImpactDependentRequest{TenantID: "tenant-a", Dependency: complianceImpactPortRevision(t, dependency), AfterCursor: page1.NextCursor, Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if !page2.Complete || page2.NextCursor != "" || len(page2.Dependents) != 1 || page2.Dependents[0].AgentKey != secondKey {
		t.Fatalf("second page = %#v", page2)
	}
	if page1.Dependents[0].AgentKey == page2.Dependents[0].AgentKey || calls != 2 {
		t.Fatalf("two-page round trip duplicated or skipped a dependent: page1=%#v page2=%#v calls=%d", page1, page2, calls)
	}
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
			if request.Header().Get(tenantAuthHeader) != "tenant-a" || request.Msg.GetFilter().GetTenantId() != "tenant-a" || request.Msg.GetFilter().GetApplicationWorkspaceId() != "workspace-a" || request.Msg.GetFilter().GetSourceStatus() != "discovered" || request.Msg.GetLimit() != 25 {
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
	page, err := store.ListVendorDiscoveries(context.Background(), ports.VendorDiscoveryFilter{TenantID: "tenant-a", ApplicationWorkspaceID: " workspace-a ", SourceStatus: "discovered", Limit: 25})
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

func TestQueryStoreEntityRelationsPreservesBoundedEdgeEvidence(t *testing.T) {
	neighborURN := "urn:cerebro:tenant-a:aws:task:one"
	server := newGraphTestServer(t, graphServiceStub{
		listEntityRelations: func(_ context.Context, request *connect.Request[cerebrographv1.ListEntityRelationsRequest]) (*connect.Response[cerebrographv1.ListEntityRelationsResponse], error) {
			if request.Header().Get(tenantAuthHeader) != "tenant-a" || request.Msg.GetTenantId() != "tenant-a" || request.Msg.GetAgentKey() != "urn:cerebro:tenant-a:aws:session:one" || request.Msg.GetExpectedGraphRevision() != 19 || request.Msg.GetLimit() != 10 {
				t.Fatalf("entity relation authority or bounds missing: headers=%v request=%#v", request.Header(), request.Msg)
			}
			if keys := request.Msg.GetNeighborAgentKeys(); len(keys) != 1 || keys[0] != neighborURN {
				t.Fatalf("neighbor agent keys = %#v", keys)
			}
			return connect.NewResponse(&cerebrographv1.ListEntityRelationsResponse{
				TenantId: "tenant-a", GraphRevision: 19,
				Relations: []*cerebrographv1.EntityRelation{{
					Direction: cerebrographv1.EntityRelationDirection_ENTITY_RELATION_DIRECTION_OUTGOING,
					Relation:  "acted_on", Entity: &cerebrographv1.GraphEntity{AgentKey: neighborURN, EntityKind: "aws.task"},
					SourceId: "aws", AttributesJson: `{"confidence":0.9}`,
				}},
			}), nil
		},
	})
	defer server.Close()
	store, err := NewQueryStore(nil, server.URL, testSharedSecret, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	page, err := store.ListEntityRelations(context.Background(), ports.EntityRelationPageRequest{
		TenantID: "tenant-a", AgentKey: "urn:cerebro:tenant-a:aws:session:one", Directions: []ports.EntityRelationDirection{ports.EntityRelationOutgoing},
		NeighborAgentKeys: []string{neighborURN}, Limit: 10, ExpectedRevision: 19,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Relations) != 1 || page.Relations[0].SourceID != "aws" || page.Relations[0].AttributesJSON != `{"confidence":0.9}` || page.Relations[0].Entity.URN != neighborURN {
		t.Fatalf("page = %#v", page)
	}
}

func TestQueryStoreCloudAttackPathsUsesTypedRustRPC(t *testing.T) {
	node := func(kind, urn, label string) *cerebrographv1.CloudAttackPathNode {
		return &cerebrographv1.CloudAttackPathNode{Urn: urn, EntityKind: kind, Label: label}
	}
	edge := func(from *cerebrographv1.CloudAttackPathNode, relation string, to *cerebrographv1.CloudAttackPathNode) *cerebrographv1.CloudAttackPathEdge {
		return &cerebrographv1.CloudAttackPathEdge{
			From: from, Relation: relation, To: to, Direction: "forward", SourceId: "aws", SourceRuntimeId: "runtime-a",
			AssertionRuntimeIds: []string{"runtime-a"}, AttributesJson: `{"source_event_id":"event-a"}`,
		}
	}
	public := node("aws.public_principal", "urn:cerebro:tenant-a:public:internet", "public")
	exposed := node("aws.network_interface", "urn:cerebro:tenant-a:resource:eni-1", "eni-1")
	account := node("cloud.account", "urn:cerebro:tenant-a:account:prod", "prod")
	principal := node("aws.role", "urn:cerebro:tenant-a:principal:admin", "admin")
	permission := node("aws.policy", "urn:cerebro:tenant-a:permission:admin", "AdministratorAccess")
	owner := node("team", "urn:cerebro:tenant-a:team:security", "Security")
	server := newGraphTestServer(t, graphServiceStub{
		cloudAttackPaths: func(_ context.Context, request *connect.Request[cerebrographv1.ListCloudAttackPathsRequest]) (*connect.Response[cerebrographv1.ListCloudAttackPathsResponse], error) {
			if request.Header().Get(tenantAuthHeader) != "tenant-a" || request.Msg.GetTenantId() != "tenant-a" || request.Msg.GetAccountId() != "prod" || request.Msg.GetRuntimeId() != "runtime-a" || !request.Msg.GetRequireAssertionProof() || request.Msg.GetLimit() != 10 || request.Msg.GetMaxDepth() != 4 || request.Msg.GetExpectedGraphRevision() != 41 {
				t.Fatalf("cloud attack path authority or bounds missing: headers=%v request=%#v", request.Header(), request.Msg)
			}
			return connect.NewResponse(&cerebrographv1.ListCloudAttackPathsResponse{
				TenantId: "tenant-a", GraphRevision: 41,
				Counts: &cerebrographv1.CloudAttackPathCounts{Paths: 1, ExposedResources: 1, PrivilegedPrincipals: 1, CloudAccounts: 1},
				Paths: []*cerebrographv1.CloudAttackPath{{
					PublicPrincipal: public, ExposedResource: exposed, CloudAccount: account, Principal: principal, Permission: permission,
					Ownerships:            []*cerebrographv1.CloudAttackPathOwnership{{Owner: owner, Edge: edge(exposed, "owned_by", owner)}},
					ReachRelation:         "can_reach",
					AccessRelation:        "can_admin",
					RelationChain:         []string{"runs_as"},
					ExposureEdge:          edge(public, "can_reach", exposed),
					ResourceAccountEdge:   edge(exposed, "belongs_to", account),
					TraversalEdges:        []*cerebrographv1.CloudAttackPathEdge{edge(exposed, "runs_as", principal)},
					PrivilegeEdge:         edge(principal, "can_admin", permission),
					PermissionAccountEdge: edge(permission, "belongs_to", account),
				}},
			}), nil
		},
	})
	defer server.Close()
	store, err := NewQueryStore(nil, server.URL, testSharedSecret, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	result, err := store.ListCloudAttackPaths(context.Background(), ports.CloudAttackPathRequest{
		TenantID: " tenant-a ", AccountID: " prod ", RuntimeID: " runtime-a ", RequireAssertionProof: true, Limit: 10, Depth: 4, ExpectedRevision: 41,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.GraphRevision != 41 || result.Counts.Paths != 1 || len(result.Paths) != 1 || len(result.Paths[0].Ownerships) != 1 || len(result.Paths[0].TraversalEdges) != 1 {
		t.Fatalf("result = %#v", result)
	}
	if result.Paths[0].PrivilegeEdge.AttributesJSON != `{"source_event_id":"event-a"}` || result.Paths[0].Principal.URN != principal.Urn {
		t.Fatalf("path = %#v", result.Paths[0])
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
