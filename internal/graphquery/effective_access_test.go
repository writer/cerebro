package graphquery

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/ports"
)

func TestGetEffectiveAccessPathsRequiresIdentitySelector(t *testing.T) {
	_, err := New(&awsExposureStubStore{}).GetEffectiveAccessPaths(context.Background(), EffectiveAccessPathRequest{TenantID: "writer"})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("GetEffectiveAccessPaths() error = %v, want %v", err, ErrInvalidRequest)
	}
}

func TestGetEffectiveAccessPathsRejectsCrossTenantSelectors(t *testing.T) {
	_, err := New(&awsExposureStubStore{}).GetEffectiveAccessPaths(context.Background(), EffectiveAccessPathRequest{
		TenantID:    "writer",
		IdentityURN: "urn:cerebro:other:identity:email:alice@example.com",
	})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("GetEffectiveAccessPaths(identity) error = %v, want %v", err, ErrInvalidRequest)
	}

	_, err = New(&awsExposureStubStore{}).GetEffectiveAccessPaths(context.Background(), EffectiveAccessPathRequest{
		TenantID:       "writer",
		IdentityURN:    "urn:cerebro:writer:identity:email:alice@example.com",
		ApplicationURN: "urn:cerebro:other:okta_application:app-1",
	})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("GetEffectiveAccessPaths(application) error = %v, want %v", err, ErrInvalidRequest)
	}
}

func TestEffectiveAccessPathRequestFromQueryRejectsZeroLimit(t *testing.T) {
	_, err := EffectiveAccessPathRequestFromQuery(url.Values{"limit": []string{"0"}})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("EffectiveAccessPathRequestFromQuery() error = %v, want %v", err, ErrInvalidRequest)
	}
}

func TestGetEffectiveAccessPathsUsesTypedFixtureAndPreservesLegacyShape(t *testing.T) {
	store := &awsExposureStubStore{effectiveResult: effectiveAccessTypedFixtureResult()}
	result, err := New(store).GetEffectiveAccessPaths(context.Background(), EffectiveAccessPathRequest{
		TenantID:       "writer",
		IdentityQuery:  "Alice",
		ApplicationURN: "urn:cerebro:writer:okta_application:app-aws-admin",
		Capability:     "Cloud Admin",
		Limit:          500,
	})
	if err != nil {
		t.Fatalf("GetEffectiveAccessPaths() error = %v", err)
	}
	if len(store.effectiveRequests) != 1 {
		t.Fatalf("typed requests = %d, want 1", len(store.effectiveRequests))
	}
	request := store.effectiveRequests[0]
	if request.TenantID != "writer" || request.IdentityURN != "" || request.IdentityQuery != "alice" || request.ApplicationURN != "urn:cerebro:writer:okta_application:app-aws-admin" || request.CapabilityURN != "" || request.CapabilityID != "cloud_admin" || request.Limit != maxEffectiveAccessPathLimit {
		t.Fatalf("typed request = %#v", request)
	}
	if result.Filters.Limit != maxEffectiveAccessPathLimit || result.Filters.IdentityQuery != "alice" {
		t.Fatalf("filters = %#v", result.Filters)
	}
	if result.Counts.Paths != 1 || result.Counts.GroupMediatedPaths != 1 || result.Counts.CapabilitiesReturned != 1 {
		t.Fatalf("counts = %#v", result.Counts)
	}
	if len(result.Paths) != 1 {
		t.Fatalf("paths = %#v", result.Paths)
	}
	path := result.Paths[0]
	expected := effectiveAccessTestPath()
	expected.Edges[1].Attributes = map[string]string{"assignment_id": "asg-1"}
	expected.Lineage = expected.QualifyLineage()
	if !reflect.DeepEqual(path, expected) {
		t.Fatalf("typed path = %#v, want %#v", path, expected)
	}
	if path.Mediator == nil || path.Mediator.Label != "Security Engineering" {
		t.Fatalf("mediator = %#v", path.Mediator)
	}
	if path.Capability.URN != "urn:cerebro:writer:privileged_capability:cloud_admin" {
		t.Fatalf("capability = %#v", path.Capability)
	}
	if got := path.Edges[1]; got.SourceID != "okta" || got.RuntimeID != "writer-okta" || got.EventID != "evt-assign" || got.At != "2026-06-10T18:00:00Z" {
		t.Fatalf("assignment edge = %#v", got)
	}
	if got := path.Edges[1].Attributes["assignment_id"]; got != "asg-1" {
		t.Fatalf("assignment attribute = %q, want asg-1", got)
	}
	if !path.Lineage.Qualified || path.Lineage.CompleteEdgeCount != 5 || path.Lineage.ProofDigest == "" {
		t.Fatalf("lineage = %#v, want five qualified edges", path.Lineage)
	}
	if result.Counts.LineageQualifiedPaths != 1 || result.Counts.LineageIncompletePaths != 0 {
		t.Fatalf("lineage counts = %#v", result.Counts)
	}
}

type typedOnlyEffectiveAccessStore struct {
	requests []ports.EffectiveAccessPathRequest
	result   *ports.EffectiveAccessPathResult
}

func (s *typedOnlyEffectiveAccessStore) Ping(context.Context) error { return nil }

func (s *typedOnlyEffectiveAccessStore) GetEntityNeighborhood(context.Context, string, int) (*ports.EntityNeighborhood, error) {
	return nil, nil
}

func (s *typedOnlyEffectiveAccessStore) ListEffectiveAccessPaths(_ context.Context, request ports.EffectiveAccessPathRequest) (*ports.EffectiveAccessPathResult, error) {
	s.requests = append(s.requests, request)
	return s.result, nil
}

func TestGetEffectiveAccessPathsUsesTypedCapabilityAlone(t *testing.T) {
	store := &typedOnlyEffectiveAccessStore{result: effectiveAccessTypedFixtureResult()}
	result, err := New(store).GetEffectiveAccessPaths(context.Background(), EffectiveAccessPathRequest{
		TenantID:      "writer",
		IdentityQuery: "alice",
	})
	if err != nil {
		t.Fatalf("GetEffectiveAccessPaths() error = %v", err)
	}
	if len(store.requests) != 1 || result == nil || len(result.Paths) != 1 {
		t.Fatalf("typed requests = %d, result = %#v; want one typed request and path", len(store.requests), result)
	}
}

func TestGetEffectiveAccessPathsRejectsInvalidTypedPath(t *testing.T) {
	fixture := effectiveAccessTypedFixtureResult()
	fixture.Paths[0].RelationChain = []string{"assigned_to"}
	store := &awsExposureStubStore{effectiveResult: fixture}
	_, err := New(store).GetEffectiveAccessPaths(context.Background(), EffectiveAccessPathRequest{
		TenantID:      "writer",
		IdentityQuery: "alice",
	})
	if !errors.Is(err, ErrRuntimeUnavailable) {
		t.Fatalf("GetEffectiveAccessPaths() error = %v, want %v", err, ErrRuntimeUnavailable)
	}
}

type neighborhoodOnlyEffectiveAccessStore struct{}

func (s *neighborhoodOnlyEffectiveAccessStore) Ping(context.Context) error { return nil }

func (s *neighborhoodOnlyEffectiveAccessStore) GetEntityNeighborhood(context.Context, string, int) (*ports.EntityNeighborhood, error) {
	return nil, nil
}

func TestGetEffectiveAccessPathsFailsClosedWithoutTypedStore(t *testing.T) {
	store := &neighborhoodOnlyEffectiveAccessStore{}
	_, err := New(store).GetEffectiveAccessPaths(context.Background(), EffectiveAccessPathRequest{
		TenantID:      "writer",
		IdentityQuery: "alice",
	})
	if !errors.Is(err, ErrRuntimeUnavailable) {
		t.Fatalf("GetEffectiveAccessPaths() error = %v, want %v", err, ErrRuntimeUnavailable)
	}
}

func TestEffectiveAccessPathCountsSplitRoleAssignments(t *testing.T) {
	counts := effectiveAccessPathCounts([]EffectiveAccessPath{
		{AssignmentKind: "direct_app_assignment", Capability: GraphEntityRef{URN: "capability:app"}},
		{AssignmentKind: "group_app_assignment", Capability: GraphEntityRef{URN: "capability:app"}},
		{AssignmentKind: "role_assignment", Capability: GraphEntityRef{URN: "capability:role"}},
		{AssignmentKind: "admin_role_assignment", Capability: GraphEntityRef{URN: "capability:admin"}},
	})
	if counts.DirectAssignments != 1 || counts.GroupMediatedPaths != 1 || counts.RolePaths != 1 || counts.AdminRolePaths != 1 || counts.CapabilitiesReturned != 3 {
		t.Fatalf("counts = %#v", counts)
	}
}

func TestEffectiveAccessPathLineageFailsClosedWhenAnEventIsMissing(t *testing.T) {
	path := effectiveAccessTestPath()
	first := path.QualifyLineage()
	second := path.QualifyLineage()
	if !first.Qualified || first.ProofDigest == "" || first.ProofDigest != second.ProofDigest {
		t.Fatalf("qualified lineage is not deterministic: first=%#v second=%#v", first, second)
	}

	path.Edges[1].EventID = ""
	incomplete := path.QualifyLineage()
	if incomplete.Qualified || incomplete.ProofDigest != "" || incomplete.CompleteEdgeCount != 4 {
		t.Fatalf("incomplete lineage = %#v", incomplete)
	}
	if len(incomplete.Gaps) != 1 || incomplete.Gaps[0].Segment != "access" || incomplete.Gaps[0].EdgeIndex != 1 || strings.Join(incomplete.Gaps[0].Fields, ",") != "event_id" {
		t.Fatalf("lineage gaps = %#v", incomplete.Gaps)
	}
}

func TestEffectiveAccessPathLineageRequiresIdentityToPrincipalProof(t *testing.T) {
	path := effectiveAccessTestPath()
	path.IdentityRelationChain = nil
	path.IdentityEdges = nil
	qualification := path.QualifyLineage()
	if qualification.Qualified || qualification.ProofDigest != "" {
		t.Fatalf("identity-unbound lineage = %#v", qualification)
	}
	if len(qualification.Gaps) != 1 || qualification.Gaps[0].Segment != "identity" || qualification.Gaps[0].EdgeIndex != -1 || strings.Join(qualification.Gaps[0].Fields, ",") != "identity_path" {
		t.Fatalf("identity gaps = %#v", qualification.Gaps)
	}
}

func TestEffectiveAccessPathLineageAllowsIdentityAsPrincipal(t *testing.T) {
	path := effectiveAccessTestPath()
	path.Identity = path.Principal
	path.IdentityRelationChain = nil
	path.IdentityEdges = nil
	qualification := path.QualifyLineage()
	if !qualification.Qualified || qualification.ProofDigest == "" || qualification.EdgeCount != len(path.Edges) {
		t.Fatalf("direct-principal lineage = %#v", qualification)
	}
}

func TestEffectiveAccessPathLineageReportsStructuralGaps(t *testing.T) {
	path := effectiveAccessTestPath()
	path.Principal.URN = "urn:cerebro:writer:okta_user:different"
	qualification := path.QualifyLineage()
	if qualification.Qualified || qualification.ProofDigest != "" {
		t.Fatalf("structurally invalid lineage = %#v", qualification)
	}
	last := qualification.Gaps[len(qualification.Gaps)-1]
	if last.Segment != "access" || last.EdgeIndex != -1 || strings.Join(last.Fields, ",") != "principal" {
		t.Fatalf("structural gaps = %#v", qualification.Gaps)
	}
}

func TestEffectiveAccessPathAccessClassification(t *testing.T) {
	mediator := GraphEntityRef{URN: "urn:cerebro:writer:okta_group:grp-finance", EntityType: "okta.group", Label: "Finance Admins"}
	path := EffectiveAccessPath{
		Mediator:       &mediator,
		AccessTarget:   GraphEntityRef{URN: "urn:cerebro:writer:okta_application:payroll", EntityType: "okta.application", Label: "Payroll"},
		Entitlement:    GraphEntityRef{URN: "urn:cerebro:writer:okta_entitlement:admin", EntityType: "okta.entitlement", Label: "Admin"},
		Capability:     GraphEntityRef{URN: "urn:cerebro:writer:privileged_capability:payroll_admin", EntityType: "privileged.capability", Label: "Payroll administrator"},
		AssignmentKind: "admin_role_assignment",
		RelationChain:  []string{"member_of", "assigned_to", "can_admin"},
		Edges: []EffectiveAccessPathEdge{{
			Relation: "can_admin",
			Attributes: map[string]string{
				"data_classification": "sensitive",
			},
		}},
	}
	if !path.IsPrivileged() {
		t.Fatalf("IsPrivileged() = false, want true")
	}
	if !path.IsSensitive() {
		t.Fatalf("IsSensitive() = false, want true")
	}
	want := []string{"group_mediated", "privileged", "role_based", "sensitive"}
	if got := path.AccessClassification(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("AccessClassification() = %#v, want %#v", got, want)
	}
}

func TestEffectiveAccessPathSupportsOperationProofRequiresChangedPrivilegedOrSensitiveAccess(t *testing.T) {
	standard := EffectiveAccessPath{
		AssignmentKind: "direct_app_assignment",
		AccessTarget:   GraphEntityRef{URN: "urn:cerebro:writer:okta_application:app-1", EntityType: "okta.application", Label: "App"},
		Entitlement:    GraphEntityRef{URN: "urn:cerebro:writer:okta_entitlement:user", EntityType: "okta.entitlement", Label: "User"},
		Capability:     GraphEntityRef{URN: "urn:cerebro:writer:capability:standard_access", EntityType: "capability", Label: "Standard access"},
	}
	if standard.SupportsOperationProof(true) {
		t.Fatalf("standard SupportsOperationProof(true) = true, want false")
	}

	privileged := standard
	privileged.Capability = GraphEntityRef{URN: "urn:cerebro:writer:privileged_capability:admin", EntityType: "privileged.capability", Label: "Administrator"}
	if privileged.SupportsOperationProof(false) {
		t.Fatalf("privileged SupportsOperationProof(false) = true, want false")
	}
	if !privileged.SupportsOperationProof(true) {
		t.Fatalf("privileged SupportsOperationProof(true) = false, want true")
	}

	sensitive := standard
	sensitive.AccessTarget = GraphEntityRef{URN: "urn:cerebro:writer:okta_application:finance", EntityType: "okta.application", Label: "Finance Reports"}
	if !sensitive.SupportsOperationProof(true) {
		t.Fatalf("sensitive SupportsOperationProof(true) = false, want true")
	}
}

func effectiveAccessTypedFixtureResult() *ports.EffectiveAccessPathResult {
	path := effectiveAccessTestPath()
	typed := ports.EffectiveAccessPath{
		Identity:              effectiveAccessCatalogEntity(path.Identity),
		Principal:             effectiveAccessCatalogEntity(path.Principal),
		AccessTarget:          effectiveAccessCatalogEntity(path.AccessTarget),
		Entitlement:           effectiveAccessCatalogEntity(path.Entitlement),
		Capability:            effectiveAccessCatalogEntity(path.Capability),
		AssignmentKind:        path.AssignmentKind,
		IdentityRelationChain: append([]string(nil), path.IdentityRelationChain...),
		RelationChain:         append([]string(nil), path.RelationChain...),
	}
	if path.Mediator != nil {
		mediator := effectiveAccessCatalogEntity(*path.Mediator)
		typed.Mediator = &mediator
	}
	for _, edge := range path.IdentityEdges {
		typed.IdentityEdges = append(typed.IdentityEdges, effectiveAccessTypedEdge(edge))
	}
	for _, edge := range path.Edges {
		typed.Edges = append(typed.Edges, effectiveAccessTypedEdge(edge))
	}
	return &ports.EffectiveAccessPathResult{
		TenantID:      "writer",
		GraphRevision: 42,
		Paths:         []ports.EffectiveAccessPath{typed},
	}
}

func effectiveAccessCatalogEntity(ref GraphEntityRef) ports.CatalogEntity {
	return ports.CatalogEntity{
		URN:        ref.URN,
		TenantID:   "writer",
		EntityType: ref.EntityType,
		Label:      ref.Label,
	}
}

func effectiveAccessTypedEdge(edge EffectiveAccessPathEdge) ports.EffectiveAccessPathEdge {
	attributes := make(map[string]string, len(edge.Attributes)+2)
	for key, value := range edge.Attributes {
		attributes[key] = value
	}
	if edge.Relation == "assigned_to" {
		attributes["assignment_id"] = "asg-1"
	}
	if edge.EventID != "" {
		attributes["event_id"] = edge.EventID
	}
	if edge.At != "" {
		attributes["at"] = edge.At
	}
	encoded, err := json.Marshal(attributes)
	if err != nil {
		panic(err)
	}
	return ports.EffectiveAccessPathEdge{
		From:           effectiveAccessCatalogEntity(edge.From),
		Relation:       edge.Relation,
		To:             effectiveAccessCatalogEntity(edge.To),
		SourceID:       edge.SourceID,
		RuntimeID:      edge.RuntimeID,
		AttributesJSON: string(encoded),
	}
}

func effectiveAccessTestPath() EffectiveAccessPath {
	identity := GraphEntityRef{URN: "urn:cerebro:writer:identity:email:alice@example.com", EntityType: "identity.email", Label: "alice@example.com"}
	principal := GraphEntityRef{URN: "urn:cerebro:writer:okta_user:00u1", EntityType: "okta.user", Label: "alice@example.com"}
	mediator := GraphEntityRef{URN: "urn:cerebro:writer:okta_group:grp-security", EntityType: "okta.group", Label: "Security Engineering"}
	accessTarget := GraphEntityRef{URN: "urn:cerebro:writer:okta_application:app-aws-admin", EntityType: "okta.application", Label: "AWS Admin Console"}
	entitlement := GraphEntityRef{URN: "urn:cerebro:writer:okta_entitlement:administratoraccess", EntityType: "okta.entitlement", Label: "AdministratorAccess"}
	capability := GraphEntityRef{URN: "urn:cerebro:writer:privileged_capability:cloud_admin", EntityType: "privileged.capability", Label: "Cloud administrator"}
	path := EffectiveAccessPath{
		Identity:              identity,
		Principal:             principal,
		Mediator:              &mediator,
		AccessTarget:          accessTarget,
		Entitlement:           entitlement,
		Capability:            capability,
		AssignmentKind:        "group_app_assignment",
		IdentityRelationChain: []string{"represents_identity"},
		IdentityEdges: []EffectiveAccessPathEdge{
			{From: identity, Relation: "represents_identity", To: principal, SourceID: "okta", RuntimeID: "writer-okta", EventID: "evt-identity", At: "2026-06-10T16:00:00Z"},
		},
		RelationChain: []string{"member_of", "assigned_to", "grants_entitlement", "confers_capability"},
		Edges: []EffectiveAccessPathEdge{
			{From: principal, Relation: "member_of", To: mediator, SourceID: "okta", RuntimeID: "writer-okta", EventID: "evt-member", At: "2026-06-10T17:00:00Z"},
			{From: mediator, Relation: "assigned_to", To: accessTarget, SourceID: "okta", RuntimeID: "writer-okta", EventID: "evt-assign", At: "2026-06-10T18:00:00Z", Attributes: map[string]string{"assignment_id": "asg-1"}},
			{From: accessTarget, Relation: "grants_entitlement", To: entitlement, SourceID: "okta", RuntimeID: "writer-okta", EventID: "evt-entitlement", At: "2026-06-10T18:00:00Z"},
			{From: entitlement, Relation: "confers_capability", To: capability, SourceID: "okta", RuntimeID: "writer-okta", EventID: "evt-capability", At: "2026-06-10T18:00:00Z"},
		},
	}
	return path
}
