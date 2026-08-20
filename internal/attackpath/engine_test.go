package attackpath

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/ports"
)

type stubStore struct {
	requests  []ports.CypherQueryRequest
	responses [][]ports.CypherRow
	err       error
}

type typedAttackPathStore struct {
	requests []ports.CloudAttackPathRequest
	result   *ports.CloudAttackPathResult
	err      error
}

func (s *stubStore) Ping(context.Context) error {
	return s.err
}

func (s *stubStore) GetEntityNeighborhood(context.Context, string, int) (*ports.EntityNeighborhood, error) {
	return nil, nil
}

func (s *stubStore) ExecuteReadCypher(_ context.Context, request ports.CypherQueryRequest) ([]ports.CypherRow, error) {
	s.requests = append(s.requests, request)
	if s.err != nil {
		return nil, s.err
	}
	if len(s.responses) == 0 {
		return nil, nil
	}
	rows := s.responses[0]
	s.responses = s.responses[1:]
	return rows, nil
}

func (s *typedAttackPathStore) ListCloudAttackPaths(_ context.Context, request ports.CloudAttackPathRequest) (*ports.CloudAttackPathResult, error) {
	s.requests = append(s.requests, request)
	return s.result, s.err
}

func TestTraverseRequiresTenant(t *testing.T) {
	_, err := New(&stubStore{}).Traverse(context.Background(), Request{})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Traverse() error = %v, want %v", err, ErrInvalidRequest)
	}
}

func TestTraverseCanRequirePerRuntimeAssertionProof(t *testing.T) {
	store := &stubStore{responses: [][]ports.CypherRow{{}, {}}}
	result, err := New(store).Traverse(context.Background(), Request{TenantID: "writer", RequireAssertionProof: true})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Filters.RequireAssertionProof || len(store.requests) != 2 {
		t.Fatalf("result=%#v requests=%d", result, len(store.requests))
	}
	for _, request := range store.requests {
		if !strings.Contains(request.Query, "RELATION_ASSERTION") {
			t.Fatalf("assertion-proof query uses logical relation:\n%s", request.Query)
		}
	}
}

func TestTraversePrefersTypedCloudAttackPathStore(t *testing.T) {
	node := func(kind, urn, label string) ports.CloudAttackPathNode {
		return ports.CloudAttackPathNode{URN: urn, EntityType: kind, Label: label}
	}
	edge := func(from ports.CloudAttackPathNode, relation string, to ports.CloudAttackPathNode, direction string) ports.CloudAttackPathEdge {
		return ports.CloudAttackPathEdge{From: from, Relation: relation, To: to, Direction: direction, SourceRuntimeID: "runtime-1", AttributesJSON: `{"source_event_id":"event-1","observed_at":"2026-07-15T08:00:00Z"}`}
	}
	public := node("aws.public_principal", "urn:cerebro:writer:aws_public_principal:public", "public")
	exposed := node("aws.network.interface", "urn:cerebro:writer:aws_network_interface:eni-1", "eni-1")
	account := node("cloud.account", "urn:cerebro:writer:cloud_account:123456789012", "123456789012")
	principal := node("aws.role", "urn:cerebro:writer:aws_role:admin", "admin")
	permission := node("aws.policy", "urn:cerebro:writer:aws_policy:admin", "admin policy")
	typed := &typedAttackPathStore{result: &ports.CloudAttackPathResult{
		TenantID: "writer",
		Counts:   ports.CloudAttackPathCounts{Paths: 1, ExposedResources: 1, PrivilegedPrincipals: 1, CloudAccounts: 1},
		Paths: []ports.CloudAttackPath{{
			PublicPrincipal:       public,
			ExposedResource:       exposed,
			CloudAccount:          account,
			Principal:             principal,
			Permission:            permission,
			ReachRelation:         "can_reach",
			AccessRelation:        "can_admin",
			RelationChain:         []string{"attached_to"},
			ExposureEdge:          edge(public, "can_reach", exposed, "forward"),
			ResourceAccountEdge:   edge(exposed, "belongs_to", account, "forward"),
			TraversalEdges:        []ports.CloudAttackPathEdge{edge(exposed, "attached_to", principal, "forward")},
			PrivilegeEdge:         edge(principal, "can_admin", permission, "forward"),
			PermissionAccountEdge: edge(permission, "belongs_to", account, "forward"),
		}},
	}}
	raw := &stubStore{}
	result, err := NewWithCapabilities(raw, typed).Traverse(context.Background(), Request{
		TenantID:              " writer ",
		AccountID:             "123456789012",
		RuntimeID:             "runtime-1",
		RequireAssertionProof: true,
		Limit:                 250,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(raw.requests) != 0 {
		t.Fatalf("raw Cypher requests = %d, want typed path read only", len(raw.requests))
	}
	if len(typed.requests) != 1 || typed.requests[0].Limit != MaxLimit || typed.requests[0].Depth != DefaultDepth || !typed.requests[0].RequireAssertionProof {
		t.Fatalf("typed requests = %#v", typed.requests)
	}
	if result.Counts.Paths != 1 || len(result.Paths) != 1 || result.NeighborhoodURN != exposed.URN {
		t.Fatalf("result = %#v", result)
	}
	if result.Paths[0].PrivilegeEdge.SourceEventID != "event-1" || result.Paths[0].PrivilegeEdge.ObservedAt.IsZero() {
		t.Fatalf("privilege edge provenance = %#v", result.Paths[0].PrivilegeEdge)
	}
}

func TestTraverseQueriesAndParsesRows(t *testing.T) {
	store := &stubStore{responses: [][]ports.CypherRow{
		{{Values: map[string]any{
			"path_count":                 int64(2),
			"exposed_resource_count":     int64(1),
			"privileged_principal_count": int64(1),
			"cloud_account_count":        int64(1),
		}}},
		{{Values: map[string]any{
			"public_urn":             "urn:cerebro:writer:aws_public_principal:public_internet",
			"public_entity_type":     "aws.public_principal",
			"public_label":           "public internet",
			"exposed_urn":            "urn:cerebro:writer:aws_network_interface:eni-1",
			"exposed_entity_type":    "aws.network.interface",
			"exposed_label":          "prod-web",
			"account_urn":            "urn:cerebro:writer:cloud_account:123456789012",
			"account_entity_type":    "cloud.account",
			"account_label":          "123456789012",
			"principal_urn":          "urn:cerebro:writer:aws_user:admin",
			"principal_entity_type":  "aws.user",
			"principal_label":        "admin",
			"permission_urn":         "urn:cerebro:writer:aws_iam_policy:AdministratorAccess",
			"permission_entity_type": "aws.iam.policy",
			"permission_label":       "AdministratorAccess",
			"ownerships": []any{
				map[string]any{
					"owner_urn": "urn:cerebro:writer:team:platform-security", "owner_entity_type": "team", "owner_label": "Platform Security",
					"from_urn": "urn:cerebro:writer:aws_network_interface:eni-1", "from_entity_type": "aws.network.interface", "from_label": "prod-web",
					"relation": "owned_by",
					"to_urn":   "urn:cerebro:writer:team:platform-security", "to_entity_type": "team", "to_label": "Platform Security",
					"direction": "forward", "source_id": "cloud_inventory", "source_runtime_id": "runtime-1",
					"attributes_json": `{"source_event_id":"event-owner","at":"2026-07-15T08:04:00Z"}`,
				},
				map[string]any{
					"owner_urn": "urn:cerebro:writer:team:service-security", "owner_entity_type": "team", "owner_label": "Service Security",
					"from_urn": "urn:cerebro:writer:aws_network_interface:eni-1", "from_entity_type": "aws.network.interface", "from_label": "prod-web",
					"relation": "owned_by",
					"to_urn":   "urn:cerebro:writer:team:service-security", "to_entity_type": "team", "to_label": "Service Security",
					"direction": "forward", "source_id": "cloud_inventory", "source_runtime_id": "runtime-1",
					"attributes_json": `{"source_event_id":"event-owner-2","at":"2026-07-15T08:04:30Z"}`,
				},
			},
			"reach_relation":  "can_reach",
			"access_relation": "can_perform",
			"relation_chain":  []any{"attached_to", "runs_as"},
			"exposure_edge": map[string]any{
				"from_urn": "urn:cerebro:writer:aws_public_principal:public_internet", "from_entity_type": "aws.public_principal", "from_label": "public internet",
				"relation": "can_reach",
				"to_urn":   "urn:cerebro:writer:aws_network_interface:eni-1", "to_entity_type": "aws.network.interface", "to_label": "prod-web",
				"direction": "forward", "source_id": "cloud_inventory", "source_runtime_id": "runtime-1",
				"assertion_runtime_ids": []any{"runtime-2", "runtime-1", "runtime-2"},
				"attributes_json":       `{"source_runtime_id":"runtime-1","event_id":"event-exposure","at":"2026-07-15T08:00:00.123456789Z","private_note":"not returned"}`,
			},
			"resource_account_edge": map[string]any{
				"from_urn": "urn:cerebro:writer:aws_network_interface:eni-1", "from_entity_type": "aws.network.interface", "from_label": "prod-web",
				"relation": "belongs_to",
				"to_urn":   "urn:cerebro:writer:cloud_account:123456789012", "to_entity_type": "cloud.account", "to_label": "123456789012",
				"direction": "forward", "source_id": "cloud_inventory", "source_runtime_id": "runtime-1",
				"attributes_json": `{"source_event_id":"event-resource-account","at":"2026-07-15T08:00:30Z"}`,
			},
			"traversal_edges": []any{
				map[string]any{"from_urn": "urn:cerebro:writer:aws_network_interface:eni-1", "from_entity_type": "aws.network.interface", "from_label": "prod-web", "relation": "attached_to", "to_urn": "urn:cerebro:writer:aws_ec2_instance:i-1", "to_entity_type": "aws.ec2.instance", "to_label": "prod-web", "direction": "forward", "source_id": "cloud_inventory", "attributes_json": `{"source_runtime_id":"runtime-1","source_event_id":"event-interface","observed_at":"2026-07-15T08:01:00Z"}`},
				map[string]any{"from_urn": "urn:cerebro:writer:aws_ec2_instance:i-1", "from_entity_type": "aws.ec2.instance", "from_label": "prod-web", "relation": "runs_as", "to_urn": "urn:cerebro:writer:aws_user:admin", "to_entity_type": "aws.user", "to_label": "admin", "direction": "forward", "source_id": "cloud_inventory", "attributes_json": `{"source_runtime_id":"runtime-1","event_id":"event-role","at":"2026-07-15T08:02:00Z"}`},
			},
			"privilege_edge": map[string]any{
				"from_urn": "urn:cerebro:writer:aws_user:admin", "from_entity_type": "aws.user", "from_label": "admin",
				"relation": "can_perform",
				"to_urn":   "urn:cerebro:writer:aws_iam_policy:AdministratorAccess", "to_entity_type": "aws.iam.policy", "to_label": "AdministratorAccess",
				"direction": "forward", "source_id": "cloud_inventory", "source_runtime_id": "runtime-1",
				"attributes_json": `{"source_runtime_id":"runtime-1","source_event_id":"event-policy","at":"2026-07-15T08:03:00Z"}`,
			},
			"permission_account_edge": map[string]any{
				"from_urn": "urn:cerebro:writer:aws_iam_policy:AdministratorAccess", "from_entity_type": "aws.iam.policy", "from_label": "AdministratorAccess",
				"relation": "belongs_to",
				"to_urn":   "urn:cerebro:writer:cloud_account:123456789012", "to_entity_type": "cloud.account", "to_label": "123456789012",
				"direction": "forward", "source_id": "cloud_inventory", "source_runtime_id": "runtime-1",
				"attributes_json": `{"source_event_id":"event-permission-account","at":"2026-07-15T08:03:30Z"}`,
			},
		}}},
	}}

	result, err := New(store).Traverse(context.Background(), Request{
		TenantID:  " writer ",
		AccountID: "123456789012",
		RuntimeID: "runtime-1",
		Limit:     500,
	})
	if err != nil {
		t.Fatalf("Traverse() error = %v", err)
	}
	if len(store.requests) != 2 {
		t.Fatalf("query count = %d, want 2", len(store.requests))
	}
	if got := store.requests[0].Params["tenant_id"]; got != "writer" {
		t.Fatalf("tenant_id param = %v, want writer", got)
	}
	if got := store.requests[0].Params["account_id"]; got != "123456789012" {
		t.Fatalf("account_id param = %v, want 123456789012", got)
	}
	if got := store.requests[0].Params["runtime_id"]; got != "runtime-1" {
		t.Fatalf("runtime_id param = %v, want runtime-1", got)
	}
	if got := store.requests[0].Params["traversal_relations"]; len(got.([]string)) == 0 {
		t.Fatalf("traversal_relations param = %v, want relation allowlist", got)
	}
	if got := store.requests[0].Params["access_relations"]; len(got.([]string)) == 0 {
		t.Fatalf("access_relations param = %v, want relation allowlist", got)
	}
	if got := store.requests[1].RowLimit; got != MaxLimit {
		t.Fatalf("sample row limit = %d, want %d", got, MaxLimit)
	}
	for _, fragment := range []string{
		"RELATION*1..4",
		"relationships(proof_path)[idx].relation = 'member_of'",
		"relation: 'owned_by'",
		"ownership.runtime_id = $runtime_id",
		"ORDER BY candidate_owner.urn, candidate_owner.entity_type, candidate_owner.label",
		"reach.runtime_id = $runtime_id",
		"resource_account.runtime_id = $runtime_id",
		"access.runtime_id = $runtime_id",
		"permission_account.runtime_id = $runtime_id",
		"all(rel IN relationships(proof_path) WHERE rel.runtime_id = $runtime_id)",
		"collect(reach) AS reach_assertions",
		"assertion_runtime_ids: reach_assertion_runtime_ids",
		"AS exposure_edge",
		"traversal_edges",
		"AS privilege_edge",
	} {
		if !strings.Contains(store.requests[1].Query, fragment) {
			t.Fatalf("sample query missing %q:\n%s", fragment, store.requests[1].Query)
		}
	}
	if result.Counts.Paths != 2 || result.Counts.ExposedResources != 1 {
		t.Fatalf("counts = %#v", result.Counts)
	}
	if len(result.Paths) != 1 || result.Paths[0].Principal.Label != "admin" {
		t.Fatalf("paths = %#v", result.Paths)
	}
	if got := result.Paths[0].TraversalEdges; len(got) != 2 || got[0].Relation != "attached_to" || got[1].To.URN != "urn:cerebro:writer:aws_user:admin" {
		t.Fatalf("traversal edges = %#v", got)
	}
	if got := result.Paths[0].Ownerships; len(got) != 2 || got[0].Owner.URN != "urn:cerebro:writer:team:platform-security" || got[1].Edge.SourceEventID != "event-owner-2" {
		t.Fatalf("ownerships = %#v", got)
	}
	if got := result.Paths[0].ExposureEdge; got.SourceID != "cloud_inventory" || got.SourceRuntimeID != "runtime-1" || got.SourceEventID != "event-exposure" || got.ObservedAt.Format("2006-01-02T15:04:05.999999999Z07:00") != "2026-07-15T08:00:00.123456789Z" {
		t.Fatalf("exposure edge = %#v", got)
	}
	if got := result.Paths[0].ExposureEdge.AssertionRuntimeIDs; !reflect.DeepEqual(got, []string{"runtime-1", "runtime-2"}) {
		t.Fatalf("exposure assertion runtime ids = %#v", got)
	}
	if got := result.Paths[0].TraversalEdges[0]; got.SourceEventID != "event-interface" || got.ObservedAt.IsZero() {
		t.Fatalf("first traversal edge = %#v", got)
	}
	if got := result.Paths[0].PrivilegeEdge; got.SourceEventID != "event-policy" || got.From.URN != result.Paths[0].Principal.URN || got.To.URN != result.Paths[0].Permission.URN {
		t.Fatalf("privilege edge = %#v", got)
	}
	if result.NeighborhoodURN != "urn:cerebro:writer:aws_network_interface:eni-1" {
		t.Fatalf("neighborhood hint = %q", result.NeighborhoodURN)
	}
}

func TestPathsFromRowsRequiresTraversalProof(t *testing.T) {
	paths := PathsFromRows([]ports.CypherRow{{Values: map[string]any{
		"public_urn":             "urn:cerebro:writer:aws_public_principal:public_internet",
		"public_entity_type":     "aws.public_principal",
		"public_label":           "public internet",
		"exposed_urn":            "urn:cerebro:writer:aws_network_interface:eni-1",
		"exposed_entity_type":    "aws.network.interface",
		"exposed_label":          "prod-web",
		"account_urn":            "urn:cerebro:writer:cloud_account:123456789012",
		"account_entity_type":    "cloud.account",
		"account_label":          "123456789012",
		"principal_urn":          "urn:cerebro:writer:aws_user:admin",
		"principal_entity_type":  "aws.user",
		"principal_label":        "admin",
		"permission_urn":         "urn:cerebro:writer:aws_iam_policy:AdministratorAccess",
		"permission_entity_type": "aws.iam.policy",
		"permission_label":       "AdministratorAccess",
		"reach_relation":         "can_reach",
		"access_relation":        "can_perform",
		"relation_chain":         []any{"runs_as"},
	}}})
	if len(paths) != 0 {
		t.Fatalf("len(paths) = %d, want 0 without traversal edge proof", len(paths))
	}
}

func TestQueryDepthIsBounded(t *testing.T) {
	if !strings.Contains(SamplesQuery(999), "RELATION*1..6") {
		t.Fatalf("SamplesQuery(999) did not cap traversal depth: %s", SamplesQuery(999))
	}
}

func TestEdgeFromItemSelectsProvenanceWithoutReturningRawAttributes(t *testing.T) {
	edge := edgeFromItem(map[string]any{
		"from_urn":              "urn:source",
		"relation":              "runs_as",
		"to_urn":                "urn:target",
		"direction":             "forward",
		"source_id":             "inventory",
		"source_runtime_id":     "runtime-property",
		"assertion_runtime_ids": []any{"runtime-second", "runtime-property", "runtime-second"},
		"attributes_json":       `{"source_runtime_id":"runtime-attributes","source_event_id":"event-1","observed_at":"2026-07-15T08:00:00-07:00","private_note":"must-not-escape"}`,
	})
	if edge.SourceID != "inventory" || edge.SourceRuntimeID != "runtime-property" || edge.SourceEventID != "event-1" || edge.ObservedAt.Format(time.RFC3339) != "2026-07-15T15:00:00Z" {
		t.Fatalf("edge = %#v", edge)
	}
	if !reflect.DeepEqual(edge.AssertionRuntimeIDs, []string{"runtime-property", "runtime-second"}) {
		t.Fatalf("assertion runtime ids = %#v", edge.AssertionRuntimeIDs)
	}
	encoded, err := json.Marshal(edge)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if strings.Contains(string(encoded), "private_note") || strings.Contains(string(encoded), "must-not-escape") || strings.Contains(string(encoded), "attributes_json") {
		t.Fatalf("edge JSON exposed raw attributes: %s", encoded)
	}
}

func TestBoundaryProofMatchesRequiresExactEndpointsAndAllowedPrivilege(t *testing.T) {
	path := Path{
		PublicPrincipal: NodeRef{URN: "urn:public"},
		ExposedResource: NodeRef{URN: "urn:exposed"},
		Principal:       NodeRef{URN: "urn:principal"},
		Permission:      NodeRef{URN: "urn:permission"},
		ReachRelation:   "can_reach",
		AccessRelation:  "can_admin",
		ExposureEdge:    Edge{From: NodeRef{URN: "urn:public"}, Relation: "can_reach", To: NodeRef{URN: "urn:exposed"}, Direction: "forward"},
		PrivilegeEdge:   Edge{From: NodeRef{URN: "urn:principal"}, Relation: "can_admin", To: NodeRef{URN: "urn:permission"}, Direction: "forward"},
	}
	if !BoundaryProofMatches(path) {
		t.Fatal("BoundaryProofMatches() = false, want true")
	}
	path.PrivilegeEdge.To.URN = "urn:other"
	if BoundaryProofMatches(path) {
		t.Fatal("BoundaryProofMatches() = true for mismatched privilege endpoint")
	}
}
