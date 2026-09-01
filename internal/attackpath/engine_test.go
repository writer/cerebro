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

type typedAttackPathStore struct {
	requests []ports.CloudAttackPathRequest
	result   *ports.CloudAttackPathResult
	err      error
}

func (s *typedAttackPathStore) ListCloudAttackPaths(_ context.Context, request ports.CloudAttackPathRequest) (*ports.CloudAttackPathResult, error) {
	s.requests = append(s.requests, request)
	return s.result, s.err
}

func TestTraverseRequiresTypedRuntimeAndTenant(t *testing.T) {
	if _, err := New(nil).Traverse(context.Background(), Request{TenantID: "writer"}); !errors.Is(err, ErrRuntimeUnavailable) {
		t.Fatalf("Traverse() error = %v, want %v", err, ErrRuntimeUnavailable)
	}
	_, err := New(&typedAttackPathStore{}).Traverse(context.Background(), Request{})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Traverse() error = %v, want %v", err, ErrInvalidRequest)
	}
}

func TestTraverseUsesTypedCloudAttackPathStore(t *testing.T) {
	path := validTypedPath("writer")
	typed := &typedAttackPathStore{result: &ports.CloudAttackPathResult{
		TenantID: "writer",
		Counts:   ports.CloudAttackPathCounts{Paths: 1, ExposedResources: 1, PrivilegedPrincipals: 1, CloudAccounts: 1},
		Paths:    []ports.CloudAttackPath{path},
	}}
	result, err := New(typed).Traverse(context.Background(), Request{
		TenantID:              " writer ",
		AccountID:             " 123456789012 ",
		RuntimeID:             " runtime-1 ",
		RequireAssertionProof: true,
		Limit:                 250,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(typed.requests) != 1 {
		t.Fatalf("typed requests = %d, want one", len(typed.requests))
	}
	request := typed.requests[0]
	if request.TenantID != "writer" || request.AccountID != "123456789012" || request.RuntimeID != "runtime-1" || request.Limit != MaxLimit || request.Depth != DefaultDepth || !request.RequireAssertionProof {
		t.Fatalf("typed request = %#v", request)
	}
	if result.Counts.Paths != 1 || len(result.Paths) != 1 || result.NeighborhoodURN != path.ExposedResource.URN {
		t.Fatalf("result = %#v", result)
	}
	if result.Paths[0].PrivilegeEdge.SourceEventID != "event-1" || result.Paths[0].PrivilegeEdge.ObservedAt.IsZero() {
		t.Fatalf("privilege edge provenance = %#v", result.Paths[0].PrivilegeEdge)
	}
	if got := result.Paths[0].PrivilegeEdge.AssertionRuntimeIDs; !reflect.DeepEqual(got, []string{"runtime-1", "runtime-2"}) {
		t.Fatalf("assertion runtime ids = %#v", got)
	}
}

func TestTraverseRejectsMalformedTypedEnvelope(t *testing.T) {
	valid := validTypedPath("writer")
	for name, result := range map[string]*ports.CloudAttackPathResult{
		"nil":           nil,
		"wrong tenant":  {TenantID: "other"},
		"over bound":    {TenantID: "writer", Paths: []ports.CloudAttackPath{valid, valid}},
		"bad truncated": {TenantID: "writer", Truncated: true},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := New(&typedAttackPathStore{result: result}).Traverse(context.Background(), Request{TenantID: "writer", Limit: 1})
			if !errors.Is(err, ErrRuntimeUnavailable) {
				t.Fatalf("Traverse() error = %v, want %v", err, ErrRuntimeUnavailable)
			}
		})
	}
}

func TestTraverseDropsTypedPathWithoutCompleteProof(t *testing.T) {
	path := validTypedPath("writer")
	path.TraversalEdges = nil
	result, err := New(&typedAttackPathStore{result: &ports.CloudAttackPathResult{
		TenantID: "writer",
		Counts:   ports.CloudAttackPathCounts{Paths: 1},
		Paths:    []ports.CloudAttackPath{path},
	}}).Traverse(context.Background(), Request{TenantID: "writer"})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Paths) != 0 {
		t.Fatalf("paths = %#v, want incomplete proof omitted", result.Paths)
	}
}

func TestNormalizeBounds(t *testing.T) {
	if NormalizeLimit(0) != DefaultLimit || NormalizeLimit(MaxLimit+1) != MaxLimit {
		t.Fatalf("NormalizeLimit() did not enforce [%d,%d]", DefaultLimit, MaxLimit)
	}
	if NormalizeDepth(0) != DefaultDepth || NormalizeDepth(MaxDepth+1) != MaxDepth {
		t.Fatalf("NormalizeDepth() did not enforce [%d,%d]", DefaultDepth, MaxDepth)
	}
}

func TestTypedEdgeSelectsProvenanceWithoutReturningRawAttributes(t *testing.T) {
	edge := edgeFromTyped(ports.CloudAttackPathEdge{
		From:                ports.CloudAttackPathNode{URN: "urn:source"},
		Relation:            "runs_as",
		To:                  ports.CloudAttackPathNode{URN: "urn:target"},
		Direction:           "forward",
		SourceID:            "inventory",
		SourceRuntimeID:     "runtime-property",
		AssertionRuntimeIDs: []string{"runtime-second", "runtime-property", "runtime-second"},
		AttributesJSON:      `{"source_runtime_id":"runtime-attributes","source_event_id":"event-1","observed_at":"2026-07-15T08:00:00-07:00","private_note":"must-not-escape"}`,
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

func validTypedPath(tenantID string) ports.CloudAttackPath {
	node := func(kind, suffix, label string) ports.CloudAttackPathNode {
		return ports.CloudAttackPathNode{URN: "urn:cerebro:" + tenantID + ":" + suffix, EntityType: kind, Label: label}
	}
	edge := func(from ports.CloudAttackPathNode, relation string, to ports.CloudAttackPathNode) ports.CloudAttackPathEdge {
		return ports.CloudAttackPathEdge{
			From: from, Relation: relation, To: to, Direction: "forward",
			SourceRuntimeID: "runtime-1", AssertionRuntimeIDs: []string{"runtime-2"},
			AttributesJSON: `{"source_event_id":"event-1","observed_at":"2026-07-15T08:00:00Z"}`,
		}
	}
	public := node("aws.public_principal", "aws_public_principal:public", "public")
	exposed := node("aws.network.interface", "aws_network_interface:eni-1", "eni-1")
	account := node("cloud.account", "cloud_account:123456789012", "123456789012")
	principal := node("aws.role", "aws_role:admin", "admin")
	permission := node("aws.policy", "aws_policy:admin", "admin policy")
	owner := node("team", "team:security", "Security")
	return ports.CloudAttackPath{
		PublicPrincipal: public, ExposedResource: exposed, CloudAccount: account, Principal: principal, Permission: permission,
		Ownerships:            []ports.CloudAttackPathOwnership{{Owner: owner, Edge: edge(exposed, "owned_by", owner)}},
		ReachRelation:         "can_reach",
		AccessRelation:        "can_admin",
		RelationChain:         []string{"attached_to"},
		ExposureEdge:          edge(public, "can_reach", exposed),
		ResourceAccountEdge:   edge(exposed, "belongs_to", account),
		TraversalEdges:        []ports.CloudAttackPathEdge{edge(exposed, "attached_to", principal)},
		PrivilegeEdge:         edge(principal, "can_admin", permission),
		PermissionAccountEdge: edge(permission, "belongs_to", account),
	}
}
