package graphquery

import (
	"context"
	"errors"
	"testing"

	"github.com/writer/cerebro/internal/attackpath"
	"github.com/writer/cerebro/internal/ports"
)

type graphAttackPathStore struct {
	requests []ports.CloudAttackPathRequest
	result   *ports.CloudAttackPathResult
	err      error
}

func (s *graphAttackPathStore) ListCloudAttackPaths(_ context.Context, request ports.CloudAttackPathRequest) (*ports.CloudAttackPathResult, error) {
	s.requests = append(s.requests, request)
	return s.result, s.err
}

func TestGetAttackPathsRequiresTenant(t *testing.T) {
	store := &graphAttackPathStore{}
	_, err := NewWithCapabilities(nil, nil, nil, nil, store).GetAttackPaths(context.Background(), AttackPathRequest{})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("GetAttackPaths() error = %v, want %v", err, ErrInvalidRequest)
	}
}

func TestGetAttackPathsUsesTypedCapability(t *testing.T) {
	path := graphTypedAttackPath("writer", "typed")
	store := &graphAttackPathStore{result: &ports.CloudAttackPathResult{
		TenantID: "writer",
		Counts:   ports.CloudAttackPathCounts{Paths: 1, ExposedResources: 1, PrivilegedPrincipals: 1, CloudAccounts: 1},
		Paths:    []ports.CloudAttackPath{path},
	}}
	result, err := NewWithCapabilities(nil, nil, nil, nil, store).GetAttackPaths(context.Background(), AttackPathRequest{
		TenantID:  "writer",
		AccountID: "123456789012",
		Limit:     500,
	})
	if err != nil {
		t.Fatalf("GetAttackPaths() error = %v", err)
	}
	if len(store.requests) != 1 || store.requests[0].TenantID != "writer" || store.requests[0].AccountID != "123456789012" || store.requests[0].Limit != attackpath.MaxLimit {
		t.Fatalf("typed requests = %#v", store.requests)
	}
	if result.Counts.Paths != 1 || len(result.Paths) != 1 || result.Paths[0].Principal.Label != "admin" {
		t.Fatalf("result = %#v", result)
	}
	if result.NeighborhoodURN != path.ExposedResource.URN {
		t.Fatalf("neighborhood hint = %q", result.NeighborhoodURN)
	}
}

func TestGetAttackPathsDoesNotUseRawCypherFallback(t *testing.T) {
	raw := &awsExposureStubStore{}
	_, err := New(raw).GetAttackPaths(context.Background(), AttackPathRequest{TenantID: "writer"})
	if !errors.Is(err, ErrRuntimeUnavailable) {
		t.Fatalf("GetAttackPaths() error = %v, want %v", err, ErrRuntimeUnavailable)
	}
	if len(raw.requests) != 0 {
		t.Fatalf("raw Cypher requests = %d, want none", len(raw.requests))
	}
}

func graphTypedAttackPath(tenantID, suffix string) ports.CloudAttackPath {
	node := func(kind, id, label string) ports.CloudAttackPathNode {
		return ports.CloudAttackPathNode{URN: "urn:cerebro:" + tenantID + ":" + id + ":" + suffix, EntityType: kind, Label: label}
	}
	edge := func(from ports.CloudAttackPathNode, relation string, to ports.CloudAttackPathNode) ports.CloudAttackPathEdge {
		return ports.CloudAttackPathEdge{From: from, Relation: relation, To: to, Direction: "forward", SourceID: "aws", SourceRuntimeID: "runtime-1"}
	}
	public := node("aws.public_principal", "public", "public internet")
	exposed := node("aws.network.interface", "resource", "prod-web")
	account := node("cloud.account", "account", "123456789012")
	principal := node("aws.user", "principal", "admin")
	permission := node("aws.iam.policy", "permission", "AdministratorAccess")
	return ports.CloudAttackPath{
		PublicPrincipal: public, ExposedResource: exposed, CloudAccount: account, Principal: principal, Permission: permission,
		ReachRelation:         "can_reach",
		AccessRelation:        "can_admin",
		RelationChain:         []string{"runs_as"},
		ExposureEdge:          edge(public, "can_reach", exposed),
		ResourceAccountEdge:   edge(exposed, "belongs_to", account),
		TraversalEdges:        []ports.CloudAttackPathEdge{edge(exposed, "runs_as", principal)},
		PrivilegeEdge:         edge(principal, "can_admin", permission),
		PermissionAccountEdge: edge(permission, "belongs_to", account),
	}
}
