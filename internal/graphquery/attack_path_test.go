package graphquery

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/ports"
)

func TestGetAttackPathsRequiresTenant(t *testing.T) {
	_, err := New(&awsExposureStubStore{}).GetAttackPaths(context.Background(), AttackPathRequest{})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("GetAttackPaths() error = %v, want %v", err, ErrInvalidRequest)
	}
}

func TestGetAttackPathsQueriesAndParsesRows(t *testing.T) {
	store := &awsExposureStubStore{responses: [][]ports.CypherRow{
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
			"principal_urn":          "urn:cerebro:writer:aws_user:admin@writer.com",
			"principal_entity_type":  "aws.user",
			"principal_label":        "admin@writer.com",
			"permission_urn":         "urn:cerebro:writer:aws_aws_iam_policy:AdministratorAccess",
			"permission_entity_type": "aws.aws.iam.policy",
			"permission_label":       "AdministratorAccess",
			"reach_relation":         "can_reach",
			"access_relation":        "can_perform",
			"relation_chain":         []any{"attached_to", "runs_as"},
			"traversal_edges": []any{
				map[string]any{"from_urn": "urn:cerebro:writer:aws_network_interface:eni-1", "from_entity_type": "aws.network.interface", "from_label": "prod-web", "relation": "attached_to", "to_urn": "urn:cerebro:writer:aws_ec2_instance:i-1", "to_entity_type": "aws.ec2.instance", "to_label": "prod-web", "direction": "forward"},
				map[string]any{"from_urn": "urn:cerebro:writer:aws_ec2_instance:i-1", "from_entity_type": "aws.ec2.instance", "from_label": "prod-web", "relation": "runs_as", "to_urn": "urn:cerebro:writer:aws_user:admin@writer.com", "to_entity_type": "aws.user", "to_label": "admin@writer.com", "direction": "forward"},
			},
		}}},
	}}

	result, err := New(store).GetAttackPaths(context.Background(), AttackPathRequest{
		TenantID:  "writer",
		AccountID: "123456789012",
		Limit:     500,
	})
	if err != nil {
		t.Fatalf("GetAttackPaths() error = %v", err)
	}
	if len(store.requests) != 2 {
		t.Fatalf("query count = %d, want 2", len(store.requests))
	}
	for _, fragment := range []string{
		"MATCH proof_path = (exposed)-[:RELATION*1..4]-(principal:Entity {tenant_id: $tenant_id})",
		"relationships(proof_path)[idx].relation = 'member_of'",
		"startNode(relationships(proof_path)[idx]) = nodes(proof_path)[idx + 1]",
		"relationships(proof_path)[idx].relation <> 'member_of'",
		"startNode(relationships(proof_path)[idx]) = nodes(proof_path)[idx]",
		"traversal_edges",
	} {
		if !strings.Contains(store.requests[1].Query, fragment) {
			t.Fatalf("sample query missing %q:\n%s", fragment, store.requests[1].Query)
		}
	}
	if got := store.requests[0].Params["tenant_id"]; got != "writer" {
		t.Fatalf("tenant_id param = %v, want writer", got)
	}
	if got := store.requests[0].Params["account_id"]; got != "123456789012" {
		t.Fatalf("account_id param = %v, want 123456789012", got)
	}
	if got := store.requests[0].Params["traversal_relations"]; len(got.([]string)) == 0 {
		t.Fatalf("traversal_relations param = %v, want relation allowlist", got)
	}
	if got := store.requests[1].RowLimit; got != maxAttackPathLimit {
		t.Fatalf("sample row limit = %d, want %d", got, maxAttackPathLimit)
	}
	if result.Counts.Paths != 2 || result.Counts.ExposedResources != 1 {
		t.Fatalf("counts = %#v", result.Counts)
	}
	if len(result.Paths) != 1 || result.Paths[0].Principal.Label != "admin@writer.com" {
		t.Fatalf("paths = %#v", result.Paths)
	}
	if got := result.Paths[0].RelationChain; len(got) != 2 || got[0] != "attached_to" || got[1] != "runs_as" {
		t.Fatalf("relation chain = %#v, want attached_to -> runs_as", got)
	}
	if got := result.Paths[0].TraversalEdges; len(got) != 2 || got[0].Relation != "attached_to" || got[1].To.URN != "urn:cerebro:writer:aws_user:admin@writer.com" {
		t.Fatalf("traversal edges = %#v", got)
	}
	if result.NeighborhoodURN != "urn:cerebro:writer:aws_network_interface:eni-1" {
		t.Fatalf("neighborhood hint = %q", result.NeighborhoodURN)
	}
}

func TestAttackPathsFromRowsRequiresTraversalProof(t *testing.T) {
	paths := attackPathsFromRows([]ports.CypherRow{{Values: map[string]any{
		"public_urn":             "urn:cerebro:writer:aws_public_principal:public_internet",
		"public_entity_type":     "aws.public_principal",
		"public_label":           "public internet",
		"exposed_urn":            "urn:cerebro:writer:aws_network_interface:eni-1",
		"exposed_entity_type":    "aws.network.interface",
		"exposed_label":          "prod-web",
		"account_urn":            "urn:cerebro:writer:cloud_account:123456789012",
		"account_entity_type":    "cloud.account",
		"account_label":          "123456789012",
		"principal_urn":          "urn:cerebro:writer:aws_user:admin@writer.com",
		"principal_entity_type":  "aws.user",
		"principal_label":        "admin@writer.com",
		"permission_urn":         "urn:cerebro:writer:aws_aws_iam_policy:AdministratorAccess",
		"permission_entity_type": "aws.aws.iam.policy",
		"permission_label":       "AdministratorAccess",
		"reach_relation":         "can_reach",
		"access_relation":        "can_perform",
		"relation_chain":         []any{"runs_as"},
	}}})
	if len(paths) != 0 {
		t.Fatalf("len(paths) = %d, want 0 without traversal edge proof", len(paths))
	}
}
