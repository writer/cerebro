package graphquery

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/ports"
)

func TestGetCrownJewelRanksRequiresTenant(t *testing.T) {
	_, err := New(&awsExposureStubStore{}).GetCrownJewelRanks(context.Background(), CrownJewelRankRequest{})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("GetCrownJewelRanks() error = %v, want %v", err, ErrInvalidRequest)
	}
}

func TestGetCrownJewelRanksQueriesAndRanksPersonalizedSubgraph(t *testing.T) {
	store := &awsExposureStubStore{responses: [][]ports.CypherRow{
		{{Values: map[string]any{
			"seed_urn":         "urn:cerebro:writer:aws_secret_store:prod-secrets",
			"seed_entity_type": "aws.secret_store",
			"seed_label":       "prod-secrets",
		}}},
		{
			{Values: crownJewelRankPathRow(
				"urn:cerebro:writer:aws_secret_store:prod-secrets",
				[]GraphEntityRef{
					{URN: "urn:cerebro:writer:aws_secret_store:prod-secrets", EntityType: "aws.secret_store", Label: "prod-secrets"},
					{URN: "urn:cerebro:writer:aws_public_principal:public_internet", EntityType: "aws.public_principal", Label: "public_internet"},
				},
				[]string{"can_reach"},
			)},
			{Values: crownJewelRankPathRow(
				"urn:cerebro:writer:aws_secret_store:prod-secrets",
				[]GraphEntityRef{
					{URN: "urn:cerebro:writer:aws_secret_store:prod-secrets", EntityType: "aws.secret_store", Label: "prod-secrets"},
					{URN: "urn:cerebro:writer:cloud_account:123456789012", EntityType: "cloud.account", Label: "123456789012"},
				},
				[]string{"belongs_to"},
			)},
			{Values: crownJewelRankPathRow(
				"urn:cerebro:writer:aws_secret_store:prod-secrets",
				[]GraphEntityRef{
					{URN: "urn:cerebro:writer:cloud_account:123456789012", EntityType: "cloud.account", Label: "123456789012"},
					{URN: "urn:cerebro:writer:aws_secret_store:prod-secrets", EntityType: "aws.secret_store", Label: "prod-secrets"},
				},
				[]string{"belongs_to"},
			)},
			{Values: crownJewelRankPathRow(
				"urn:cerebro:writer:aws_secret_store:prod-secrets",
				[]GraphEntityRef{
					{URN: "urn:cerebro:writer:aws_secret_store:prod-secrets", EntityType: "aws.secret_store", Label: "prod-secrets"},
					{URN: "urn:cerebro:writer:cloud_account:123456789012", EntityType: "cloud.account", Label: "123456789012"},
					{URN: "urn:cerebro:writer:aws_iam_policy:AdministratorAccess", EntityType: "aws.iam_policy", Label: "AdministratorAccess"},
					{URN: "urn:cerebro:writer:aws_iam_role:admin", EntityType: "aws.iam_role", Label: "admin"},
				},
				[]string{"belongs_to", "belongs_to", "can_perform"},
			)},
		},
	}}

	result, err := New(store).GetCrownJewelRanks(context.Background(), CrownJewelRankRequest{
		TenantID:   "writer",
		AccountID:  "123456789012",
		EntityType: "aws.secret_store",
		Depth:      3,
		Limit:      5,
		SeedLimit:  5,
	})
	if err != nil {
		t.Fatalf("GetCrownJewelRanks() error = %v", err)
	}
	if len(store.requests) != 2 {
		t.Fatalf("query count = %d, want 2", len(store.requests))
	}
	if got := store.requests[0].Params["account_id"]; got != "123456789012" {
		t.Fatalf("account_id param = %v, want 123456789012", got)
	}
	if !strings.Contains(store.requests[1].Query, "*1..3") {
		t.Fatalf("edge query = %q, want depth 3", store.requests[1].Query)
	}
	if !strings.Contains(store.requests[1].Query, "LIMIT $path_limit_per_seed") {
		t.Fatalf("edge query = %q, want per-seed complete-path cap", store.requests[1].Query)
	}
	if got := store.requests[1].Params["path_limit_per_seed"]; got != int64(ports.MaxCypherQueryRows) {
		t.Fatalf("path_limit_per_seed = %v, want %d", got, ports.MaxCypherQueryRows)
	}
	if !strings.Contains(store.requests[1].Query, "ORDER BY path_len, path_key") {
		t.Fatalf("edge query = %q, want stable complete-path ordering", store.requests[1].Query)
	}
	if !strings.Contains(store.requests[1].Query, "ORDER BY seed_urn, path_len, path_key") {
		t.Fatalf("edge query = %q, want stable path row ordering", store.requests[1].Query)
	}
	relations, ok := store.requests[1].Params["relations"].([]string)
	if !ok || slices.Contains(relations, "tagged_as") {
		t.Fatalf("traversal relations = %#v, want shared crown_jewel tag excluded", store.requests[1].Params["relations"])
	}
	if result.Counts.Seeds != 1 || result.Counts.Relations != 4 || len(result.Rankings) == 0 {
		t.Fatalf("result = %#v", result)
	}
	secret, ok := crownJewelRankByURN(result.Rankings, "urn:cerebro:writer:aws_secret_store:prod-secrets")
	if !ok || !secret.Seed || secret.Distance != 0 || !slices.Contains(secret.Relations, "can_reach") {
		t.Fatalf("secret rank = %#v, ok=%t", secret, ok)
	}
	role, ok := crownJewelRankByURN(result.Rankings, "urn:cerebro:writer:aws_iam_role:admin")
	if !ok || role.Score <= 0 || !slices.Contains(role.Relations, "can_perform") {
		t.Fatalf("role rank = %#v, ok=%t", role, ok)
	}
}

//nolint:unparam // Helper keeps seed URN explicit in crown-jewel path fixtures.
func crownJewelRankPathRow(seedURN string, nodes []GraphEntityRef, relations []string) map[string]any {
	pathNodes := make([]any, 0, len(nodes))
	for _, node := range nodes {
		pathNodes = append(pathNodes, map[string]any{
			"urn":         node.URN,
			"entity_type": node.EntityType,
			"label":       node.Label,
		})
	}
	pathRelations := make([]any, 0, len(relations))
	for _, relation := range relations {
		pathRelations = append(pathRelations, relation)
	}
	return map[string]any{
		"seed_urn":       seedURN,
		"path_nodes":     pathNodes,
		"path_relations": pathRelations,
	}
}

func crownJewelRankByURN(ranks []CrownJewelRank, urn string) (CrownJewelRank, bool) {
	for _, rank := range ranks {
		if rank.Entity.URN == urn {
			return rank, true
		}
	}
	return CrownJewelRank{}, false
}
