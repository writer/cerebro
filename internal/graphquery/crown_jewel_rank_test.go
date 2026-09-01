package graphquery

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/writer/cerebro/internal/ports"
)

type crownJewelPathStub struct {
	request ports.CrownJewelPathRequest
	result  *ports.CrownJewelPathResult
	err     error
}

func (s *crownJewelPathStub) ListCrownJewelPaths(_ context.Context, request ports.CrownJewelPathRequest) (*ports.CrownJewelPathResult, error) {
	s.request = request
	return s.result, s.err
}

func TestGetCrownJewelRanksRequiresTenant(t *testing.T) {
	_, err := NewWithCapabilities(nil, nil, nil, &crownJewelPathStub{}).GetCrownJewelRanks(context.Background(), CrownJewelRankRequest{})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("GetCrownJewelRanks() error = %v, want %v", err, ErrInvalidRequest)
	}
}

func TestGetCrownJewelRanksUsesTypedRustPaths(t *testing.T) {
	secret := crownJewelCatalogEntity("urn:cerebro:writer:aws_secret_store:prod-secrets", "aws.secret_store", "prod-secrets")
	public := crownJewelCatalogEntity("urn:cerebro:writer:aws_public_principal:public_internet", "aws.public_principal", "public_internet")
	account := crownJewelCatalogEntity("urn:cerebro:writer:cloud_account:123456789012", "cloud.account", "123456789012")
	policy := crownJewelCatalogEntity("urn:cerebro:writer:aws_iam_policy:AdministratorAccess", "aws.iam_policy", "AdministratorAccess")
	role := crownJewelCatalogEntity("urn:cerebro:writer:aws_iam_role:admin", "aws.iam_role", "admin")
	store := &crownJewelPathStub{result: &ports.CrownJewelPathResult{
		TenantID: "writer",
		Seeds:    []ports.CatalogEntity{secret},
		Paths: []ports.CrownJewelPath{
			{Seed: secret, Nodes: []ports.CatalogEntity{secret, public}, Relations: []string{"can_reach"}},
			{Seed: secret, Nodes: []ports.CatalogEntity{secret, account}, Relations: []string{"belongs_to"}},
			{Seed: secret, Nodes: []ports.CatalogEntity{secret, account, policy, role}, Relations: []string{"belongs_to", "belongs_to", "can_perform"}},
		},
	}}

	result, err := NewWithCapabilities(nil, nil, nil, store).GetCrownJewelRanks(context.Background(), CrownJewelRankRequest{
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
	if store.request != (ports.CrownJewelPathRequest{
		TenantID: "writer", AccountID: "123456789012", EntityType: "aws.secret_store",
		Limit: ports.MaxCypherQueryRows, SeedLimit: 5, Depth: 3,
	}) {
		t.Fatalf("typed request = %#v", store.request)
	}
	if result.Counts.Seeds != 1 || result.Counts.Relations != 4 || len(result.Rankings) == 0 {
		t.Fatalf("result = %#v", result)
	}
	secretRank, ok := crownJewelRankByURN(result.Rankings, secret.URN)
	if !ok || !secretRank.Seed || secretRank.Distance != 0 || !slices.Contains(secretRank.Relations, "can_reach") {
		t.Fatalf("secret rank = %#v, ok=%t", secretRank, ok)
	}
	roleRank, ok := crownJewelRankByURN(result.Rankings, role.URN)
	if !ok || roleRank.Score <= 0 || !slices.Contains(roleRank.Relations, "can_perform") {
		t.Fatalf("role rank = %#v, ok=%t", roleRank, ok)
	}
}

func crownJewelCatalogEntity(urn, kind, label string) ports.CatalogEntity {
	return ports.CatalogEntity{URN: urn, TenantID: "writer", EntityType: kind, Label: label}
}

func crownJewelRankByURN(ranks []CrownJewelRank, urn string) (CrownJewelRank, bool) {
	for _, rank := range ranks {
		if rank.Entity.URN == urn {
			return rank, true
		}
	}
	return CrownJewelRank{}, false
}
