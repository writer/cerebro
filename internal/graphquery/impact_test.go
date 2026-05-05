package graphquery

import (
	"context"
	"errors"
	"testing"

	"github.com/writer/cerebro/internal/ports"
)

type impactStubStore struct {
	neighborhoods map[string]*ports.EntityNeighborhood
	queries       []string
}

func (s *impactStubStore) Ping(context.Context) error { return nil }

func (s *impactStubStore) GetEntityNeighborhood(_ context.Context, rootURN string, _ int) (*ports.EntityNeighborhood, error) {
	s.queries = append(s.queries, rootURN)
	neighborhood, ok := s.neighborhoods[rootURN]
	if !ok {
		return nil, ports.ErrGraphEntityNotFound
	}
	return neighborhood, nil
}

func TestGetImpactVulnerabilityGroupsCanonicalPackageAssetsAndEvidence(t *testing.T) {
	vulnerabilityURN := "urn:cerebro:writer:vulnerability:cve-2026-4242"
	canonicalPackageURN := "urn:cerebro:writer:package:canonical:golang.org/x/crypto"
	githubPackageURN := "urn:cerebro:writer:package:go:golang.org/x/crypto"
	sentinelOnePackageURN := "urn:cerebro:writer:package:sentinelone:golang.org/x/crypto"
	alertURN := "urn:cerebro:writer:github_dependabot_alert:writer/cerebro:42"
	agentURN := "urn:cerebro:writer:sentinelone_agent:agent-42"
	store := &impactStubStore{neighborhoods: map[string]*ports.EntityNeighborhood{
		vulnerabilityURN: {
			Root: node(vulnerabilityURN, "vulnerability", "CVE-2026-4242"),
			Neighbors: []*ports.NeighborhoodNode{
				node(canonicalPackageURN, "package", "golang.org/x/crypto"),
				node(githubPackageURN, "package", "golang.org/x/crypto"),
				node(sentinelOnePackageURN, "package", "golang.org/x/crypto"),
				node(alertURN, "github.dependabot_alert", "GHSA"),
				node(agentURN, "sentinelone.agent", "macbook-42"),
			},
			Relations: []*ports.NeighborhoodRelation{
				rel(canonicalPackageURN, "affected_by", vulnerabilityURN),
				rel(githubPackageURN, "affected_by", vulnerabilityURN),
				rel(sentinelOnePackageURN, "affected_by", vulnerabilityURN),
				rel(alertURN, "affected_by", vulnerabilityURN),
				rel(agentURN, "affected_by", vulnerabilityURN),
			},
		},
		canonicalPackageURN:   emptyNeighborhood(canonicalPackageURN, "package"),
		githubPackageURN:      emptyNeighborhood(githubPackageURN, "package"),
		sentinelOnePackageURN: emptyNeighborhood(sentinelOnePackageURN, "package"),
		alertURN:              emptyNeighborhood(alertURN, "github.dependabot_alert"),
		agentURN:              emptyNeighborhood(agentURN, "sentinelone.agent"),
	}}

	result, err := New(store).GetImpact(context.Background(), ImpactRequest{
		Kind:       ImpactKindVulnerability,
		TenantID:   "writer",
		Identifier: "CVE-2026-4242",
		Depth:      1,
	})
	if err != nil {
		t.Fatalf("GetImpact() error = %v", err)
	}
	if result.RootURN != vulnerabilityURN {
		t.Fatalf("RootURN = %q, want %q", result.RootURN, vulnerabilityURN)
	}
	if len(result.Packages) != 3 {
		t.Fatalf("len(Packages) = %d, want 3", len(result.Packages))
	}
	if len(result.Assets) != 1 || result.Assets[0].URN != agentURN {
		t.Fatalf("Assets = %#v, want S1 agent", result.Assets)
	}
	if len(result.Evidence) != 1 || result.Evidence[0].URN != alertURN {
		t.Fatalf("Evidence = %#v, want GitHub alert", result.Evidence)
	}
}

func TestGetImpactPackageNormalizesVersionedPURL(t *testing.T) {
	rootURN := "urn:cerebro:writer:package:canonical:pkg:npm/foo"
	store := &impactStubStore{neighborhoods: map[string]*ports.EntityNeighborhood{
		rootURN: emptyNeighborhood(rootURN, "package"),
	}}

	result, err := New(store).GetImpact(context.Background(), ImpactRequest{
		Kind:       ImpactKindPackage,
		TenantID:   "writer",
		Identifier: "pkg:npm/foo@1.2.3?repository_url=https://registry.npmjs.org#dist",
	})
	if err != nil {
		t.Fatalf("GetImpact() error = %v", err)
	}
	if result.RootURN != rootURN {
		t.Fatalf("RootURN = %q, want %q", result.RootURN, rootURN)
	}
}

func TestGetImpactRequiresTenantForPackageAndVulnerability(t *testing.T) {
	_, err := New(&impactStubStore{}).GetImpact(context.Background(), ImpactRequest{Kind: ImpactKindVulnerability, Identifier: "CVE-2026-4242"})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("GetImpact() error = %v, want %v", err, ErrInvalidRequest)
	}
}

func TestGetImpactRejectsRawURNForPackageAndVulnerability(t *testing.T) {
	_, err := New(&impactStubStore{}).GetImpact(context.Background(), ImpactRequest{
		Kind:       ImpactKindPackage,
		TenantID:   "writer",
		Identifier: "urn:cerebro:other:package:canonical:pkg:npm/foo",
	})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("GetImpact(raw package urn) error = %v, want %v", err, ErrInvalidRequest)
	}
	_, err = New(&impactStubStore{}).GetImpact(context.Background(), ImpactRequest{
		Kind:       ImpactKindVulnerability,
		TenantID:   "writer",
		Identifier: "urn:cerebro:other:vulnerability:cve-2026-4242",
	})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("GetImpact(raw vulnerability urn) error = %v, want %v", err, ErrInvalidRequest)
	}
}

func TestGetImpactPackageDoesNotFallbackToLegacyPURLIdentity(t *testing.T) {
	store := &impactStubStore{neighborhoods: map[string]*ports.EntityNeighborhood{
		"urn:cerebro:writer:package:canonical:pkg:MAVEN/org.example/artifact": emptyNeighborhood("urn:cerebro:writer:package:canonical:pkg:MAVEN/org.example/artifact", "package"),
	}}

	_, err := New(store).GetImpact(context.Background(), ImpactRequest{
		Kind:       ImpactKindPackage,
		TenantID:   "writer",
		Identifier: "pkg:MAVEN/org.example/artifact@1.2.3?classifier=sources",
	})
	if !errors.Is(err, ports.ErrGraphEntityNotFound) {
		t.Fatalf("GetImpact() error = %v, want %v", err, ports.ErrGraphEntityNotFound)
	}
	if len(store.queries) != 1 {
		t.Fatalf("queries = %#v, want no fallback lookup", store.queries)
	}
}

func node(urn string, entityType string, label string) *ports.NeighborhoodNode {
	return &ports.NeighborhoodNode{URN: urn, EntityType: entityType, Label: label}
}

func rel(fromURN string, relation string, toURN string) *ports.NeighborhoodRelation {
	return &ports.NeighborhoodRelation{FromURN: fromURN, Relation: relation, ToURN: toURN}
}

func emptyNeighborhood(rootURN string, entityType string) *ports.EntityNeighborhood {
	return &ports.EntityNeighborhood{Root: node(rootURN, entityType, rootURN)}
}
