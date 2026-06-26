package graphquery

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/ports"
)

type impactStubStore struct {
	neighborhoods map[string]*ports.EntityNeighborhood
	lookupDelay   time.Duration

	mu            sync.Mutex
	queries       []string
	activeLookups int
	maxLookups    int
}

func (s *impactStubStore) Ping(context.Context) error { return nil }

func (s *impactStubStore) GetEntityNeighborhood(_ context.Context, rootURN string, _ int) (*ports.EntityNeighborhood, error) {
	s.mu.Lock()
	s.queries = append(s.queries, rootURN)
	s.activeLookups++
	if s.activeLookups > s.maxLookups {
		s.maxLookups = s.activeLookups
	}
	s.mu.Unlock()

	if s.lookupDelay > 0 {
		time.Sleep(s.lookupDelay)
	}

	s.mu.Lock()
	s.activeLookups--
	s.mu.Unlock()

	neighborhood, ok := s.neighborhoods[rootURN]
	if !ok {
		return nil, ports.ErrGraphEntityNotFound
	}
	return neighborhood, nil
}

func (s *impactStubStore) ExecuteReadCypher(_ context.Context, _ ports.CypherQueryRequest) ([]ports.CypherRow, error) {
	return nil, nil
}

func TestSortedImpactRelationsOrdersByRelationFields(t *testing.T) {
	relations := map[string]*ports.NeighborhoodRelation{
		"shuffled-1": rel("urn:cerebro:writer:asset:b", "depends_on", "urn:cerebro:writer:asset:a"),
		"shuffled-2": rel("urn:cerebro:writer:asset:a", "owns", "urn:cerebro:writer:asset:c"),
		"shuffled-3": rel("urn:cerebro:writer:asset:a", "depends_on", "urn:cerebro:writer:asset:b"),
	}

	result := sortedImpactRelations(relations)

	if len(result) != 3 {
		t.Fatalf("sortedImpactRelations() len = %d, want 3", len(result))
	}
	if result[0].FromURN != "urn:cerebro:writer:asset:a" || result[0].Relation != "depends_on" || result[0].ToURN != "urn:cerebro:writer:asset:b" {
		t.Fatalf("sortedImpactRelations()[0] = %#v, want asset:a depends_on asset:b", result[0])
	}
	if result[1].FromURN != "urn:cerebro:writer:asset:a" || result[1].Relation != "owns" || result[1].ToURN != "urn:cerebro:writer:asset:c" {
		t.Fatalf("sortedImpactRelations()[1] = %#v, want asset:a owns asset:c", result[1])
	}
	if result[2].FromURN != "urn:cerebro:writer:asset:b" || result[2].Relation != "depends_on" || result[2].ToURN != "urn:cerebro:writer:asset:a" {
		t.Fatalf("sortedImpactRelations()[2] = %#v, want asset:b depends_on asset:a", result[2])
	}
}

func (s *impactStubStore) queryURNs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.queries...)
}

func (s *impactStubStore) maxConcurrentLookups() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.maxLookups
}

type impactBatchStubStore struct {
	impactStubStore

	batchMu    sync.Mutex
	batchCalls [][]string
}

func (s *impactBatchStubStore) GetEntityNeighborhoods(_ context.Context, rootURNs []string, _ int) (map[string]*ports.EntityNeighborhood, error) {
	roots := append([]string(nil), rootURNs...)
	s.batchMu.Lock()
	s.batchCalls = append(s.batchCalls, roots)
	s.batchMu.Unlock()

	neighborhoods := make(map[string]*ports.EntityNeighborhood, len(roots))
	for _, rootURN := range roots {
		neighborhood, ok := s.neighborhoods[rootURN]
		if !ok {
			continue
		}
		neighborhoods[rootURN] = neighborhood
	}
	return neighborhoods, nil
}

func (s *impactBatchStubStore) batchedRoots() [][]string {
	s.batchMu.Lock()
	defer s.batchMu.Unlock()
	calls := make([][]string, 0, len(s.batchCalls))
	for _, roots := range s.batchCalls {
		calls = append(calls, append([]string(nil), roots...))
	}
	return calls
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

func TestGetImpactUsesBatchedFrontierLookupWhenAvailable(t *testing.T) {
	rootURN := "urn:cerebro:writer:vulnerability:cve-2026-4242"
	firstPackageURN := "urn:cerebro:writer:package:canonical:pkg:npm/foo"
	secondPackageURN := "urn:cerebro:writer:package:canonical:pkg:npm/bar"
	store := &impactBatchStubStore{impactStubStore: impactStubStore{neighborhoods: map[string]*ports.EntityNeighborhood{
		rootURN: {
			Root: node(rootURN, "vulnerability", "CVE-2026-4242"),
			Neighbors: []*ports.NeighborhoodNode{
				node(firstPackageURN, "package", "foo"),
				node(secondPackageURN, "package", "bar"),
			},
		},
		firstPackageURN:  emptyNeighborhood(firstPackageURN, "package"),
		secondPackageURN: emptyNeighborhood(secondPackageURN, "package"),
	}}}

	if _, err := New(store).GetImpact(context.Background(), ImpactRequest{
		Kind:       ImpactKindVulnerability,
		TenantID:   "writer",
		Identifier: "CVE-2026-4242",
		Depth:      2,
	}); err != nil {
		t.Fatalf("GetImpact() error = %v", err)
	}
	if queries := store.queryURNs(); len(queries) != 0 {
		t.Fatalf("single-root queries = %#v, want batched path only", queries)
	}
	calls := store.batchedRoots()
	if len(calls) != 2 {
		t.Fatalf("batch calls = %#v, want root and frontier batches", calls)
	}
	if len(calls[0]) != 1 || calls[0][0] != rootURN {
		t.Fatalf("first batch = %#v, want root", calls[0])
	}
	if len(calls[1]) != 2 || calls[1][0] != firstPackageURN || calls[1][1] != secondPackageURN {
		t.Fatalf("second batch = %#v, want package frontier", calls[1])
	}
}

func TestGetImpactDepthDoesNotExpandPastRequestedHops(t *testing.T) {
	rootURN := "urn:cerebro:writer:vulnerability:cve-2026-4242"
	directURN := "urn:cerebro:writer:package:canonical:pkg:npm/foo"
	secondHopURN := "urn:cerebro:writer:sentinelone_agent:agent-42"
	store := &impactStubStore{neighborhoods: map[string]*ports.EntityNeighborhood{
		rootURN: {
			Root:      node(rootURN, "vulnerability", "CVE-2026-4242"),
			Neighbors: []*ports.NeighborhoodNode{node(directURN, "package", "foo")},
			Relations: []*ports.NeighborhoodRelation{rel(directURN, "affected_by", rootURN)},
		},
		directURN: {
			Root:      node(directURN, "package", "foo"),
			Neighbors: []*ports.NeighborhoodNode{node(secondHopURN, "sentinelone.agent", "agent-42")},
			Relations: []*ports.NeighborhoodRelation{rel(secondHopURN, "has_package", directURN)},
		},
		secondHopURN: emptyNeighborhood(secondHopURN, "sentinelone.agent"),
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
	queries := store.queryURNs()
	if len(queries) != 1 || queries[0] != rootURN {
		t.Fatalf("queries = %#v, want only root lookup", queries)
	}
	if len(result.Packages) != 1 || result.Packages[0].URN != directURN {
		t.Fatalf("Packages = %#v, want direct package only", result.Packages)
	}
	if len(result.Assets) != 0 {
		t.Fatalf("Assets = %#v, want no second-hop asset", result.Assets)
	}
	if len(result.Relations) != 1 || result.Relations[0].FromURN != directURN {
		t.Fatalf("Relations = %#v, want only direct relation", result.Relations)
	}
}

func TestGetImpactLimitExcludesRelationsForDroppedNodes(t *testing.T) {
	rootURN := "urn:cerebro:writer:vulnerability:cve-2026-4242"
	packageURN := "urn:cerebro:writer:package:canonical:pkg:npm/foo"
	store := &impactStubStore{neighborhoods: map[string]*ports.EntityNeighborhood{
		rootURN: {
			Root:      node(rootURN, "vulnerability", "CVE-2026-4242"),
			Neighbors: []*ports.NeighborhoodNode{node(packageURN, "package", "foo")},
			Relations: []*ports.NeighborhoodRelation{rel(packageURN, "affected_by", rootURN)},
		},
		packageURN: emptyNeighborhood(packageURN, "package"),
	}}

	result, err := New(store).GetImpact(context.Background(), ImpactRequest{
		Kind:       ImpactKindVulnerability,
		TenantID:   "writer",
		Identifier: "CVE-2026-4242",
		Depth:      1,
		Limit:      1,
	})
	if err != nil {
		t.Fatalf("GetImpact() error = %v", err)
	}
	if result.Root == nil || result.Root.URN != rootURN {
		t.Fatalf("Root = %#v, want root node", result.Root)
	}
	if len(result.Packages) != 0 {
		t.Fatalf("Packages = %#v, want dropped package excluded", result.Packages)
	}
	if len(result.Relations) != 0 {
		t.Fatalf("Relations = %#v, want relations with dropped endpoints excluded", result.Relations)
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
	if queries := store.queryURNs(); len(queries) != 1 {
		t.Fatalf("queries = %#v, want no fallback lookup", queries)
	}
}

func TestGetImpactExpandsFrontierConcurrently(t *testing.T) {
	rootURN := "urn:cerebro:writer:vulnerability:cve-2026-4242"
	firstPackageURN := "urn:cerebro:writer:package:canonical:pkg:npm/foo"
	secondPackageURN := "urn:cerebro:writer:package:canonical:pkg:npm/bar"
	thirdPackageURN := "urn:cerebro:writer:package:canonical:pkg:npm/baz"
	store := &impactStubStore{
		lookupDelay: 10 * time.Millisecond,
		neighborhoods: map[string]*ports.EntityNeighborhood{
			rootURN: {
				Root: node(rootURN, "vulnerability", "CVE-2026-4242"),
				Neighbors: []*ports.NeighborhoodNode{
					node(firstPackageURN, "package", "foo"),
					node(secondPackageURN, "package", "bar"),
					node(thirdPackageURN, "package", "baz"),
				},
			},
			firstPackageURN:  emptyNeighborhood(firstPackageURN, "package"),
			secondPackageURN: emptyNeighborhood(secondPackageURN, "package"),
			thirdPackageURN:  emptyNeighborhood(thirdPackageURN, "package"),
		},
	}

	if _, err := New(store).GetImpact(context.Background(), ImpactRequest{
		Kind:       ImpactKindVulnerability,
		TenantID:   "writer",
		Identifier: "CVE-2026-4242",
		Depth:      2,
	}); err != nil {
		t.Fatalf("GetImpact() error = %v", err)
	}
	if got := store.maxConcurrentLookups(); got < 2 {
		t.Fatalf("max concurrent lookups = %d, want parallel frontier expansion", got)
	}
}

func TestGetImpactReturnsParallelLookupErrors(t *testing.T) {
	rootURN := "urn:cerebro:writer:vulnerability:cve-2026-4242"
	firstPackageURN := "urn:cerebro:writer:package:canonical:pkg:npm/foo"
	secondPackageURN := "urn:cerebro:writer:package:canonical:pkg:npm/bar"
	store := &impactStubStore{neighborhoods: map[string]*ports.EntityNeighborhood{
		rootURN: {
			Root: node(rootURN, "vulnerability", "CVE-2026-4242"),
			Neighbors: []*ports.NeighborhoodNode{
				node(firstPackageURN, "package", "foo"),
				node(secondPackageURN, "package", "bar"),
			},
		},
		firstPackageURN: {
			Root: node(firstPackageURN, "package", "foo"),
		},
	}}

	_, err := New(store).GetImpact(context.Background(), ImpactRequest{
		Kind:       ImpactKindVulnerability,
		TenantID:   "writer",
		Identifier: "CVE-2026-4242",
		Depth:      2,
		Limit:      4,
	})
	if !errors.Is(err, ports.ErrGraphEntityNotFound) {
		t.Fatalf("GetImpact() error = %v, want %v", err, ports.ErrGraphEntityNotFound)
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
