package graphquery

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/writer/cerebro/internal/ports"
)

const (
	defaultCrownJewelRankLimit     = 25
	maxCrownJewelRankLimit         = 100
	defaultCrownJewelRankDepth     = 2
	maxCrownJewelRankDepth         = 3
	defaultCrownJewelRankSeedLimit = 25
	maxCrownJewelRankSeedLimit     = 100
	crownJewelRankDamping          = 0.85
	crownJewelRankIterations       = 20
)

type CrownJewelRankRequest struct {
	TenantID   string
	AccountID  string
	EntityType string
	Limit      uint32
	Depth      uint32
	SeedLimit  uint32
}

type CrownJewelRankResult struct {
	TenantID string                `json:"tenant_id"`
	Filters  CrownJewelRankFilters `json:"filters"`
	Counts   CrownJewelRankCounts  `json:"counts"`
	Seeds    []GraphEntityRef      `json:"seeds"`
	Rankings []CrownJewelRank      `json:"rankings"`
}

type CrownJewelRankFilters struct {
	AccountID  string `json:"account_id,omitempty"`
	EntityType string `json:"entity_type,omitempty"`
	Limit      int    `json:"limit"`
	Depth      int    `json:"depth"`
	SeedLimit  int    `json:"seed_limit"`
}

type CrownJewelRankCounts struct {
	Seeds      int `json:"seeds"`
	Candidates int `json:"candidates"`
	Relations  int `json:"relations"`
}

type CrownJewelRank struct {
	Entity    GraphEntityRef `json:"entity"`
	Score     float64        `json:"score"`
	Seed      bool           `json:"seed"`
	Distance  int            `json:"distance"`
	SeedHits  int            `json:"seed_hits"`
	Relations []string       `json:"relations,omitempty"`
}

func (s *Service) GetCrownJewelRanks(ctx context.Context, request CrownJewelRankRequest) (*CrownJewelRankResult, error) {
	if s == nil || s.crownJewels == nil {
		return nil, ErrRuntimeUnavailable
	}
	tenantID := strings.TrimSpace(request.TenantID)
	if tenantID == "" {
		return nil, fmt.Errorf("%w: tenant_id is required", ErrInvalidRequest)
	}
	limit := normalizeCrownJewelRankLimit(request.Limit)
	depth := normalizeCrownJewelRankDepth(request.Depth)
	seedLimit := normalizeCrownJewelRankSeedLimit(request.SeedLimit)
	result := &CrownJewelRankResult{
		TenantID: tenantID,
		Filters: CrownJewelRankFilters{
			AccountID:  strings.TrimSpace(request.AccountID),
			EntityType: strings.TrimSpace(request.EntityType),
			Limit:      limit,
			Depth:      depth,
			SeedLimit:  seedLimit,
		},
	}

	paths, err := s.crownJewels.ListCrownJewelPaths(ctx, ports.CrownJewelPathRequest{
		TenantID:   tenantID,
		AccountID:  result.Filters.AccountID,
		EntityType: result.Filters.EntityType,
		Limit:      ports.MaxCypherQueryRows,
		SeedLimit:  seedLimit,
		Depth:      depth,
	})
	if err != nil {
		return nil, err
	}
	if paths == nil || paths.TenantID != tenantID {
		return nil, errors.New("crown jewel path runtime returned an invalid tenant")
	}
	seeds := make([]GraphEntityRef, 0, len(paths.Seeds))
	for _, seed := range paths.Seeds {
		seeds = append(seeds, catalogGraphRef(seed))
	}
	result.Seeds = seeds
	result.Counts.Seeds = len(seeds)
	if len(seeds) == 0 {
		return result, nil
	}
	graph := newCrownJewelRankGraph(seeds)
	graph.addPaths(paths.Paths)
	rankings := graph.rank(limit)
	result.Rankings = rankings
	result.Counts.Candidates = len(graph.nodes)
	result.Counts.Relations = graph.relationCount()
	return result, nil
}

func normalizeCrownJewelRankLimit(limit uint32) int {
	return normalizeCrownJewelBound(limit, defaultCrownJewelRankLimit, maxCrownJewelRankLimit)
}

func normalizeCrownJewelRankDepth(depth uint32) int {
	return normalizeCrownJewelBound(depth, defaultCrownJewelRankDepth, maxCrownJewelRankDepth)
}

func normalizeCrownJewelRankSeedLimit(limit uint32) int {
	return normalizeCrownJewelBound(limit, defaultCrownJewelRankSeedLimit, maxCrownJewelRankSeedLimit)
}

func normalizeCrownJewelBound(value uint32, fallback int, maxValue int) int {
	maxBound := uint32(math.MaxUint32)
	if maxValue >= 0 && maxValue < math.MaxUint32 {
		maxBound = uint32(maxValue)
	}
	switch {
	case value == 0:
		return fallback
	case value > maxBound:
		return maxValue
	default:
		return int(value)
	}
}

type crownJewelRankGraph struct {
	nodes        map[string]GraphEntityRef
	seeds        map[string]struct{}
	edges        map[string]map[string]struct{}
	relations    map[string]map[string]struct{}
	seedHits     map[string]map[string]struct{}
	relationKeys map[string]struct{}
}

func newCrownJewelRankGraph(seeds []GraphEntityRef) *crownJewelRankGraph {
	graph := &crownJewelRankGraph{
		nodes:        map[string]GraphEntityRef{},
		seeds:        map[string]struct{}{},
		edges:        map[string]map[string]struct{}{},
		relations:    map[string]map[string]struct{}{},
		seedHits:     map[string]map[string]struct{}{},
		relationKeys: map[string]struct{}{},
	}
	for _, seed := range seeds {
		if seed.URN == "" {
			continue
		}
		graph.nodes[seed.URN] = seed
		graph.seeds[seed.URN] = struct{}{}
		graph.addSeedHit(seed.URN, seed.URN)
	}
	return graph
}

func (g *crownJewelRankGraph) addPaths(paths []ports.CrownJewelPath) {
	for _, path := range paths {
		if len(path.Nodes) < 2 || len(path.Relations) != len(path.Nodes)-1 {
			continue
		}
		for index, relation := range path.Relations {
			g.addRankEdge(path.Seed.URN, catalogGraphRef(path.Nodes[index]), catalogGraphRef(path.Nodes[index+1]), relation)
		}
	}
}

func (g *crownJewelRankGraph) addRankEdge(seedURN string, from GraphEntityRef, to GraphEntityRef, relation string) {
	if seedURN == "" || from.URN == "" || to.URN == "" || relation == "" {
		return
	}
	g.nodes[from.URN] = from
	g.nodes[to.URN] = to
	g.addEdge(from.URN, to.URN)
	g.addRelation(from.URN, relation)
	g.addRelation(to.URN, relation)
	g.addSeedHit(from.URN, seedURN)
	g.addSeedHit(to.URN, seedURN)
	g.relationKeys[crownJewelRelationKey(from.URN, relation, to.URN)] = struct{}{}
}

func crownJewelRelationKey(left string, relation string, right string) string {
	if right < left {
		left, right = right, left
	}
	return left + "|" + relation + "|" + right
}

func (g *crownJewelRankGraph) addEdge(left string, right string) {
	if left == "" || right == "" || left == right {
		return
	}
	if g.edges[left] == nil {
		g.edges[left] = map[string]struct{}{}
	}
	if g.edges[right] == nil {
		g.edges[right] = map[string]struct{}{}
	}
	g.edges[left][right] = struct{}{}
	g.edges[right][left] = struct{}{}
}

func (g *crownJewelRankGraph) addRelation(urn string, relation string) {
	if urn == "" || relation == "" {
		return
	}
	if g.relations[urn] == nil {
		g.relations[urn] = map[string]struct{}{}
	}
	g.relations[urn][relation] = struct{}{}
}

func (g *crownJewelRankGraph) addSeedHit(urn string, seedURN string) {
	if urn == "" || seedURN == "" {
		return
	}
	if g.seedHits[urn] == nil {
		g.seedHits[urn] = map[string]struct{}{}
	}
	g.seedHits[urn][seedURN] = struct{}{}
}

func (g *crownJewelRankGraph) relationCount() int {
	return len(g.relationKeys)
}

func (g *crownJewelRankGraph) rank(limit int) []CrownJewelRank {
	if len(g.nodes) == 0 || len(g.seeds) == 0 || limit <= 0 {
		return nil
	}
	seedWeight := 1.0 / float64(len(g.seeds))
	seedWeights := map[string]float64{}
	ranks := map[string]float64{}
	for urn := range g.nodes {
		if _, ok := g.seeds[urn]; ok {
			seedWeights[urn] = seedWeight
			ranks[urn] = seedWeight
		} else {
			ranks[urn] = 0
		}
	}
	for i := 0; i < crownJewelRankIterations; i++ {
		next := map[string]float64{}
		for urn := range g.nodes {
			next[urn] = (1 - crownJewelRankDamping) * seedWeights[urn]
		}
		for urn, rank := range ranks {
			neighbors := g.edges[urn]
			if len(neighbors) == 0 {
				for seedURN, weight := range seedWeights {
					next[seedURN] += crownJewelRankDamping * rank * weight
				}
				continue
			}
			share := crownJewelRankDamping * rank / float64(len(neighbors))
			for neighbor := range neighbors {
				next[neighbor] += share
			}
		}
		ranks = next
	}
	distances := g.distances()
	rankings := make([]CrownJewelRank, 0, len(g.nodes))
	for urn, node := range g.nodes {
		if excludedCrownJewelRankEntity(node) {
			continue
		}
		_, seed := g.seeds[urn]
		rankings = append(rankings, CrownJewelRank{
			Entity:    node,
			Score:     math.Round(ranks[urn]*1_000_000) / 1_000_000,
			Seed:      seed,
			Distance:  distances[urn],
			SeedHits:  len(g.seedHits[urn]),
			Relations: sortedSet(g.relations[urn]),
		})
	}
	sort.Slice(rankings, func(i, j int) bool {
		if rankings[i].Score != rankings[j].Score {
			return rankings[i].Score > rankings[j].Score
		}
		if rankings[i].Distance != rankings[j].Distance {
			return rankings[i].Distance < rankings[j].Distance
		}
		return rankings[i].Entity.URN < rankings[j].Entity.URN
	})
	if len(rankings) > limit {
		rankings = rankings[:limit]
	}
	return rankings
}

func (g *crownJewelRankGraph) distances() map[string]int {
	distances := map[string]int{}
	queue := make([]string, 0, len(g.seeds))
	for seedURN := range g.seeds {
		distances[seedURN] = 0
		queue = append(queue, seedURN)
	}
	for len(queue) > 0 {
		urn := queue[0]
		queue = queue[1:]
		for neighbor := range g.edges[urn] {
			if _, ok := distances[neighbor]; ok {
				continue
			}
			distances[neighbor] = distances[urn] + 1
			queue = append(queue, neighbor)
		}
	}
	return distances
}

func excludedCrownJewelRankEntity(entity GraphEntityRef) bool {
	return entity.EntityType == "asset.tag" || strings.HasSuffix(entity.URN, ":asset_tag:crown_jewel")
}

func sortedSet(values map[string]struct{}) []string {
	if len(values) == 0 {
		return nil
	}
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
