package graphrebuild

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"

	"github.com/writer/cerebro/internal/graphstore"
	"github.com/writer/cerebro/internal/ports"
)

type memoryGraphStore struct {
	mu       sync.Mutex
	entities map[string]memoryEntity
	links    map[string]memoryLink
}

type memoryEntity struct {
	URN        string
	TenantID   string
	SourceID   string
	EntityType string
	Label      string
}

type memoryLink struct {
	TenantID string
	SourceID string
	FromURN  string
	ToURN    string
	Relation string
}

func newMemoryGraphStore() (graphStore, error) {
	return &memoryGraphStore{
		entities: make(map[string]memoryEntity),
		links:    make(map[string]memoryLink),
	}, nil
}

func (s *memoryGraphStore) Ping(context.Context) error {
	if s == nil {
		return errors.New("scratch graph store is not configured")
	}
	return nil
}

func (s *memoryGraphStore) Close() error {
	return nil
}

func (s *memoryGraphStore) UpsertProjectedEntity(_ context.Context, entity *ports.ProjectedEntity) error {
	if entity == nil {
		return errors.New("projected entity is required")
	}
	urn := strings.TrimSpace(entity.URN)
	if urn == "" {
		return errors.New("projected entity urn is required")
	}
	tenantID := strings.TrimSpace(entity.TenantID)
	if tenantID == "" {
		return errors.New("projected entity tenant id is required")
	}
	sourceID := strings.TrimSpace(entity.SourceID)
	if sourceID == "" {
		return errors.New("projected entity source id is required")
	}
	entityType := strings.TrimSpace(entity.EntityType)
	if entityType == "" {
		return errors.New("projected entity type is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entities[urn] = memoryEntity{
		URN:        urn,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: entityType,
		Label:      strings.TrimSpace(entity.Label),
	}
	return nil
}

func (s *memoryGraphStore) UpsertProjectedLink(_ context.Context, link *ports.ProjectedLink) error {
	if link == nil {
		return errors.New("projected link is required")
	}
	fromURN := strings.TrimSpace(link.FromURN)
	if fromURN == "" {
		return errors.New("projected link from urn is required")
	}
	toURN := strings.TrimSpace(link.ToURN)
	if toURN == "" {
		return errors.New("projected link to urn is required")
	}
	relation := strings.TrimSpace(link.Relation)
	if relation == "" {
		return errors.New("projected link relation is required")
	}
	tenantID := strings.TrimSpace(link.TenantID)
	if tenantID == "" {
		return errors.New("projected link tenant id is required")
	}
	sourceID := strings.TrimSpace(link.SourceID)
	if sourceID == "" {
		return errors.New("projected link source id is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.links[linkKey(fromURN, relation, toURN)] = memoryLink{
		TenantID: tenantID,
		SourceID: sourceID,
		FromURN:  fromURN,
		ToURN:    toURN,
		Relation: relation,
	}
	return nil
}

func (s *memoryGraphStore) Counts(context.Context) (graphstore.Counts, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return graphstore.Counts{Nodes: int64(len(s.entities)), Relations: int64(len(s.links))}, nil
}

func (s *memoryGraphStore) IntegrityChecks(context.Context) ([]graphstore.IntegrityCheck, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	checks := []graphstore.IntegrityCheck{
		{Name: "tenant_mismatched_relations", Expected: 0},
		{Name: "blank_entity_labels", Expected: 0},
		{Name: "blank_entity_types", Expected: 0},
		{Name: "blank_relation_types", Expected: 0},
		{Name: "self_referential_relations", Expected: 0},
	}
	for _, entity := range s.entities {
		if entity.Label == "" {
			checks[1].Actual++
		}
		if entity.EntityType == "" {
			checks[2].Actual++
		}
	}
	for _, link := range s.links {
		from := s.entities[link.FromURN]
		to := s.entities[link.ToURN]
		if from.TenantID != link.TenantID || to.TenantID != link.TenantID || from.TenantID != to.TenantID {
			checks[0].Actual++
		}
		if link.Relation == "" {
			checks[3].Actual++
		}
		if link.FromURN == link.ToURN {
			checks[4].Actual++
		}
	}
	for index := range checks {
		checks[index].Passed = checks[index].Actual == checks[index].Expected
	}
	return checks, nil
}

func (s *memoryGraphStore) PathPatterns(_ context.Context, limit int) ([]graphstore.PathPattern, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	counts := make(map[string]graphstore.PathPattern)
	for _, first := range s.links {
		for _, second := range s.links {
			if first.ToURN != second.FromURN {
				continue
			}
			from := s.entities[first.FromURN]
			via := s.entities[first.ToURN]
			to := s.entities[second.ToURN]
			pattern := graphstore.PathPattern{
				FromType:       from.EntityType,
				FirstRelation:  first.Relation,
				ViaType:        via.EntityType,
				SecondRelation: second.Relation,
				ToType:         to.EntityType,
			}
			key := strings.Join([]string{pattern.FromType, pattern.FirstRelation, pattern.ViaType, pattern.SecondRelation, pattern.ToType}, "|")
			pattern.Count = counts[key].Count + 1
			counts[key] = pattern
		}
	}
	patterns := make([]graphstore.PathPattern, 0, len(counts))
	for _, pattern := range counts {
		patterns = append(patterns, pattern)
	}
	sort.Slice(patterns, func(i, j int) bool {
		if patterns[i].Count == patterns[j].Count {
			return pathPatternKey(patterns[i]) < pathPatternKey(patterns[j])
		}
		return patterns[i].Count > patterns[j].Count
	})
	if limit > 0 && len(patterns) > limit {
		patterns = patterns[:limit]
	}
	return patterns, nil
}

func (s *memoryGraphStore) Topology(context.Context) (graphstore.Topology, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	inDegree := make(map[string]int)
	outDegree := make(map[string]int)
	for _, link := range s.links {
		outDegree[link.FromURN]++
		inDegree[link.ToURN]++
	}
	var topology graphstore.Topology
	for urn := range s.entities {
		incoming := inDegree[urn]
		outgoing := outDegree[urn]
		switch {
		case incoming == 0 && outgoing == 0:
			topology.Isolated++
		case incoming == 0:
			topology.SourcesOnly++
		case outgoing == 0:
			topology.SinksOnly++
		default:
			topology.Intermediates++
		}
	}
	return topology, nil
}

func (s *memoryGraphStore) SampleTraversals(_ context.Context, limit int) ([]graphstore.Traversal, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	traversals := []graphstore.Traversal{}
	for _, first := range s.links {
		for _, second := range s.links {
			if first.ToURN != second.FromURN {
				continue
			}
			from := s.entities[first.FromURN]
			via := s.entities[first.ToURN]
			to := s.entities[second.ToURN]
			traversals = append(traversals, graphstore.Traversal{
				FromURN:        from.URN,
				FromLabel:      from.Label,
				FirstRelation:  first.Relation,
				ViaURN:         via.URN,
				ViaLabel:       via.Label,
				SecondRelation: second.Relation,
				ToURN:          to.URN,
				ToLabel:        to.Label,
			})
		}
	}
	sort.Slice(traversals, func(i, j int) bool {
		return traversalKey(traversals[i]) < traversalKey(traversals[j])
	})
	if limit > 0 && len(traversals) > limit {
		traversals = traversals[:limit]
	}
	return traversals, nil
}

func linkKey(fromURN string, relation string, toURN string) string {
	return strings.Join([]string{fromURN, relation, toURN}, "|")
}

func pathPatternKey(pattern graphstore.PathPattern) string {
	return strings.Join([]string{pattern.FromType, pattern.FirstRelation, pattern.ViaType, pattern.SecondRelation, pattern.ToType}, "|")
}

func traversalKey(traversal graphstore.Traversal) string {
	return strings.Join([]string{traversal.FromURN, traversal.FirstRelation, traversal.ViaURN, traversal.SecondRelation, traversal.ToURN}, "|")
}
