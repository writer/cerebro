package main

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"

	"github.com/writer/cerebro/internal/graphstore"
	"github.com/writer/cerebro/internal/ports"
)

type graphTestStore struct {
	mu          sync.Mutex
	entities    map[string]*ports.ProjectedEntity
	links       map[string]*ports.ProjectedLink
	checkpoints map[string]graphstore.IngestCheckpoint
	runs        map[string]graphstore.IngestRun
}

func newGraphTestStore() *graphTestStore {
	return &graphTestStore{
		entities:    make(map[string]*ports.ProjectedEntity),
		links:       make(map[string]*ports.ProjectedLink),
		checkpoints: make(map[string]graphstore.IngestCheckpoint),
		runs:        make(map[string]graphstore.IngestRun),
	}
}

func (s *graphTestStore) Ping(context.Context) error { return nil }

func (s *graphTestStore) UpsertProjectedEntity(_ context.Context, entity *ports.ProjectedEntity) error {
	if entity == nil || strings.TrimSpace(entity.URN) == "" {
		return errors.New("projected entity urn is required")
	}
	clone := *entity
	clone.URN = strings.TrimSpace(entity.URN)
	clone.TenantID = strings.TrimSpace(entity.TenantID)
	clone.SourceID = strings.TrimSpace(entity.SourceID)
	clone.EntityType = strings.TrimSpace(entity.EntityType)
	clone.Label = strings.TrimSpace(entity.Label)
	clone.Attributes = cloneGraphTestStringMap(entity.Attributes)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entities[clone.URN] = &clone
	return nil
}

func (s *graphTestStore) UpsertProjectedLink(_ context.Context, link *ports.ProjectedLink) error {
	if link == nil || strings.TrimSpace(link.FromURN) == "" || strings.TrimSpace(link.ToURN) == "" || strings.TrimSpace(link.Relation) == "" {
		return errors.New("projected link endpoints and relation are required")
	}
	clone := *link
	clone.TenantID = strings.TrimSpace(link.TenantID)
	clone.SourceID = strings.TrimSpace(link.SourceID)
	clone.FromURN = strings.TrimSpace(link.FromURN)
	clone.ToURN = strings.TrimSpace(link.ToURN)
	clone.Relation = strings.TrimSpace(link.Relation)
	clone.Attributes = cloneGraphTestStringMap(link.Attributes)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.links[testLinkKey(&clone)] = &clone
	return nil
}

func (s *graphTestStore) Counts(context.Context) (graphstore.Counts, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return graphstore.Counts{Nodes: int64(len(s.entities)), Relations: int64(len(s.links))}, nil
}

func (s *graphTestStore) GetEntityNeighborhood(_ context.Context, urn string, limit int) (*ports.EntityNeighborhood, error) {
	urn = strings.TrimSpace(urn)
	s.mu.Lock()
	defer s.mu.Unlock()
	root, ok := s.entities[urn]
	if !ok {
		return nil, ports.ErrGraphEntityNotFound
	}
	result := &ports.EntityNeighborhood{
		Root: &ports.NeighborhoodNode{URN: root.URN, EntityType: root.EntityType, Label: root.Label},
	}
	seen := map[string]struct{}{root.URN: {}}
	for _, link := range sortedTestLinks(s.links) {
		if link.FromURN != urn && link.ToURN != urn {
			continue
		}
		otherURN := link.ToURN
		if link.ToURN == urn {
			otherURN = link.FromURN
		}
		if _, exists := seen[otherURN]; !exists {
			if limit > 0 && len(result.Neighbors) >= limit {
				continue
			}
			if entity, ok := s.entities[otherURN]; ok {
				result.Neighbors = append(result.Neighbors, &ports.NeighborhoodNode{
					URN:        entity.URN,
					EntityType: entity.EntityType,
					Label:      entity.Label,
				})
				seen[otherURN] = struct{}{}
			}
		}
		result.Relations = append(result.Relations, &ports.NeighborhoodRelation{
			FromURN:    link.FromURN,
			Relation:   link.Relation,
			ToURN:      link.ToURN,
			Attributes: cloneGraphTestStringMap(link.Attributes),
		})
	}
	return result, nil
}

func (s *graphTestStore) IntegrityChecks(context.Context) ([]graphstore.IntegrityCheck, error) {
	return []graphstore.IntegrityCheck{
		{Name: "tenant_mismatched_relations", Expected: 0, Actual: 0, Passed: true},
		{Name: "blank_entity_labels", Expected: 0, Actual: 0, Passed: true},
		{Name: "blank_entity_types", Expected: 0, Actual: 0, Passed: true},
		{Name: "blank_relation_types", Expected: 0, Actual: 0, Passed: true},
		{Name: "self_referential_relations", Expected: 0, Actual: 0, Passed: true},
	}, nil
}

func (s *graphTestStore) PathPatterns(_ context.Context, limit int) ([]graphstore.PathPattern, error) {
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
			if from == nil || via == nil || to == nil {
				continue
			}
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
			return patternKey(patterns[i]) < patternKey(patterns[j])
		}
		return patterns[i].Count > patterns[j].Count
	})
	if limit > 0 && len(patterns) > limit {
		patterns = patterns[:limit]
	}
	return patterns, nil
}

func (s *graphTestStore) PutIngestCheckpoint(_ context.Context, checkpoint graphstore.IngestCheckpoint) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.checkpoints[checkpoint.ID] = checkpoint
	return nil
}

func (s *graphTestStore) GetIngestCheckpoint(_ context.Context, id string) (graphstore.IngestCheckpoint, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	checkpoint, ok := s.checkpoints[id]
	return checkpoint, ok, nil
}

func (s *graphTestStore) PutIngestRun(_ context.Context, run graphstore.IngestRun) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.runs[run.ID] = run
	return nil
}

func (s *graphTestStore) GetIngestRun(_ context.Context, id string) (graphstore.IngestRun, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	run, ok := s.runs[id]
	return run, ok, nil
}

func (s *graphTestStore) ListIngestRuns(_ context.Context, filter graphstore.IngestRunFilter) ([]graphstore.IngestRun, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	runs := make([]graphstore.IngestRun, 0, len(s.runs))
	for _, run := range s.runs {
		if filter.RuntimeID != "" && run.RuntimeID != filter.RuntimeID {
			continue
		}
		if filter.Status != "" && run.Status != filter.Status {
			continue
		}
		runs = append(runs, run)
	}
	sort.Slice(runs, func(i, j int) bool {
		return runs[i].ID < runs[j].ID
	})
	if filter.Limit > 0 && len(runs) > filter.Limit {
		runs = runs[:filter.Limit]
	}
	return runs, nil
}

func sortedTestLinks(links map[string]*ports.ProjectedLink) []*ports.ProjectedLink {
	keys := make([]string, 0, len(links))
	for key := range links {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	sorted := make([]*ports.ProjectedLink, 0, len(keys))
	for _, key := range keys {
		sorted = append(sorted, links[key])
	}
	return sorted
}

func testLinkKey(link *ports.ProjectedLink) string {
	return strings.Join([]string{link.FromURN, link.Relation, link.ToURN}, "|")
}

func patternKey(pattern graphstore.PathPattern) string {
	return strings.Join([]string{pattern.FromType, pattern.FirstRelation, pattern.ViaType, pattern.SecondRelation, pattern.ToType}, "|")
}

func cloneGraphTestStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}
