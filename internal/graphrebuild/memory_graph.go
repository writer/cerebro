package graphrebuild

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"

	"github.com/writer/cerebro/internal/graphstore"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/projectionmeta"
)

type memoryGraphStore struct {
	mu       sync.RWMutex
	entities map[string]memoryEntity
	// links is the materialized logical view: at most one entry per
	// (from_urn, relation, to_urn), kept in sync with linkAssertions by
	// reconcileMemoryLink so every other read path (Counts,
	// IntegrityChecks, PathPatterns, Topology, SampleTraversals) can keep
	// reading it unchanged.
	links map[string]memoryLink
	// linkAssertions tracks each independent (tenant, source, runtime)
	// assertion of a logical link separately, keyed by logical link key
	// (linkKey) and then by assertion scope key
	// (memoryLinkAssertionKey): a logical link survives in links iff at
	// least one assertion remains, so one source/runtime retracting its
	// own assertion (via UpsertProjectedLink replay or a narrowed
	// ReplaceProjectedLinkSets) can never remove another source/
	// runtime's independently asserted fact.
	linkAssertions map[string]map[string]memoryLink

	// linkSetObservations models Contract C9's guarded replace semantics
	// even though this scratch dry-run store otherwise has no other
	// entity observation-precedence concept: a marker per owner/
	// relation/direction/tenant/source/runtime scope keeps the last
	// applied Observation. A narrowed or authoritative-empty set
	// retracts exactly this (tenant, source, runtime) scope's own
	// linkAssertions entries for the set's (owner, relation, direction)
	// by scanning linkAssertions directly (see
	// ReplaceProjectedLinkSets), so it never touches another scope's
	// assertion of the same logical link regardless of whether that
	// assertion was written by a previous link set or a plain
	// UpsertProjectedLink.
	linkSetObservations map[string]map[string]string
}

type memoryEntity struct {
	URN        string
	TenantID   string
	SourceID   string
	RuntimeID  string
	EntityType string
	Label      string
	Attributes map[string]string
}

type memoryLink struct {
	TenantID  string
	SourceID  string
	RuntimeID string
	FromURN   string
	ToURN     string
	Relation  string
}

type memoryURNPair struct {
	first  string
	second string
}

type memoryTraversalSample struct {
	key       string
	traversal graphstore.Traversal
}

type memoryTraversalSampler struct {
	limit   int
	samples []memoryTraversalSample
}

func newMemoryGraphStore() (graphStore, error) {
	return &memoryGraphStore{
		entities:       make(map[string]memoryEntity),
		links:          make(map[string]memoryLink),
		linkAssertions: make(map[string]map[string]memoryLink),
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

// UpsertProjectedEntity applies Contract G's G1 semantics for the scratch
// store: entity.CreateOnly only creates the entity when absent and
// otherwise changes nothing (not even typed source/runtime ownership,
// label, or attributes); a stale strict-precedence observation
// (projectionmeta.StaleStrictObservation) against an existing entity
// changes nothing at all; an accepted observation merges attributes and
// then deletes each entity.RetractedAttributes key absent from the
// incoming Attributes.
func (s *memoryGraphStore) UpsertProjectedEntity(_ context.Context, entity *ports.ProjectedEntity) error {
	if err := validateMemoryProjectedEntity(entity); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.upsertProjectedEntityLocked(entity)
	return nil
}

// validateMemoryProjectedEntity rejects an entity missing required
// identity fields, shared by UpsertProjectedEntity and
// ReplaceProjectedLinkSets' Endpoints materialization (R06).
func validateMemoryProjectedEntity(entity *ports.ProjectedEntity) error {
	if entity == nil {
		return errors.New("projected entity is required")
	}
	if strings.TrimSpace(entity.URN) == "" {
		return errors.New("projected entity urn is required")
	}
	if strings.TrimSpace(entity.TenantID) == "" {
		return errors.New("projected entity tenant id is required")
	}
	if strings.TrimSpace(entity.SourceID) == "" {
		return errors.New("projected entity source id is required")
	}
	if strings.TrimSpace(entity.EntityType) == "" {
		return errors.New("projected entity type is required")
	}
	return nil
}

// upsertProjectedEntityLocked applies one already-validated entity's G1
// semantics; callers must already hold s.mu.
func (s *memoryGraphStore) upsertProjectedEntityLocked(entity *ports.ProjectedEntity) {
	urn := strings.TrimSpace(entity.URN)
	tenantID := strings.TrimSpace(entity.TenantID)
	sourceID := strings.TrimSpace(entity.SourceID)
	entityType := strings.TrimSpace(entity.EntityType)
	existing, exists := s.entities[urn]
	if entity.CreateOnly && exists {
		return
	}
	incoming := cloneMemoryAttributes(entity.Attributes)
	if exists && projectionmeta.StaleStrictObservation(existing.Attributes, incoming) {
		return
	}
	label := strings.TrimSpace(entity.Label)
	fallbackLabel := label == ""
	if label == "" {
		label = urn
	}
	if exists && fallbackLabel {
		label = existing.Label
	}
	attributes := incoming
	if exists {
		attributes = ports.ApplyRetractedAttributes(mergeMemoryAttributes(existing.Attributes, incoming), entity.Attributes, entity.RetractedAttributes)
	}
	runtimeID := strings.TrimSpace(entity.RuntimeID)
	if runtimeID == "" && exists {
		runtimeID = existing.RuntimeID
	}
	s.entities[urn] = memoryEntity{
		URN:        urn,
		TenantID:   tenantID,
		SourceID:   sourceID,
		RuntimeID:  runtimeID,
		EntityType: entityType,
		Label:      label,
		Attributes: attributes,
	}
}

// UpsertProjectedLink records one independent (tenant, source, runtime)
// assertion of a logical link and reconciles the materialized logical view
// from every assertion still on record, so retracting or replaying one
// source/runtime's assertion (including an identical replay) never affects
// another's.
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
	runtimeID := strings.TrimSpace(link.RuntimeID)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.setMemoryLinkAssertion(fromURN, relation, toURN, tenantID, sourceID, runtimeID)
	return nil
}

// ReplaceProjectedLinkSets applies each guarded link set (Contract C9),
// keyed by owner/relation/direction/tenant/source/runtime scope. See the
// linkSetObservations field for how the Observation guard is enforced
// without any other entity/link observation-precedence concept in this
// scratch store. A narrowed or authoritative-empty set retracts only this
// exact (tenant, source, runtime) scope's own linkAssertions entries for
// the set's (owner, relation, direction), found by scanning linkAssertions
// rather than any separately cached ownership set, so the retraction
// always matches live assertion state (whether created by a previous link
// set or a plain UpsertProjectedLink) and another source/runtime's
// assertion of the exact same logical link is never touched. An Incomplete
// set must carry no links or endpoints: it only advances the scope's
// Observation guard and never retracts, asserts, or materializes
// anything. Once a set is accepted and not Incomplete, its Endpoints are
// CreateOnly-materialized (R06, never overwriting an existing entity)
// before links are asserted, matching the real stores' guarantee that a
// stale or losing set's Endpoints can never reach the scratch graph.
func (s *memoryGraphStore) ReplaceProjectedLinkSets(_ context.Context, sets []*ports.ProjectedLinkSet) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.replaceProjectedLinkSetsLocked(sets)
	return err
}

// ReplaceProjectedLinkSetsReportingAccepted applies the exact same guarded
// semantics as ReplaceProjectedLinkSets and additionally returns the
// subset of sets this call actually accepted (not rejected as stale),
// computed by the same guard evaluated here rather than re-implemented by
// a caller (R06 P2): previewGraphStore uses this to count only genuinely
// accepted endpoints/links instead of showing a stale set's requested
// content in the preview.
func (s *memoryGraphStore) ReplaceProjectedLinkSetsReportingAccepted(_ context.Context, sets []*ports.ProjectedLinkSet) ([]*ports.ProjectedLinkSet, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.replaceProjectedLinkSetsLocked(sets)
}

// replaceProjectedLinkSetsLocked is the single guarded implementation both
// public methods share; callers must already hold s.mu. It returns exactly
// the input sets this call did not reject as stale, in the same order.
func (s *memoryGraphStore) replaceProjectedLinkSetsLocked(sets []*ports.ProjectedLinkSet) ([]*ports.ProjectedLinkSet, error) {
	if s.linkSetObservations == nil {
		s.linkSetObservations = map[string]map[string]string{}
	}
	if s.linkAssertions == nil {
		s.linkAssertions = map[string]map[string]memoryLink{}
	}
	if s.entities == nil {
		s.entities = map[string]memoryEntity{}
	}
	accepted := make([]*ports.ProjectedLinkSet, 0, len(sets))
	for _, set := range sets {
		if set == nil {
			continue
		}
		ownerURN := strings.TrimSpace(set.OwnerURN)
		relation := strings.TrimSpace(set.Relation)
		tenantID := strings.TrimSpace(set.TenantID)
		sourceID := strings.TrimSpace(set.SourceID)
		runtimeID := strings.TrimSpace(set.RuntimeID)
		if ownerURN == "" || relation == "" || tenantID == "" || sourceID == "" {
			return accepted, errors.New("projected link set owner urn, relation, tenant id, and source id are required")
		}
		if err := ports.ValidateProjectedLinkSetIncomplete(set); err != nil {
			return accepted, err
		}
		if err := ports.ValidateProjectedLinkSetEndpoints(set); err != nil {
			return accepted, err
		}
		key := ports.ProjectedLinkSetOwnerKey(set)
		if stored, ok := s.linkSetObservations[key]; ok && projectionmeta.CompareObservations(stored, set.Observation) == projectionmeta.ObservationOlder {
			continue
		}
		accepted = append(accepted, set)
		if set.Incomplete {
			// An accepted incomplete observation advances the scope's
			// ordering guard but neither retracts nor asserts any link,
			// nor materializes any endpoint.
			s.linkSetObservations[key] = set.Observation
			continue
		}
		for _, endpoint := range set.Endpoints {
			if endpoint == nil {
				continue
			}
			if err := validateMemoryProjectedEntity(endpoint); err != nil {
				return accepted, err
			}
			s.upsertProjectedEntityLocked(endpoint)
		}
		assertionKey := memoryLinkAssertionKey(tenantID, sourceID, runtimeID)
		desiredKeys := make(map[string]struct{}, len(set.Links))
		for _, link := range set.Links {
			if link == nil {
				continue
			}
			desiredKeys[linkKey(strings.TrimSpace(link.FromURN), relation, strings.TrimSpace(link.ToURN))] = struct{}{}
		}
		for logicalKey, assertions := range s.linkAssertions {
			current, ok := assertions[assertionKey]
			if !ok || current.Relation != relation {
				continue
			}
			ownerSide := current.ToURN
			if set.Outgoing {
				ownerSide = current.FromURN
			}
			if ownerSide != ownerURN {
				continue
			}
			if _, desired := desiredKeys[logicalKey]; desired {
				continue
			}
			s.clearMemoryLinkAssertion(logicalKey, assertionKey)
		}
		for _, link := range set.Links {
			if link == nil {
				continue
			}
			fromURN := strings.TrimSpace(link.FromURN)
			toURN := strings.TrimSpace(link.ToURN)
			s.setMemoryLinkAssertion(fromURN, relation, toURN, tenantID, sourceID, runtimeID)
		}
		s.linkSetObservations[key] = set.Observation
	}
	return accepted, nil
}

func (s *memoryGraphStore) Counts(context.Context) (graphstore.Counts, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return graphstore.Counts{Nodes: int64(len(s.entities)), Relations: int64(len(s.links))}, nil
}

func (s *memoryGraphStore) IntegrityChecks(context.Context) ([]graphstore.IntegrityCheck, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	outgoingLinks := s.memoryOutgoingLinksByFromURN()
	linkedURNs := s.memoryLinkedURNPairs()
	checks := []graphstore.IntegrityCheck{
		{Name: "tenant_mismatched_relations", Expected: 0},
		{Name: "blank_entity_labels", Expected: 0},
		{Name: "blank_entity_types", Expected: 0},
		{Name: "blank_relation_types", Expected: 0},
		{Name: "self_referential_relations", Expected: 0},
		{Name: "github_code_repositories_without_owner_link", Expected: 0},
		{Name: "aws_public_endpoints_without_instance_link", Expected: 0},
		{Name: "cross_kind_identity_fragmentation", Expected: 0},
	}
	for _, entity := range s.entities {
		if entity.Label == "" {
			checks[1].Actual++
		}
		if entity.EntityType == "" {
			checks[2].Actual++
		}
		if memoryEntityRequiresRepositoryOwnerLink(entity) && !s.memoryEntityHasOutgoingLinkTo(outgoingLinks, entity.URN, "belongs_to", "github.org") {
			checks[5].Actual++
		}
		if memoryEntityRequiresInstanceLink(entity) && !s.memoryEntityHasInstanceLink(outgoingLinks, entity.URN) {
			checks[6].Actual++
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
	checks[7].Actual = s.crossKindIdentityFragmentation(linkedURNs)
	for index := range checks {
		checks[index].Passed = checks[index].Actual == checks[index].Expected
	}
	return checks, nil
}

// crossKindIdentityFragmentation counts pairs of entities that share a tenant and
// URN id-portion but carry different URN kinds and are not linked to each other.
// This is the signature of a relationship target that fragments identity: the
// same real object is projected under two kinds (e.g. a typed node and a runtime
// stub) that never merge. Directly-linked twins (such as identifier/identity
// nodes) are intentionally excluded because they are a deliberate paired model.
func (s *memoryGraphStore) crossKindIdentityFragmentation(linkedURNs map[memoryURNPair]struct{}) int64 {
	type idKey struct {
		tenant string
		id     string
	}
	type kindedURN struct {
		kind string
		urn  string
	}
	groups := map[idKey][]kindedURN{}
	for _, entity := range s.entities {
		kind, id, ok := projectionURNKindAndID(entity.URN)
		if !ok {
			continue
		}
		key := idKey{tenant: entity.TenantID, id: id}
		groups[key] = append(groups[key], kindedURN{kind: kind, urn: entity.URN})
	}
	var fragmented int64
	for _, group := range groups {
		for i := 0; i < len(group); i++ {
			for j := i + 1; j < len(group); j++ {
				if group[i].kind == group[j].kind {
					continue
				}
				if memoryEntitiesLinked(linkedURNs, group[i].urn, group[j].urn) {
					continue
				}
				fragmented++
			}
		}
	}
	return fragmented
}

// projectionURNKindAndID splits a cerebro projection URN of the form
// urn:cerebro:<tenant>:<kind>:<id...> into its kind and id-portion. The id-portion
// keeps any trailing colons so multi-segment ids are compared intact.
func projectionURNKindAndID(urn string) (kind string, id string, ok bool) {
	parts := strings.SplitN(strings.TrimSpace(urn), ":", 5)
	if len(parts) < 5 || parts[0] != "urn" || parts[1] != "cerebro" {
		return "", "", false
	}
	return parts[3], parts[4], true
}

func cloneMemoryAttributes(attributes map[string]string) map[string]string {
	if len(attributes) == 0 {
		return nil
	}
	clone := make(map[string]string, len(attributes))
	for key, value := range attributes {
		clone[key] = value
	}
	return clone
}

func mergeMemoryAttributes(existing map[string]string, incoming map[string]string) map[string]string {
	if len(existing) == 0 {
		return cloneMemoryAttributes(incoming)
	}
	merged := cloneMemoryAttributes(existing)
	for key, value := range incoming {
		merged[key] = value
	}
	return merged
}

func memoryEntityRequiresInstanceLink(entity memoryEntity) bool {
	switch entity.EntityType {
	case "aws.elastic.ip", "aws.network.interface":
	default:
		return false
	}
	return strings.TrimSpace(entity.Attributes["attached_instance_id"]) != "" || strings.TrimSpace(entity.Attributes["associated_instance_id"]) != ""
}

func memoryEntityRequiresRepositoryOwnerLink(entity memoryEntity) bool {
	return entity.SourceID == "github" &&
		entity.EntityType == "github.code.repository" &&
		strings.TrimSpace(entity.Attributes["owner_login"]) != ""
}

func (s *memoryGraphStore) memoryEntityHasInstanceLink(outgoingLinks map[string][]memoryLink, urn string) bool {
	return s.memoryEntityHasOutgoingLinkTo(outgoingLinks, urn, "attached_to", "aws.ec2.instance") ||
		s.memoryEntityHasOutgoingLinkTo(outgoingLinks, urn, "associated_with", "aws.ec2.instance")
}

func (s *memoryGraphStore) memoryEntityHasOutgoingLinkTo(outgoingLinks map[string][]memoryLink, urn string, relation string, targetType string) bool {
	for _, link := range outgoingLinks[urn] {
		if link.Relation != relation {
			continue
		}
		if s.entities[link.ToURN].EntityType == targetType {
			return true
		}
	}
	return false
}

func (s *memoryGraphStore) PathPatterns(_ context.Context, limit int) ([]graphstore.PathPattern, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	outgoingLinks := s.memoryOutgoingLinksByFromURN()
	counts := make(map[string]graphstore.PathPattern)
	s.visitMemoryTwoHopLinks(outgoingLinks, func(first memoryLink, second memoryLink) {
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
	})
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
	s.mu.RLock()
	defer s.mu.RUnlock()
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
	s.mu.RLock()
	defer s.mu.RUnlock()
	outgoingLinks := s.memoryOutgoingLinksByFromURN()
	sampler := newMemoryTraversalSampler(limit)
	s.visitMemoryTwoHopLinks(outgoingLinks, func(first memoryLink, second memoryLink) {
		from := s.entities[first.FromURN]
		via := s.entities[first.ToURN]
		to := s.entities[second.ToURN]
		sampler.Add(graphstore.Traversal{
			FromURN:        from.URN,
			FromLabel:      from.Label,
			FirstRelation:  first.Relation,
			ViaURN:         via.URN,
			ViaLabel:       via.Label,
			SecondRelation: second.Relation,
			ToURN:          to.URN,
			ToLabel:        to.Label,
		})
	})
	return sampler.Traversals(), nil
}

func (s *memoryGraphStore) memoryOutgoingLinksByFromURN() map[string][]memoryLink {
	outgoingLinks := make(map[string][]memoryLink, len(s.links))
	for _, link := range s.links {
		outgoingLinks[link.FromURN] = append(outgoingLinks[link.FromURN], link)
	}
	return outgoingLinks
}

func (s *memoryGraphStore) memoryLinkedURNPairs() map[memoryURNPair]struct{} {
	linkedURNs := make(map[memoryURNPair]struct{}, len(s.links))
	for _, link := range s.links {
		linkedURNs[memoryLinkedURNPair(link.FromURN, link.ToURN)] = struct{}{}
	}
	return linkedURNs
}

func (s *memoryGraphStore) visitMemoryTwoHopLinks(outgoingLinks map[string][]memoryLink, visit func(memoryLink, memoryLink)) {
	for _, first := range s.links {
		for _, second := range outgoingLinks[first.ToURN] {
			if graphstore.SuppressTwoHopPath(first.Relation, second.Relation) {
				continue
			}
			visit(first, second)
		}
	}
}

func memoryEntitiesLinked(linkedURNs map[memoryURNPair]struct{}, first string, second string) bool {
	_, ok := linkedURNs[memoryLinkedURNPair(first, second)]
	return ok
}

func memoryLinkedURNPair(first string, second string) memoryURNPair {
	if second < first {
		first, second = second, first
	}
	return memoryURNPair{first: first, second: second}
}

func newMemoryTraversalSampler(limit int) *memoryTraversalSampler {
	return &memoryTraversalSampler{
		limit:   limit,
		samples: make([]memoryTraversalSample, 0, max(limit, 0)),
	}
}

func (s *memoryTraversalSampler) Add(traversal graphstore.Traversal) {
	if s == nil {
		return
	}
	sample := memoryTraversalSample{key: traversalKey(traversal), traversal: traversal}
	if s.limit <= 0 {
		s.samples = append(s.samples, sample)
		return
	}
	if len(s.samples) < s.limit {
		s.samples = append(s.samples, sample)
		return
	}
	maxIndex := 0
	for index := 1; index < len(s.samples); index++ {
		if s.samples[index].key > s.samples[maxIndex].key {
			maxIndex = index
		}
	}
	if sample.key < s.samples[maxIndex].key {
		s.samples[maxIndex] = sample
	}
}

func (s *memoryTraversalSampler) Traversals() []graphstore.Traversal {
	if s == nil || len(s.samples) == 0 {
		return nil
	}
	sort.Slice(s.samples, func(i, j int) bool {
		return s.samples[i].key < s.samples[j].key
	})
	traversals := make([]graphstore.Traversal, 0, len(s.samples))
	for _, sample := range s.samples {
		traversals = append(traversals, sample.traversal)
	}
	return traversals
}

func linkKey(fromURN string, relation string, toURN string) string {
	return strings.Join([]string{fromURN, relation, toURN}, "|")
}

// memoryLinkAssertionKey identifies one independent (tenant, source,
// runtime) assertion scope of a logical link.
func memoryLinkAssertionKey(tenantID string, sourceID string, runtimeID string) string {
	return strings.Join([]string{tenantID, sourceID, runtimeID}, "\x00")
}

// setMemoryLinkAssertion records one (tenant, source, runtime) assertion of
// a logical link and reconciles the materialized view. Callers must hold
// s.mu for writing.
func (s *memoryGraphStore) setMemoryLinkAssertion(fromURN string, relation string, toURN string, tenantID string, sourceID string, runtimeID string) {
	logicalKey := linkKey(fromURN, relation, toURN)
	if s.linkAssertions == nil {
		s.linkAssertions = map[string]map[string]memoryLink{}
	}
	if s.linkAssertions[logicalKey] == nil {
		s.linkAssertions[logicalKey] = map[string]memoryLink{}
	}
	s.linkAssertions[logicalKey][memoryLinkAssertionKey(tenantID, sourceID, runtimeID)] = memoryLink{
		TenantID:  tenantID,
		SourceID:  sourceID,
		RuntimeID: runtimeID,
		FromURN:   fromURN,
		ToURN:     toURN,
		Relation:  relation,
	}
	s.reconcileMemoryLink(logicalKey)
}

// clearMemoryLinkAssertion removes one (tenant, source, runtime) assertion
// of a logical link (identified by its already-built assertionKey) and
// reconciles the materialized view. Callers must hold s.mu for writing.
func (s *memoryGraphStore) clearMemoryLinkAssertion(logicalKey string, assertionKey string) {
	assertions := s.linkAssertions[logicalKey]
	if assertions == nil {
		return
	}
	delete(assertions, assertionKey)
	if len(assertions) == 0 {
		delete(s.linkAssertions, logicalKey)
	}
	s.reconcileMemoryLink(logicalKey)
}

// reconcileMemoryLink materializes s.links[logicalKey] from whichever
// assertions still cover it: a logical link survives iff at least one
// (tenant, source, runtime) assertion remains, independent of which
// assertion was written or retracted last. The deterministic choice among
// multiple surviving assertions (lexicographically smallest assertion key)
// only affects which assertion's provenance is reflected in the
// materialized view; it never affects whether the link exists.
func (s *memoryGraphStore) reconcileMemoryLink(logicalKey string) {
	assertions := s.linkAssertions[logicalKey]
	if len(assertions) == 0 {
		delete(s.links, logicalKey)
		return
	}
	keys := make([]string, 0, len(assertions))
	for assertionKey := range assertions {
		keys = append(keys, assertionKey)
	}
	sort.Strings(keys)
	s.links[logicalKey] = assertions[keys[0]]
}

func pathPatternKey(pattern graphstore.PathPattern) string {
	return strings.Join([]string{pattern.FromType, pattern.FirstRelation, pattern.ViaType, pattern.SecondRelation, pattern.ToType}, "|")
}

func traversalKey(traversal graphstore.Traversal) string {
	return strings.Join([]string{traversal.FromURN, traversal.FirstRelation, traversal.ViaURN, traversal.SecondRelation, traversal.ToURN}, "|")
}
