package graph

import (
	"sort"
	"strings"
	"time"
)

const (
	defaultEntityLimit = 100
	maxEntityLimit     = 500
	entitySampleLimit  = 5
)

// EntityQueryOptions tunes typed entity/resource reads over the graph substrate.
type EntityQueryOptions struct {
	ID            string               `json:"id,omitempty"`
	Kinds         []NodeKind           `json:"kinds,omitempty"`
	Categories    []NodeKindCategory   `json:"categories,omitempty"`
	Capabilities  []NodeKindCapability `json:"capabilities,omitempty"`
	Provider      string               `json:"provider,omitempty"`
	Account       string               `json:"account,omitempty"`
	Region        string               `json:"region,omitempty"`
	Risk          RiskLevel            `json:"risk,omitempty"`
	Search        string               `json:"search,omitempty"`
	TagKey        string               `json:"tag_key,omitempty"`
	TagValue      string               `json:"tag_value,omitempty"`
	HasFindings   *bool                `json:"has_findings,omitempty"`
	ValidAt       time.Time            `json:"valid_at,omitempty"`
	RecordedAt    time.Time            `json:"recorded_at,omitempty"`
	Limit         int                  `json:"limit,omitempty"`
	Offset        int                  `json:"offset,omitempty"`
	IncludeDetail bool                 `json:"-"`
}

// EntityQueryFilters echoes the applied entity filters.
type EntityQueryFilters struct {
	ID           string               `json:"id,omitempty"`
	Kinds        []NodeKind           `json:"kinds,omitempty"`
	Categories   []NodeKindCategory   `json:"categories,omitempty"`
	Capabilities []NodeKindCapability `json:"capabilities,omitempty"`
	Provider     string               `json:"provider,omitempty"`
	Account      string               `json:"account,omitempty"`
	Region       string               `json:"region,omitempty"`
	Risk         RiskLevel            `json:"risk,omitempty"`
	Search       string               `json:"search,omitempty"`
	TagKey       string               `json:"tag_key,omitempty"`
	TagValue     string               `json:"tag_value,omitempty"`
	HasFindings  *bool                `json:"has_findings,omitempty"`
}

// EntityTemporalMetadata exposes the shared time axes on one entity.
type EntityTemporalMetadata struct {
	ObservedAt      time.Time  `json:"observed_at,omitempty"`
	ValidFrom       time.Time  `json:"valid_from,omitempty"`
	ValidTo         *time.Time `json:"valid_to,omitempty"`
	RecordedAt      time.Time  `json:"recorded_at,omitempty"`
	TransactionFrom time.Time  `json:"transaction_from,omitempty"`
	TransactionTo   *time.Time `json:"transaction_to,omitempty"`
}

// EntityLinkSummary captures high-level graph linkage counts for one entity.
type EntityLinkSummary struct {
	IncomingCount int `json:"incoming_count"`
	OutgoingCount int `json:"outgoing_count"`
}

// EntityRelationshipSummary groups visible related entities by edge kind and direction.
type EntityRelationshipSummary struct {
	Direction       string   `json:"direction"`
	EdgeKind        EdgeKind `json:"edge_kind"`
	RelatedKind     NodeKind `json:"related_kind"`
	Count           int      `json:"count"`
	SampleEntityIDs []string `json:"sample_entity_ids,omitempty"`
}

// EntityClaimPredicateSummary captures the claim predicates currently attached to one entity.
type EntityClaimPredicateSummary struct {
	Predicate string `json:"predicate"`
	Count     int    `json:"count"`
}

// EntityKnowledgeSupportSummary captures attached claim/evidence/observation support.
type EntityKnowledgeSupportSummary struct {
	ClaimCount           int                           `json:"claim_count"`
	SupportedClaimCount  int                           `json:"supported_claim_count"`
	ConflictedClaimCount int                           `json:"conflicted_claim_count"`
	EvidenceCount        int                           `json:"evidence_count"`
	ObservationCount     int                           `json:"observation_count"`
	Predicates           []EntityClaimPredicateSummary `json:"predicates,omitempty"`
}

// EntityRecord is the typed read model for durable graph entities.
type EntityRecord struct {
	ID            string                        `json:"id"`
	Kind          NodeKind                      `json:"kind"`
	Name          string                        `json:"name,omitempty"`
	Provider      string                        `json:"provider,omitempty"`
	Account       string                        `json:"account,omitempty"`
	Region        string                        `json:"region,omitempty"`
	Risk          RiskLevel                     `json:"risk,omitempty"`
	Categories    []NodeKindCategory            `json:"categories,omitempty"`
	Capabilities  []NodeKindCapability          `json:"capabilities,omitempty"`
	CanonicalRef  *EntityCanonicalRef           `json:"canonical_ref,omitempty"`
	ExternalRefs  []EntityExternalRef           `json:"external_refs,omitempty"`
	Aliases       []EntityAliasRecord           `json:"aliases,omitempty"`
	Tags          map[string]string             `json:"tags,omitempty"`
	Findings      []string                      `json:"findings,omitempty"`
	Temporal      EntityTemporalMetadata        `json:"temporal"`
	Links         EntityLinkSummary             `json:"links"`
	Knowledge     EntityKnowledgeSupportSummary `json:"knowledge"`
	Facets        []EntityFacetRecord           `json:"facets,omitempty"`
	Posture       *EntityPostureSummary         `json:"posture,omitempty"`
	Subresources  []EntitySubresourceRecord     `json:"subresources,omitempty"`
	Relationships []EntityRelationshipSummary   `json:"relationships,omitempty"`
	Properties    map[string]any                `json:"properties,omitempty"`
}

// EntityCollectionSummary captures high-level entity coverage signals.
type EntityCollectionSummary struct {
	MatchedEntities           int `json:"matched_entities"`
	ResourceEntities          int `json:"resource_entities"`
	IdentityEntities          int `json:"identity_entities"`
	BusinessEntities          int `json:"business_entities"`
	InternetExposableEntities int `json:"internet_exposable_entities"`
	SensitiveEntities         int `json:"sensitive_entities"`
	FindingBackedEntities     int `json:"finding_backed_entities"`
	KnowledgeBackedEntities   int `json:"knowledge_backed_entities"`
}

// EntityCollection is the typed response for entity reads.
type EntityCollection struct {
	GeneratedAt time.Time                 `json:"generated_at"`
	ValidAt     time.Time                 `json:"valid_at"`
	RecordedAt  time.Time                 `json:"recorded_at"`
	Filters     EntityQueryFilters        `json:"filters"`
	Summary     EntityCollectionSummary   `json:"summary"`
	Entities    []EntityRecord            `json:"entities,omitempty"`
	Count       int                       `json:"count"`
	Pagination  ClaimCollectionPagination `json:"pagination"`
}

// QueryEntities returns typed platform entity records at a bitemporal slice.
func QueryEntities(g *Graph, opts EntityQueryOptions) EntityCollection {
	query := normalizeEntityQueryOptions(opts)
	result := EntityCollection{
		GeneratedAt: temporalNowUTC(),
		ValidAt:     query.ValidAt,
		RecordedAt:  query.RecordedAt,
		Filters: EntityQueryFilters{
			ID:           query.ID,
			Kinds:        append([]NodeKind(nil), query.Kinds...),
			Categories:   append([]NodeKindCategory(nil), query.Categories...),
			Capabilities: append([]NodeKindCapability(nil), query.Capabilities...),
			Provider:     query.Provider,
			Account:      query.Account,
			Region:       query.Region,
			Risk:         query.Risk,
			Search:       query.Search,
			TagKey:       query.TagKey,
			TagValue:     query.TagValue,
			HasFindings:  cloneOptionalBool(query.HasFindings),
		},
		Pagination: ClaimCollectionPagination{
			Limit:  query.Limit,
			Offset: query.Offset,
		},
	}
	if g == nil {
		return result
	}

	records := make([]EntityRecord, 0)
	for _, node := range g.GetAllNodesBitemporal(query.ValidAt, query.RecordedAt) {
		if node == nil || !entityQueryAllowedNodeKind(node.Kind) {
			continue
		}
		record := buildEntityRecord(g, node, query.ValidAt, query.RecordedAt, query.IncludeDetail)
		if !entityMatchesQuery(record, query) {
			continue
		}
		records = append(records, record)
		updateEntityCollectionSummary(&result.Summary, record)
	}

	sort.Slice(records, func(i, j int) bool {
		ri := entityRiskOrder(records[i].Risk)
		rj := entityRiskOrder(records[j].Risk)
		if ri != rj {
			return ri < rj
		}
		if records[i].Kind != records[j].Kind {
			return records[i].Kind < records[j].Kind
		}
		if records[i].Name != records[j].Name {
			return records[i].Name < records[j].Name
		}
		return records[i].ID < records[j].ID
	})

	total := len(records)
	result.Pagination.Total = total
	if query.Offset > total {
		query.Offset = total
		result.Pagination.Offset = total
	}
	end := query.Offset + query.Limit
	if end > total {
		end = total
	}
	if query.Offset < end {
		result.Entities = append(result.Entities, records[query.Offset:end]...)
	}
	result.Count = len(result.Entities)
	result.Pagination.HasMore = end < total
	return result
}

// GetEntityRecord returns one typed entity record at a bitemporal slice.
func GetEntityRecord(g *Graph, id string, validAt, recordedAt time.Time) (EntityRecord, bool) {
	id = strings.TrimSpace(id)
	if id == "" {
		return EntityRecord{}, false
	}
	if g == nil {
		return EntityRecord{}, false
	}
	if validAt.IsZero() {
		validAt = temporalNowUTC()
	}
	if recordedAt.IsZero() {
		recordedAt = temporalNowUTC()
	}
	validAt = validAt.UTC()
	recordedAt = recordedAt.UTC()
	g.mu.RLock()
	node, ok := g.nodes[id]
	if !ok || node == nil || !entityQueryAllowedNodeKind(node.Kind) || !entityHistoricalVisibleAtLocked(node, validAt, recordedAt) {
		g.mu.RUnlock()
		return EntityRecord{}, false
	}
	node = cloneNode(node)
	g.mu.RUnlock()
	return buildEntityRecord(g, node, validAt, recordedAt, true), true
}

func normalizeEntityQueryOptions(opts EntityQueryOptions) EntityQueryOptions {
	if opts.ValidAt.IsZero() {
		opts.ValidAt = temporalNowUTC()
	} else {
		opts.ValidAt = opts.ValidAt.UTC()
	}
	if opts.RecordedAt.IsZero() {
		opts.RecordedAt = temporalNowUTC()
	} else {
		opts.RecordedAt = opts.RecordedAt.UTC()
	}
	opts.ID = strings.TrimSpace(opts.ID)
	opts.Provider = strings.ToLower(strings.TrimSpace(opts.Provider))
	opts.Account = strings.TrimSpace(opts.Account)
	opts.Region = strings.ToLower(strings.TrimSpace(opts.Region))
	opts.Risk = RiskLevel(strings.ToLower(strings.TrimSpace(string(opts.Risk))))
	opts.Search = strings.ToLower(strings.TrimSpace(opts.Search))
	opts.TagKey = strings.ToLower(strings.TrimSpace(opts.TagKey))
	opts.TagValue = strings.ToLower(strings.TrimSpace(opts.TagValue))
	opts.Kinds = uniqueSortedNodeKinds(opts.Kinds)
	opts.Categories = uniqueSortedNodeCategories(opts.Categories)
	opts.Capabilities = uniqueSortedNodeCapabilities(opts.Capabilities)
	if opts.Limit <= 0 {
		opts.Limit = defaultEntityLimit
	}
	if opts.Limit > maxEntityLimit {
		opts.Limit = maxEntityLimit
	}
	if opts.Offset < 0 {
		opts.Offset = 0
	}
	return opts
}

func buildEntityRecord(g *Graph, node *Node, validAt, recordedAt time.Time, includeDetail bool) EntityRecord {
	record := EntityRecord{
		ID:         node.ID,
		Kind:       node.Kind,
		Name:       strings.TrimSpace(node.Name),
		Provider:   strings.TrimSpace(node.Provider),
		Account:    strings.TrimSpace(node.Account),
		Region:     strings.TrimSpace(node.Region),
		Risk:       node.Risk,
		Tags:       cloneStringMap(node.Tags),
		Findings:   append([]string(nil), node.Findings...),
		Properties: cloneNodeProperties(node),
	}
	if def, ok := GlobalSchemaRegistry().NodeKindDefinition(node.Kind); ok {
		record.Categories = append([]NodeKindCategory(nil), def.Categories...)
		record.Capabilities = append([]NodeKindCapability(nil), def.Capabilities...)
	}
	record.Temporal = entityTemporalMetadata(node)
	record.Relationships = buildEntityRelationshipSummaries(g, node.ID, validAt, recordedAt)
	record.Links = EntityLinkSummary{
		IncomingCount: len(g.GetInEdgesBitemporal(node.ID, validAt, recordedAt)),
		OutgoingCount: len(g.GetOutEdgesBitemporal(node.ID, validAt, recordedAt)),
	}
	record.Knowledge = buildEntityKnowledgeSupportSummary(g, node.ID, validAt, recordedAt)
	if includeDetail {
		canonicalRef := buildEntityCanonicalRef(node)
		record.CanonicalRef = &canonicalRef
		record.ExternalRefs = buildEntityExternalRefs(node)
		record.Aliases = buildEntityAliasRecords(g, node, validAt, recordedAt)
		claims := collectClaimRecords(g, ClaimQueryOptions{
			SubjectID:  node.ID,
			ValidAt:    validAt,
			RecordedAt: recordedAt,
			Limit:      maxClaimQueryLimit,
		})
		record.Facets = buildEntityFacetRecords(g, node, validAt, recordedAt, claims)
		record.Posture = buildEntityPostureSummary(claims, validAt)
		record.Subresources = buildEntitySubresourceRecords(g, node.ID, validAt, recordedAt)
	}
	return record
}

func entityTemporalMetadata(node *Node) EntityTemporalMetadata {
	meta := EntityTemporalMetadata{}
	if ts, ok := graphObservedAt(node); ok {
		meta.ObservedAt = ts
	}
	if ts, ok := nodePropertyTime(node, "valid_from"); ok {
		meta.ValidFrom = ts
	}
	if ts, ok := nodePropertyTime(node, "valid_to"); ok {
		meta.ValidTo = &ts
	}
	if ts, ok := nodePropertyTime(node, "recorded_at"); ok {
		meta.RecordedAt = ts
	}
	if ts, ok := nodePropertyTime(node, "transaction_from"); ok {
		meta.TransactionFrom = ts
	}
	if ts, ok := nodePropertyTime(node, "transaction_to"); ok {
		meta.TransactionTo = &ts
	}
	return meta
}

func buildEntityRelationshipSummaries(g *Graph, entityID string, validAt, recordedAt time.Time) []EntityRelationshipSummary {
	type aggregate struct {
		summary EntityRelationshipSummary
		seen    map[string]struct{}
	}
	grouped := make(map[string]*aggregate)

	appendEdge := func(direction string, edge *Edge, otherID string) {
		other, ok := g.GetNode(otherID)
		if !ok || other == nil || !entityQueryAllowedNodeKind(other.Kind) {
			return
		}
		key := direction + "|" + string(edge.Kind) + "|" + string(other.Kind)
		entry, ok := grouped[key]
		if !ok {
			entry = &aggregate{
				summary: EntityRelationshipSummary{
					Direction:   direction,
					EdgeKind:    edge.Kind,
					RelatedKind: other.Kind,
				},
				seen: make(map[string]struct{}),
			}
			grouped[key] = entry
		}
		entry.summary.Count++
		if _, exists := entry.seen[otherID]; exists {
			return
		}
		entry.seen[otherID] = struct{}{}
		if len(entry.summary.SampleEntityIDs) < entitySampleLimit {
			entry.summary.SampleEntityIDs = append(entry.summary.SampleEntityIDs, otherID)
		}
	}

	for _, edge := range g.GetOutEdgesBitemporal(entityID, validAt, recordedAt) {
		if edge == nil {
			continue
		}
		appendEdge("outgoing", edge, edge.Target)
	}
	for _, edge := range g.GetInEdgesBitemporal(entityID, validAt, recordedAt) {
		if edge == nil {
			continue
		}
		appendEdge("incoming", edge, edge.Source)
	}

	out := make([]EntityRelationshipSummary, 0, len(grouped))
	for _, entry := range grouped {
		sort.Strings(entry.summary.SampleEntityIDs)
		out = append(out, entry.summary)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Direction != out[j].Direction {
			return out[i].Direction < out[j].Direction
		}
		if out[i].EdgeKind != out[j].EdgeKind {
			return out[i].EdgeKind < out[j].EdgeKind
		}
		if out[i].RelatedKind != out[j].RelatedKind {
			return out[i].RelatedKind < out[j].RelatedKind
		}
		return out[i].Count > out[j].Count
	})
	return out
}

func buildEntityKnowledgeSupportSummary(g *Graph, entityID string, validAt, recordedAt time.Time) EntityKnowledgeSupportSummary {
	summary := EntityKnowledgeSupportSummary{}
	predicateCounts := make(map[string]int)
	evidenceIDs := make(map[string]struct{})
	observationIDs := make(map[string]struct{})
	for _, edge := range g.GetInEdgesBitemporal(entityID, validAt, recordedAt) {
		if edge == nil || edge.Kind != EdgeKindTargets {
			continue
		}
		other, ok := g.GetNode(edge.Source)
		if !ok || other == nil {
			continue
		}
		switch other.Kind {
		case NodeKindClaim:
			summary.ClaimCount++
			predicate := strings.TrimSpace(readString(other.Properties, "predicate"))
			if predicate != "" {
				predicateCounts[predicate]++
			}
			if record, ok := GetClaimRecord(g, other.ID, validAt, recordedAt); ok {
				if record.Derived.Supported {
					summary.SupportedClaimCount++
				}
				if record.Derived.Conflicted {
					summary.ConflictedClaimCount++
				}
				for _, evidenceID := range record.Links.EvidenceIDs {
					evidenceIDs[evidenceID] = struct{}{}
				}
			}
		case NodeKindEvidence:
			evidenceIDs[other.ID] = struct{}{}
		case NodeKindObservation:
			observationIDs[other.ID] = struct{}{}
		}
	}
	summary.EvidenceCount = len(evidenceIDs)
	summary.ObservationCount = len(observationIDs)
	if len(predicateCounts) == 0 {
		return summary
	}
	summary.Predicates = make([]EntityClaimPredicateSummary, 0, len(predicateCounts))
	for predicate, count := range predicateCounts {
		summary.Predicates = append(summary.Predicates, EntityClaimPredicateSummary{
			Predicate: predicate,
			Count:     count,
		})
	}
	sort.Slice(summary.Predicates, func(i, j int) bool {
		if summary.Predicates[i].Count != summary.Predicates[j].Count {
			return summary.Predicates[i].Count > summary.Predicates[j].Count
		}
		return summary.Predicates[i].Predicate < summary.Predicates[j].Predicate
	})
	return summary
}

func entityMatchesQuery(record EntityRecord, query EntityQueryOptions) bool {
	if query.ID != "" && record.ID != query.ID {
		return false
	}
	if len(query.Kinds) > 0 {
		match := false
		for _, kind := range query.Kinds {
			if record.Kind == kind {
				match = true
				break
			}
		}
		if !match {
			return false
		}
	}
	if len(query.Categories) > 0 {
		for _, category := range query.Categories {
			if !entityHasCategory(record, category) {
				return false
			}
		}
	}
	if len(query.Capabilities) > 0 {
		for _, capability := range query.Capabilities {
			if !entityHasCapability(record, capability) {
				return false
			}
		}
	}
	if query.Provider != "" && strings.ToLower(record.Provider) != query.Provider {
		return false
	}
	if query.Account != "" && record.Account != query.Account {
		return false
	}
	if query.Region != "" && strings.ToLower(record.Region) != query.Region {
		return false
	}
	if query.Risk != "" && record.Risk != query.Risk {
		return false
	}
	if query.TagKey != "" {
		value, ok := record.Tags[query.TagKey]
		if !ok {
			for key, candidate := range record.Tags {
				if strings.EqualFold(key, query.TagKey) {
					value = candidate
					ok = true
					break
				}
			}
		}
		if !ok {
			return false
		}
		if query.TagValue != "" && !strings.EqualFold(strings.TrimSpace(value), query.TagValue) {
			return false
		}
	}
	if query.HasFindings != nil {
		hasFindings := len(record.Findings) > 0
		if hasFindings != *query.HasFindings {
			return false
		}
	}
	if query.Search != "" {
		needle := query.Search
		haystack := strings.ToLower(strings.Join([]string{
			record.ID,
			string(record.Kind),
			record.Name,
			record.Provider,
			record.Account,
			record.Region,
		}, " "))
		if !strings.Contains(haystack, needle) {
			return false
		}
	}
	return true
}

func entityHasCategory(record EntityRecord, category NodeKindCategory) bool {
	for _, candidate := range record.Categories {
		if candidate == category {
			return true
		}
	}
	return false
}

func entityHasCapability(record EntityRecord, capability NodeKindCapability) bool {
	for _, candidate := range record.Capabilities {
		if candidate == capability {
			return true
		}
	}
	return false
}

func updateEntityCollectionSummary(summary *EntityCollectionSummary, record EntityRecord) {
	summary.MatchedEntities++
	if entityHasCategory(record, NodeCategoryResource) {
		summary.ResourceEntities++
	}
	if entityHasCategory(record, NodeCategoryIdentity) {
		summary.IdentityEntities++
	}
	if entityHasCategory(record, NodeCategoryBusiness) {
		summary.BusinessEntities++
	}
	if entityHasCapability(record, NodeCapabilityInternetExposable) {
		summary.InternetExposableEntities++
	}
	if entityHasCapability(record, NodeCapabilitySensitiveData) {
		summary.SensitiveEntities++
	}
	if len(record.Findings) > 0 {
		summary.FindingBackedEntities++
	}
	if record.Knowledge.ClaimCount > 0 || record.Knowledge.EvidenceCount > 0 || record.Knowledge.ObservationCount > 0 {
		summary.KnowledgeBackedEntities++
	}
}

func entityRiskOrder(level RiskLevel) int {
	switch level {
	case RiskCritical:
		return 0
	case RiskHigh:
		return 1
	case RiskMedium:
		return 2
	case RiskLow:
		return 3
	default:
		return 4
	}
}

func entityQueryAllowedNodeKind(kind NodeKind) bool {
	switch kind {
	case NodeKindClaim, NodeKindEvidence, NodeKindObservation, NodeKindSource, NodeKindDecision, NodeKindAction, NodeKindOutcome,
		NodeKindBucketPolicyStatement, NodeKindBucketPublicAccessBlock, NodeKindBucketEncryptionConfig, NodeKindBucketLoggingConfig, NodeKindBucketVersioningConfig:
		return false
	default:
		return true
	}
}

func cloneOptionalBool(value *bool) *bool {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}
