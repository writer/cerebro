package graph

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"
)

const (
	defaultClaimGroupLimit    = 100
	maxClaimGroupLimit        = 500
	defaultClaimTimelineLimit = 250
	maxClaimTimelineLimit     = 1000
	defaultClaimDiffLimit     = 100
	maxClaimDiffLimit         = 500
)

// ClaimGroupQueryOptions tunes adjudication-focused claim group reads.
type ClaimGroupQueryOptions struct {
	GroupID            string    `json:"group_id,omitempty"`
	SubjectID          string    `json:"subject_id,omitempty"`
	Predicate          string    `json:"predicate,omitempty"`
	IncludeResolved    bool      `json:"include_resolved,omitempty"`
	NeedsAdjudication  *bool     `json:"needs_adjudication,omitempty"`
	IncludeSingleValue bool      `json:"include_single_value,omitempty"`
	ValidAt            time.Time `json:"valid_at,omitempty"`
	RecordedAt         time.Time `json:"recorded_at,omitempty"`
	Limit              int       `json:"limit,omitempty"`
	Offset             int       `json:"offset,omitempty"`
	IncludeClaims      bool      `json:"include_claims,omitempty"`
}

// ClaimGroupQueryFilters echoes the applied group-query filters.
type ClaimGroupQueryFilters struct {
	GroupID            string `json:"group_id,omitempty"`
	SubjectID          string `json:"subject_id,omitempty"`
	Predicate          string `json:"predicate,omitempty"`
	IncludeResolved    bool   `json:"include_resolved,omitempty"`
	IncludeSingleValue bool   `json:"include_single_value,omitempty"`
	NeedsAdjudication  *bool  `json:"needs_adjudication,omitempty"`
}

// ClaimGroupValueRecord summarizes one distinct value inside a claim group.
type ClaimGroupValueRecord struct {
	Value             string    `json:"value"`
	ClaimIDs          []string  `json:"claim_ids,omitempty"`
	ActiveClaimIDs    []string  `json:"active_claim_ids,omitempty"`
	ResolvedClaimIDs  []string  `json:"resolved_claim_ids,omitempty"`
	SourceIDs         []string  `json:"source_ids,omitempty"`
	EvidenceIDs       []string  `json:"evidence_ids,omitempty"`
	HighestConfidence float64   `json:"highest_confidence,omitempty"`
	LatestObservedAt  time.Time `json:"latest_observed_at,omitempty"`
}

// ClaimGroupDerivedState exposes adjudication and quality signals for one group.
type ClaimGroupDerivedState struct {
	NeedsAdjudication  bool   `json:"needs_adjudication"`
	HasConflict        bool   `json:"has_conflict"`
	HasResolvedClaims  bool   `json:"has_resolved_claims"`
	ActiveClaimCount   int    `json:"active_claim_count"`
	ResolvedClaimCount int    `json:"resolved_claim_count"`
	UnsupportedClaims  int    `json:"unsupported_claims"`
	SourcelessClaims   int    `json:"sourceless_claims"`
	DistinctValueCount int    `json:"distinct_value_count"`
	RecommendedAction  string `json:"recommended_action,omitempty"`
}

// ClaimGroupRecord is the typed adjudication queue record for one subject/predicate pair.
type ClaimGroupRecord struct {
	ID                string                  `json:"id"`
	SubjectID         string                  `json:"subject_id"`
	Predicate         string                  `json:"predicate"`
	ClaimIDs          []string                `json:"claim_ids,omitempty"`
	ActiveClaimIDs    []string                `json:"active_claim_ids,omitempty"`
	ResolvedClaimIDs  []string                `json:"resolved_claim_ids,omitempty"`
	SourceIDs         []string                `json:"source_ids,omitempty"`
	EvidenceIDs       []string                `json:"evidence_ids,omitempty"`
	HighestConfidence float64                 `json:"highest_confidence,omitempty"`
	LatestObservedAt  time.Time               `json:"latest_observed_at,omitempty"`
	Values            []ClaimGroupValueRecord `json:"values,omitempty"`
	Claims            []ClaimRecord           `json:"claims,omitempty"`
	Derived           ClaimGroupDerivedState  `json:"derived"`
}

// ClaimGroupCollectionSummary captures high-level adjudication backlog signals.
type ClaimGroupCollectionSummary struct {
	MatchedGroups             int `json:"matched_groups"`
	GroupsNeedingAdjudication int `json:"groups_needing_adjudication"`
	ConflictGroups            int `json:"conflict_groups"`
	UnsupportedGroups         int `json:"unsupported_groups"`
	SourcelessGroups          int `json:"sourceless_groups"`
	ActiveClaims              int `json:"active_claims"`
	ResolvedClaims            int `json:"resolved_claims"`
}

// ClaimGroupCollection is the typed response for claim adjudication queue reads.
type ClaimGroupCollection struct {
	GeneratedAt time.Time                   `json:"generated_at"`
	ValidAt     time.Time                   `json:"valid_at"`
	RecordedAt  time.Time                   `json:"recorded_at"`
	Filters     ClaimGroupQueryFilters      `json:"filters"`
	Summary     ClaimGroupCollectionSummary `json:"summary"`
	Groups      []ClaimGroupRecord          `json:"groups,omitempty"`
	Count       int                         `json:"count"`
	Pagination  ClaimCollectionPagination   `json:"pagination"`
}

// ClaimTimelineOptions tunes one claim explanation timeline.
type ClaimTimelineOptions struct {
	ValidAt    time.Time `json:"valid_at,omitempty"`
	RecordedAt time.Time `json:"recorded_at,omitempty"`
	Limit      int       `json:"limit,omitempty"`
}

// ClaimTimelineEntry is one typed event or supporting object in a claim timeline.
type ClaimTimelineEntry struct {
	ID               string                   `json:"id"`
	EntryType        string                   `json:"entry_type"`
	RelationshipKind string                   `json:"relationship_kind,omitempty"`
	Direction        string                   `json:"direction,omitempty"`
	ChainDepth       int                      `json:"chain_depth,omitempty"`
	ViaClaimID       string                   `json:"via_claim_id,omitempty"`
	Summary          string                   `json:"summary,omitempty"`
	Claim            *ClaimRecord             `json:"claim,omitempty"`
	Artifact         *KnowledgeArtifactRecord `json:"artifact,omitempty"`
	Source           *KnowledgeSourceRecord   `json:"source,omitempty"`
}

// ClaimTimelineSummary captures composition and truncation metadata for one timeline.
type ClaimTimelineSummary struct {
	TotalEntries        int  `json:"total_entries"`
	ReturnedEntries     int  `json:"returned_entries"`
	EntriesTruncated    bool `json:"entries_truncated,omitempty"`
	ClaimEntries        int  `json:"claim_entries"`
	EvidenceEntries     int  `json:"evidence_entries"`
	ObservationEntries  int  `json:"observation_entries"`
	SourceEntries       int  `json:"source_entries"`
	SupportEntries      int  `json:"support_entries"`
	RefutationEntries   int  `json:"refutation_entries"`
	SupersessionEntries int  `json:"supersession_entries"`
	ConflictEntries     int  `json:"conflict_entries"`
}

// ClaimTimeline is the typed explanation timeline for one claim.
type ClaimTimeline struct {
	GeneratedAt time.Time            `json:"generated_at"`
	ClaimID     string               `json:"claim_id"`
	ValidAt     time.Time            `json:"valid_at"`
	RecordedAt  time.Time            `json:"recorded_at"`
	Summary     ClaimTimelineSummary `json:"summary"`
	Entries     []ClaimTimelineEntry `json:"entries,omitempty"`
}

// ClaimExplanationSummary captures high-level explanation signals for one claim.
type ClaimExplanationSummary struct {
	Supported         bool `json:"supported"`
	SourceBacked      bool `json:"source_backed"`
	Conflicted        bool `json:"conflicted"`
	NeedsAdjudication bool `json:"needs_adjudication"`
	EvidenceCount     int  `json:"evidence_count"`
	ObservationCount  int  `json:"observation_count"`
	SourceCount       int  `json:"source_count"`
	SupportingClaims  int  `json:"supporting_claims"`
	RefutingClaims    int  `json:"refuting_claims"`
	ConflictingClaims int  `json:"conflicting_claims"`
}

// ClaimExplanation is the typed answer for why one claim is true, weak, or disputed.
type ClaimExplanation struct {
	GeneratedAt        time.Time                 `json:"generated_at"`
	ValidAt            time.Time                 `json:"valid_at"`
	RecordedAt         time.Time                 `json:"recorded_at"`
	Claim              ClaimRecord               `json:"claim"`
	Group              *ClaimGroupRecord         `json:"group,omitempty"`
	Sources            []KnowledgeSourceRecord   `json:"sources,omitempty"`
	Evidence           []KnowledgeArtifactRecord `json:"evidence,omitempty"`
	Observations       []KnowledgeArtifactRecord `json:"observations,omitempty"`
	SupportingClaims   []ClaimRecord             `json:"supporting_claims,omitempty"`
	RefutingClaims     []ClaimRecord             `json:"refuting_claims,omitempty"`
	ConflictingClaims  []ClaimRecord             `json:"conflicting_claims,omitempty"`
	SupersedesClaims   []ClaimRecord             `json:"supersedes_claims,omitempty"`
	SupersededByClaims []ClaimRecord             `json:"superseded_by_claims,omitempty"`
	Summary            ClaimExplanationSummary   `json:"summary"`
	WhyTrue            []string                  `json:"why_true,omitempty"`
	WhyDisputed        []string                  `json:"why_disputed,omitempty"`
	RepairActions      []string                  `json:"repair_actions,omitempty"`
}

// ClaimDiffQueryOptions tunes bitemporal claim-layer diffs.
type ClaimDiffQueryOptions struct {
	ClaimID         string    `json:"claim_id,omitempty"`
	SubjectID       string    `json:"subject_id,omitempty"`
	Predicate       string    `json:"predicate,omitempty"`
	ObjectID        string    `json:"object_id,omitempty"`
	ObjectValue     string    `json:"object_value,omitempty"`
	ClaimType       string    `json:"claim_type,omitempty"`
	Status          string    `json:"status,omitempty"`
	SourceID        string    `json:"source_id,omitempty"`
	EvidenceID      string    `json:"evidence_id,omitempty"`
	IncludeResolved bool      `json:"include_resolved,omitempty"`
	FromValidAt     time.Time `json:"from_valid_at,omitempty"`
	FromRecordedAt  time.Time `json:"from_recorded_at,omitempty"`
	ToValidAt       time.Time `json:"to_valid_at,omitempty"`
	ToRecordedAt    time.Time `json:"to_recorded_at,omitempty"`
	Limit           int       `json:"limit,omitempty"`
	Offset          int       `json:"offset,omitempty"`
}

// ClaimDiffQueryFilters echoes the applied diff-query filters.
type ClaimDiffQueryFilters struct {
	ClaimID         string `json:"claim_id,omitempty"`
	SubjectID       string `json:"subject_id,omitempty"`
	Predicate       string `json:"predicate,omitempty"`
	ObjectID        string `json:"object_id,omitempty"`
	ObjectValue     string `json:"object_value,omitempty"`
	ClaimType       string `json:"claim_type,omitempty"`
	Status          string `json:"status,omitempty"`
	SourceID        string `json:"source_id,omitempty"`
	EvidenceID      string `json:"evidence_id,omitempty"`
	IncludeResolved bool   `json:"include_resolved,omitempty"`
}

// ClaimDiffRecord captures one added, removed, or modified claim between slices.
type ClaimDiffRecord struct {
	ClaimID        string       `json:"claim_id"`
	ChangeType     string       `json:"change_type"`
	Summary        string       `json:"summary,omitempty"`
	ModifiedFields []string     `json:"modified_fields,omitempty"`
	Before         *ClaimRecord `json:"before,omitempty"`
	After          *ClaimRecord `json:"after,omitempty"`
}

// ClaimDiffSummary captures high-level change counts.
type ClaimDiffSummary struct {
	AddedClaims    int `json:"added_claims"`
	RemovedClaims  int `json:"removed_claims"`
	ModifiedClaims int `json:"modified_claims"`
}

// ClaimDiffCollection is the typed response for claim-layer diffs.
type ClaimDiffCollection struct {
	GeneratedAt    time.Time                 `json:"generated_at"`
	FromValidAt    time.Time                 `json:"from_valid_at"`
	FromRecordedAt time.Time                 `json:"from_recorded_at"`
	ToValidAt      time.Time                 `json:"to_valid_at"`
	ToRecordedAt   time.Time                 `json:"to_recorded_at"`
	Filters        ClaimDiffQueryFilters     `json:"filters"`
	Summary        ClaimDiffSummary          `json:"summary"`
	Diffs          []ClaimDiffRecord         `json:"diffs,omitempty"`
	Count          int                       `json:"count"`
	Pagination     ClaimCollectionPagination `json:"pagination"`
}

type claimGroupAccumulator struct {
	record ClaimGroupRecord
	values map[string]*ClaimGroupValueRecord
}

type claimTimelineQueueItem struct {
	claimID          string
	relationshipKind string
	direction        string
	depth            int
	viaClaimID       string
}

// QueryClaimGroups returns typed adjudication backlog groups over the claim layer.
func QueryClaimGroups(g *Graph, opts ClaimGroupQueryOptions) ClaimGroupCollection {
	query := normalizeClaimGroupQueryOptions(opts)
	result := ClaimGroupCollection{
		GeneratedAt: temporalNowUTC(),
		ValidAt:     query.ValidAt,
		RecordedAt:  query.RecordedAt,
		Filters: ClaimGroupQueryFilters{
			GroupID:            query.GroupID,
			SubjectID:          query.SubjectID,
			Predicate:          query.Predicate,
			IncludeResolved:    query.IncludeResolved,
			IncludeSingleValue: query.IncludeSingleValue,
			NeedsAdjudication:  query.NeedsAdjudication,
		},
		Pagination: ClaimCollectionPagination{
			Limit:  query.Limit,
			Offset: query.Offset,
		},
	}
	if g == nil {
		return result
	}

	records := collectClaimRecords(g, ClaimQueryOptions{
		SubjectID:       query.SubjectID,
		Predicate:       query.Predicate,
		IncludeResolved: query.IncludeResolved,
		ValidAt:         query.ValidAt,
		RecordedAt:      query.RecordedAt,
		Limit:           maxClaimQueryLimit,
	})
	groups := buildClaimGroupRecords(records, query.IncludeClaims)
	filtered := make([]ClaimGroupRecord, 0, len(groups))
	for _, group := range groups {
		if !claimGroupMatchesQuery(group, query) {
			continue
		}
		filtered = append(filtered, group)
		updateClaimGroupCollectionSummary(&result.Summary, group)
	}
	sortClaimGroupRecords(filtered)
	applyClaimPagination(&result.Pagination, &result.Count, query.Offset, query.Limit, len(filtered))
	if result.Pagination.Offset < len(filtered) {
		end := result.Pagination.Offset + query.Limit
		if end > len(filtered) {
			end = len(filtered)
		}
		result.Groups = append(result.Groups, filtered[result.Pagination.Offset:end]...)
		result.Count = len(result.Groups)
		result.Pagination.HasMore = end < len(filtered)
	}
	return result
}

// GetClaimGroupRecord returns one typed adjudication group at a specific bitemporal slice.
func GetClaimGroupRecord(g *Graph, groupID string, validAt, recordedAt time.Time, includeResolved bool) (ClaimGroupRecord, bool) {
	groupID = strings.TrimSpace(groupID)
	if groupID == "" {
		return ClaimGroupRecord{}, false
	}
	result := QueryClaimGroups(g, ClaimGroupQueryOptions{
		GroupID:            groupID,
		IncludeResolved:    includeResolved,
		IncludeSingleValue: true,
		IncludeClaims:      true,
		ValidAt:            validAt,
		RecordedAt:         recordedAt,
		Limit:              1,
	})
	if len(result.Groups) == 0 {
		return ClaimGroupRecord{}, false
	}
	return result.Groups[0], true
}

// GetClaimTimeline returns one typed timeline showing support, refutation, supersession, and provenance chains.
func GetClaimTimeline(g *Graph, claimID string, opts ClaimTimelineOptions) (ClaimTimeline, bool) {
	query := normalizeClaimTimelineOptions(opts)
	claim, ok := GetClaimRecord(g, strings.TrimSpace(claimID), query.ValidAt, query.RecordedAt)
	if !ok {
		return ClaimTimeline{}, false
	}

	result := ClaimTimeline{
		GeneratedAt: temporalNowUTC(),
		ClaimID:     claim.ID,
		ValidAt:     query.ValidAt,
		RecordedAt:  query.RecordedAt,
	}
	entries := make([]ClaimTimelineEntry, 0, 24)
	seenArtifacts := make(map[string]struct{})
	seenSources := make(map[string]struct{})
	seenClaims := make(map[string]struct{})
	queue := []claimTimelineQueueItem{{claimID: claim.ID, direction: "self"}}

	for len(queue) > 0 {
		item := queue[0]
		queue = queue[1:]
		if _, seen := seenClaims[item.claimID]; seen {
			continue
		}
		record, ok := GetClaimRecord(g, item.claimID, query.ValidAt, query.RecordedAt)
		if !ok {
			continue
		}
		seenClaims[item.claimID] = struct{}{}
		entries = append(entries, ClaimTimelineEntry{
			ID:               "claim:" + record.ID,
			EntryType:        "claim",
			RelationshipKind: item.relationshipKind,
			Direction:        item.direction,
			ChainDepth:       item.depth,
			ViaClaimID:       item.viaClaimID,
			Summary:          claimTimelineClaimSummary(record, item.relationshipKind),
			Claim:            &record,
		})

		for _, sourceID := range record.Links.SourceIDs {
			if _, seen := seenSources[sourceID]; seen {
				continue
			}
			source, ok := GetSourceRecord(g, sourceID, query.ValidAt, query.RecordedAt)
			if !ok {
				continue
			}
			seenSources[sourceID] = struct{}{}
			entries = append(entries, ClaimTimelineEntry{
				ID:               "source:" + source.ID,
				EntryType:        "source",
				RelationshipKind: string(EdgeKindAssertedBy),
				Direction:        "outbound",
				ChainDepth:       item.depth,
				ViaClaimID:       record.ID,
				Summary:          fmt.Sprintf("Source %s asserted this claim", firstNonEmpty(source.CanonicalName, source.ID)),
				Source:           &source,
			})
		}
		for _, artifactID := range record.Links.EvidenceIDs {
			if _, seen := seenArtifacts[artifactID]; seen {
				continue
			}
			artifact, ok := getKnowledgeArtifactRecordForAnyKind(g, artifactID, query.ValidAt, query.RecordedAt)
			if !ok {
				continue
			}
			seenArtifacts[artifactID] = struct{}{}
			entries = append(entries, ClaimTimelineEntry{
				ID:               string(artifact.Kind) + ":" + artifact.ID,
				EntryType:        string(artifact.Kind),
				RelationshipKind: string(EdgeKindBasedOn),
				Direction:        "outbound",
				ChainDepth:       item.depth,
				ViaClaimID:       record.ID,
				Summary:          claimTimelineArtifactSummary(artifact),
				Artifact:         &artifact,
			})
		}

		queue = append(queue,
			claimTimelineQueueItems(record.Links.SupportingClaimIDs, string(EdgeKindSupports), "inbound", item.depth+1, record.ID)...,
		)
		queue = append(queue,
			claimTimelineQueueItems(record.Links.RefutingClaimIDs, string(EdgeKindRefutes), "inbound", item.depth+1, record.ID)...,
		)
		queue = append(queue,
			claimTimelineQueueItems(record.Links.SupersedesClaimIDs, string(EdgeKindSupersedes), "outbound", item.depth+1, record.ID)...,
		)
		queue = append(queue,
			claimTimelineQueueItems(record.Links.SupersededByClaimIDs, string(EdgeKindSupersedes), "inbound", item.depth+1, record.ID)...,
		)
		queue = append(queue,
			claimTimelineQueueItems(record.Links.ConflictingClaimIDs, string(EdgeKindContradicts), "peer", item.depth+1, record.ID)...,
		)
	}

	sortClaimTimelineEntries(entries)
	result.Summary.TotalEntries = len(entries)
	for _, entry := range entries {
		updateClaimTimelineSummary(&result.Summary, entry)
	}
	if len(entries) > query.Limit {
		result.Entries = append(result.Entries, entries[:query.Limit]...)
		result.Summary.EntriesTruncated = true
	} else {
		result.Entries = append(result.Entries, entries...)
	}
	result.Summary.ReturnedEntries = len(result.Entries)
	return result, true
}

// ExplainClaim builds a typed explanation payload for why one claim is true, weak, or disputed.
func ExplainClaim(g *Graph, claimID string, validAt, recordedAt time.Time) (ClaimExplanation, bool) {
	claim, ok := GetClaimRecord(g, strings.TrimSpace(claimID), validAt, recordedAt)
	if !ok {
		return ClaimExplanation{}, false
	}
	result := ClaimExplanation{
		GeneratedAt: temporalNowUTC(),
		ValidAt:     firstNonZeroUTC(validAt, temporalNowUTC()),
		RecordedAt:  firstNonZeroUTC(recordedAt, temporalNowUTC()),
		Claim:       claim,
	}
	if group, ok := GetClaimGroupRecord(g, buildClaimGroupID(claim.SubjectID, claim.Predicate), validAt, recordedAt, true); ok {
		result.Group = &group
		result.Summary.NeedsAdjudication = group.Derived.NeedsAdjudication
	}

	result.SupportingClaims = collectClaimRecordsByID(g, claim.Links.SupportingClaimIDs, validAt, recordedAt)
	result.RefutingClaims = collectClaimRecordsByID(g, claim.Links.RefutingClaimIDs, validAt, recordedAt)
	result.ConflictingClaims = collectClaimRecordsByID(g, claim.Links.ConflictingClaimIDs, validAt, recordedAt)
	result.SupersedesClaims = collectClaimRecordsByID(g, claim.Links.SupersedesClaimIDs, validAt, recordedAt)
	result.SupersededByClaims = collectClaimRecordsByID(g, claim.Links.SupersededByClaimIDs, validAt, recordedAt)
	result.Sources = collectSourceRecordsByID(g, claim.Links.SourceIDs, validAt, recordedAt)
	artifacts := collectArtifactRecordsByID(g, claim.Links.EvidenceIDs, validAt, recordedAt)
	for _, artifact := range artifacts {
		switch artifact.Kind {
		case NodeKindObservation:
			result.Observations = append(result.Observations, artifact)
		default:
			result.Evidence = append(result.Evidence, artifact)
		}
	}
	result.Summary.Supported = claim.Derived.Supported
	result.Summary.SourceBacked = claim.Derived.SourceBacked
	result.Summary.Conflicted = claim.Derived.Conflicted
	result.Summary.EvidenceCount = len(result.Evidence)
	result.Summary.ObservationCount = len(result.Observations)
	result.Summary.SourceCount = len(result.Sources)
	result.Summary.SupportingClaims = len(result.SupportingClaims)
	result.Summary.RefutingClaims = len(result.RefutingClaims)
	result.Summary.ConflictingClaims = len(result.ConflictingClaims)
	result.WhyTrue = buildClaimWhyTrue(claim, result)
	result.WhyDisputed = buildClaimWhyDisputed(claim, result)
	result.RepairActions = buildClaimRepairActions(claim, result)
	return result, true
}

// DiffClaims compares two bitemporal slices of the claim layer.
func DiffClaims(g *Graph, opts ClaimDiffQueryOptions) ClaimDiffCollection {
	query := normalizeClaimDiffQueryOptions(opts)
	result := ClaimDiffCollection{
		GeneratedAt:    temporalNowUTC(),
		FromValidAt:    query.FromValidAt,
		FromRecordedAt: query.FromRecordedAt,
		ToValidAt:      query.ToValidAt,
		ToRecordedAt:   query.ToRecordedAt,
		Filters: ClaimDiffQueryFilters{
			ClaimID:         query.ClaimID,
			SubjectID:       query.SubjectID,
			Predicate:       query.Predicate,
			ObjectID:        query.ObjectID,
			ObjectValue:     query.ObjectValue,
			ClaimType:       query.ClaimType,
			Status:          query.Status,
			SourceID:        query.SourceID,
			EvidenceID:      query.EvidenceID,
			IncludeResolved: query.IncludeResolved,
		},
		Pagination: ClaimCollectionPagination{
			Limit:  query.Limit,
			Offset: query.Offset,
		},
	}
	if g == nil {
		return result
	}

	fromRecords := collectClaimRecords(g, ClaimQueryOptions{
		ClaimID:         query.ClaimID,
		SubjectID:       query.SubjectID,
		Predicate:       query.Predicate,
		ObjectID:        query.ObjectID,
		ObjectValue:     query.ObjectValue,
		ClaimType:       query.ClaimType,
		Status:          query.Status,
		SourceID:        query.SourceID,
		EvidenceID:      query.EvidenceID,
		IncludeResolved: query.IncludeResolved,
		ValidAt:         query.FromValidAt,
		RecordedAt:      query.FromRecordedAt,
		Limit:           maxClaimQueryLimit,
	})
	toRecords := collectClaimRecords(g, ClaimQueryOptions{
		ClaimID:         query.ClaimID,
		SubjectID:       query.SubjectID,
		Predicate:       query.Predicate,
		ObjectID:        query.ObjectID,
		ObjectValue:     query.ObjectValue,
		ClaimType:       query.ClaimType,
		Status:          query.Status,
		SourceID:        query.SourceID,
		EvidenceID:      query.EvidenceID,
		IncludeResolved: query.IncludeResolved,
		ValidAt:         query.ToValidAt,
		RecordedAt:      query.ToRecordedAt,
		Limit:           maxClaimQueryLimit,
	})

	fromByID := claimRecordMap(fromRecords)
	toByID := claimRecordMap(toRecords)
	allIDs := make([]string, 0, len(fromByID)+len(toByID))
	seenIDs := make(map[string]struct{}, len(fromByID)+len(toByID))
	for id := range fromByID {
		allIDs = append(allIDs, id)
		seenIDs[id] = struct{}{}
	}
	for id := range toByID {
		if _, ok := seenIDs[id]; ok {
			continue
		}
		allIDs = append(allIDs, id)
	}
	sort.Strings(allIDs)

	diffs := make([]ClaimDiffRecord, 0, len(allIDs))
	for _, claimID := range allIDs {
		before, beforeOK := fromByID[claimID]
		after, afterOK := toByID[claimID]
		switch {
		case !beforeOK && afterOK:
			diffs = append(diffs, ClaimDiffRecord{
				ClaimID:    claimID,
				ChangeType: "added",
				Summary:    "Claim became visible in the target slice",
				After:      claimRecordPtr(after),
			})
			result.Summary.AddedClaims++
		case beforeOK && !afterOK:
			diffs = append(diffs, ClaimDiffRecord{
				ClaimID:    claimID,
				ChangeType: "removed",
				Summary:    "Claim is no longer visible in the target slice",
				Before:     claimRecordPtr(before),
			})
			result.Summary.RemovedClaims++
		case beforeOK && afterOK:
			modifiedFields := diffClaimRecordFields(before, after)
			if len(modifiedFields) == 0 {
				continue
			}
			diffs = append(diffs, ClaimDiffRecord{
				ClaimID:        claimID,
				ChangeType:     "modified",
				Summary:        fmt.Sprintf("Claim changed across slices: %s", strings.Join(modifiedFields, ", ")),
				ModifiedFields: modifiedFields,
				Before:         claimRecordPtr(before),
				After:          claimRecordPtr(after),
			})
			result.Summary.ModifiedClaims++
		}
	}

	sortClaimDiffRecords(diffs)
	applyClaimPagination(&result.Pagination, &result.Count, query.Offset, query.Limit, len(diffs))
	if result.Pagination.Offset < len(diffs) {
		end := result.Pagination.Offset + query.Limit
		if end > len(diffs) {
			end = len(diffs)
		}
		result.Diffs = append(result.Diffs, diffs[result.Pagination.Offset:end]...)
		result.Count = len(result.Diffs)
		result.Pagination.HasMore = end < len(diffs)
	}
	return result
}

func normalizeClaimGroupQueryOptions(opts ClaimGroupQueryOptions) ClaimGroupQueryOptions {
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
	opts.GroupID = strings.TrimSpace(opts.GroupID)
	opts.SubjectID = strings.TrimSpace(opts.SubjectID)
	opts.Predicate = strings.TrimSpace(opts.Predicate)
	if opts.Limit <= 0 {
		opts.Limit = defaultClaimGroupLimit
	}
	if opts.Limit > maxClaimGroupLimit {
		opts.Limit = maxClaimGroupLimit
	}
	if opts.Offset < 0 {
		opts.Offset = 0
	}
	return opts
}

func normalizeClaimTimelineOptions(opts ClaimTimelineOptions) ClaimTimelineOptions {
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
	if opts.Limit <= 0 {
		opts.Limit = defaultClaimTimelineLimit
	}
	if opts.Limit > maxClaimTimelineLimit {
		opts.Limit = maxClaimTimelineLimit
	}
	return opts
}

func normalizeClaimDiffQueryOptions(opts ClaimDiffQueryOptions) ClaimDiffQueryOptions {
	now := temporalNowUTC()
	opts.ClaimID = strings.TrimSpace(opts.ClaimID)
	opts.SubjectID = strings.TrimSpace(opts.SubjectID)
	opts.Predicate = strings.TrimSpace(opts.Predicate)
	opts.ObjectID = strings.TrimSpace(opts.ObjectID)
	opts.ObjectValue = strings.TrimSpace(opts.ObjectValue)
	opts.ClaimType = strings.ToLower(strings.TrimSpace(opts.ClaimType))
	if rawStatus := strings.TrimSpace(opts.Status); rawStatus != "" {
		opts.Status = normalizeClaimStatus(rawStatus)
	}
	opts.SourceID = strings.TrimSpace(opts.SourceID)
	opts.EvidenceID = strings.TrimSpace(opts.EvidenceID)
	if opts.FromValidAt.IsZero() {
		opts.FromValidAt = now
	} else {
		opts.FromValidAt = opts.FromValidAt.UTC()
	}
	if opts.FromRecordedAt.IsZero() {
		opts.FromRecordedAt = now
	} else {
		opts.FromRecordedAt = opts.FromRecordedAt.UTC()
	}
	if opts.ToValidAt.IsZero() {
		opts.ToValidAt = now
	} else {
		opts.ToValidAt = opts.ToValidAt.UTC()
	}
	if opts.ToRecordedAt.IsZero() {
		opts.ToRecordedAt = now
	} else {
		opts.ToRecordedAt = opts.ToRecordedAt.UTC()
	}
	if opts.Limit <= 0 {
		opts.Limit = defaultClaimDiffLimit
	}
	if opts.Limit > maxClaimDiffLimit {
		opts.Limit = maxClaimDiffLimit
	}
	if opts.Offset < 0 {
		opts.Offset = 0
	}
	return opts
}

func buildClaimGroupRecords(records []ClaimRecord, includeClaims bool) []ClaimGroupRecord {
	groups := make(map[string]*claimGroupAccumulator)
	for _, record := range records {
		groupID := buildClaimGroupID(record.SubjectID, record.Predicate)
		acc := groups[groupID]
		if acc == nil {
			acc = &claimGroupAccumulator{
				record: ClaimGroupRecord{
					ID:        groupID,
					SubjectID: record.SubjectID,
					Predicate: record.Predicate,
				},
				values: make(map[string]*ClaimGroupValueRecord),
			}
			groups[groupID] = acc
		}
		acc.record.ClaimIDs = append(acc.record.ClaimIDs, record.ID)
		if record.Derived.Resolved {
			acc.record.ResolvedClaimIDs = append(acc.record.ResolvedClaimIDs, record.ID)
			acc.record.Derived.ResolvedClaimCount++
			acc.record.Derived.HasResolvedClaims = true
		} else {
			acc.record.ActiveClaimIDs = append(acc.record.ActiveClaimIDs, record.ID)
			acc.record.Derived.ActiveClaimCount++
		}
		if record.Derived.Sourceless {
			acc.record.Derived.SourcelessClaims++
		}
		if !record.Derived.Supported {
			acc.record.Derived.UnsupportedClaims++
		}
		if record.Confidence > acc.record.HighestConfidence {
			acc.record.HighestConfidence = record.Confidence
		}
		if record.ObservedAt.After(acc.record.LatestObservedAt) {
			acc.record.LatestObservedAt = record.ObservedAt
		}
		acc.record.SourceIDs = append(acc.record.SourceIDs, record.Links.SourceIDs...)
		acc.record.EvidenceIDs = append(acc.record.EvidenceIDs, record.Links.EvidenceIDs...)
		if includeClaims {
			acc.record.Claims = append(acc.record.Claims, record)
		}

		valueKey := claimRecordComparableValue(record)
		valueRecord := acc.values[valueKey]
		if valueRecord == nil {
			valueRecord = &ClaimGroupValueRecord{Value: claimRecordDisplayValue(record)}
			acc.values[valueKey] = valueRecord
		}
		valueRecord.ClaimIDs = append(valueRecord.ClaimIDs, record.ID)
		if record.Derived.Resolved {
			valueRecord.ResolvedClaimIDs = append(valueRecord.ResolvedClaimIDs, record.ID)
		} else {
			valueRecord.ActiveClaimIDs = append(valueRecord.ActiveClaimIDs, record.ID)
		}
		valueRecord.SourceIDs = append(valueRecord.SourceIDs, record.Links.SourceIDs...)
		valueRecord.EvidenceIDs = append(valueRecord.EvidenceIDs, record.Links.EvidenceIDs...)
		if record.Confidence > valueRecord.HighestConfidence {
			valueRecord.HighestConfidence = record.Confidence
		}
		if record.ObservedAt.After(valueRecord.LatestObservedAt) {
			valueRecord.LatestObservedAt = record.ObservedAt
		}
	}

	out := make([]ClaimGroupRecord, 0, len(groups))
	for _, acc := range groups {
		acc.record.ClaimIDs = uniqueSortedStrings(trimNonEmpty(acc.record.ClaimIDs))
		acc.record.ActiveClaimIDs = uniqueSortedStrings(trimNonEmpty(acc.record.ActiveClaimIDs))
		acc.record.ResolvedClaimIDs = uniqueSortedStrings(trimNonEmpty(acc.record.ResolvedClaimIDs))
		acc.record.SourceIDs = uniqueSortedStrings(trimNonEmpty(acc.record.SourceIDs))
		acc.record.EvidenceIDs = uniqueSortedStrings(trimNonEmpty(acc.record.EvidenceIDs))
		acc.record.Values = make([]ClaimGroupValueRecord, 0, len(acc.values))
		for _, valueRecord := range acc.values {
			valueRecord.ClaimIDs = uniqueSortedStrings(trimNonEmpty(valueRecord.ClaimIDs))
			valueRecord.ActiveClaimIDs = uniqueSortedStrings(trimNonEmpty(valueRecord.ActiveClaimIDs))
			valueRecord.ResolvedClaimIDs = uniqueSortedStrings(trimNonEmpty(valueRecord.ResolvedClaimIDs))
			valueRecord.SourceIDs = uniqueSortedStrings(trimNonEmpty(valueRecord.SourceIDs))
			valueRecord.EvidenceIDs = uniqueSortedStrings(trimNonEmpty(valueRecord.EvidenceIDs))
			acc.record.Values = append(acc.record.Values, *valueRecord)
		}
		sort.Slice(acc.record.Values, func(i, j int) bool {
			if len(acc.record.Values[i].ActiveClaimIDs) == len(acc.record.Values[j].ActiveClaimIDs) {
				return acc.record.Values[i].Value < acc.record.Values[j].Value
			}
			return len(acc.record.Values[i].ActiveClaimIDs) > len(acc.record.Values[j].ActiveClaimIDs)
		})
		if includeClaims {
			sortClaimRecords(acc.record.Claims)
		}
		acc.record.Derived.DistinctValueCount = len(acc.record.Values)
		acc.record.Derived.HasConflict = len(acc.record.Values) > 1
		acc.record.Derived.NeedsAdjudication = len(acc.record.ActiveClaimIDs) > 1 && len(activeClaimGroupValueKeys(acc.record.Values)) > 1
		acc.record.Derived.RecommendedAction = claimGroupRecommendedAction(acc.record.Derived)
		out = append(out, acc.record)
	}
	return out
}

func claimGroupMatchesQuery(record ClaimGroupRecord, opts ClaimGroupQueryOptions) bool {
	if opts.GroupID != "" && record.ID != opts.GroupID {
		return false
	}
	if opts.SubjectID != "" && record.SubjectID != opts.SubjectID {
		return false
	}
	if opts.Predicate != "" && !strings.EqualFold(record.Predicate, opts.Predicate) {
		return false
	}
	if !opts.IncludeSingleValue && len(record.Values) <= 1 {
		return false
	}
	if opts.NeedsAdjudication != nil && record.Derived.NeedsAdjudication != *opts.NeedsAdjudication {
		return false
	}
	return true
}

func updateClaimGroupCollectionSummary(summary *ClaimGroupCollectionSummary, record ClaimGroupRecord) {
	if summary == nil {
		return
	}
	summary.MatchedGroups++
	summary.ActiveClaims += record.Derived.ActiveClaimCount
	summary.ResolvedClaims += record.Derived.ResolvedClaimCount
	if record.Derived.NeedsAdjudication {
		summary.GroupsNeedingAdjudication++
	}
	if record.Derived.HasConflict {
		summary.ConflictGroups++
	}
	if record.Derived.UnsupportedClaims > 0 {
		summary.UnsupportedGroups++
	}
	if record.Derived.SourcelessClaims > 0 {
		summary.SourcelessGroups++
	}
}

func sortClaimGroupRecords(records []ClaimGroupRecord) {
	sort.Slice(records, func(i, j int) bool {
		if records[i].Derived.NeedsAdjudication != records[j].Derived.NeedsAdjudication {
			return records[i].Derived.NeedsAdjudication
		}
		if records[i].Derived.UnsupportedClaims != records[j].Derived.UnsupportedClaims {
			return records[i].Derived.UnsupportedClaims > records[j].Derived.UnsupportedClaims
		}
		if !records[i].LatestObservedAt.Equal(records[j].LatestObservedAt) {
			return records[i].LatestObservedAt.After(records[j].LatestObservedAt)
		}
		return records[i].ID < records[j].ID
	})
}

func buildClaimGroupID(subjectID, predicate string) string {
	return "claim_group:" + slugifyKnowledgeKey(subjectID) + ":" + slugifyKnowledgeKey(predicate)
}

func activeClaimGroupValueKeys(values []ClaimGroupValueRecord) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if len(value.ActiveClaimIDs) == 0 {
			continue
		}
		out = append(out, strings.ToLower(strings.TrimSpace(value.Value)))
	}
	return uniqueSortedStrings(trimNonEmpty(out))
}

func claimGroupRecommendedAction(derived ClaimGroupDerivedState) string {
	switch {
	case derived.NeedsAdjudication:
		return "adjudicate"
	case derived.UnsupportedClaims > 0:
		return "backfill_evidence"
	case derived.SourcelessClaims > 0:
		return "backfill_source"
	case derived.HasResolvedClaims:
		return "review_history"
	default:
		return "monitor"
	}
}

func collectClaimRecordsByID(g *Graph, ids []string, validAt, recordedAt time.Time) []ClaimRecord {
	if len(ids) == 0 {
		return nil
	}
	out := make([]ClaimRecord, 0, len(ids))
	seen := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		record, ok := GetClaimRecord(g, id, validAt, recordedAt)
		if !ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, record)
	}
	sortClaimRecords(out)
	return out
}

func collectArtifactRecordsByID(g *Graph, ids []string, validAt, recordedAt time.Time) []KnowledgeArtifactRecord {
	if len(ids) == 0 {
		return nil
	}
	out := make([]KnowledgeArtifactRecord, 0, len(ids))
	seen := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		record, ok := getKnowledgeArtifactRecordForAnyKind(g, id, validAt, recordedAt)
		if !ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, record)
	}
	sortKnowledgeArtifactRecords(out)
	return out
}

func collectSourceRecordsByID(g *Graph, ids []string, validAt, recordedAt time.Time) []KnowledgeSourceRecord {
	if len(ids) == 0 {
		return nil
	}
	out := make([]KnowledgeSourceRecord, 0, len(ids))
	seen := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		record, ok := GetSourceRecord(g, id, validAt, recordedAt)
		if !ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, record)
	}
	sortKnowledgeSourceRecords(out)
	return out
}

func claimTimelineQueueItems(ids []string, relationshipKind, direction string, depth int, viaClaimID string) []claimTimelineQueueItem {
	out := make([]claimTimelineQueueItem, 0, len(ids))
	for _, id := range uniqueSortedStrings(trimNonEmpty(ids)) {
		out = append(out, claimTimelineQueueItem{
			claimID:          id,
			relationshipKind: relationshipKind,
			direction:        direction,
			depth:            depth,
			viaClaimID:       viaClaimID,
		})
	}
	return out
}

func sortClaimTimelineEntries(entries []ClaimTimelineEntry) {
	sort.Slice(entries, func(i, j int) bool {
		iRecorded, iValid, iObserved, iID := claimTimelineEntrySortKey(entries[i])
		jRecorded, jValid, jObserved, jID := claimTimelineEntrySortKey(entries[j])
		if !iRecorded.Equal(jRecorded) {
			return iRecorded.After(jRecorded)
		}
		if !iValid.Equal(jValid) {
			return iValid.After(jValid)
		}
		if !iObserved.Equal(jObserved) {
			return iObserved.After(jObserved)
		}
		return iID < jID
	})
}

func claimTimelineEntrySortKey(entry ClaimTimelineEntry) (time.Time, time.Time, time.Time, string) {
	switch {
	case entry.Claim != nil:
		return entry.Claim.RecordedAt, entry.Claim.ValidFrom, entry.Claim.ObservedAt, entry.ID
	case entry.Artifact != nil:
		return entry.Artifact.RecordedAt, entry.Artifact.ValidFrom, entry.Artifact.ObservedAt, entry.ID
	case entry.Source != nil:
		return entry.Source.RecordedAt, entry.Source.ValidFrom, entry.Source.ObservedAt, entry.ID
	default:
		return time.Time{}, time.Time{}, time.Time{}, entry.ID
	}
}

func updateClaimTimelineSummary(summary *ClaimTimelineSummary, entry ClaimTimelineEntry) {
	if summary == nil {
		return
	}
	switch entry.EntryType {
	case "claim":
		summary.ClaimEntries++
		switch entry.RelationshipKind {
		case string(EdgeKindSupports):
			summary.SupportEntries++
		case string(EdgeKindRefutes):
			summary.RefutationEntries++
		case string(EdgeKindSupersedes):
			summary.SupersessionEntries++
		case string(EdgeKindContradicts):
			summary.ConflictEntries++
		}
	case string(NodeKindEvidence):
		summary.EvidenceEntries++
	case string(NodeKindObservation):
		summary.ObservationEntries++
	case "source":
		summary.SourceEntries++
	}
}

func claimTimelineClaimSummary(record ClaimRecord, relationshipKind string) string {
	switch relationshipKind {
	case string(EdgeKindSupports):
		return "Supporting claim"
	case string(EdgeKindRefutes):
		return "Refuting claim"
	case string(EdgeKindSupersedes):
		if record.Derived.Resolved {
			return "Superseded claim"
		}
		return "Superseding claim"
	case string(EdgeKindContradicts):
		return "Conflicting claim"
	default:
		return "Primary claim"
	}
}

func claimTimelineArtifactSummary(record KnowledgeArtifactRecord) string {
	if record.Kind == NodeKindObservation {
		return fmt.Sprintf("Observation %s supports the claim", firstNonEmpty(record.ArtifactType, record.ID))
	}
	return fmt.Sprintf("Evidence %s supports the claim", firstNonEmpty(record.ArtifactType, record.ID))
}

func buildClaimWhyTrue(claim ClaimRecord, explanation ClaimExplanation) []string {
	out := make([]string, 0, 4)
	if len(explanation.Evidence) > 0 || len(explanation.Observations) > 0 {
		out = append(out, fmt.Sprintf("Backed by %d evidence and observation artifacts", len(explanation.Evidence)+len(explanation.Observations)))
	}
	if len(explanation.SupportingClaims) > 0 {
		out = append(out, fmt.Sprintf("Supported by %d upstream claims", len(explanation.SupportingClaims)))
	}
	if len(explanation.Sources) > 0 {
		out = append(out, fmt.Sprintf("Asserted by %d named sources", len(explanation.Sources)))
	}
	if claim.Status == "asserted" && len(out) == 0 {
		out = append(out, "Claim is currently asserted but has weak support")
	}
	return out
}

func buildClaimWhyDisputed(claim ClaimRecord, explanation ClaimExplanation) []string {
	out := make([]string, 0, 6)
	if len(explanation.ConflictingClaims) > 0 {
		out = append(out, fmt.Sprintf("%d conflicting claims assert different values for the same subject and predicate", len(explanation.ConflictingClaims)))
	}
	if len(explanation.RefutingClaims) > 0 {
		out = append(out, fmt.Sprintf("%d claims explicitly refute this claim", len(explanation.RefutingClaims)))
	}
	if len(explanation.SupersededByClaims) > 0 {
		out = append(out, fmt.Sprintf("%d newer claims supersede this claim", len(explanation.SupersededByClaims)))
	}
	if !claim.Derived.Supported {
		out = append(out, "No evidence artifacts or supporting claims are linked")
	}
	if !claim.Derived.SourceBacked {
		out = append(out, "No asserted_by source link is present")
	}
	if claim.Derived.Resolved {
		out = append(out, fmt.Sprintf("Claim status is %s", claim.Status))
	}
	return out
}

func buildClaimRepairActions(claim ClaimRecord, explanation ClaimExplanation) []string {
	out := make([]string, 0, 4)
	if explanation.Summary.NeedsAdjudication {
		out = append(out, "Adjudicate the conflicting claim group and select the authoritative value")
	}
	if !claim.Derived.Supported {
		out = append(out, "Attach evidence or supporting claims")
	}
	if !claim.Derived.SourceBacked {
		out = append(out, "Attach explicit source attribution")
	}
	if claim.Derived.Superseded && claim.Status == "asserted" {
		out = append(out, "Record supersession or correction explicitly on the claim lifecycle")
	}
	return uniqueSortedStrings(trimNonEmpty(out))
}

func claimRecordComparableValue(record ClaimRecord) string {
	return strings.ToLower(strings.TrimSpace(firstNonEmpty(record.ObjectID, record.ObjectValue, record.Summary)))
}

func claimRecordDisplayValue(record ClaimRecord) string {
	return firstNonEmpty(record.ObjectID, record.ObjectValue, record.Summary, record.ID)
}

func getKnowledgeArtifactRecordForAnyKind(g *Graph, id string, validAt, recordedAt time.Time) (KnowledgeArtifactRecord, bool) {
	if record, ok := GetEvidenceRecord(g, id, validAt, recordedAt); ok {
		return record, true
	}
	return GetObservationRecord(g, id, validAt, recordedAt)
}

func sortKnowledgeArtifactRecords(records []KnowledgeArtifactRecord) {
	sort.Slice(records, func(i, j int) bool {
		if !records[i].RecordedAt.Equal(records[j].RecordedAt) {
			return records[i].RecordedAt.After(records[j].RecordedAt)
		}
		if !records[i].ObservedAt.Equal(records[j].ObservedAt) {
			return records[i].ObservedAt.After(records[j].ObservedAt)
		}
		return records[i].ID < records[j].ID
	})
}

func sortKnowledgeSourceRecords(records []KnowledgeSourceRecord) {
	sort.Slice(records, func(i, j int) bool {
		if !records[i].RecordedAt.Equal(records[j].RecordedAt) {
			return records[i].RecordedAt.After(records[j].RecordedAt)
		}
		if !records[i].ObservedAt.Equal(records[j].ObservedAt) {
			return records[i].ObservedAt.After(records[j].ObservedAt)
		}
		return records[i].ID < records[j].ID
	})
}

func applyClaimPagination(pagination *ClaimCollectionPagination, count *int, offset, limit, total int) {
	if pagination == nil {
		return
	}
	pagination.Total = total
	pagination.Limit = limit
	pagination.Offset = offset
	if offset > total {
		pagination.Offset = total
	}
	if count != nil {
		*count = 0
	}
}

func claimRecordMap(records []ClaimRecord) map[string]ClaimRecord {
	out := make(map[string]ClaimRecord, len(records))
	for _, record := range records {
		out[record.ID] = record
	}
	return out
}

func diffClaimRecordFields(before, after ClaimRecord) []string {
	modified := make([]string, 0, 12)
	if before.ClaimType != after.ClaimType {
		modified = append(modified, "claim_type")
	}
	if before.SubjectID != after.SubjectID {
		modified = append(modified, "subject_id")
	}
	if before.Predicate != after.Predicate {
		modified = append(modified, "predicate")
	}
	if before.ObjectID != after.ObjectID {
		modified = append(modified, "object_id")
	}
	if before.ObjectValue != after.ObjectValue {
		modified = append(modified, "object_value")
	}
	if before.Status != after.Status {
		modified = append(modified, "status")
	}
	if before.Summary != after.Summary {
		modified = append(modified, "summary")
	}
	if before.Confidence != after.Confidence {
		modified = append(modified, "confidence")
	}
	if !before.ObservedAt.Equal(after.ObservedAt) {
		modified = append(modified, "observed_at")
	}
	if !before.ValidFrom.Equal(after.ValidFrom) {
		modified = append(modified, "valid_from")
	}
	if !equalTimePtr(before.ValidTo, after.ValidTo) {
		modified = append(modified, "valid_to")
	}
	if !before.RecordedAt.Equal(after.RecordedAt) {
		modified = append(modified, "recorded_at")
	}
	if !before.TransactionFrom.Equal(after.TransactionFrom) {
		modified = append(modified, "transaction_from")
	}
	if !equalTimePtr(before.TransactionTo, after.TransactionTo) {
		modified = append(modified, "transaction_to")
	}
	if before.SourceSystem != after.SourceSystem {
		modified = append(modified, "source_system")
	}
	if before.SourceEventID != after.SourceEventID {
		modified = append(modified, "source_event_id")
	}
	if !reflect.DeepEqual(before.Links, after.Links) {
		modified = append(modified, "links")
	}
	if !reflect.DeepEqual(before.Derived, after.Derived) {
		modified = append(modified, "derived")
	}
	if !reflect.DeepEqual(before.Metadata, after.Metadata) {
		modified = append(modified, "metadata")
	}
	return modified
}

func sortClaimDiffRecords(records []ClaimDiffRecord) {
	sort.Slice(records, func(i, j int) bool {
		iRecorded, iID := claimDiffSortKey(records[i])
		jRecorded, jID := claimDiffSortKey(records[j])
		if !iRecorded.Equal(jRecorded) {
			return iRecorded.After(jRecorded)
		}
		return iID < jID
	})
}

func claimDiffSortKey(record ClaimDiffRecord) (time.Time, string) {
	if record.After != nil {
		return record.After.RecordedAt, record.ClaimID
	}
	if record.Before != nil {
		return record.Before.RecordedAt, record.ClaimID
	}
	return time.Time{}, record.ClaimID
}

func claimRecordPtr(record ClaimRecord) *ClaimRecord {
	copy := record
	return &copy
}

func equalTimePtr(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Equal(*b)
}

func firstNonZeroUTC(value, fallback time.Time) time.Time {
	if !value.IsZero() {
		return value.UTC()
	}
	return fallback.UTC()
}
