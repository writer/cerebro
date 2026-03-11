package graph

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"
)

// KnowledgeDiffQueryOptions tunes cross-slice knowledge diffs over claims,
// evidence, and observations.
type KnowledgeDiffQueryOptions struct {
	Kinds           []NodeKind `json:"kinds,omitempty"`
	ClaimID         string     `json:"claim_id,omitempty"`
	SubjectID       string     `json:"subject_id,omitempty"`
	Predicate       string     `json:"predicate,omitempty"`
	ObjectID        string     `json:"object_id,omitempty"`
	ObjectValue     string     `json:"object_value,omitempty"`
	ClaimType       string     `json:"claim_type,omitempty"`
	Status          string     `json:"status,omitempty"`
	TargetID        string     `json:"target_id,omitempty"`
	SourceID        string     `json:"source_id,omitempty"`
	ArtifactType    string     `json:"artifact_type,omitempty"`
	IncludeResolved bool       `json:"include_resolved,omitempty"`
	FromSnapshotID  string     `json:"from_snapshot_id,omitempty"`
	ToSnapshotID    string     `json:"to_snapshot_id,omitempty"`
	FromValidAt     time.Time  `json:"from_valid_at,omitempty"`
	FromRecordedAt  time.Time  `json:"from_recorded_at,omitempty"`
	ToValidAt       time.Time  `json:"to_valid_at,omitempty"`
	ToRecordedAt    time.Time  `json:"to_recorded_at,omitempty"`
}

// KnowledgeDiffQueryFilters echoes the applied knowledge diff filters.
type KnowledgeDiffQueryFilters struct {
	Kinds           []string `json:"kinds,omitempty"`
	ClaimID         string   `json:"claim_id,omitempty"`
	SubjectID       string   `json:"subject_id,omitempty"`
	Predicate       string   `json:"predicate,omitempty"`
	ObjectID        string   `json:"object_id,omitempty"`
	ObjectValue     string   `json:"object_value,omitempty"`
	ClaimType       string   `json:"claim_type,omitempty"`
	Status          string   `json:"status,omitempty"`
	TargetID        string   `json:"target_id,omitempty"`
	SourceID        string   `json:"source_id,omitempty"`
	ArtifactType    string   `json:"artifact_type,omitempty"`
	IncludeResolved bool     `json:"include_resolved,omitempty"`
}

// KnowledgeArtifactDiffRecord captures one evidence/observation change.
type KnowledgeArtifactDiffRecord struct {
	ArtifactID     string                   `json:"artifact_id"`
	Kind           NodeKind                 `json:"kind"`
	ChangeType     string                   `json:"change_type"`
	Summary        string                   `json:"summary,omitempty"`
	ModifiedFields []string                 `json:"modified_fields,omitempty"`
	Before         *KnowledgeArtifactRecord `json:"before,omitempty"`
	After          *KnowledgeArtifactRecord `json:"after,omitempty"`
}

// KnowledgeDiffSummary captures aggregate change counts across the knowledge layer.
type KnowledgeDiffSummary struct {
	AddedClaims          int `json:"added_claims"`
	RemovedClaims        int `json:"removed_claims"`
	ModifiedClaims       int `json:"modified_claims"`
	AddedEvidence        int `json:"added_evidence"`
	RemovedEvidence      int `json:"removed_evidence"`
	ModifiedEvidence     int `json:"modified_evidence"`
	AddedObservations    int `json:"added_observations"`
	RemovedObservations  int `json:"removed_observations"`
	ModifiedObservations int `json:"modified_observations"`
}

// KnowledgeDiffCollection is the typed response for cross-slice knowledge diffs.
type KnowledgeDiffCollection struct {
	GeneratedAt    time.Time                     `json:"generated_at"`
	ComparisonMode string                        `json:"comparison_mode"`
	FromSnapshotID string                        `json:"from_snapshot_id,omitempty"`
	ToSnapshotID   string                        `json:"to_snapshot_id,omitempty"`
	FromValidAt    time.Time                     `json:"from_valid_at,omitempty"`
	FromRecordedAt time.Time                     `json:"from_recorded_at,omitempty"`
	ToValidAt      time.Time                     `json:"to_valid_at,omitempty"`
	ToRecordedAt   time.Time                     `json:"to_recorded_at,omitempty"`
	Filters        KnowledgeDiffQueryFilters     `json:"filters"`
	Summary        KnowledgeDiffSummary          `json:"summary"`
	ClaimDiffs     []ClaimDiffRecord             `json:"claim_diffs,omitempty"`
	ArtifactDiffs  []KnowledgeArtifactDiffRecord `json:"artifact_diffs,omitempty"`
}

// DiffKnowledgeGraphs compares the knowledge layer between two graph views.
func DiffKnowledgeGraphs(fromGraph, toGraph *Graph, opts KnowledgeDiffQueryOptions) KnowledgeDiffCollection {
	query := normalizeKnowledgeDiffQueryOptions(opts)
	result := KnowledgeDiffCollection{
		GeneratedAt:    temporalNowUTC(),
		ComparisonMode: knowledgeDiffMode(query),
		FromSnapshotID: query.FromSnapshotID,
		ToSnapshotID:   query.ToSnapshotID,
		FromValidAt:    query.FromValidAt,
		FromRecordedAt: query.FromRecordedAt,
		ToValidAt:      query.ToValidAt,
		ToRecordedAt:   query.ToRecordedAt,
		Filters: KnowledgeDiffQueryFilters{
			Kinds:           knowledgeDiffKindsAsStrings(query.Kinds),
			ClaimID:         query.ClaimID,
			SubjectID:       query.SubjectID,
			Predicate:       query.Predicate,
			ObjectID:        query.ObjectID,
			ObjectValue:     query.ObjectValue,
			ClaimType:       query.ClaimType,
			Status:          query.Status,
			TargetID:        query.TargetID,
			SourceID:        query.SourceID,
			ArtifactType:    query.ArtifactType,
			IncludeResolved: query.IncludeResolved,
		},
	}

	if includesKnowledgeKind(query.Kinds, NodeKindClaim) {
		result.ClaimDiffs = diffKnowledgeClaims(fromGraph, toGraph, query)
		for _, diff := range result.ClaimDiffs {
			switch diff.ChangeType {
			case "added":
				result.Summary.AddedClaims++
			case "removed":
				result.Summary.RemovedClaims++
			case "modified":
				result.Summary.ModifiedClaims++
			}
		}
	}
	for _, kind := range []NodeKind{NodeKindEvidence, NodeKindObservation} {
		if !includesKnowledgeKind(query.Kinds, kind) {
			continue
		}
		artifactDiffs := diffKnowledgeArtifacts(fromGraph, toGraph, kind, query)
		result.ArtifactDiffs = append(result.ArtifactDiffs, artifactDiffs...)
		for _, diff := range artifactDiffs {
			switch diff.Kind {
			case NodeKindObservation:
				switch diff.ChangeType {
				case "added":
					result.Summary.AddedObservations++
				case "removed":
					result.Summary.RemovedObservations++
				case "modified":
					result.Summary.ModifiedObservations++
				}
			default:
				switch diff.ChangeType {
				case "added":
					result.Summary.AddedEvidence++
				case "removed":
					result.Summary.RemovedEvidence++
				case "modified":
					result.Summary.ModifiedEvidence++
				}
			}
		}
	}
	sortClaimDiffRecords(result.ClaimDiffs)
	sortKnowledgeArtifactDiffRecords(result.ArtifactDiffs)
	return result
}

func normalizeKnowledgeDiffQueryOptions(opts KnowledgeDiffQueryOptions) KnowledgeDiffQueryOptions {
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
	opts.TargetID = strings.TrimSpace(opts.TargetID)
	opts.SourceID = strings.TrimSpace(opts.SourceID)
	opts.ArtifactType = strings.ToLower(strings.TrimSpace(opts.ArtifactType))
	opts.FromSnapshotID = strings.TrimSpace(opts.FromSnapshotID)
	opts.ToSnapshotID = strings.TrimSpace(opts.ToSnapshotID)
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
	if len(opts.Kinds) == 0 {
		opts.Kinds = []NodeKind{NodeKindClaim, NodeKindEvidence, NodeKindObservation}
	} else {
		normalized := make([]NodeKind, 0, len(opts.Kinds))
		seen := map[NodeKind]struct{}{}
		for _, kind := range opts.Kinds {
			kind = NodeKind(strings.TrimSpace(strings.ToLower(string(kind))))
			switch kind {
			case NodeKindClaim, NodeKindEvidence, NodeKindObservation:
				if _, ok := seen[kind]; ok {
					continue
				}
				seen[kind] = struct{}{}
				normalized = append(normalized, kind)
			}
		}
		if len(normalized) == 0 {
			normalized = []NodeKind{NodeKindClaim, NodeKindEvidence, NodeKindObservation}
		}
		opts.Kinds = normalized
	}
	return opts
}

func knowledgeDiffMode(opts KnowledgeDiffQueryOptions) string {
	if opts.FromSnapshotID != "" || opts.ToSnapshotID != "" {
		return "snapshot_pair"
	}
	return "bitemporal"
}

func knowledgeDiffKindsAsStrings(kinds []NodeKind) []string {
	if len(kinds) == 0 {
		return nil
	}
	out := make([]string, 0, len(kinds))
	for _, kind := range kinds {
		out = append(out, string(kind))
	}
	sort.Strings(out)
	return out
}

func includesKnowledgeKind(kinds []NodeKind, want NodeKind) bool {
	for _, kind := range kinds {
		if kind == want {
			return true
		}
	}
	return false
}

func diffKnowledgeClaims(fromGraph, toGraph *Graph, opts KnowledgeDiffQueryOptions) []ClaimDiffRecord {
	fromRecords := collectClaimRecords(fromGraph, ClaimQueryOptions{
		ClaimID:         opts.ClaimID,
		SubjectID:       opts.SubjectID,
		Predicate:       opts.Predicate,
		ObjectID:        opts.ObjectID,
		ObjectValue:     opts.ObjectValue,
		ClaimType:       opts.ClaimType,
		Status:          opts.Status,
		SourceID:        opts.SourceID,
		IncludeResolved: opts.IncludeResolved,
		ValidAt:         opts.FromValidAt,
		RecordedAt:      opts.FromRecordedAt,
		Limit:           maxClaimQueryLimit,
	})
	toRecords := collectClaimRecords(toGraph, ClaimQueryOptions{
		ClaimID:         opts.ClaimID,
		SubjectID:       opts.SubjectID,
		Predicate:       opts.Predicate,
		ObjectID:        opts.ObjectID,
		ObjectValue:     opts.ObjectValue,
		ClaimType:       opts.ClaimType,
		Status:          opts.Status,
		SourceID:        opts.SourceID,
		IncludeResolved: opts.IncludeResolved,
		ValidAt:         opts.ToValidAt,
		RecordedAt:      opts.ToRecordedAt,
		Limit:           maxClaimQueryLimit,
	})
	fromByID := claimRecordMap(fromRecords)
	toByID := claimRecordMap(toRecords)
	allIDs := sortedUnionMapKeys(fromByID, toByID)
	out := make([]ClaimDiffRecord, 0, len(allIDs))
	for _, claimID := range allIDs {
		before, beforeOK := fromByID[claimID]
		after, afterOK := toByID[claimID]
		switch {
		case !beforeOK && afterOK:
			out = append(out, ClaimDiffRecord{ClaimID: claimID, ChangeType: "added", Summary: "Claim became visible in the target slice", After: claimRecordPtr(after)})
		case beforeOK && !afterOK:
			out = append(out, ClaimDiffRecord{ClaimID: claimID, ChangeType: "removed", Summary: "Claim is no longer visible in the target slice", Before: claimRecordPtr(before)})
		case beforeOK && afterOK:
			modifiedFields := diffClaimRecordFields(before, after)
			if len(modifiedFields) == 0 {
				continue
			}
			out = append(out, ClaimDiffRecord{
				ClaimID:        claimID,
				ChangeType:     "modified",
				Summary:        fmt.Sprintf("Claim changed across slices: %s", strings.Join(modifiedFields, ", ")),
				ModifiedFields: modifiedFields,
				Before:         claimRecordPtr(before),
				After:          claimRecordPtr(after),
			})
		}
	}
	return out
}

func diffKnowledgeArtifacts(fromGraph, toGraph *Graph, kind NodeKind, opts KnowledgeDiffQueryOptions) []KnowledgeArtifactDiffRecord {
	fromRecords := collectKnowledgeArtifactRecords(fromGraph, kind, KnowledgeArtifactQueryOptions{
		ID:         "",
		TargetID:   opts.TargetID,
		ClaimID:    opts.ClaimID,
		SourceID:   opts.SourceID,
		Type:       opts.ArtifactType,
		ValidAt:    opts.FromValidAt,
		RecordedAt: opts.FromRecordedAt,
		Limit:      maxKnowledgeArtifactLimit,
	})
	toRecords := collectKnowledgeArtifactRecords(toGraph, kind, KnowledgeArtifactQueryOptions{
		ID:         "",
		TargetID:   opts.TargetID,
		ClaimID:    opts.ClaimID,
		SourceID:   opts.SourceID,
		Type:       opts.ArtifactType,
		ValidAt:    opts.ToValidAt,
		RecordedAt: opts.ToRecordedAt,
		Limit:      maxKnowledgeArtifactLimit,
	})
	fromByID := knowledgeArtifactRecordMap(fromRecords)
	toByID := knowledgeArtifactRecordMap(toRecords)
	allIDs := sortedUnionMapKeys(fromByID, toByID)
	out := make([]KnowledgeArtifactDiffRecord, 0, len(allIDs))
	for _, artifactID := range allIDs {
		before, beforeOK := fromByID[artifactID]
		after, afterOK := toByID[artifactID]
		switch {
		case !beforeOK && afterOK:
			out = append(out, KnowledgeArtifactDiffRecord{ArtifactID: artifactID, Kind: after.Kind, ChangeType: "added", Summary: "Artifact became visible in the target slice", After: knowledgeArtifactRecordPtr(after)})
		case beforeOK && !afterOK:
			out = append(out, KnowledgeArtifactDiffRecord{ArtifactID: artifactID, Kind: before.Kind, ChangeType: "removed", Summary: "Artifact is no longer visible in the target slice", Before: knowledgeArtifactRecordPtr(before)})
		case beforeOK && afterOK:
			modifiedFields := diffKnowledgeArtifactFields(before, after)
			if len(modifiedFields) == 0 {
				continue
			}
			out = append(out, KnowledgeArtifactDiffRecord{
				ArtifactID:     artifactID,
				Kind:           after.Kind,
				ChangeType:     "modified",
				Summary:        fmt.Sprintf("Artifact changed across slices: %s", strings.Join(modifiedFields, ", ")),
				ModifiedFields: modifiedFields,
				Before:         knowledgeArtifactRecordPtr(before),
				After:          knowledgeArtifactRecordPtr(after),
			})
		}
	}
	return out
}

func collectKnowledgeArtifactRecords(g *Graph, kind NodeKind, opts KnowledgeArtifactQueryOptions) []KnowledgeArtifactRecord {
	query := normalizeKnowledgeArtifactQueryOptions(opts)
	if g == nil {
		return nil
	}
	records := make([]KnowledgeArtifactRecord, 0)
	for _, node := range g.GetAllNodesBitemporal(query.ValidAt, query.RecordedAt) {
		if node == nil || node.Kind != kind {
			continue
		}
		record := buildKnowledgeArtifactRecord(g, node, query.ValidAt, query.RecordedAt)
		if !knowledgeArtifactMatchesQuery(record, query) {
			continue
		}
		records = append(records, record)
	}
	sort.Slice(records, func(i, j int) bool {
		if !records[i].RecordedAt.Equal(records[j].RecordedAt) {
			return records[i].RecordedAt.After(records[j].RecordedAt)
		}
		if !records[i].ObservedAt.Equal(records[j].ObservedAt) {
			return records[i].ObservedAt.After(records[j].ObservedAt)
		}
		return records[i].ID < records[j].ID
	})
	return records
}

func knowledgeArtifactRecordMap(records []KnowledgeArtifactRecord) map[string]KnowledgeArtifactRecord {
	mapped := make(map[string]KnowledgeArtifactRecord, len(records))
	for _, record := range records {
		mapped[record.ID] = record
	}
	return mapped
}

func sortedUnionMapKeys[T any](left, right map[string]T) []string {
	ids := make([]string, 0, len(left)+len(right))
	seen := make(map[string]struct{}, len(left)+len(right))
	for id := range left {
		ids = append(ids, id)
		seen[id] = struct{}{}
	}
	for id := range right {
		if _, ok := seen[id]; ok {
			continue
		}
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func knowledgeArtifactRecordPtr(record KnowledgeArtifactRecord) *KnowledgeArtifactRecord {
	cloned := record
	cloned.Links.TargetIDs = append([]string(nil), record.Links.TargetIDs...)
	cloned.Links.ClaimIDs = append([]string(nil), record.Links.ClaimIDs...)
	cloned.Links.ReferencedByIDs = append([]string(nil), record.Links.ReferencedByIDs...)
	cloned.Links.SourceIDs = append([]string(nil), record.Links.SourceIDs...)
	cloned.Metadata = cloneAnyMap(record.Metadata)
	return &cloned
}

func diffKnowledgeArtifactFields(before, after KnowledgeArtifactRecord) []string {
	modified := make([]string, 0, 16)
	if before.Kind != after.Kind {
		modified = append(modified, "kind")
	}
	if before.ArtifactType != after.ArtifactType {
		modified = append(modified, "artifact_type")
	}
	if before.SubjectID != after.SubjectID {
		modified = append(modified, "subject_id")
	}
	if before.Detail != after.Detail {
		modified = append(modified, "detail")
	}
	if before.SourceSystem != after.SourceSystem {
		modified = append(modified, "source_system")
	}
	if before.SourceEventID != after.SourceEventID {
		modified = append(modified, "source_event_id")
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
	if before.Confidence != after.Confidence {
		modified = append(modified, "confidence")
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

func sortKnowledgeArtifactDiffRecords(records []KnowledgeArtifactDiffRecord) {
	sort.Slice(records, func(i, j int) bool {
		if records[i].Kind != records[j].Kind {
			return records[i].Kind < records[j].Kind
		}
		if records[i].ChangeType != records[j].ChangeType {
			return records[i].ChangeType < records[j].ChangeType
		}
		return records[i].ArtifactID < records[j].ArtifactID
	})
}
