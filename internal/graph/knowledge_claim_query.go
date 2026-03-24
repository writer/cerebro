package graph

import (
	"sort"
	"strings"
	"time"
)

const (
	defaultClaimQueryLimit = 100
	maxClaimQueryLimit     = 500
)

// ClaimQueryOptions tunes claim collection reads over the bitemporal graph.
type ClaimQueryOptions struct {
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
	Supported       *bool     `json:"supported,omitempty"`
	Sourceless      *bool     `json:"sourceless,omitempty"`
	Conflicted      *bool     `json:"conflicted,omitempty"`
	ValidAt         time.Time `json:"valid_at,omitempty"`
	RecordedAt      time.Time `json:"recorded_at,omitempty"`
	Limit           int       `json:"limit,omitempty"`
	Offset          int       `json:"offset,omitempty"`
}

// ClaimQueryFilters echoes the applied claim-collection filters.
type ClaimQueryFilters struct {
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
	Supported       *bool  `json:"supported,omitempty"`
	Sourceless      *bool  `json:"sourceless,omitempty"`
	Conflicted      *bool  `json:"conflicted,omitempty"`
}

// ClaimCollectionPagination captures pagination metadata for claim reads.
type ClaimCollectionPagination struct {
	Total   int  `json:"total"`
	Limit   int  `json:"limit"`
	Offset  int  `json:"offset"`
	HasMore bool `json:"has_more"`
}

// ClaimCollectionSummary captures quality indicators over the matched claim set.
type ClaimCollectionSummary struct {
	MatchedClaims      int `json:"matched_claims"`
	ActiveClaims       int `json:"active_claims"`
	ResolvedClaims     int `json:"resolved_claims"`
	SupportedClaims    int `json:"supported_claims"`
	UnsupportedClaims  int `json:"unsupported_claims"`
	SourceBackedClaims int `json:"source_backed_claims"`
	SourcelessClaims   int `json:"sourceless_claims"`
	ConflictedClaims   int `json:"conflicted_claims"`
	SupersededClaims   int `json:"superseded_claims"`
}

// ClaimLinkSummary captures graph links attached to one claim.
type ClaimLinkSummary struct {
	SourceIDs            []string `json:"source_ids,omitempty"`
	EvidenceIDs          []string `json:"evidence_ids,omitempty"`
	SupportingClaimIDs   []string `json:"supporting_claim_ids,omitempty"`
	RefutingClaimIDs     []string `json:"refuting_claim_ids,omitempty"`
	SupersedesClaimIDs   []string `json:"supersedes_claim_ids,omitempty"`
	SupersededByClaimIDs []string `json:"superseded_by_claim_ids,omitempty"`
	ConflictingClaimIDs  []string `json:"conflicting_claim_ids,omitempty"`
}

// ClaimDerivedState exposes derived query signals so clients do not need to
// reconstruct supportability or contradiction state from raw edges.
type ClaimDerivedState struct {
	Supported             bool `json:"supported"`
	SourceBacked          bool `json:"source_backed"`
	Sourceless            bool `json:"sourceless"`
	Resolved              bool `json:"resolved"`
	Conflicted            bool `json:"conflicted"`
	Superseded            bool `json:"superseded"`
	EvidenceCount         int  `json:"evidence_count"`
	SourceCount           int  `json:"source_count"`
	SupportingClaimCount  int  `json:"supporting_claim_count"`
	RefutingClaimCount    int  `json:"refuting_claim_count"`
	ConflictingClaimCount int  `json:"conflicting_claim_count"`
	SupersededByCount     int  `json:"superseded_by_count"`
}

// ClaimRecord is the canonical read model for one platform claim.
type ClaimRecord struct {
	ID              string            `json:"id"`
	ClaimType       string            `json:"claim_type,omitempty"`
	SubjectID       string            `json:"subject_id"`
	Predicate       string            `json:"predicate"`
	ObjectID        string            `json:"object_id,omitempty"`
	ObjectValue     string            `json:"object_value,omitempty"`
	Status          string            `json:"status"`
	Summary         string            `json:"summary,omitempty"`
	Confidence      float64           `json:"confidence,omitempty"`
	ObservedAt      time.Time         `json:"observed_at,omitempty"`
	ValidFrom       time.Time         `json:"valid_from,omitempty"`
	ValidTo         *time.Time        `json:"valid_to,omitempty"`
	RecordedAt      time.Time         `json:"recorded_at,omitempty"`
	TransactionFrom time.Time         `json:"transaction_from,omitempty"`
	TransactionTo   *time.Time        `json:"transaction_to,omitempty"`
	SourceSystem    string            `json:"source_system,omitempty"`
	SourceEventID   string            `json:"source_event_id,omitempty"`
	Links           ClaimLinkSummary  `json:"links"`
	Derived         ClaimDerivedState `json:"derived"`
	Metadata        map[string]any    `json:"metadata,omitempty"`
}

// ClaimCollection is the typed platform response for claim collection queries.
type ClaimCollection struct {
	GeneratedAt time.Time                 `json:"generated_at"`
	ValidAt     time.Time                 `json:"valid_at"`
	RecordedAt  time.Time                 `json:"recorded_at"`
	Filters     ClaimQueryFilters         `json:"filters"`
	Summary     ClaimCollectionSummary    `json:"summary"`
	Claims      []ClaimRecord             `json:"claims,omitempty"`
	Count       int                       `json:"count"`
	Pagination  ClaimCollectionPagination `json:"pagination"`
}

// QueryClaims returns a typed claim collection over the current or historical graph.
func QueryClaims(g *Graph, opts ClaimQueryOptions) ClaimCollection {
	query := normalizeClaimQueryOptions(opts)
	result := ClaimCollection{
		GeneratedAt: temporalNowUTC(),
		ValidAt:     query.ValidAt,
		RecordedAt:  query.RecordedAt,
		Filters: ClaimQueryFilters{
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
			Supported:       query.Supported,
			Sourceless:      query.Sourceless,
			Conflicted:      query.Conflicted,
		},
		Pagination: ClaimCollectionPagination{
			Limit:  query.Limit,
			Offset: query.Offset,
		},
	}
	if g == nil {
		return result
	}

	records := collectClaimRecords(g, query)
	sortClaimRecords(records)
	for _, record := range records {
		updateClaimCollectionSummary(&result.Summary, record)
	}

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
		result.Claims = append(result.Claims, records[query.Offset:end]...)
	}
	result.Count = len(result.Claims)
	result.Pagination.HasMore = end < total
	return result
}

// GetClaimRecord returns one typed claim record at a specific bitemporal slice.
func GetClaimRecord(g *Graph, claimID string, validAt, recordedAt time.Time) (ClaimRecord, bool) {
	claimID = strings.TrimSpace(claimID)
	if claimID == "" {
		return ClaimRecord{}, false
	}
	result := QueryClaims(g, ClaimQueryOptions{
		ClaimID:         claimID,
		IncludeResolved: true,
		ValidAt:         validAt,
		RecordedAt:      recordedAt,
		Limit:           1,
	})
	if len(result.Claims) == 0 {
		return ClaimRecord{}, false
	}
	return result.Claims[0], true
}

func normalizeClaimQueryOptions(opts ClaimQueryOptions) ClaimQueryOptions {
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
	if opts.Limit <= 0 {
		opts.Limit = defaultClaimQueryLimit
	}
	if opts.Limit > maxClaimQueryLimit {
		opts.Limit = maxClaimQueryLimit
	}
	if opts.Offset < 0 {
		opts.Offset = 0
	}
	return opts
}

func visibleClaimsAt(g *Graph, validAt, recordedAt time.Time) []*Node {
	if g == nil {
		return nil
	}
	nodes := g.GetAllNodesBitemporal(validAt, recordedAt)
	out := make([]*Node, 0, len(nodes))
	for _, node := range nodes {
		if node != nil && node.Kind == NodeKindClaim {
			out = append(out, node)
		}
	}
	return out
}

func collectClaimRecords(g *Graph, opts ClaimQueryOptions) []ClaimRecord {
	if g == nil {
		return nil
	}
	visibleClaims := visibleClaimsAt(g, opts.ValidAt, opts.RecordedAt)
	conflictPeers := buildClaimConflictPeerMap(g, visibleClaims, opts.ValidAt, opts.RecordedAt)
	records := make([]ClaimRecord, 0, len(visibleClaims))
	for _, claim := range visibleClaims {
		record := buildClaimRecord(g, claim, opts.ValidAt, opts.RecordedAt, conflictPeers[claim.ID])
		if !claimMatchesQuery(record, opts) {
			continue
		}
		records = append(records, record)
	}
	return records
}

func sortClaimRecords(records []ClaimRecord) {
	sort.Slice(records, func(i, j int) bool {
		if !records[i].RecordedAt.Equal(records[j].RecordedAt) {
			return records[i].RecordedAt.After(records[j].RecordedAt)
		}
		if !records[i].ValidFrom.Equal(records[j].ValidFrom) {
			return records[i].ValidFrom.After(records[j].ValidFrom)
		}
		if !records[i].ObservedAt.Equal(records[j].ObservedAt) {
			return records[i].ObservedAt.After(records[j].ObservedAt)
		}
		return records[i].ID < records[j].ID
	})
}

func buildClaimRecord(g *Graph, claim *Node, validAt, recordedAt time.Time, conflictingClaimIDs []string) ClaimRecord {
	record := ClaimRecord{
		ID:            claim.ID,
		ClaimType:     strings.ToLower(strings.TrimSpace(readString(claim.Properties, "claim_type"))),
		SubjectID:     strings.TrimSpace(readString(claim.Properties, "subject_id")),
		Predicate:     strings.TrimSpace(readString(claim.Properties, "predicate")),
		ObjectID:      strings.TrimSpace(readString(claim.Properties, "object_id")),
		ObjectValue:   strings.TrimSpace(readString(claim.Properties, "object_value")),
		Status:        normalizeClaimStatus(readString(claim.Properties, "status")),
		Summary:       strings.TrimSpace(readString(claim.Properties, "summary")),
		Confidence:    nodePropertyFloat(claim, "confidence"),
		SourceSystem:  firstNonEmpty(nodePropertyString(claim, "source_system"), strings.TrimSpace(claim.Provider)),
		SourceEventID: nodePropertyString(claim, "source_event_id"),
	}
	if ts, ok := graphObservedAt(claim); ok {
		record.ObservedAt = ts
	}
	if ts, ok := nodePropertyTime(claim, "valid_from"); ok {
		record.ValidFrom = ts
	}
	if ts, ok := nodePropertyTime(claim, "valid_to"); ok {
		record.ValidTo = &ts
	}
	if ts, ok := nodePropertyTime(claim, "recorded_at"); ok {
		record.RecordedAt = ts
	}
	if ts, ok := nodePropertyTime(claim, "transaction_from"); ok {
		record.TransactionFrom = ts
	}
	if ts, ok := nodePropertyTime(claim, "transaction_to"); ok {
		record.TransactionTo = &ts
	}

	record.Links = ClaimLinkSummary{
		SourceIDs:            claimLinkTargetsAt(g, claim.ID, EdgeKindAssertedBy, validAt, recordedAt),
		EvidenceIDs:          claimLinkTargetsAt(g, claim.ID, EdgeKindBasedOn, validAt, recordedAt),
		SupportingClaimIDs:   claimLinkSourcesAt(g, claim.ID, EdgeKindSupports, validAt, recordedAt),
		RefutingClaimIDs:     claimLinkSourcesAt(g, claim.ID, EdgeKindRefutes, validAt, recordedAt),
		SupersedesClaimIDs:   claimLinkTargetsAt(g, claim.ID, EdgeKindSupersedes, validAt, recordedAt),
		SupersededByClaimIDs: claimLinkSourcesAt(g, claim.ID, EdgeKindSupersedes, validAt, recordedAt),
		ConflictingClaimIDs:  uniqueSortedStrings(trimNonEmpty(conflictingClaimIDs)),
	}
	record.Derived = ClaimDerivedState{
		EvidenceCount:         len(record.Links.EvidenceIDs),
		SourceCount:           len(record.Links.SourceIDs),
		SupportingClaimCount:  len(record.Links.SupportingClaimIDs),
		RefutingClaimCount:    len(record.Links.RefutingClaimIDs),
		ConflictingClaimCount: len(record.Links.ConflictingClaimIDs),
		SupersededByCount:     len(record.Links.SupersededByClaimIDs),
	}
	record.Derived.Supported = record.Derived.EvidenceCount > 0 || record.Derived.SupportingClaimCount > 0
	record.Derived.SourceBacked = record.Derived.SourceCount > 0
	record.Derived.Sourceless = !record.Derived.SourceBacked
	record.Derived.Conflicted = record.Derived.ConflictingClaimCount > 0
	record.Derived.Superseded = record.Derived.SupersededByCount > 0 || record.Status == "superseded" || record.Status == "corrected"
	record.Derived.Resolved = claimStatusResolved(record.Status) || record.Derived.Superseded
	record.Metadata = claimMetadataProperties(claim.Properties)
	return record
}

func buildClaimConflictPeerMap(g *Graph, claims []*Node, validAt, recordedAt time.Time) map[string][]string {
	type groupedClaim struct {
		id    string
		value string
	}
	grouped := make(map[string][]groupedClaim)
	for _, claim := range claims {
		if claim == nil {
			continue
		}
		status := normalizeClaimStatus(readString(claim.Properties, "status"))
		if claimStatusResolved(status) || claimSupersededAt(g, claim.ID, validAt, recordedAt) {
			continue
		}
		subjectID := strings.TrimSpace(readString(claim.Properties, "subject_id"))
		predicate := strings.TrimSpace(readString(claim.Properties, "predicate"))
		if subjectID == "" || predicate == "" {
			continue
		}
		groupKey := subjectID + "|" + predicate
		grouped[groupKey] = append(grouped[groupKey], groupedClaim{
			id:    claim.ID,
			value: claimComparableValue(claim),
		})
	}

	peers := make(map[string][]string)
	for _, claimsForGroup := range grouped {
		values := make(map[string][]string)
		for _, claim := range claimsForGroup {
			values[claim.value] = append(values[claim.value], claim.id)
		}
		if len(values) <= 1 {
			continue
		}
		for _, claim := range claimsForGroup {
			others := make([]string, 0, len(claimsForGroup)-1)
			for value, ids := range values {
				if value == claim.value {
					continue
				}
				others = append(others, ids...)
			}
			peers[claim.id] = uniqueSortedStrings(trimNonEmpty(others))
		}
	}
	return peers
}

func claimSupersededAt(g *Graph, claimID string, validAt, recordedAt time.Time) bool {
	if g == nil || strings.TrimSpace(claimID) == "" {
		return false
	}
	for _, edge := range g.GetInEdgesBitemporal(claimID, validAt, recordedAt) {
		if edge != nil && edge.Kind == EdgeKindSupersedes {
			return true
		}
	}
	return false
}

func claimMatchesQuery(record ClaimRecord, opts ClaimQueryOptions) bool {
	if opts.ClaimID != "" && record.ID != opts.ClaimID {
		return false
	}
	if opts.SubjectID != "" && record.SubjectID != opts.SubjectID {
		return false
	}
	if opts.Predicate != "" && !strings.EqualFold(record.Predicate, opts.Predicate) {
		return false
	}
	if opts.ObjectID != "" && record.ObjectID != opts.ObjectID {
		return false
	}
	if opts.ObjectValue != "" && !strings.EqualFold(record.ObjectValue, opts.ObjectValue) {
		return false
	}
	if opts.ClaimType != "" && !strings.EqualFold(record.ClaimType, opts.ClaimType) {
		return false
	}
	if opts.Status == "" {
		if !opts.IncludeResolved && record.Derived.Resolved {
			return false
		}
	} else if record.Status != opts.Status {
		return false
	}
	if opts.SourceID != "" && !containsExactString(record.Links.SourceIDs, opts.SourceID) {
		return false
	}
	if opts.EvidenceID != "" && !containsExactString(record.Links.EvidenceIDs, opts.EvidenceID) {
		return false
	}
	if opts.Supported != nil && record.Derived.Supported != *opts.Supported {
		return false
	}
	if opts.Sourceless != nil && record.Derived.Sourceless != *opts.Sourceless {
		return false
	}
	if opts.Conflicted != nil && record.Derived.Conflicted != *opts.Conflicted {
		return false
	}
	return true
}

func updateClaimCollectionSummary(summary *ClaimCollectionSummary, record ClaimRecord) {
	if summary == nil {
		return
	}
	summary.MatchedClaims++
	if record.Derived.Resolved {
		summary.ResolvedClaims++
	} else {
		summary.ActiveClaims++
	}
	if record.Derived.Supported {
		summary.SupportedClaims++
	} else {
		summary.UnsupportedClaims++
	}
	if record.Derived.SourceBacked {
		summary.SourceBackedClaims++
	} else {
		summary.SourcelessClaims++
	}
	if record.Derived.Conflicted {
		summary.ConflictedClaims++
	}
	if record.Derived.Superseded {
		summary.SupersededClaims++
	}
}

func claimLinkTargetsAt(g *Graph, claimID string, kind EdgeKind, validAt, recordedAt time.Time) []string {
	if g == nil || strings.TrimSpace(claimID) == "" {
		return nil
	}
	out := make([]string, 0, 2)
	for _, edge := range g.GetOutEdgesBitemporal(claimID, validAt, recordedAt) {
		if edge == nil || edge.Kind != kind {
			continue
		}
		out = append(out, edge.Target)
	}
	return uniqueSortedStrings(trimNonEmpty(out))
}

func claimLinkSourcesAt(g *Graph, claimID string, kind EdgeKind, validAt, recordedAt time.Time) []string {
	if g == nil || strings.TrimSpace(claimID) == "" {
		return nil
	}
	out := make([]string, 0, 2)
	for _, edge := range g.GetInEdgesBitemporal(claimID, validAt, recordedAt) {
		if edge == nil || edge.Kind != kind {
			continue
		}
		out = append(out, edge.Source)
	}
	return uniqueSortedStrings(trimNonEmpty(out))
}

func claimMetadataProperties(properties map[string]any) map[string]any {
	if len(properties) == 0 {
		return nil
	}
	out := cloneAnyMap(properties)
	for _, key := range []string{
		"claim_type",
		"subject_id",
		"predicate",
		"object_id",
		"object_value",
		"status",
		"summary",
		"source_system",
		"source_event_id",
		"observed_at",
		"valid_from",
		"valid_to",
		"recorded_at",
		"transaction_from",
		"transaction_to",
		"confidence",
	} {
		delete(out, key)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func containsExactString(values []string, want string) bool {
	want = strings.TrimSpace(want)
	if want == "" {
		return false
	}
	for _, value := range values {
		if strings.TrimSpace(value) == want {
			return true
		}
	}
	return false
}
