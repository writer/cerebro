package graph

import (
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"
)

const (
	defaultClaimConflictLimit = 25
)

// ClaimWriteRequest records one world-model claim plus its provenance links.
type ClaimWriteRequest struct {
	ID                 string         `json:"id,omitempty"`
	ClaimType          string         `json:"claim_type,omitempty"`
	SubjectID          string         `json:"subject_id"`
	Predicate          string         `json:"predicate"`
	ObjectID           string         `json:"object_id,omitempty"`
	ObjectValue        string         `json:"object_value,omitempty"`
	Status             string         `json:"status,omitempty"`
	Summary            string         `json:"summary,omitempty"`
	EvidenceIDs        []string       `json:"evidence_ids,omitempty"`
	SupportingClaimIDs []string       `json:"supporting_claim_ids,omitempty"`
	RefutingClaimIDs   []string       `json:"refuting_claim_ids,omitempty"`
	SupersedesClaimID  string         `json:"supersedes_claim_id,omitempty"`
	SourceID           string         `json:"source_id,omitempty"`
	SourceName         string         `json:"source_name,omitempty"`
	SourceType         string         `json:"source_type,omitempty"`
	SourceURL          string         `json:"source_url,omitempty"`
	TrustTier          string         `json:"trust_tier,omitempty"`
	ReliabilityScore   float64        `json:"reliability_score,omitempty"`
	SourceSystem       string         `json:"source_system,omitempty"`
	SourceEventID      string         `json:"source_event_id,omitempty"`
	ObservedAt         time.Time      `json:"observed_at,omitempty"`
	ValidFrom          time.Time      `json:"valid_from,omitempty"`
	ValidTo            *time.Time     `json:"valid_to,omitempty"`
	RecordedAt         time.Time      `json:"recorded_at,omitempty"`
	TransactionFrom    time.Time      `json:"transaction_from,omitempty"`
	TransactionTo      *time.Time     `json:"transaction_to,omitempty"`
	Confidence         float64        `json:"confidence,omitempty"`
	Metadata           map[string]any `json:"metadata,omitempty"`
}

// ClaimWriteResult summarizes one claim write.
type ClaimWriteResult struct {
	ClaimID                string    `json:"claim_id"`
	SourceID               string    `json:"source_id,omitempty"`
	EvidenceLinked         int       `json:"evidence_linked"`
	SupportingClaimsLinked int       `json:"supporting_claims_linked"`
	RefutingClaimsLinked   int       `json:"refuting_claims_linked"`
	SupersedesLinked       bool      `json:"supersedes_linked"`
	ObservedAt             time.Time `json:"observed_at,omitempty"`
	RecordedAt             time.Time `json:"recorded_at,omitempty"`
}

// ClaimConflictReportOptions tunes active claim conflict reporting.
type ClaimConflictReportOptions struct {
	ValidAt         time.Time     `json:"valid_at,omitempty"`
	RecordedAt      time.Time     `json:"recorded_at,omitempty"`
	MaxConflicts    int           `json:"max_conflicts,omitempty"`
	IncludeResolved bool          `json:"include_resolved,omitempty"`
	StaleAfter      time.Duration `json:"stale_after,omitempty"`
}

// ClaimConflictReport summarizes active contradictory claims.
type ClaimConflictReport struct {
	GeneratedAt     time.Time                     `json:"generated_at"`
	ValidAt         time.Time                     `json:"valid_at"`
	RecordedAt      time.Time                     `json:"recorded_at"`
	Summary         ClaimConflictReportSummary    `json:"summary"`
	Conflicts       []ClaimConflict               `json:"conflicts,omitempty"`
	Recommendations []ClaimConflictRecommendation `json:"recommendations,omitempty"`
}

// ClaimConflictReportSummary captures high-level quality indicators for the claim layer.
type ClaimConflictReportSummary struct {
	TotalClaims               int  `json:"total_claims"`
	ActiveClaims              int  `json:"active_claims"`
	ConflictGroups            int  `json:"conflict_groups"`
	TotalConflictGroups       int  `json:"total_conflict_groups"`
	ReturnedConflictGroups    int  `json:"returned_conflict_groups"`
	ConflictingClaims         int  `json:"conflicting_claims"`
	TotalConflictingClaims    int  `json:"total_conflicting_claims"`
	ReturnedConflictingClaims int  `json:"returned_conflicting_claims"`
	ConflictsTruncated        bool `json:"conflicts_truncated,omitempty"`
	UnsupportedClaims         int  `json:"unsupported_claims"`
	SourcelessClaims          int  `json:"sourceless_claims"`
	StaleClaims               int  `json:"stale_claims"`
}

// ClaimConflict captures one contradictory claim set over the same subject/predicate.
type ClaimConflict struct {
	Key               string    `json:"key"`
	SubjectID         string    `json:"subject_id"`
	Predicate         string    `json:"predicate"`
	ClaimIDs          []string  `json:"claim_ids,omitempty"`
	Values            []string  `json:"values,omitempty"`
	SourceIDs         []string  `json:"source_ids,omitempty"`
	Statuses          []string  `json:"statuses,omitempty"`
	HighestConfidence float64   `json:"highest_confidence"`
	LatestObservedAt  time.Time `json:"latest_observed_at,omitempty"`
}

// ClaimConflictRecommendation points to the next repair step for the knowledge layer.
type ClaimConflictRecommendation struct {
	Priority string `json:"priority"`
	Title    string `json:"title"`
	Detail   string `json:"detail"`
}

type claimConflictAccumulator struct {
	subjectID         string
	predicate         string
	claimIDs          []string
	values            []string
	sourceIDs         []string
	statuses          []string
	highestConfidence float64
	latestObservedAt  time.Time
}

// WriteClaim records one first-class claim and links it to the world entities it references.
func WriteClaim(g *Graph, req ClaimWriteRequest) (ClaimWriteResult, error) {
	if g == nil {
		return ClaimWriteResult{}, fmt.Errorf("graph is required")
	}

	request, err := normalizeClaimWriteRequest(req)
	if err != nil {
		return ClaimWriteResult{}, err
	}
	if _, ok := g.GetNode(request.SubjectID); !ok {
		return ClaimWriteResult{}, fmt.Errorf("subject not found: %s", request.SubjectID)
	}
	if request.ObjectID != "" {
		if _, ok := g.GetNode(request.ObjectID); !ok {
			return ClaimWriteResult{}, fmt.Errorf("object not found: %s", request.ObjectID)
		}
	}
	for _, evidenceID := range request.EvidenceIDs {
		node, ok := g.GetNode(evidenceID)
		if !ok {
			return ClaimWriteResult{}, fmt.Errorf("evidence not found: %s", evidenceID)
		}
		if node.Kind != NodeKindEvidence && node.Kind != NodeKindObservation {
			return ClaimWriteResult{}, fmt.Errorf("node %s is not evidence or observation", evidenceID)
		}
	}
	for _, supportingID := range request.SupportingClaimIDs {
		node, ok := g.GetNode(supportingID)
		if !ok || node.Kind != NodeKindClaim {
			return ClaimWriteResult{}, fmt.Errorf("supporting claim not found: %s", supportingID)
		}
	}
	for _, refutingID := range request.RefutingClaimIDs {
		node, ok := g.GetNode(refutingID)
		if !ok || node.Kind != NodeKindClaim {
			return ClaimWriteResult{}, fmt.Errorf("refuting claim not found: %s", refutingID)
		}
	}
	if request.SupersedesClaimID != "" {
		node, ok := g.GetNode(request.SupersedesClaimID)
		if !ok || node.Kind != NodeKindClaim {
			return ClaimWriteResult{}, fmt.Errorf("superseded claim not found: %s", request.SupersedesClaimID)
		}
	}

	metadata := NormalizeWriteMetadata(request.ObservedAt, request.ValidFrom, request.ValidTo, request.SourceSystem, request.SourceEventID, request.Confidence, WriteMetadataDefaults{
		SourceSystem:      "api",
		SourceEventPrefix: "claim",
		DefaultConfidence: 0.80,
		RecordedAt:        request.RecordedAt,
		TransactionFrom:   request.TransactionFrom,
		TransactionTo:     request.TransactionTo,
	})

	claimID := request.ID
	if claimID == "" {
		claimID = fmt.Sprintf("claim:%s:%s:%d", slugifyKnowledgeKey(request.SubjectID), slugifyKnowledgeKey(request.Predicate), metadata.RecordedAt.UnixNano())
	}
	properties := cloneAnyMap(request.Metadata)
	if properties == nil {
		properties = make(map[string]any)
	}
	properties["claim_type"] = request.ClaimType
	properties["subject_id"] = request.SubjectID
	properties["predicate"] = request.Predicate
	properties["status"] = request.Status
	properties["summary"] = request.Summary
	if request.ObjectID != "" {
		properties["object_id"] = request.ObjectID
	}
	if request.ObjectValue != "" {
		properties["object_value"] = request.ObjectValue
	}
	if request.SourceName != "" {
		properties["source_name"] = request.SourceName
	}
	if request.SourceType != "" {
		properties["source_type"] = request.SourceType
	}
	if request.SourceURL != "" {
		properties["source_url"] = request.SourceURL
	}
	if request.TrustTier != "" {
		properties["source_trust_tier"] = request.TrustTier
	}
	if request.ReliabilityScore > 0 {
		properties["source_reliability_score"] = request.ReliabilityScore
	}
	metadata.ApplyTo(properties)

	g.AddNode(&Node{
		ID:         claimID,
		Kind:       NodeKindClaim,
		Name:       firstNonEmpty(request.Summary, request.Predicate, claimID),
		Provider:   metadata.SourceSystem,
		Properties: properties,
		Risk:       RiskNone,
	})

	edgeProperties := metadata.PropertyMap()
	g.AddEdge(&Edge{
		ID:         fmt.Sprintf("%s->%s:%s", claimID, request.SubjectID, EdgeKindTargets),
		Source:     claimID,
		Target:     request.SubjectID,
		Kind:       EdgeKindTargets,
		Effect:     EdgeEffectAllow,
		Properties: cloneAnyMap(edgeProperties),
	})
	if request.ObjectID != "" {
		g.AddEdge(&Edge{
			ID:         fmt.Sprintf("%s->%s:%s", claimID, request.ObjectID, EdgeKindRefers),
			Source:     claimID,
			Target:     request.ObjectID,
			Kind:       EdgeKindRefers,
			Effect:     EdgeEffectAllow,
			Properties: cloneAnyMap(edgeProperties),
		})
	}

	sourceID := ""
	if request.SourceID != "" || request.SourceName != "" || request.SourceType != "" {
		sourceID = firstNonEmpty(request.SourceID, buildSourceNodeID(request.SourceType, request.SourceName))
		sourceProperties := map[string]any{
			"source_type":       firstNonEmpty(request.SourceType, "system"),
			"canonical_name":    firstNonEmpty(request.SourceName, sourceID),
			"url":               request.SourceURL,
			"trust_tier":        firstNonEmpty(request.TrustTier, "verified"),
			"reliability_score": clampUnit(request.ReliabilityScore),
		}
		if existingSource, ok := g.GetNode(sourceID); ok && existingSource != nil {
			if err := validateClaimSourceNode(existingSource, sourceProperties); err != nil {
				return ClaimWriteResult{}, err
			}
		} else {
			metadata.ApplyTo(sourceProperties)
			g.AddNode(&Node{
				ID:         sourceID,
				Kind:       NodeKindSource,
				Name:       firstNonEmpty(request.SourceName, sourceID),
				Provider:   metadata.SourceSystem,
				Properties: sourceProperties,
				Risk:       RiskNone,
			})
		}
		g.AddEdge(&Edge{
			ID:         fmt.Sprintf("%s->%s:%s", claimID, sourceID, EdgeKindAssertedBy),
			Source:     claimID,
			Target:     sourceID,
			Kind:       EdgeKindAssertedBy,
			Effect:     EdgeEffectAllow,
			Properties: cloneAnyMap(edgeProperties),
		})
	}

	for _, evidenceID := range request.EvidenceIDs {
		g.AddEdge(&Edge{
			ID:         fmt.Sprintf("%s->%s:%s", claimID, evidenceID, EdgeKindBasedOn),
			Source:     claimID,
			Target:     evidenceID,
			Kind:       EdgeKindBasedOn,
			Effect:     EdgeEffectAllow,
			Properties: cloneAnyMap(edgeProperties),
		})
	}
	for _, supportingID := range request.SupportingClaimIDs {
		g.AddEdge(&Edge{
			ID:         fmt.Sprintf("%s->%s:%s", supportingID, claimID, EdgeKindSupports),
			Source:     supportingID,
			Target:     claimID,
			Kind:       EdgeKindSupports,
			Effect:     EdgeEffectAllow,
			Properties: cloneAnyMap(edgeProperties),
		})
	}
	for _, refutingID := range request.RefutingClaimIDs {
		g.AddEdge(&Edge{
			ID:         fmt.Sprintf("%s->%s:%s", refutingID, claimID, EdgeKindRefutes),
			Source:     refutingID,
			Target:     claimID,
			Kind:       EdgeKindRefutes,
			Effect:     EdgeEffectAllow,
			Properties: cloneAnyMap(edgeProperties),
		})
	}
	supersedesLinked := false
	if request.SupersedesClaimID != "" {
		g.AddEdge(&Edge{
			ID:         fmt.Sprintf("%s->%s:%s", claimID, request.SupersedesClaimID, EdgeKindSupersedes),
			Source:     claimID,
			Target:     request.SupersedesClaimID,
			Kind:       EdgeKindSupersedes,
			Effect:     EdgeEffectAllow,
			Properties: cloneAnyMap(edgeProperties),
		})
		supersedesLinked = true
	}

	return ClaimWriteResult{
		ClaimID:                claimID,
		SourceID:               sourceID,
		EvidenceLinked:         len(request.EvidenceIDs),
		SupportingClaimsLinked: len(request.SupportingClaimIDs),
		RefutingClaimsLinked:   len(request.RefutingClaimIDs),
		SupersedesLinked:       supersedesLinked,
		ObservedAt:             metadata.ObservedAt,
		RecordedAt:             metadata.RecordedAt,
	}, nil
}

// BuildClaimConflictReport inspects active claims for contradictory values and weak provenance.
func BuildClaimConflictReport(g *Graph, opts ClaimConflictReportOptions) ClaimConflictReport {
	now := temporalNowUTC()
	if opts.ValidAt.IsZero() {
		opts.ValidAt = now
	}
	if opts.RecordedAt.IsZero() {
		opts.RecordedAt = now
	}
	if opts.MaxConflicts <= 0 {
		opts.MaxConflicts = defaultClaimConflictLimit
	}

	report := ClaimConflictReport{
		GeneratedAt: now,
		ValidAt:     opts.ValidAt.UTC(),
		RecordedAt:  opts.RecordedAt.UTC(),
	}
	if g == nil {
		return report
	}

	active := make([]*Node, 0)
	for _, node := range g.GetAllNodesBitemporal(opts.ValidAt, opts.RecordedAt) {
		if node == nil || node.Kind != NodeKindClaim {
			continue
		}
		report.Summary.TotalClaims++
		status := normalizeClaimStatus(readString(node.Properties, "status"))
		if !opts.IncludeResolved && claimStatusResolved(status) {
			continue
		}
		active = append(active, node)
		report.Summary.ActiveClaims++
		if claimUnsupportedAt(g, node, opts.ValidAt, opts.RecordedAt) {
			report.Summary.UnsupportedClaims++
		}
		if claimSourcelessAt(g, node, opts.ValidAt, opts.RecordedAt) {
			report.Summary.SourcelessClaims++
		}
		if opts.StaleAfter > 0 {
			if observedAt, ok := graphObservedAt(node); ok && observedAt.Before(now.Add(-opts.StaleAfter)) {
				report.Summary.StaleClaims++
			}
		}
	}

	groups := make(map[string]*claimConflictAccumulator)
	conflictingClaimSet := make(map[string]struct{})
	for _, claim := range active {
		subjectID := strings.TrimSpace(readString(claim.Properties, "subject_id"))
		predicate := strings.TrimSpace(readString(claim.Properties, "predicate"))
		if subjectID == "" || predicate == "" {
			continue
		}
		groupKey := subjectID + "|" + predicate
		acc := groups[groupKey]
		if acc == nil {
			acc = &claimConflictAccumulator{subjectID: subjectID, predicate: predicate}
			groups[groupKey] = acc
		}
		acc.claimIDs = append(acc.claimIDs, claim.ID)
		acc.values = append(acc.values, claimComparableValue(claim))
		acc.statuses = append(acc.statuses, normalizeClaimStatus(readString(claim.Properties, "status")))
		acc.sourceIDs = append(acc.sourceIDs, claimSourceIDsAt(g, claim, opts.ValidAt, opts.RecordedAt)...)
		if confidence := readFloat(claim.Properties, "confidence"); confidence > acc.highestConfidence {
			acc.highestConfidence = confidence
		}
		if observedAt, ok := graphObservedAt(claim); ok && observedAt.After(acc.latestObservedAt) {
			acc.latestObservedAt = observedAt
		}
	}

	allConflicts := make([]ClaimConflict, 0)
	for key, acc := range groups {
		values := uniqueSortedStrings(normalizeNonEmptyStrings(acc.values))
		if len(values) <= 1 {
			continue
		}
		report.Summary.ConflictGroups++
		report.Summary.TotalConflictGroups++
		for _, claimID := range acc.claimIDs {
			conflictingClaimSet[claimID] = struct{}{}
		}
		allConflicts = append(allConflicts, ClaimConflict{
			Key:               key,
			SubjectID:         acc.subjectID,
			Predicate:         acc.predicate,
			ClaimIDs:          uniqueSortedStrings(acc.claimIDs),
			Values:            values,
			SourceIDs:         uniqueSortedStrings(normalizeNonEmptyStrings(acc.sourceIDs)),
			Statuses:          uniqueSortedStrings(normalizeNonEmptyStrings(acc.statuses)),
			HighestConfidence: acc.highestConfidence,
			LatestObservedAt:  acc.latestObservedAt,
		})
	}
	sort.Slice(allConflicts, func(i, j int) bool {
		if len(allConflicts[i].ClaimIDs) == len(allConflicts[j].ClaimIDs) {
			return allConflicts[i].Key < allConflicts[j].Key
		}
		return len(allConflicts[i].ClaimIDs) > len(allConflicts[j].ClaimIDs)
	})
	conflicts := append([]ClaimConflict(nil), allConflicts...)
	if len(conflicts) > opts.MaxConflicts {
		conflicts = conflicts[:opts.MaxConflicts]
		report.Summary.ConflictsTruncated = true
	}
	report.Conflicts = conflicts
	report.Summary.ConflictingClaims = len(conflictingClaimSet)
	report.Summary.TotalConflictingClaims = len(conflictingClaimSet)
	report.Summary.ReturnedConflictGroups = len(conflicts)
	report.Summary.ReturnedConflictingClaims = countConflictClaimIDs(conflicts)
	report.Recommendations = buildClaimConflictRecommendations(report.Summary)
	return report
}

func normalizeClaimWriteRequest(req ClaimWriteRequest) (ClaimWriteRequest, error) {
	out := req
	out.ID = strings.TrimSpace(req.ID)
	out.ClaimType = normalizeClaimType(req.ClaimType, req.ObjectID, req.ObjectValue)
	out.SubjectID = strings.TrimSpace(req.SubjectID)
	out.Predicate = strings.TrimSpace(req.Predicate)
	out.ObjectID = strings.TrimSpace(req.ObjectID)
	out.ObjectValue = strings.TrimSpace(req.ObjectValue)
	out.Status = normalizeClaimStatus(req.Status)
	out.Summary = strings.TrimSpace(req.Summary)
	out.SourceID = strings.TrimSpace(req.SourceID)
	out.SourceName = strings.TrimSpace(req.SourceName)
	out.SourceType = strings.TrimSpace(req.SourceType)
	if out.SourceType != "" {
		out.SourceType = normalizeSourceType(out.SourceType)
	}
	out.SourceURL = strings.TrimSpace(req.SourceURL)
	out.TrustTier = strings.TrimSpace(req.TrustTier)
	if out.TrustTier != "" {
		out.TrustTier = normalizeTrustTier(out.TrustTier)
	}
	out.SourceSystem = strings.TrimSpace(req.SourceSystem)
	out.SourceEventID = strings.TrimSpace(req.SourceEventID)
	out.SupersedesClaimID = strings.TrimSpace(req.SupersedesClaimID)
	out.EvidenceIDs = uniqueSortedStrings(trimNonEmpty(req.EvidenceIDs))
	out.SupportingClaimIDs = uniqueSortedStrings(trimNonEmpty(req.SupportingClaimIDs))
	out.RefutingClaimIDs = uniqueSortedStrings(trimNonEmpty(req.RefutingClaimIDs))
	out.ReliabilityScore = clampUnit(req.ReliabilityScore)
	out.Confidence = clampUnit(req.Confidence)
	if out.SubjectID == "" {
		return ClaimWriteRequest{}, fmt.Errorf("subject_id is required")
	}
	if out.Predicate == "" {
		return ClaimWriteRequest{}, fmt.Errorf("predicate is required")
	}
	if out.ObjectID == "" && out.ObjectValue == "" {
		return ClaimWriteRequest{}, fmt.Errorf("object_id or object_value is required")
	}
	return out, nil
}

func normalizeClaimType(raw, objectID, objectValue string) string {
	value := strings.ToLower(strings.TrimSpace(raw))
	if value != "" {
		return value
	}
	if strings.TrimSpace(objectID) != "" {
		return "relation"
	}
	if strings.TrimSpace(objectValue) != "" {
		return "attribute"
	}
	return "relation"
}

func normalizeClaimStatus(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "disputed":
		return "disputed"
	case "corrected":
		return "corrected"
	case "retracted":
		return "retracted"
	case "superseded":
		return "superseded"
	case "refuted":
		return "refuted"
	default:
		return "asserted"
	}
}

func normalizeSourceType(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "human", "document", "sensor", "model", "pipeline", "external_api":
		return strings.ToLower(strings.TrimSpace(raw))
	default:
		return "system"
	}
}

func normalizeTrustTier(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "authoritative", "derived", "unverified":
		return strings.ToLower(strings.TrimSpace(raw))
	default:
		return "verified"
	}
}

func claimStatusResolved(status string) bool {
	switch normalizeClaimStatus(status) {
	case "corrected", "retracted", "superseded", "refuted":
		return true
	default:
		return false
	}
}

func validateClaimSourceNode(existing *Node, desired map[string]any) error {
	if existing == nil {
		return nil
	}
	if existing.Kind != NodeKindSource {
		return fmt.Errorf("source id %s already exists as %s", existing.ID, existing.Kind)
	}
	checks := []struct {
		key string
	}{
		{key: "source_type"},
		{key: "canonical_name"},
		{key: "url"},
		{key: "trust_tier"},
	}
	for _, check := range checks {
		want := strings.TrimSpace(readString(desired, check.key))
		if want == "" {
			continue
		}
		got := strings.TrimSpace(readString(existing.Properties, check.key))
		if got != "" && !strings.EqualFold(got, want) {
			return fmt.Errorf("source %s conflicts on %s", existing.ID, check.key)
		}
	}
	wantReliability := readFloat(desired, "reliability_score")
	gotReliability := readFloat(existing.Properties, "reliability_score")
	if wantReliability > 0 && gotReliability > 0 && gotReliability != wantReliability {
		return fmt.Errorf("source %s conflicts on reliability_score", existing.ID)
	}
	return nil
}

func countConflictClaimIDs(conflicts []ClaimConflict) int {
	if len(conflicts) == 0 {
		return 0
	}
	claimIDs := make(map[string]struct{}, len(conflicts)*2)
	for _, conflict := range conflicts {
		for _, claimID := range conflict.ClaimIDs {
			if claimID == "" {
				continue
			}
			claimIDs[claimID] = struct{}{}
		}
	}
	return len(claimIDs)
}

func claimUnsupportedAt(g *Graph, claim *Node, validAt, recordedAt time.Time) bool {
	if g == nil || claim == nil {
		return true
	}
	for _, edge := range g.GetOutEdgesBitemporal(claim.ID, validAt, recordedAt) {
		if edge == nil {
			continue
		}
		if edge.Kind == EdgeKindBasedOn {
			return false
		}
	}
	for _, edge := range g.GetInEdgesBitemporal(claim.ID, validAt, recordedAt) {
		if edge == nil {
			continue
		}
		if edge.Kind == EdgeKindSupports {
			return false
		}
	}
	return true
}

func claimSourcelessAt(g *Graph, claim *Node, validAt, recordedAt time.Time) bool {
	if g == nil || claim == nil {
		return true
	}
	for _, edge := range g.GetOutEdgesBitemporal(claim.ID, validAt, recordedAt) {
		if edge != nil && edge.Kind == EdgeKindAssertedBy {
			return false
		}
	}
	return true
}

func claimSourceIDsAt(g *Graph, claim *Node, validAt, recordedAt time.Time) []string {
	if g == nil || claim == nil {
		return nil
	}
	out := make([]string, 0, 2)
	for _, edge := range g.GetOutEdgesBitemporal(claim.ID, validAt, recordedAt) {
		if edge == nil || edge.Kind != EdgeKindAssertedBy {
			continue
		}
		out = append(out, edge.Target)
	}
	return out
}

func claimComparableValue(claim *Node) string {
	if claim == nil {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(firstNonEmpty(
		readString(claim.Properties, "object_id"),
		readString(claim.Properties, "object_value"),
		readString(claim.Properties, "summary"),
	)))
}

func buildClaimConflictRecommendations(summary ClaimConflictReportSummary) []ClaimConflictRecommendation {
	recommendations := make([]ClaimConflictRecommendation, 0, 4)
	conflictGroups := summary.TotalConflictGroups
	if conflictGroups == 0 {
		conflictGroups = summary.ConflictGroups
	}
	if conflictGroups > 0 {
		recommendations = append(recommendations, ClaimConflictRecommendation{
			Priority: "high",
			Title:    "Resolve contradictory active claims",
			Detail:   fmt.Sprintf("%d subject/predicate groups currently disagree on value and need adjudication or supersession.", conflictGroups),
		})
	}
	if summary.UnsupportedClaims > 0 {
		recommendations = append(recommendations, ClaimConflictRecommendation{
			Priority: "high",
			Title:    "Attach evidence to unsupported claims",
			Detail:   fmt.Sprintf("%d active claims have no evidence links or upstream supporting claims.", summary.UnsupportedClaims),
		})
	}
	if summary.SourcelessClaims > 0 {
		recommendations = append(recommendations, ClaimConflictRecommendation{
			Priority: "medium",
			Title:    "Backfill source attribution",
			Detail:   fmt.Sprintf("%d active claims are missing asserted_by source links.", summary.SourcelessClaims),
		})
	}
	if summary.StaleClaims > 0 {
		recommendations = append(recommendations, ClaimConflictRecommendation{
			Priority: "medium",
			Title:    "Refresh stale claims",
			Detail:   fmt.Sprintf("%d active claims have aged beyond the configured freshness window.", summary.StaleClaims),
		})
	}
	return recommendations
}

func buildSourceNodeID(sourceType, sourceName string) string {
	return "source:" + slugifyKnowledgeKey(firstNonEmpty(sourceType, "system")) + ":" + slugifyKnowledgeKey(firstNonEmpty(sourceName, "unknown"))
}

func slugifyKnowledgeKey(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "unknown"
	}
	var b strings.Builder
	lastDash := false
	for _, r := range value {
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			b.WriteRune(r)
			lastDash = false
		case !lastDash:
			b.WriteByte('-')
			lastDash = true
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "unknown"
	}
	return out
}

func trimNonEmpty(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func normalizeNonEmptyStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(strings.ToLower(value))
		if trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}
