package graph

import (
	"fmt"
	"strings"
	"time"
)

const (
	ClaimAdjudicationAcceptExisting = "accept_existing"
	ClaimAdjudicationReplaceValue   = "replace_value"
	ClaimAdjudicationRetractGroup   = "retract_group"
)

// ClaimAdjudicationWriteRequest captures one append-only adjudication action
// over a claim group. The action emits a new claim version rather than
// destructively editing historical claims in place.
type ClaimAdjudicationWriteRequest struct {
	GroupID              string         `json:"group_id,omitempty"`
	Action               string         `json:"action"`
	AuthoritativeClaimID string         `json:"authoritative_claim_id,omitempty"`
	ClaimType            string         `json:"claim_type,omitempty"`
	ObjectID             string         `json:"object_id,omitempty"`
	ObjectValue          string         `json:"object_value,omitempty"`
	Summary              string         `json:"summary,omitempty"`
	Rationale            string         `json:"rationale,omitempty"`
	Actor                string         `json:"actor,omitempty"`
	EvidenceIDs          []string       `json:"evidence_ids,omitempty"`
	SupportingClaimIDs   []string       `json:"supporting_claim_ids,omitempty"`
	SourceID             string         `json:"source_id,omitempty"`
	SourceName           string         `json:"source_name,omitempty"`
	SourceType           string         `json:"source_type,omitempty"`
	SourceURL            string         `json:"source_url,omitempty"`
	TrustTier            string         `json:"trust_tier,omitempty"`
	ReliabilityScore     float64        `json:"reliability_score,omitempty"`
	SourceSystem         string         `json:"source_system,omitempty"`
	SourceEventID        string         `json:"source_event_id,omitempty"`
	ObservedAt           time.Time      `json:"observed_at,omitempty"`
	ValidFrom            time.Time      `json:"valid_from,omitempty"`
	ValidTo              *time.Time     `json:"valid_to,omitempty"`
	RecordedAt           time.Time      `json:"recorded_at,omitempty"`
	TransactionFrom      time.Time      `json:"transaction_from,omitempty"`
	TransactionTo        *time.Time     `json:"transaction_to,omitempty"`
	Confidence           float64        `json:"confidence,omitempty"`
	Metadata             map[string]any `json:"metadata,omitempty"`
}

// ClaimAdjudicationWriteResult summarizes one adjudication write.
type ClaimAdjudicationWriteResult struct {
	GroupID              string            `json:"group_id"`
	Action               string            `json:"action"`
	CreatedClaimID       string            `json:"created_claim_id,omitempty"`
	AuthoritativeClaimID string            `json:"authoritative_claim_id,omitempty"`
	AffectedClaimIDs     []string          `json:"affected_claim_ids,omitempty"`
	SupersededClaimIDs   []string          `json:"superseded_claim_ids,omitempty"`
	ObservedAt           time.Time         `json:"observed_at,omitempty"`
	RecordedAt           time.Time         `json:"recorded_at,omitempty"`
	Group                *ClaimGroupRecord `json:"group,omitempty"`
}

// AdjudicateClaimGroup applies an append-only adjudication action to a claim
// group by emitting a new authoritative or terminal claim version that
// supersedes the group's active claims.
func AdjudicateClaimGroup(g *Graph, req ClaimAdjudicationWriteRequest) (ClaimAdjudicationWriteResult, error) {
	if g == nil {
		return ClaimAdjudicationWriteResult{}, fmt.Errorf("graph is required")
	}

	request, err := normalizeClaimAdjudicationWriteRequest(req)
	if err != nil {
		return ClaimAdjudicationWriteResult{}, err
	}

	group, ok := GetClaimGroupRecord(g, request.GroupID, request.ValidFrom, request.RecordedAt, true)
	if !ok {
		return ClaimAdjudicationWriteResult{}, fmt.Errorf("claim group not found: %s", request.GroupID)
	}
	if len(group.ActiveClaimIDs) == 0 {
		return ClaimAdjudicationWriteResult{}, fmt.Errorf("claim group has no active claims: %s", request.GroupID)
	}

	authoritative := ClaimRecord{}
	if request.AuthoritativeClaimID != "" {
		authoritative, ok = GetClaimRecord(g, request.AuthoritativeClaimID, request.ValidFrom, request.RecordedAt)
		if !ok {
			return ClaimAdjudicationWriteResult{}, fmt.Errorf("authoritative claim not found: %s", request.AuthoritativeClaimID)
		}
		if authoritative.SubjectID != group.SubjectID || !strings.EqualFold(authoritative.Predicate, group.Predicate) {
			return ClaimAdjudicationWriteResult{}, fmt.Errorf("authoritative claim %s does not belong to group %s", request.AuthoritativeClaimID, request.GroupID)
		}
	}

	sourceRecord, _ := firstSourceRecordForClaim(g, authoritative, request.ValidFrom, request.RecordedAt)
	claimReq, err := buildAdjudicatedClaimWriteRequest(request, group, authoritative, sourceRecord)
	if err != nil {
		return ClaimAdjudicationWriteResult{}, err
	}
	writeResult, err := WriteClaim(g, claimReq)
	if err != nil {
		return ClaimAdjudicationWriteResult{}, err
	}

	metadata := NormalizeWriteMetadata(claimReq.ObservedAt, claimReq.ValidFrom, claimReq.ValidTo, claimReq.SourceSystem, claimReq.SourceEventID, claimReq.Confidence, WriteMetadataDefaults{
		SourceSystem:      "api",
		SourceEventPrefix: "claim_adjudication",
		DefaultConfidence: 0.90,
		RecordedAt:        claimReq.RecordedAt,
		TransactionFrom:   claimReq.TransactionFrom,
		TransactionTo:     claimReq.TransactionTo,
	})
	for _, claimID := range group.ActiveClaimIDs {
		if claimID == claimReq.SupersedesClaimID || claimID == writeResult.ClaimID {
			continue
		}
		appendClaimRelationship(g, writeResult.ClaimID, claimID, EdgeKindSupersedes, metadata)
	}

	currentGroup, _ := GetClaimGroupRecord(g, request.GroupID, metadata.ValidFrom, metadata.RecordedAt, true)
	result := ClaimAdjudicationWriteResult{
		GroupID:              request.GroupID,
		Action:               request.Action,
		CreatedClaimID:       writeResult.ClaimID,
		AuthoritativeClaimID: request.AuthoritativeClaimID,
		AffectedClaimIDs:     append([]string(nil), group.ClaimIDs...),
		SupersededClaimIDs:   append([]string(nil), group.ActiveClaimIDs...),
		ObservedAt:           writeResult.ObservedAt,
		RecordedAt:           writeResult.RecordedAt,
	}
	if currentGroup.ID != "" {
		result.Group = &currentGroup
	}
	return result, nil
}

func normalizeClaimAdjudicationWriteRequest(req ClaimAdjudicationWriteRequest) (ClaimAdjudicationWriteRequest, error) {
	out := req
	out.GroupID = strings.TrimSpace(req.GroupID)
	out.Action = normalizeClaimAdjudicationAction(req.Action)
	out.AuthoritativeClaimID = strings.TrimSpace(req.AuthoritativeClaimID)
	out.ClaimType = strings.TrimSpace(req.ClaimType)
	out.ObjectID = strings.TrimSpace(req.ObjectID)
	out.ObjectValue = strings.TrimSpace(req.ObjectValue)
	out.Summary = strings.TrimSpace(req.Summary)
	out.Rationale = strings.TrimSpace(req.Rationale)
	out.Actor = strings.TrimSpace(req.Actor)
	out.EvidenceIDs = uniqueSortedStrings(trimNonEmpty(req.EvidenceIDs))
	out.SupportingClaimIDs = uniqueSortedStrings(trimNonEmpty(req.SupportingClaimIDs))
	out.SourceID = strings.TrimSpace(req.SourceID)
	out.SourceName = strings.TrimSpace(req.SourceName)
	out.SourceType = strings.TrimSpace(req.SourceType)
	out.SourceURL = strings.TrimSpace(req.SourceURL)
	out.TrustTier = strings.TrimSpace(req.TrustTier)
	out.SourceSystem = strings.TrimSpace(req.SourceSystem)
	out.SourceEventID = strings.TrimSpace(req.SourceEventID)
	out.ReliabilityScore = clampUnit(req.ReliabilityScore)
	out.Confidence = clampUnit(req.Confidence)
	out.ValidFrom = firstNonZeroUTC(req.ValidFrom, temporalNowUTC())
	out.RecordedAt = firstNonZeroUTC(req.RecordedAt, temporalNowUTC())
	out.ObservedAt = firstNonZeroUTC(req.ObservedAt, out.ValidFrom)
	out.TransactionFrom = firstNonZeroUTC(req.TransactionFrom, out.RecordedAt)
	out.ValidTo = cloneTimePtr(req.ValidTo)
	out.TransactionTo = cloneTimePtr(req.TransactionTo)

	if out.GroupID == "" {
		return ClaimAdjudicationWriteRequest{}, fmt.Errorf("group_id is required")
	}
	if out.Action == "" {
		return ClaimAdjudicationWriteRequest{}, fmt.Errorf("action is required")
	}
	if out.Action == ClaimAdjudicationAcceptExisting && out.AuthoritativeClaimID == "" {
		return ClaimAdjudicationWriteRequest{}, fmt.Errorf("authoritative_claim_id is required for accept_existing")
	}
	if out.Action == ClaimAdjudicationReplaceValue && out.ObjectID == "" && out.ObjectValue == "" {
		return ClaimAdjudicationWriteRequest{}, fmt.Errorf("object_id or object_value is required for replace_value")
	}
	return out, nil
}

func normalizeClaimAdjudicationAction(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case ClaimAdjudicationAcceptExisting:
		return ClaimAdjudicationAcceptExisting
	case ClaimAdjudicationReplaceValue:
		return ClaimAdjudicationReplaceValue
	case ClaimAdjudicationRetractGroup:
		return ClaimAdjudicationRetractGroup
	default:
		return ""
	}
}

func buildAdjudicatedClaimWriteRequest(req ClaimAdjudicationWriteRequest, group ClaimGroupRecord, authoritative ClaimRecord, source *KnowledgeSourceRecord) (ClaimWriteRequest, error) {
	claimType := firstNonEmpty(strings.TrimSpace(req.ClaimType), authoritative.ClaimType)
	objectID := strings.TrimSpace(req.ObjectID)
	objectValue := strings.TrimSpace(req.ObjectValue)
	summary := strings.TrimSpace(req.Summary)
	evidenceIDs := append([]string(nil), req.EvidenceIDs...)
	supportingClaimIDs := append([]string(nil), req.SupportingClaimIDs...)
	sourceID := strings.TrimSpace(req.SourceID)
	sourceName := strings.TrimSpace(req.SourceName)
	sourceType := strings.TrimSpace(req.SourceType)
	sourceURL := strings.TrimSpace(req.SourceURL)
	trustTier := strings.TrimSpace(req.TrustTier)
	reliabilityScore := req.ReliabilityScore
	confidence := req.Confidence
	status := "asserted"

	switch req.Action {
	case ClaimAdjudicationAcceptExisting:
		if authoritative.ID == "" {
			return ClaimWriteRequest{}, fmt.Errorf("authoritative claim is required")
		}
		if objectID == "" {
			objectID = authoritative.ObjectID
		}
		if objectValue == "" {
			objectValue = authoritative.ObjectValue
		}
		if claimType == "" {
			claimType = authoritative.ClaimType
		}
		if summary == "" {
			summary = firstNonEmpty(authoritative.Summary, fmt.Sprintf("Adjudicated canonical claim for %s", group.ID))
		}
		evidenceIDs = uniqueSortedStrings(append(evidenceIDs, authoritative.Links.EvidenceIDs...))
		supportingClaimIDs = uniqueSortedStrings(append(supportingClaimIDs, authoritative.ID))
		if confidence <= 0 {
			confidence = authoritative.Confidence
		}
	case ClaimAdjudicationReplaceValue:
		if summary == "" {
			summary = fmt.Sprintf("Adjudicated replacement claim for %s", group.ID)
		}
		if objectID == "" && objectValue == "" {
			return ClaimWriteRequest{}, fmt.Errorf("object_id or object_value is required")
		}
	case ClaimAdjudicationRetractGroup:
		status = "retracted"
		if summary == "" {
			summary = fmt.Sprintf("Retracted claim group %s", group.ID)
		}
		if objectID == "" && objectValue == "" {
			objectValue = "retracted"
		}
		if claimType == "" {
			claimType = "attribute"
		}
	default:
		return ClaimWriteRequest{}, fmt.Errorf("unsupported adjudication action: %s", req.Action)
	}

	if source != nil {
		if sourceID == "" {
			sourceID = source.ID
		}
		if sourceName == "" {
			sourceName = source.CanonicalName
		}
		if sourceType == "" {
			sourceType = source.SourceType
		}
		if sourceURL == "" {
			sourceURL = source.URL
		}
		if trustTier == "" {
			trustTier = source.TrustTier
		}
		if reliabilityScore <= 0 {
			reliabilityScore = source.ReliabilityScore
		}
	}
	if confidence <= 0 {
		confidence = 0.90
	}

	metadata := cloneAnyMap(req.Metadata)
	if metadata == nil {
		metadata = make(map[string]any)
	}
	metadata["adjudication_action"] = req.Action
	metadata["adjudication_group_id"] = group.ID
	metadata["adjudicated_claim_ids"] = append([]string(nil), group.ActiveClaimIDs...)
	if req.Rationale != "" {
		metadata["adjudication_rationale"] = req.Rationale
	}
	if req.Actor != "" {
		metadata["adjudicated_by"] = req.Actor
	}
	if req.AuthoritativeClaimID != "" {
		metadata["authoritative_claim_id"] = req.AuthoritativeClaimID
	}

	return ClaimWriteRequest{
		ClaimType:          firstNonEmpty(claimType, "attribute"),
		SubjectID:          group.SubjectID,
		Predicate:          group.Predicate,
		ObjectID:           objectID,
		ObjectValue:        objectValue,
		Status:             status,
		Summary:            summary,
		EvidenceIDs:        evidenceIDs,
		SupportingClaimIDs: supportingClaimIDs,
		SupersedesClaimID:  firstClaimID(group.ActiveClaimIDs),
		SourceID:           sourceID,
		SourceName:         sourceName,
		SourceType:         sourceType,
		SourceURL:          sourceURL,
		TrustTier:          trustTier,
		ReliabilityScore:   reliabilityScore,
		SourceSystem:       req.SourceSystem,
		SourceEventID:      req.SourceEventID,
		ObservedAt:         req.ObservedAt,
		ValidFrom:          req.ValidFrom,
		ValidTo:            cloneTimePtr(req.ValidTo),
		RecordedAt:         req.RecordedAt,
		TransactionFrom:    req.TransactionFrom,
		TransactionTo:      cloneTimePtr(req.TransactionTo),
		Confidence:         confidence,
		Metadata:           metadata,
	}, nil
}

func firstSourceRecordForClaim(g *Graph, claim ClaimRecord, validAt, recordedAt time.Time) (*KnowledgeSourceRecord, bool) {
	for _, sourceID := range claim.Links.SourceIDs {
		record, ok := GetSourceRecord(g, sourceID, validAt, recordedAt)
		if !ok {
			continue
		}
		return &record, true
	}
	return nil, false
}

func appendClaimRelationship(g *Graph, sourceID, targetID string, kind EdgeKind, metadata WriteMetadata) {
	if g == nil || strings.TrimSpace(sourceID) == "" || strings.TrimSpace(targetID) == "" {
		return
	}
	g.AddEdge(&Edge{
		ID:         fmt.Sprintf("%s->%s:%s", strings.TrimSpace(sourceID), strings.TrimSpace(targetID), kind),
		Source:     strings.TrimSpace(sourceID),
		Target:     strings.TrimSpace(targetID),
		Kind:       kind,
		Effect:     EdgeEffectAllow,
		Properties: metadata.PropertyMap(),
	})
}

func firstClaimID(values []string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
