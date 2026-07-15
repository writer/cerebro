package trustclaims

import (
	"fmt"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/evidencepackets"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/workflowevents"
)

// CitationFromQuestionnaire preserves the source-event and resource lineage of
// a questionnaire answer when it becomes an external factual claim.
func CitationFromQuestionnaire(citation ports.QuestionnaireCitation, trusted bool) Citation {
	observedAt, _ := time.Parse(time.RFC3339Nano, strings.TrimSpace(citation.ObservedAt))
	expiresAt := parseOptionalTime(citation.ExpiresAt)
	resourceRefs := make([]ResourceRef, 0, len(citation.GraphRootURNs)+1)
	if resourceURN := strings.TrimSpace(citation.ResourceURN); resourceURN != "" {
		resourceRefs = append(resourceRefs, ResourceRef{URN: resourceURN})
	}
	for _, urn := range citation.GraphRootURNs {
		resourceRefs = append(resourceRefs, ResourceRef{URN: urn})
	}
	state := normalizeFreshnessState(citation.FreshnessStatus)
	return Citation{
		ID:               citation.ID,
		EvidenceID:       firstNonEmpty(citation.EvidenceID, citation.ID),
		EvidencePacketID: citation.EvidencePacketID,
		EvidenceType:     citation.EvidenceType,
		SourceID:         firstNonEmpty(citation.SourceID, citation.Source),
		RuntimeID:        citation.RuntimeID,
		SourceEventIDs:   citation.SourceEventIDs,
		ResourceRefs:     resourceRefs,
		State:            state,
		Trusted:          trusted,
		ObservedAt:       observedAt,
		ExpiresAt:        expiresAt,
	}
}

// CitationFromEvidencePacket converts the existing evidence-packet reasoning
// contract without inferring trust or silently upgrading freshness.
func CitationFromEvidencePacket(reference evidencepackets.QuestionnaireEvidenceRef, trusted bool) Citation {
	observedAt, _ := time.Parse(time.RFC3339Nano, strings.TrimSpace(reference.Freshness.ObservedAt))
	expiresAt := parseOptionalTime(reference.Freshness.ExpiresAt)
	resources := make([]ResourceRef, 0, len(reference.GraphRootURNs))
	for _, urn := range reference.GraphRootURNs {
		resources = append(resources, ResourceRef{URN: urn})
	}
	return Citation{
		ID:               reference.ID,
		EvidenceID:       reference.ID,
		EvidencePacketID: reference.EvidencePacketID,
		EvidenceType:     reference.EvidenceType,
		SourceID:         firstNonEmpty(reference.SourceID, reference.Source),
		RuntimeID:        reference.RuntimeID,
		SourceEventIDs:   reference.SourceEventIDs,
		ResourceRefs:     resources,
		State:            normalizeFreshnessState(reference.Freshness.Status),
		Trusted:          trusted,
		ObservedAt:       observedAt,
		ExpiresAt:        expiresAt,
	}
}

// WorkflowDecision maps a trust-claim transition onto the existing durable
// knowledge-decision event contract. The caller remains responsible for
// appending the event before projecting current state.
func (transition ClaimTransition) WorkflowDecision() workflowevents.DecisionRecorded {
	evidenceIDs := make([]string, 0, len(transition.Receipt.Citations))
	for _, citation := range transition.Receipt.Citations {
		evidenceIDs = append(evidenceIDs, citation.EvidenceID)
	}
	return workflowevents.DecisionRecorded{
		TenantID:      transition.TenantID,
		DecisionID:    transition.Receipt.ReceiptID + ":v" + fmt.Sprintf("%d", transition.Receipt.Version),
		DecisionType:  transition.TransitionType,
		Status:        transition.Receipt.Status,
		Rationale:     transition.Receipt.TransitionReason,
		TargetIDs:     uniqueSortedStrings([]string{transition.ClaimID, transition.Receipt.ReceiptID}),
		EvidenceIDs:   uniqueSortedStrings(evidenceIDs),
		SourceSystem:  "cerebro-trust-claims",
		SourceEventID: transition.FromDigest,
		ObservedAt:    transition.Receipt.IssuedAt.UTC().Format(time.RFC3339Nano),
		ValidFrom:     transition.Receipt.IssuedAt.UTC().Format(time.RFC3339Nano),
		Confidence:    1,
		Metadata: map[string]any{
			"receipt_digest":  transition.Receipt.Digest,
			"previous_digest": transition.FromDigest,
			"receipt_version": transition.Receipt.Version,
			"transition_type": transition.TransitionType,
		},
	}
}

func normalizeFreshnessState(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "current", "fresh", "supported":
		return CitationCurrent
	case "conflict", "conflicted":
		return CitationConflicted
	case "revoked", "retracted":
		return CitationRevoked
	default:
		return CitationStale
	}
}

func parseOptionalTime(value string) *time.Time {
	parsed, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(value))
	if err != nil {
		return nil
	}
	return &parsed
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}
