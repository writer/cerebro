package graph

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	defaultClaimProofLimit = 64
	maxClaimProofLimit     = 256
)

// ClaimProofOptions tunes proof/justification expansion for one claim.
type ClaimProofOptions struct {
	ValidAt    time.Time `json:"valid_at,omitempty"`
	RecordedAt time.Time `json:"recorded_at,omitempty"`
	Limit      int       `json:"limit,omitempty"`
}

// ClaimProofNode is one typed node included in a proof fragment.
type ClaimProofNode struct {
	ID      string `json:"id"`
	Kind    string `json:"kind"`
	Role    string `json:"role,omitempty"`
	Summary string `json:"summary,omitempty"`
}

// ClaimProofEdge is one typed edge included in a proof fragment.
type ClaimProofEdge struct {
	Kind     string `json:"kind"`
	SourceID string `json:"source_id"`
	TargetID string `json:"target_id"`
	Summary  string `json:"summary,omitempty"`
}

// ClaimProofRecord is one explanation-grade proof fragment for a claim.
type ClaimProofRecord struct {
	ID        string           `json:"id"`
	ProofType string           `json:"proof_type"`
	Summary   string           `json:"summary,omitempty"`
	Nodes     []ClaimProofNode `json:"nodes,omitempty"`
	Edges     []ClaimProofEdge `json:"edges,omitempty"`
}

// ClaimProofSummary captures proof-composition and truncation metadata.
type ClaimProofSummary struct {
	TotalProofs        int  `json:"total_proofs"`
	ReturnedProofs     int  `json:"returned_proofs"`
	ProofsTruncated    bool `json:"proofs_truncated,omitempty"`
	SourceProofs       int  `json:"source_proofs"`
	EvidenceProofs     int  `json:"evidence_proofs"`
	ObservationProofs  int  `json:"observation_proofs"`
	SupportProofs      int  `json:"support_proofs"`
	RefutationProofs   int  `json:"refutation_proofs"`
	ConflictProofs     int  `json:"conflict_proofs"`
	SupersessionProofs int  `json:"supersession_proofs"`
}

// ClaimProofCollection is the typed proof answer for one claim.
type ClaimProofCollection struct {
	GeneratedAt time.Time          `json:"generated_at"`
	ClaimID     string             `json:"claim_id"`
	ValidAt     time.Time          `json:"valid_at"`
	RecordedAt  time.Time          `json:"recorded_at"`
	Summary     ClaimProofSummary  `json:"summary"`
	Proofs      []ClaimProofRecord `json:"proofs,omitempty"`
}

// BuildClaimProofs returns typed proof fragments explaining why a claim is
// supported, disputed, superseded, or provenance-backed.
func BuildClaimProofs(g *Graph, claimID string, opts ClaimProofOptions) (ClaimProofCollection, bool) {
	query := normalizeClaimProofOptions(opts)
	claim, ok := GetClaimRecord(g, strings.TrimSpace(claimID), query.ValidAt, query.RecordedAt)
	if !ok {
		return ClaimProofCollection{}, false
	}

	collection := ClaimProofCollection{
		GeneratedAt: temporalNowUTC(),
		ClaimID:     claim.ID,
		ValidAt:     query.ValidAt,
		RecordedAt:  query.RecordedAt,
	}

	proofs := make([]ClaimProofRecord, 0, 24)
	for _, source := range collectSourceRecordsByID(g, claim.Links.SourceIDs, query.ValidAt, query.RecordedAt) {
		proofs = append(proofs, ClaimProofRecord{
			ID:        fmt.Sprintf("claim_proof:%s:source:%s", slugifyKnowledgeKey(claim.ID), slugifyKnowledgeKey(source.ID)),
			ProofType: "source",
			Summary:   fmt.Sprintf("Claim is attributed to source %s", firstNonEmpty(source.CanonicalName, source.ID)),
			Nodes: []ClaimProofNode{
				claimProofClaimNode(claim, "claim"),
				claimProofSourceNode(source, "source"),
			},
			Edges: []ClaimProofEdge{claimProofEdge(string(EdgeKindAssertedBy), claim.ID, source.ID, "Claim asserted by source")},
		})
	}
	for _, artifact := range collectArtifactRecordsByID(g, claim.Links.EvidenceIDs, query.ValidAt, query.RecordedAt) {
		proof := ClaimProofRecord{
			ID:      fmt.Sprintf("claim_proof:%s:artifact:%s", slugifyKnowledgeKey(claim.ID), slugifyKnowledgeKey(artifact.ID)),
			Summary: fmt.Sprintf("Claim is based on %s %s", artifact.Kind, artifact.ID),
			Nodes: []ClaimProofNode{
				claimProofClaimNode(claim, "claim"),
				claimProofArtifactNode(artifact, "artifact"),
			},
			Edges: []ClaimProofEdge{claimProofEdge(string(EdgeKindBasedOn), claim.ID, artifact.ID, "Claim based on artifact")},
		}
		if artifact.Kind == NodeKindObservation {
			proof.ProofType = "observation"
		} else {
			proof.ProofType = "evidence"
		}
		for _, targetID := range artifact.Links.TargetIDs {
			proof.Nodes = append(proof.Nodes, ClaimProofNode{ID: targetID, Kind: "entity", Role: "target", Summary: targetID})
			proof.Edges = append(proof.Edges, claimProofEdge(string(EdgeKindTargets), artifact.ID, targetID, "Artifact targets entity"))
		}
		proofs = append(proofs, proof)
	}
	for _, supporting := range collectClaimRecordsByID(g, claim.Links.SupportingClaimIDs, query.ValidAt, query.RecordedAt) {
		proofs = append(proofs, buildClaimRelationshipProof(g, "support", supporting, claim, query.ValidAt, query.RecordedAt))
	}
	for _, refuting := range collectClaimRecordsByID(g, claim.Links.RefutingClaimIDs, query.ValidAt, query.RecordedAt) {
		proofs = append(proofs, buildClaimRelationshipProof(g, "refutation", refuting, claim, query.ValidAt, query.RecordedAt))
	}
	for _, conflicting := range collectClaimRecordsByID(g, claim.Links.ConflictingClaimIDs, query.ValidAt, query.RecordedAt) {
		proofs = append(proofs, ClaimProofRecord{
			ID:        fmt.Sprintf("claim_proof:%s:conflict:%s", slugifyKnowledgeKey(claim.ID), slugifyKnowledgeKey(conflicting.ID)),
			ProofType: "conflict",
			Summary:   fmt.Sprintf("Claim conflicts with %s", conflicting.ID),
			Nodes: []ClaimProofNode{
				claimProofClaimNode(conflicting, "conflicting_claim"),
				claimProofClaimNode(claim, "claim"),
			},
			Edges: []ClaimProofEdge{claimProofEdge(string(EdgeKindContradicts), conflicting.ID, claim.ID, "Claims assert different values")},
		})
	}
	for _, newer := range collectClaimRecordsByID(g, claim.Links.SupersededByClaimIDs, query.ValidAt, query.RecordedAt) {
		proofs = append(proofs, buildClaimRelationshipProof(g, "supersession", newer, claim, query.ValidAt, query.RecordedAt))
	}
	for _, older := range collectClaimRecordsByID(g, claim.Links.SupersedesClaimIDs, query.ValidAt, query.RecordedAt) {
		proofs = append(proofs, ClaimProofRecord{
			ID:        fmt.Sprintf("claim_proof:%s:supersedes:%s", slugifyKnowledgeKey(claim.ID), slugifyKnowledgeKey(older.ID)),
			ProofType: "supersession",
			Summary:   fmt.Sprintf("Claim supersedes %s", older.ID),
			Nodes: []ClaimProofNode{
				claimProofClaimNode(claim, "claim"),
				claimProofClaimNode(older, "superseded_claim"),
			},
			Edges: []ClaimProofEdge{claimProofEdge(string(EdgeKindSupersedes), claim.ID, older.ID, "Newer claim supersedes older claim")},
		})
	}

	sortClaimProofRecords(proofs)
	collection.Summary.TotalProofs = len(proofs)
	for _, proof := range proofs {
		updateClaimProofSummary(&collection.Summary, proof)
	}
	if len(proofs) > query.Limit {
		collection.Proofs = append(collection.Proofs, proofs[:query.Limit]...)
		collection.Summary.ProofsTruncated = true
	} else {
		collection.Proofs = append(collection.Proofs, proofs...)
	}
	collection.Summary.ReturnedProofs = len(collection.Proofs)
	return collection, true
}

func normalizeClaimProofOptions(opts ClaimProofOptions) ClaimProofOptions {
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
		opts.Limit = defaultClaimProofLimit
	}
	if opts.Limit > maxClaimProofLimit {
		opts.Limit = maxClaimProofLimit
	}
	return opts
}

func buildClaimRelationshipProof(g *Graph, proofType string, other ClaimRecord, claim ClaimRecord, validAt, recordedAt time.Time) ClaimProofRecord {
	proof := ClaimProofRecord{
		ID:        fmt.Sprintf("claim_proof:%s:%s:%s", slugifyKnowledgeKey(claim.ID), slugifyKnowledgeKey(proofType), slugifyKnowledgeKey(other.ID)),
		ProofType: proofType,
		Nodes: []ClaimProofNode{
			claimProofClaimNode(other, otherRoleForProofType(proofType)),
			claimProofClaimNode(claim, "claim"),
		},
	}
	switch proofType {
	case "support":
		proof.Summary = fmt.Sprintf("Supporting claim %s supports this claim", other.ID)
		proof.Edges = append(proof.Edges, claimProofEdge(string(EdgeKindSupports), other.ID, claim.ID, "Supporting claim"))
	case "refutation":
		proof.Summary = fmt.Sprintf("Refuting claim %s disputes this claim", other.ID)
		proof.Edges = append(proof.Edges, claimProofEdge(string(EdgeKindRefutes), other.ID, claim.ID, "Refuting claim"))
	case "supersession":
		proof.Summary = fmt.Sprintf("Newer claim %s supersedes this claim", other.ID)
		proof.Edges = append(proof.Edges, claimProofEdge(string(EdgeKindSupersedes), other.ID, claim.ID, "Superseding claim"))
	}
	for _, source := range collectSourceRecordsByID(g, other.Links.SourceIDs, validAt, recordedAt) {
		proof.Nodes = append(proof.Nodes, claimProofSourceNode(source, "source"))
		proof.Edges = append(proof.Edges, claimProofEdge(string(EdgeKindAssertedBy), other.ID, source.ID, "Related claim asserted by source"))
	}
	for _, artifact := range collectArtifactRecordsByID(g, other.Links.EvidenceIDs, validAt, recordedAt) {
		proof.Nodes = append(proof.Nodes, claimProofArtifactNode(artifact, artifactRoleForProof(artifact)))
		proof.Edges = append(proof.Edges, claimProofEdge(string(EdgeKindBasedOn), other.ID, artifact.ID, "Related claim based on artifact"))
	}
	return proof
}

func sortClaimProofRecords(proofs []ClaimProofRecord) {
	sort.Slice(proofs, func(i, j int) bool {
		if proofs[i].ProofType != proofs[j].ProofType {
			return proofs[i].ProofType < proofs[j].ProofType
		}
		if proofs[i].Summary != proofs[j].Summary {
			return proofs[i].Summary < proofs[j].Summary
		}
		return proofs[i].ID < proofs[j].ID
	})
}

func updateClaimProofSummary(summary *ClaimProofSummary, proof ClaimProofRecord) {
	if summary == nil {
		return
	}
	switch proof.ProofType {
	case "source":
		summary.SourceProofs++
	case "evidence":
		summary.EvidenceProofs++
	case "observation":
		summary.ObservationProofs++
	case "support":
		summary.SupportProofs++
	case "refutation":
		summary.RefutationProofs++
	case "conflict":
		summary.ConflictProofs++
	case "supersession":
		summary.SupersessionProofs++
	}
}

func claimProofClaimNode(record ClaimRecord, role string) ClaimProofNode {
	return ClaimProofNode{
		ID:      record.ID,
		Kind:    string(NodeKindClaim),
		Role:    role,
		Summary: firstNonEmpty(record.Summary, record.Predicate, record.ID),
	}
}

func claimProofArtifactNode(record KnowledgeArtifactRecord, role string) ClaimProofNode {
	return ClaimProofNode{
		ID:      record.ID,
		Kind:    string(record.Kind),
		Role:    role,
		Summary: firstNonEmpty(record.Detail, record.ArtifactType, record.ID),
	}
}

func claimProofSourceNode(record KnowledgeSourceRecord, role string) ClaimProofNode {
	return ClaimProofNode{
		ID:      record.ID,
		Kind:    string(NodeKindSource),
		Role:    role,
		Summary: firstNonEmpty(record.CanonicalName, record.SourceType, record.ID),
	}
}

func claimProofEdge(kind, sourceID, targetID, summary string) ClaimProofEdge {
	return ClaimProofEdge{
		Kind:     kind,
		SourceID: sourceID,
		TargetID: targetID,
		Summary:  summary,
	}
}

func otherRoleForProofType(proofType string) string {
	switch proofType {
	case "support":
		return "supporting_claim"
	case "refutation":
		return "refuting_claim"
	case "supersession":
		return "superseding_claim"
	default:
		return "related_claim"
	}
}

func artifactRoleForProof(record KnowledgeArtifactRecord) string {
	if record.Kind == NodeKindObservation {
		return "observation"
	}
	return "evidence"
}
