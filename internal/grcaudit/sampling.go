package grcaudit

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

// SampleAlgorithmHashRankedV1 is a deterministic, without-replacement sampling algorithm.
const SampleAlgorithmHashRankedV1 = "hash_ranked_v1"

// PopulationSnapshot is an immutable population used for audit sample refinement.
type PopulationSnapshot struct {
	ID         string   `json:"id"`
	SubjectIDs []string `json:"subject_ids"`
	Digest     string   `json:"digest"`
}

// SampleRevision is one immutable auditor-selected sample revision.
type SampleRevision struct {
	ID                 string    `json:"id"`
	TenantID           string    `json:"tenant_id"`
	EngagementID       string    `json:"engagement_id"`
	EvidenceRequestID  string    `json:"evidence_request_id"`
	Revision           uint64    `json:"revision"`
	PredecessorID      string    `json:"predecessor_id,omitempty"`
	PopulationID       string    `json:"population_id"`
	PopulationDigest   string    `json:"population_digest"`
	Algorithm          string    `json:"algorithm"`
	Seed               string    `json:"seed"`
	RequestedSize      uint32    `json:"requested_size"`
	SelectedSubjectIDs []string  `json:"selected_subject_ids"`
	SelectionDigest    string    `json:"selection_digest"`
	CreatedBy          string    `json:"created_by"`
	CreatedAt          time.Time `json:"created_at"`
	RevisionHash       string    `json:"revision_hash"`
}

// SampleRefinementRequest creates a new immutable sample without modifying its population.
type SampleRefinementRequest struct {
	TenantID          string
	EngagementID      string
	EvidenceRequestID string
	Population        PopulationSnapshot
	Seed              string
	Size              uint32
	Predecessor       *SampleRevision
	CreatedBy         string
	CreatedAt         time.Time
}

// NormalizePopulation canonicalizes one population and verifies a supplied digest.
func NormalizePopulation(population PopulationSnapshot) (PopulationSnapshot, error) {
	id, err := required(population.ID, "population id")
	if err != nil {
		return PopulationSnapshot{}, err
	}
	subjects := normalizedStrings(population.SubjectIDs)
	if len(subjects) == 0 {
		return PopulationSnapshot{}, fmt.Errorf("%w: population subjects are required", ErrInvalidRequest)
	}
	digest, err := canonicalDigest(struct {
		ID         string   `json:"id"`
		SubjectIDs []string `json:"subject_ids"`
	}{ID: id, SubjectIDs: subjects})
	if err != nil {
		return PopulationSnapshot{}, fmt.Errorf("hash population: %w", err)
	}
	if supplied := strings.TrimSpace(population.Digest); supplied != "" && supplied != digest {
		return PopulationSnapshot{}, fmt.Errorf("%w: population digest does not match subjects", ErrInvalidRequest)
	}
	return PopulationSnapshot{ID: id, SubjectIDs: subjects, Digest: digest}, nil
}

// RefineSample selects a reproducible sample by ranking each normalized subject
// with SHA-256 over algorithm, seed, and subject identity.
func RefineSample(request SampleRefinementRequest) (SampleRevision, error) {
	tenantID, err := required(request.TenantID, "tenant id")
	if err != nil {
		return SampleRevision{}, err
	}
	engagementID, err := required(request.EngagementID, "engagement id")
	if err != nil {
		return SampleRevision{}, err
	}
	evidenceRequestID, err := required(request.EvidenceRequestID, "evidence request id")
	if err != nil {
		return SampleRevision{}, err
	}
	seed, err := required(request.Seed, "sample seed")
	if err != nil {
		return SampleRevision{}, err
	}
	actor, err := required(request.CreatedBy, "created by")
	if err != nil {
		return SampleRevision{}, err
	}
	createdAt := request.CreatedAt.UTC()
	if createdAt.IsZero() {
		return SampleRevision{}, fmt.Errorf("%w: created at is required", ErrInvalidRequest)
	}
	population, err := NormalizePopulation(request.Population)
	if err != nil {
		return SampleRevision{}, err
	}
	if request.Size == 0 || uint64(request.Size) > uint64(len(population.SubjectIDs)) {
		return SampleRevision{}, fmt.Errorf("%w: sample size must be between 1 and population size", ErrInvalidRequest)
	}
	revisionNumber := uint64(1)
	predecessorID := ""
	if request.Predecessor != nil {
		previous := request.Predecessor
		if strings.TrimSpace(previous.ID) == "" || previous.Revision == 0 {
			return SampleRevision{}, fmt.Errorf("%w: sample predecessor identity is invalid", ErrInvalidRequest)
		}
		if previous.TenantID != tenantID || previous.EngagementID != engagementID || previous.EvidenceRequestID != evidenceRequestID || previous.PopulationID != population.ID || previous.PopulationDigest != population.Digest {
			return SampleRevision{}, fmt.Errorf("%w: sample predecessor scope does not match", ErrInvalidRequest)
		}
		revisionNumber = previous.Revision + 1
		predecessorID = previous.ID
	}
	selected := hashRankedSubjects(population.SubjectIDs, seed, int(request.Size))
	selectionDigest, err := canonicalDigest(struct {
		PopulationDigest string   `json:"population_digest"`
		Algorithm        string   `json:"algorithm"`
		Seed             string   `json:"seed"`
		Subjects         []string `json:"subjects"`
	}{PopulationDigest: population.Digest, Algorithm: SampleAlgorithmHashRankedV1, Seed: seed, Subjects: selected})
	if err != nil {
		return SampleRevision{}, fmt.Errorf("hash sample selection: %w", err)
	}
	revision := SampleRevision{
		TenantID:           tenantID,
		EngagementID:       engagementID,
		EvidenceRequestID:  evidenceRequestID,
		Revision:           revisionNumber,
		PredecessorID:      predecessorID,
		PopulationID:       population.ID,
		PopulationDigest:   population.Digest,
		Algorithm:          SampleAlgorithmHashRankedV1,
		Seed:               seed,
		RequestedSize:      request.Size,
		SelectedSubjectIDs: selected,
		SelectionDigest:    selectionDigest,
		CreatedBy:          actor,
		CreatedAt:          createdAt,
	}
	revisionHash, err := canonicalDigest(revision)
	if err != nil {
		return SampleRevision{}, fmt.Errorf("hash sample revision: %w", err)
	}
	revision.RevisionHash = revisionHash
	revision.ID = digestID("audit-sample-revision-", revisionHash)
	return revision, nil
}

type rankedSubject struct {
	id   string
	rank string
}

func hashRankedSubjects(subjectIDs []string, seed string, size int) []string {
	ranked := make([]rankedSubject, 0, len(subjectIDs))
	for _, subjectID := range subjectIDs {
		sum := sha256.Sum256([]byte(strings.Join([]string{SampleAlgorithmHashRankedV1, seed, subjectID}, "\x00")))
		ranked = append(ranked, rankedSubject{id: subjectID, rank: hex.EncodeToString(sum[:])})
	}
	sort.Slice(ranked, func(i, j int) bool {
		if ranked[i].rank != ranked[j].rank {
			return ranked[i].rank < ranked[j].rank
		}
		return ranked[i].id < ranked[j].id
	})
	selected := make([]string, 0, size)
	for _, item := range ranked[:size] {
		selected = append(selected, item.id)
	}
	return selected
}
