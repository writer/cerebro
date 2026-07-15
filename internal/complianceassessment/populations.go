package complianceassessment

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"strings"
	"time"
)

var (
	ErrInvalidPopulation = errors.New("invalid assessment population")
	ErrInvalidSample     = errors.New("invalid assessment sample")
)

const DeterministicSampleAlgorithm = "compliance-sample/v1"

type PopulationSubject struct {
	ID   string `json:"id"`
	Type string `json:"type,omitempty"`
}

type PopulationSnapshot struct {
	ID               string    `json:"id"`
	RunID            string    `json:"run_id"`
	ObjectiveID      string    `json:"objective_id"`
	QueryDigest      string    `json:"query_digest"`
	SourceWatermark  time.Time `json:"source_watermark"`
	ExpectedCount    uint64    `json:"expected_count"`
	ObservedCount    uint64    `json:"observed_count"`
	Complete         bool      `json:"complete"`
	ExclusionReasons []string  `json:"exclusion_reasons,omitempty"`
	ContentDigest    string    `json:"content_digest"`
}

type SampleSelection struct {
	ID               string              `json:"id"`
	PopulationID     string              `json:"population_id"`
	Algorithm        string              `json:"algorithm"`
	Seed             string              `json:"seed"`
	RequestedSize    uint32              `json:"requested_size"`
	PopulationDigest string              `json:"population_digest"`
	Subjects         []PopulationSubject `json:"subjects"`
	SelectionDigest  string              `json:"selection_digest"`
}

// NormalizePopulation deduplicates stable subject identities and sorts them by
// type and ID. Display names and collection order never affect population or
// sample identity.
func NormalizePopulation(subjects []PopulationSubject) ([]PopulationSubject, error) {
	seen := map[string]struct{}{}
	normalized := make([]PopulationSubject, 0, len(subjects))
	for _, subject := range subjects {
		subject.ID = strings.TrimSpace(subject.ID)
		subject.Type = strings.TrimSpace(subject.Type)
		if subject.ID == "" {
			return nil, ErrInvalidPopulation
		}
		key := subject.Type + "\x00" + subject.ID
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		normalized = append(normalized, subject)
	}
	sort.Slice(normalized, func(i, j int) bool {
		return normalized[i].Type+"\x00"+normalized[i].ID < normalized[j].Type+"\x00"+normalized[j].ID
	})
	return normalized, nil
}

func PopulationDigest(subjects []PopulationSubject) (string, error) {
	normalized, err := NormalizePopulation(subjects)
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte("compliance-population/v1"))
	for _, subject := range normalized {
		_, _ = hash.Write([]byte{0})
		_, _ = hash.Write([]byte(subject.Type))
		_, _ = hash.Write([]byte{0})
		_, _ = hash.Write([]byte(subject.ID))
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

// SelectDeterministicSample uses a versioned hash rank rather than math/rand,
// making selections stable across process retries and Go releases.
func SelectDeterministicSample(populationID, seed string, requested uint32, subjects []PopulationSubject) (SampleSelection, error) {
	populationID = strings.TrimSpace(populationID)
	seed = strings.TrimSpace(seed)
	if populationID == "" || seed == "" || requested == 0 {
		return SampleSelection{}, ErrInvalidSample
	}
	normalized, err := NormalizePopulation(subjects)
	if err != nil {
		return SampleSelection{}, err
	}
	if uint64(requested) > uint64(len(normalized)) {
		return SampleSelection{}, ErrInvalidSample
	}
	populationDigest, err := PopulationDigest(normalized)
	if err != nil {
		return SampleSelection{}, err
	}
	type rankedSubject struct {
		subject PopulationSubject
		rank    [sha256.Size]byte
	}
	ranked := make([]rankedSubject, 0, len(normalized))
	for _, subject := range normalized {
		ranked = append(ranked, rankedSubject{subject: subject, rank: sha256.Sum256([]byte(
			DeterministicSampleAlgorithm + "\x00" + seed + "\x00" + subject.Type + "\x00" + subject.ID,
		))})
	}
	sort.Slice(ranked, func(i, j int) bool {
		left := hex.EncodeToString(ranked[i].rank[:]) + "\x00" + ranked[i].subject.Type + "\x00" + ranked[i].subject.ID
		right := hex.EncodeToString(ranked[j].rank[:]) + "\x00" + ranked[j].subject.Type + "\x00" + ranked[j].subject.ID
		return left < right
	})
	selected := make([]PopulationSubject, 0, requested)
	for _, item := range ranked[:requested] {
		selected = append(selected, item.subject)
	}
	selectionDigest, err := PopulationDigest(selected)
	if err != nil {
		return SampleSelection{}, err
	}
	return SampleSelection{
		PopulationID: populationID, Algorithm: DeterministicSampleAlgorithm, Seed: seed,
		RequestedSize: requested, PopulationDigest: populationDigest,
		Subjects: selected, SelectionDigest: selectionDigest,
	}, nil
}
