package grcaudit

import (
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestRefineSampleIsDeterministicAcrossPopulationOrder(t *testing.T) {
	createdAt := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	base := SampleRefinementRequest{
		TenantID:          "tenant-a",
		EngagementID:      "engagement-a",
		EvidenceRequestID: "request-a",
		Population:        PopulationSnapshot{ID: "population-a", SubjectIDs: []string{"subject-c", "subject-a", "subject-b", "subject-d", "subject-a"}},
		Seed:              "auditor-seed-a",
		Size:              3,
		CreatedBy:         "auditor-a",
		CreatedAt:         createdAt,
	}
	first, err := RefineSample(base)
	if err != nil {
		t.Fatalf("RefineSample(first) error = %v", err)
	}
	base.Population.SubjectIDs = []string{"subject-d", "subject-b", "subject-c", "subject-a"}
	second, err := RefineSample(base)
	if err != nil {
		t.Fatalf("RefineSample(second) error = %v", err)
	}
	if first.ID != second.ID || first.RevisionHash != second.RevisionHash || first.SelectionDigest != second.SelectionDigest || !reflect.DeepEqual(first.SelectedSubjectIDs, second.SelectedSubjectIDs) {
		t.Fatalf("deterministic samples differ:\nfirst=%+v\nsecond=%+v", first, second)
	}
	if len(first.SelectedSubjectIDs) != 3 {
		t.Fatalf("selected subjects = %#v, want three", first.SelectedSubjectIDs)
	}
	if len(first.PopulationDigest) == 0 || first.Algorithm != SampleAlgorithmHashRankedV1 {
		t.Fatalf("sample contract = %+v", first)
	}
}

func TestRefineSampleRejectsInvalidPredecessorIdentity(t *testing.T) {
	request := SampleRefinementRequest{
		TenantID:          "tenant-a",
		EngagementID:      "engagement-a",
		EvidenceRequestID: "request-a",
		Population:        PopulationSnapshot{ID: "population-a", SubjectIDs: []string{"subject-a"}},
		Seed:              "seed-a",
		Size:              1,
		Predecessor:       &SampleRevision{TenantID: "tenant-a", EngagementID: "engagement-a", EvidenceRequestID: "request-a", PopulationID: "population-a"},
		CreatedBy:         "auditor-a",
		CreatedAt:         time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC),
	}
	if _, err := RefineSample(request); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("RefineSample() error = %v, want ErrInvalidRequest", err)
	}
}

func TestRefineSampleCreatesPredecessorLinkedRevision(t *testing.T) {
	createdAt := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	request := SampleRefinementRequest{
		TenantID:          "tenant-a",
		EngagementID:      "engagement-a",
		EvidenceRequestID: "request-a",
		Population:        PopulationSnapshot{ID: "population-a", SubjectIDs: []string{"subject-a", "subject-b", "subject-c"}},
		Seed:              "seed-a",
		Size:              2,
		CreatedBy:         "auditor-a",
		CreatedAt:         createdAt,
	}
	first, err := RefineSample(request)
	if err != nil {
		t.Fatalf("RefineSample(first) error = %v", err)
	}
	request.Predecessor = &first
	request.Seed = "seed-b"
	request.CreatedAt = createdAt.Add(time.Hour)
	second, err := RefineSample(request)
	if err != nil {
		t.Fatalf("RefineSample(second) error = %v", err)
	}
	if second.Revision != 2 || second.PredecessorID != first.ID || second.SelectionDigest == first.SelectionDigest {
		t.Fatalf("sample revision lineage = first %+v second %+v", first, second)
	}
}
