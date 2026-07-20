package complianceassessment

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/compliance"
	"github.com/writer/cerebro/internal/sourcecoverage"
)

var (
	ErrSourceTrustProjectionConflict = errors.New("source trust projection conflict")
	ErrSourceCheckNotFound           = errors.New("source check snapshot not found")
	ErrObjectiveSourceNotFound       = errors.New("objective source assessment not found")
)

const (
	AggregateTypeSourceCheckSnapshot       = "assessment_source_check"
	AggregateTypeObjectiveSourceAssessment = "assessment_objective_source_assessment"
)

type SourceCheckRecordedPayload struct {
	RunID                 string                   `json:"run_id"`
	ObjectiveID           string                   `json:"objective_id"`
	Snapshot              SourceCheckSnapshot      `json:"snapshot"`
	CertificationRevision *compliance.RevisionRef  `json:"certification_revision,omitempty"`
	ProofRevisions        []compliance.RevisionRef `json:"proof_revisions,omitempty"`
	ContentDigest         string                   `json:"content_digest"`
}

type ObjectiveSourceAssessmentRecord struct {
	ID                     string                     `json:"id"`
	TenantID               string                     `json:"tenant_id"`
	RunID                  string                     `json:"run_id"`
	ObjectiveID            string                     `json:"objective_id"`
	Requirement            ObjectiveSourceRequirement `json:"requirement"`
	RequirementRevision    compliance.RevisionRef     `json:"requirement_revision"`
	ExpectedSourceCheckIDs []string                   `json:"expected_source_check_ids"`
	ExpectedCheckCount     uint64                     `json:"expected_check_count"`
	ObservedCheckCount     uint64                     `json:"observed_check_count"`
	Complete               bool                       `json:"complete"`
	Assessment             ObjectiveSourceAssessment  `json:"assessment"`
	AssessedAt             time.Time                  `json:"assessed_at"`
	ContentDigest          string                     `json:"content_digest"`
}

type SourceTrustStateStore interface {
	GetSourceCheckSnapshot(context.Context, string, string, string, string) (*SourceCheckRecordedPayload, error)
	GetObjectiveSourceAssessment(context.Context, string, string, string) (*ObjectiveSourceAssessmentRecord, error)
}

// CanonicalObjectiveSourceRequirement normalizes the semantic requirement that
// is bound to an immutable objective source assessment.
func CanonicalObjectiveSourceRequirement(value ObjectiveSourceRequirement) (ObjectiveSourceRequirement, error) {
	value.ObjectiveID = strings.TrimSpace(value.ObjectiveID)
	if value.ObjectiveID == "" {
		return ObjectiveSourceRequirement{}, fmt.Errorf("%w: objective id is required", ErrInvalidSourceCheck)
	}
	sources := make([]SourceCheckRequirement, len(value.Sources))
	seen := make(map[string]struct{}, len(sources))
	for index, original := range value.Sources {
		original.RequiredFields = append([]string(nil), original.RequiredFields...)
		source := normalizeSourceRequirement(original)
		if len(source.RequiredFields) == 0 {
			source.RequiredFields = nil
		}
		if source.SourceID == "" || source.DimensionID == "" {
			return ObjectiveSourceRequirement{}, fmt.Errorf("%w: sources[%d] is incomplete", ErrInvalidSourceCheck, index)
		}
		certification, ok := sourcecoverage.ParseCertificationTier(string(source.MinimumCertification))
		if !ok {
			return ObjectiveSourceRequirement{}, fmt.Errorf("%w: sources[%d] has unknown certification minimum", ErrInvalidSourceCheck, index)
		}
		source.MinimumCertification = certification
		key := source.SourceID + "\x00" + source.DimensionID
		if _, duplicate := seen[key]; duplicate {
			return ObjectiveSourceRequirement{}, fmt.Errorf("%w: duplicate source dimension requirement", ErrInvalidSourceCheck)
		}
		seen[key] = struct{}{}
		sources[index] = source
	}
	sort.Slice(sources, func(i, j int) bool {
		left := sources[i].SourceID + "\x00" + sources[i].DimensionID
		right := sources[j].SourceID + "\x00" + sources[j].DimensionID
		return left < right
	})
	if len(sources) == 0 {
		sources = nil
	}
	value.Sources = sources
	return value, nil
}
