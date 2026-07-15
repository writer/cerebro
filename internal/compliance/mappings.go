package compliance

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

var ErrInvalidMapping = errors.New("invalid compliance mapping")

type MappingRelationship string

const (
	MappingEquivalent MappingRelationship = "equivalent"
	MappingSubset     MappingRelationship = "subset"
	MappingSuperset   MappingRelationship = "superset"
	MappingOverlap    MappingRelationship = "overlap"
	MappingNone       MappingRelationship = "none"
)

type MappingDecisionState string

const (
	MappingProposed MappingDecisionState = "proposed"
	MappingApproved MappingDecisionState = "approved"
	MappingRejected MappingDecisionState = "rejected"
	MappingRetired  MappingDecisionState = "retired"
)

// ControlMapping records an explicit, reviewable relationship between exact
// source and target revisions. It never grants coverage by implication.
type ControlMapping struct {
	ID                  string               `json:"id"`
	RevisionID          string               `json:"revision_id"`
	Source              RevisionRef          `json:"source"`
	Target              RevisionRef          `json:"target"`
	Granularity         string               `json:"granularity"`
	Relationship        MappingRelationship  `json:"relationship"`
	Method              string               `json:"method"`
	Rationale           string               `json:"rationale"`
	CoverageBasisPoints uint16               `json:"coverage_basis_points"`
	Gaps                []string             `json:"gaps,omitempty"`
	Provenance          []SubjectRef         `json:"provenance,omitempty"`
	DecisionState       MappingDecisionState `json:"decision_state"`
	AuthorID            string               `json:"author_id"`
	ReviewerID          string               `json:"reviewer_id,omitempty"`
}

func (mapping ControlMapping) Validate() error {
	if strings.TrimSpace(mapping.ID) == "" || strings.TrimSpace(mapping.RevisionID) == "" {
		return fmt.Errorf("%w: id and revision_id are required", ErrInvalidMapping)
	}
	if err := mapping.Source.Validate(); err != nil {
		return fmt.Errorf("%w: source: %w", ErrInvalidMapping, err)
	}
	if err := mapping.Target.Validate(); err != nil {
		return fmt.Errorf("%w: target: %w", ErrInvalidMapping, err)
	}
	if mapping.Source.ID == mapping.Target.ID && mapping.Source.RevisionID == mapping.Target.RevisionID {
		return fmt.Errorf("%w: source and target must differ", ErrInvalidMapping)
	}
	switch mapping.Relationship {
	case MappingEquivalent, MappingSubset, MappingSuperset, MappingOverlap, MappingNone:
	default:
		return fmt.Errorf("%w: relationship %q", ErrInvalidMapping, mapping.Relationship)
	}
	switch mapping.DecisionState {
	case MappingProposed, MappingApproved, MappingRejected, MappingRetired:
	default:
		return fmt.Errorf("%w: decision_state %q", ErrInvalidMapping, mapping.DecisionState)
	}
	if mapping.CoverageBasisPoints > 10000 {
		return fmt.Errorf("%w: coverage_basis_points exceeds 10000", ErrInvalidMapping)
	}
	if mapping.Relationship == MappingNone && mapping.CoverageBasisPoints != 0 {
		return fmt.Errorf("%w: none relationship must have zero coverage", ErrInvalidMapping)
	}
	if mapping.Relationship == MappingEquivalent && mapping.CoverageBasisPoints != 10000 {
		return fmt.Errorf("%w: equivalent relationship must have full coverage", ErrInvalidMapping)
	}
	if strings.TrimSpace(mapping.Granularity) == "" || strings.TrimSpace(mapping.Method) == "" || strings.TrimSpace(mapping.Rationale) == "" || strings.TrimSpace(mapping.AuthorID) == "" {
		return fmt.Errorf("%w: granularity, method, rationale, and author_id are required", ErrInvalidMapping)
	}
	if mapping.DecisionState != MappingProposed && strings.TrimSpace(mapping.ReviewerID) == "" {
		return fmt.Errorf("%w: reviewer_id is required for decided mappings", ErrInvalidMapping)
	}
	for index, reference := range mapping.Provenance {
		if err := reference.Validate(); err != nil {
			return fmt.Errorf("%w: provenance[%d]: %w", ErrInvalidMapping, index, err)
		}
	}
	return nil
}

func NormalizeControlMapping(mapping ControlMapping) ControlMapping {
	mapping.ID = strings.TrimSpace(mapping.ID)
	mapping.RevisionID = strings.TrimSpace(mapping.RevisionID)
	mapping.Granularity = strings.TrimSpace(mapping.Granularity)
	mapping.Method = strings.TrimSpace(mapping.Method)
	mapping.Rationale = strings.TrimSpace(mapping.Rationale)
	mapping.AuthorID = strings.TrimSpace(mapping.AuthorID)
	mapping.ReviewerID = strings.TrimSpace(mapping.ReviewerID)
	mapping.Source = NormalizeRevisionRef(mapping.Source)
	mapping.Target = NormalizeRevisionRef(mapping.Target)
	mapping.Gaps = normalizedSortedStrings(mapping.Gaps)
	mapping.Provenance = append([]SubjectRef(nil), mapping.Provenance...)
	for index := range mapping.Provenance {
		mapping.Provenance[index].Type = strings.TrimSpace(mapping.Provenance[index].Type)
		mapping.Provenance[index].ID = strings.TrimSpace(mapping.Provenance[index].ID)
	}
	sort.Slice(mapping.Provenance, func(i, j int) bool {
		return mapping.Provenance[i].Type+"\x00"+mapping.Provenance[i].ID < mapping.Provenance[j].Type+"\x00"+mapping.Provenance[j].ID
	})
	mapping.Provenance = deduplicateSubjectRefs(mapping.Provenance)
	return mapping
}

func deduplicateSubjectRefs(values []SubjectRef) []SubjectRef {
	result := make([]SubjectRef, 0, len(values))
	for _, value := range values {
		if len(result) != 0 && result[len(result)-1] == value {
			continue
		}
		result = append(result, value)
	}
	return result
}

func normalizedSortedStrings(values []string) []string {
	seen := map[string]struct{}{}
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		normalized = append(normalized, value)
	}
	sort.Strings(normalized)
	return normalized
}
