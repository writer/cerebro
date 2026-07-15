package complianceassessment

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/compliance"
)

var (
	ErrInvalidReview     = errors.New("invalid compliance review")
	ErrVersionConflict   = errors.New("compliance version conflict")
	ErrInvalidTransition = errors.New("invalid compliance transition")
	ErrIndependentReview = errors.New("independent verification required")
)

// ReviewDecision is the human decision recorded above an immutable automated result.
type ReviewDecision string

const (
	ReviewAccept         ReviewDecision = "accept"
	ReviewRequestChanges ReviewDecision = "request_changes"
	ReviewReject         ReviewDecision = "reject"
	ReviewOverride       ReviewDecision = "override"
)

// Review is the mutable pointer to immutable review revisions for one result hash.
type Review struct {
	ID                  string `json:"id"`
	TenantID            string `json:"tenant_id"`
	AssessmentRunID     string `json:"assessment_run_id"`
	ObjectiveResultID   string `json:"objective_result_id"`
	AutomatedResultHash string `json:"automated_result_hash"`
	Version             uint64 `json:"version"`
	CurrentRevision     uint64 `json:"current_revision"`
	CurrentRevisionID   string `json:"current_revision_id"`
}

// ReviewRevision is an immutable human decision over one unchanged automated hash.
type ReviewRevision struct {
	ID                   string           `json:"id"`
	TenantID             string           `json:"tenant_id"`
	ReviewID             string           `json:"review_id"`
	AssessmentRunID      string           `json:"assessment_run_id"`
	ObjectiveResultID    string           `json:"objective_result_id"`
	Revision             uint64           `json:"revision"`
	PredecessorID        string           `json:"predecessor_id,omitempty"`
	AutomatedResultHash  string           `json:"automated_result_hash"`
	Decision             ReviewDecision   `json:"decision"`
	EffectiveDisposition DispositionState `json:"effective_disposition"`
	EffectiveAuditor     AuditorState     `json:"effective_auditor_state"`
	Rationale            string           `json:"rationale"`
	ActorID              string           `json:"actor_id"`
	ActorRole            string           `json:"actor_role"`
	EvidenceIDs          []string         `json:"evidence_ids,omitempty"`
	RiskIDs              []string         `json:"risk_ids,omitempty"`
	ExceptionIDs         []string         `json:"exception_ids,omitempty"`
	CreatedAt            time.Time        `json:"created_at"`
	RevisionHash         string           `json:"revision_hash"`
}

// ReviewRevisionInput contains one reviewer decision and its supporting basis.
type ReviewRevisionInput struct {
	Decision             ReviewDecision
	EffectiveDisposition DispositionState
	EffectiveAuditor     AuditorState
	Rationale            string
	ActorID              string
	ActorRole            string
	EvidenceIDs          []string
	RiskIDs              []string
	ExceptionIDs         []string
	CreatedAt            time.Time
}

// NewReview creates a stable review and immutable first revision.
func NewReview(tenantID, assessmentRunID, resultID, automatedResultHash string, input ReviewRevisionInput) (Review, ReviewRevision, error) {
	tenantID, err := requiredReviewValue(tenantID, "tenant id")
	if err != nil {
		return Review{}, ReviewRevision{}, err
	}
	assessmentRunID, err = requiredReviewValue(assessmentRunID, "assessment run id")
	if err != nil {
		return Review{}, ReviewRevision{}, err
	}
	resultID, err = requiredReviewValue(resultID, "objective result id")
	if err != nil {
		return Review{}, ReviewRevision{}, err
	}
	automatedResultHash = strings.TrimSpace(automatedResultHash)
	if err := compliance.ValidateContentDigest(compliance.ContentDigest(automatedResultHash)); err != nil {
		return Review{}, ReviewRevision{}, fmt.Errorf("%w: automated result hash: %w", ErrInvalidReview, err)
	}
	reviewDigest := digestBytes([]byte(strings.Join([]string{tenantID, assessmentRunID, resultID, automatedResultHash}, "\x00")))
	review := Review{
		ID:                  stableDomainID("compliance-review-", reviewDigest),
		TenantID:            tenantID,
		AssessmentRunID:     assessmentRunID,
		ObjectiveResultID:   resultID,
		AutomatedResultHash: automatedResultHash,
		Version:             1,
		CurrentRevision:     1,
	}
	revision, err := buildReviewRevision(review, 1, "", input)
	if err != nil {
		return Review{}, ReviewRevision{}, err
	}
	review.CurrentRevisionID = revision.ID
	return review, revision, nil
}

// ReviseReview appends an immutable review revision with optimistic concurrency.
func ReviseReview(current Review, expectedVersion uint64, input ReviewRevisionInput) (Review, ReviewRevision, error) {
	if current.Version != expectedVersion {
		return Review{}, ReviewRevision{}, versionConflict(expectedVersion, current.Version)
	}
	if strings.TrimSpace(current.ID) == "" || current.CurrentRevision == 0 || strings.TrimSpace(current.CurrentRevisionID) == "" {
		return Review{}, ReviewRevision{}, fmt.Errorf("%w: current review is incomplete", ErrInvalidReview)
	}
	if err := compliance.ValidateContentDigest(compliance.ContentDigest(current.AutomatedResultHash)); err != nil {
		return Review{}, ReviewRevision{}, fmt.Errorf("%w: automated result hash: %w", ErrInvalidReview, err)
	}
	revision, err := buildReviewRevision(current, current.CurrentRevision+1, current.CurrentRevisionID, input)
	if err != nil {
		return Review{}, ReviewRevision{}, err
	}
	next := current
	next.Version++
	next.CurrentRevision++
	next.CurrentRevisionID = revision.ID
	return next, revision, nil
}

func buildReviewRevision(review Review, revisionNumber uint64, predecessorID string, input ReviewRevisionInput) (ReviewRevision, error) {
	actorID, err := requiredReviewValue(input.ActorID, "actor id")
	if err != nil {
		return ReviewRevision{}, err
	}
	actorRole, err := requiredReviewValue(input.ActorRole, "actor role")
	if err != nil {
		return ReviewRevision{}, err
	}
	rationale, err := requiredReviewValue(input.Rationale, "rationale")
	if err != nil {
		return ReviewRevision{}, err
	}
	createdAt := CanonicalTime(input.CreatedAt)
	if createdAt.IsZero() {
		return ReviewRevision{}, fmt.Errorf("%w: created_at is required", ErrInvalidReview)
	}
	if !validReviewDecision(input.Decision) || !knownDispositionState(input.EffectiveDisposition) || !knownAuditorState(input.EffectiveAuditor) {
		return ReviewRevision{}, fmt.Errorf("%w: decision or effective state is unknown", ErrInvalidReview)
	}
	if err := validateReviewDecision(input.Decision, input.EffectiveDisposition, input.EffectiveAuditor); err != nil {
		return ReviewRevision{}, err
	}
	revision := ReviewRevision{
		TenantID:             strings.TrimSpace(review.TenantID),
		ReviewID:             strings.TrimSpace(review.ID),
		AssessmentRunID:      strings.TrimSpace(review.AssessmentRunID),
		ObjectiveResultID:    strings.TrimSpace(review.ObjectiveResultID),
		Revision:             revisionNumber,
		PredecessorID:        strings.TrimSpace(predecessorID),
		AutomatedResultHash:  strings.TrimSpace(review.AutomatedResultHash),
		Decision:             input.Decision,
		EffectiveDisposition: input.EffectiveDisposition,
		EffectiveAuditor:     input.EffectiveAuditor,
		Rationale:            rationale,
		ActorID:              actorID,
		ActorRole:            actorRole,
		EvidenceIDs:          normalizedStrings(input.EvidenceIDs),
		RiskIDs:              normalizedStrings(input.RiskIDs),
		ExceptionIDs:         normalizedStrings(input.ExceptionIDs),
		CreatedAt:            createdAt,
	}
	hash, err := hashDomainValue(revision)
	if err != nil {
		return ReviewRevision{}, err
	}
	revision.RevisionHash = hash
	revision.ID = stableDomainID("compliance-review-revision-", hash)
	return revision, nil
}

func validateReviewDecision(decision ReviewDecision, disposition DispositionState, auditor AuditorState) error {
	switch decision {
	case ReviewAccept:
		if auditor != AuditorAccepted {
			return fmt.Errorf("%w: accept requires accepted auditor state", ErrInvalidReview)
		}
	case ReviewRequestChanges:
		if auditor != AuditorChangesRequested {
			return fmt.Errorf("%w: request_changes requires changes_requested auditor state", ErrInvalidReview)
		}
	case ReviewReject:
		if auditor != AuditorRejected {
			return fmt.Errorf("%w: reject requires rejected auditor state", ErrInvalidReview)
		}
	case ReviewOverride:
		if disposition != DispositionReviewOverride {
			return fmt.Errorf("%w: override requires review_override disposition", ErrInvalidReview)
		}
	}
	return nil
}

func validReviewDecision(value ReviewDecision) bool {
	switch value {
	case ReviewAccept, ReviewRequestChanges, ReviewReject, ReviewOverride:
		return true
	default:
		return false
	}
}

func requiredReviewValue(value, name string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("%w: %s is required", ErrInvalidReview, name)
	}
	return value, nil
}

func versionConflict(expected, current uint64) error {
	return fmt.Errorf("%w: expected %d, current %d", ErrVersionConflict, expected, current)
}

func hashDomainValue(value any) (string, error) {
	data, err := canonicalBytes(value)
	if err != nil {
		return "", err
	}
	return digestBytes(data), nil
}

func stableDomainID(prefix, digest string) string {
	return prefix + strings.TrimPrefix(digest, "sha256:")
}
