package complianceassessment

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

var ErrInvalidException = errors.New("invalid compliance exception")

// ExceptionState is the explicit lifecycle of a temporary deviation.
type ExceptionState string

const (
	ExceptionProposed ExceptionState = "proposed"
	ExceptionApproved ExceptionState = "approved"
	ExceptionRejected ExceptionState = "rejected"
	ExceptionExpired  ExceptionState = "expired"
	ExceptionRevoked  ExceptionState = "revoked"
	ExceptionClosed   ExceptionState = "closed"
)

// Exception is a temporary disposition linked to a risk, never a test outcome.
type Exception struct {
	ID                      string         `json:"id"`
	TenantID                string         `json:"tenant_id"`
	ProgramID               string         `json:"program_id"`
	ScopeRevisionID         string         `json:"scope_revision_id"`
	ObjectiveID             string         `json:"objective_id"`
	SubjectID               string         `json:"subject_id"`
	RiskID                  string         `json:"risk_id,omitempty"`
	State                   ExceptionState `json:"state"`
	OwnerID                 string         `json:"owner_id,omitempty"`
	Rationale               string         `json:"rationale,omitempty"`
	CompensatingControls    []string       `json:"compensating_controls,omitempty"`
	Approval                *Approval      `json:"approval,omitempty"`
	ExpiresAt               time.Time      `json:"expires_at,omitempty"`
	VerificationRequired    bool           `json:"verification_required"`
	VerificationEvidenceIDs []string       `json:"verification_evidence_ids,omitempty"`
	VerifiedBy              string         `json:"verified_by,omitempty"`
	Version                 uint64         `json:"version"`
	UpdatedAt               time.Time      `json:"updated_at"`
}

// ExceptionInput creates a proposed exception.
type ExceptionInput struct {
	ID                   string
	TenantID             string
	ProgramID            string
	ScopeRevisionID      string
	ObjectiveID          string
	SubjectID            string
	RiskID               string
	OwnerID              string
	VerificationRequired bool
	CreatedAt            time.Time
}

// ExceptionTransitionInput supplies one explicit exception decision.
type ExceptionTransitionInput struct {
	To                      ExceptionState
	RiskID                  string
	OwnerID                 string
	Rationale               string
	CompensatingControls    []string
	Approval                *Approval
	ExpiresAt               time.Time
	VerificationEvidenceIDs []string
	VerifiedBy              string
	At                      time.Time
}

// NewException creates a proposed deviation record.
func NewException(input ExceptionInput) (Exception, error) {
	for name, value := range map[string]string{
		"exception id": input.ID, "tenant id": input.TenantID, "program id": input.ProgramID,
		"scope revision id": input.ScopeRevisionID, "objective id": input.ObjectiveID, "subject id": input.SubjectID,
	} {
		if strings.TrimSpace(value) == "" {
			return Exception{}, fmt.Errorf("%w: %s is required", ErrInvalidException, name)
		}
	}
	createdAt := CanonicalTime(input.CreatedAt)
	if createdAt.IsZero() {
		return Exception{}, fmt.Errorf("%w: created_at is required", ErrInvalidException)
	}
	return Exception{
		ID:                   strings.TrimSpace(input.ID),
		TenantID:             strings.TrimSpace(input.TenantID),
		ProgramID:            strings.TrimSpace(input.ProgramID),
		ScopeRevisionID:      strings.TrimSpace(input.ScopeRevisionID),
		ObjectiveID:          strings.TrimSpace(input.ObjectiveID),
		SubjectID:            strings.TrimSpace(input.SubjectID),
		RiskID:               strings.TrimSpace(input.RiskID),
		State:                ExceptionProposed,
		OwnerID:              strings.TrimSpace(input.OwnerID),
		VerificationRequired: input.VerificationRequired,
		Version:              1,
		UpdatedAt:            createdAt,
	}, nil
}

// TransitionException applies an explicit exception transition with optimistic concurrency.
func TransitionException(current Exception, expectedVersion uint64, input ExceptionTransitionInput) (Exception, error) {
	if current.Version != expectedVersion {
		return Exception{}, versionConflict(expectedVersion, current.Version)
	}
	if !exceptionTransitionAllowed(current.State, input.To) {
		return Exception{}, fmt.Errorf("%w: exception transition %q to %q", ErrInvalidTransition, current.State, input.To)
	}
	at := CanonicalTime(input.At)
	if at.IsZero() {
		return Exception{}, fmt.Errorf("%w: transition time is required", ErrInvalidException)
	}
	next := cloneException(current)
	next.State = input.To
	if value := strings.TrimSpace(input.RiskID); value != "" {
		next.RiskID = value
	}
	if value := strings.TrimSpace(input.OwnerID); value != "" {
		next.OwnerID = value
	}
	if value := strings.TrimSpace(input.Rationale); value != "" {
		next.Rationale = value
	}
	if input.CompensatingControls != nil {
		next.CompensatingControls = normalizedStrings(input.CompensatingControls)
	}
	if input.Approval != nil {
		approval := normalizeApproval(*input.Approval)
		next.Approval = &approval
	}
	if !input.ExpiresAt.IsZero() {
		next.ExpiresAt = CanonicalTime(input.ExpiresAt)
	}
	if input.VerificationEvidenceIDs != nil {
		next.VerificationEvidenceIDs = normalizedStrings(input.VerificationEvidenceIDs)
	}
	if value := strings.TrimSpace(input.VerifiedBy); value != "" {
		next.VerifiedBy = value
	}
	if next.State == ExceptionApproved {
		if err := validateApprovedException(next, at); err != nil {
			return Exception{}, err
		}
	}
	if next.State == ExceptionClosed {
		if err := validateExceptionClosure(next); err != nil {
			return Exception{}, err
		}
	}
	next.Version++
	next.UpdatedAt = at
	return next, nil
}

// ExpireException records an approved exception crossing its expiry boundary.
func ExpireException(current Exception, expectedVersion uint64, at time.Time) (Exception, error) {
	if current.Version != expectedVersion {
		return Exception{}, versionConflict(expectedVersion, current.Version)
	}
	at = CanonicalTime(at)
	if current.State != ExceptionApproved || current.ExpiresAt.IsZero() || at.Before(current.ExpiresAt) {
		return Exception{}, fmt.Errorf("%w: approved exception has not expired", ErrInvalidTransition)
	}
	next := cloneException(current)
	next.State = ExceptionExpired
	next.Version++
	next.UpdatedAt = at
	return next, nil
}

func validateApprovedException(value Exception, at time.Time) error {
	if strings.TrimSpace(value.RiskID) == "" || strings.TrimSpace(value.OwnerID) == "" || strings.TrimSpace(value.Rationale) == "" || len(value.CompensatingControls) == 0 {
		return fmt.Errorf("%w: approved exception requires linked risk, owner, rationale, and compensating controls", ErrInvalidException)
	}
	if err := validateApproval(value.Approval); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidException, err)
	}
	if value.Approval.ApprovedAt.After(at) {
		return fmt.Errorf("%w: approval cannot postdate exception approval", ErrInvalidException)
	}
	if value.ExpiresAt.IsZero() || !value.ExpiresAt.After(at) {
		return fmt.Errorf("%w: approved exception requires a future expiry", ErrInvalidException)
	}
	return nil
}

func validateExceptionClosure(value Exception) error {
	if !value.VerificationRequired {
		return nil
	}
	if len(value.VerificationEvidenceIDs) == 0 || strings.TrimSpace(value.VerifiedBy) == "" {
		return fmt.Errorf("%w: closure requires verification evidence and verifier", ErrInvalidException)
	}
	if value.VerifiedBy == value.OwnerID || (value.Approval != nil && value.VerifiedBy == value.Approval.ApprovedBy) {
		return ErrIndependentReview
	}
	return nil
}

func cloneException(value Exception) Exception {
	value.CompensatingControls = append([]string(nil), value.CompensatingControls...)
	value.VerificationEvidenceIDs = append([]string(nil), value.VerificationEvidenceIDs...)
	if value.Approval != nil {
		approval := *value.Approval
		value.Approval = &approval
	}
	return value
}

func exceptionTransitionAllowed(from, to ExceptionState) bool {
	if from == to {
		return validExceptionState(to)
	}
	switch from {
	case ExceptionProposed:
		return to == ExceptionApproved || to == ExceptionRejected
	case ExceptionApproved:
		return to == ExceptionRevoked || to == ExceptionClosed
	case ExceptionExpired:
		return to == ExceptionProposed || to == ExceptionClosed
	case ExceptionRevoked:
		return to == ExceptionClosed
	default:
		return false
	}
}

func validExceptionState(value ExceptionState) bool {
	switch value {
	case ExceptionProposed, ExceptionApproved, ExceptionRejected, ExceptionExpired, ExceptionRevoked, ExceptionClosed:
		return true
	default:
		return false
	}
}
