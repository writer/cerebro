package complianceassessment

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

var ErrInvalidRisk = errors.New("invalid compliance risk")

// RiskState is the explicit lifecycle state of a program risk.
type RiskState string

const (
	RiskOpen             RiskState = "open"
	RiskAssessing        RiskState = "assessing"
	RiskTreatmentPlanned RiskState = "treatment_planned"
	RiskAccepted         RiskState = "accepted"
	RiskRejected         RiskState = "rejected"
	RiskMitigated        RiskState = "mitigated"
	RiskClosed           RiskState = "closed"
	RiskExpired          RiskState = "expired"
)

// RiskTreatment identifies the approved response to a risk.
type RiskTreatment string

const (
	RiskTreatmentNone        RiskTreatment = "none"
	RiskTreatmentAvoid       RiskTreatment = "avoid"
	RiskTreatmentMitigate    RiskTreatment = "mitigate"
	RiskTreatmentTransfer    RiskTreatment = "transfer"
	RiskTreatmentAccept      RiskTreatment = "accept"
	RiskTreatmentShare       RiskTreatment = "share"
	RiskTreatmentContingency RiskTreatment = "contingency"
)

// Approval records the authorized approval supporting a disposition.
type Approval struct {
	ID         string    `json:"id"`
	ApprovedBy string    `json:"approved_by"`
	ApprovedAt time.Time `json:"approved_at"`
}

// Risk is the current projection of a stable program risk.
type Risk struct {
	ID                      string        `json:"id"`
	TenantID                string        `json:"tenant_id"`
	ProgramID               string        `json:"program_id"`
	ScopeRevisionID         string        `json:"scope_revision_id"`
	SubjectID               string        `json:"subject_id"`
	ObjectiveID             string        `json:"objective_id"`
	Title                   string        `json:"title"`
	BusinessContext         string        `json:"business_context"`
	Likelihood              string        `json:"likelihood"`
	Impact                  string        `json:"impact"`
	Severity                string        `json:"severity"`
	State                   RiskState     `json:"state"`
	Treatment               RiskTreatment `json:"treatment"`
	OwnerID                 string        `json:"owner_id,omitempty"`
	Rationale               string        `json:"rationale,omitempty"`
	CompensatingControls    []string      `json:"compensating_controls,omitempty"`
	Approval                *Approval     `json:"approval,omitempty"`
	ExpiresAt               time.Time     `json:"expires_at,omitempty"`
	VerificationRequired    bool          `json:"verification_required"`
	VerificationEvidenceIDs []string      `json:"verification_evidence_ids,omitempty"`
	VerifiedBy              string        `json:"verified_by,omitempty"`
	Version                 uint64        `json:"version"`
	UpdatedAt               time.Time     `json:"updated_at"`
}

// RiskInput creates one stable risk record.
type RiskInput struct {
	ID                   string
	TenantID             string
	ProgramID            string
	ScopeRevisionID      string
	SubjectID            string
	ObjectiveID          string
	Title                string
	BusinessContext      string
	Likelihood           string
	Impact               string
	Severity             string
	OwnerID              string
	VerificationRequired bool
	CreatedAt            time.Time
}

// RiskTransitionInput supplies the explicit basis for a lifecycle transition.
type RiskTransitionInput struct {
	To                      RiskState
	Treatment               RiskTreatment
	OwnerID                 string
	Rationale               string
	CompensatingControls    []string
	Approval                *Approval
	ExpiresAt               time.Time
	VerificationEvidenceIDs []string
	VerifiedBy              string
	At                      time.Time
}

// NewRisk creates a risk in the open state.
func NewRisk(input RiskInput) (Risk, error) {
	for name, value := range map[string]string{
		"risk id": input.ID, "tenant id": input.TenantID, "program id": input.ProgramID,
		"scope revision id": input.ScopeRevisionID, "subject id": input.SubjectID,
		"objective id": input.ObjectiveID, "title": input.Title, "business context": input.BusinessContext,
		"likelihood": input.Likelihood, "impact": input.Impact, "severity": input.Severity,
	} {
		if strings.TrimSpace(value) == "" {
			return Risk{}, fmt.Errorf("%w: %s is required", ErrInvalidRisk, name)
		}
	}
	createdAt := CanonicalTime(input.CreatedAt)
	if createdAt.IsZero() {
		return Risk{}, fmt.Errorf("%w: created_at is required", ErrInvalidRisk)
	}
	return Risk{
		ID:                   strings.TrimSpace(input.ID),
		TenantID:             strings.TrimSpace(input.TenantID),
		ProgramID:            strings.TrimSpace(input.ProgramID),
		ScopeRevisionID:      strings.TrimSpace(input.ScopeRevisionID),
		SubjectID:            strings.TrimSpace(input.SubjectID),
		ObjectiveID:          strings.TrimSpace(input.ObjectiveID),
		Title:                strings.TrimSpace(input.Title),
		BusinessContext:      strings.TrimSpace(input.BusinessContext),
		Likelihood:           strings.TrimSpace(input.Likelihood),
		Impact:               strings.TrimSpace(input.Impact),
		Severity:             strings.TrimSpace(input.Severity),
		State:                RiskOpen,
		Treatment:            RiskTreatmentNone,
		OwnerID:              strings.TrimSpace(input.OwnerID),
		VerificationRequired: input.VerificationRequired,
		Version:              1,
		UpdatedAt:            createdAt,
	}, nil
}

// TransitionRisk applies one explicit lifecycle transition using optimistic concurrency.
func TransitionRisk(current Risk, expectedVersion uint64, input RiskTransitionInput) (Risk, error) {
	if current.Version != expectedVersion {
		return Risk{}, versionConflict(expectedVersion, current.Version)
	}
	if !riskTransitionAllowed(current.State, input.To) {
		return Risk{}, fmt.Errorf("%w: risk transition %q to %q", ErrInvalidTransition, current.State, input.To)
	}
	at := CanonicalTime(input.At)
	if at.IsZero() {
		return Risk{}, fmt.Errorf("%w: transition time is required", ErrInvalidRisk)
	}
	next := cloneRisk(current)
	next.State = input.To
	if input.Treatment != "" {
		if !validRiskTreatment(input.Treatment) {
			return Risk{}, fmt.Errorf("%w: unknown treatment %q", ErrInvalidRisk, input.Treatment)
		}
		next.Treatment = input.Treatment
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
	if next.State == RiskAccepted {
		if err := validateRenewalApproval(current.Approval, input.Approval, current.UpdatedAt); err != nil {
			return Risk{}, fmt.Errorf("%w: %w", ErrInvalidRisk, err)
		}
		if err := validateAcceptedRisk(next, at); err != nil {
			return Risk{}, err
		}
	}
	if next.State == RiskClosed {
		if err := validateRiskClosure(next); err != nil {
			return Risk{}, err
		}
	}
	next.Version++
	next.UpdatedAt = at
	return next, nil
}

// ExpireAcceptedRisk records expiry without silently preserving acceptance.
func ExpireAcceptedRisk(current Risk, expectedVersion uint64, at time.Time) (Risk, error) {
	if current.Version != expectedVersion {
		return Risk{}, versionConflict(expectedVersion, current.Version)
	}
	at = CanonicalTime(at)
	if current.State != RiskAccepted || current.ExpiresAt.IsZero() || at.Before(current.ExpiresAt) {
		return Risk{}, fmt.Errorf("%w: accepted risk has not expired", ErrInvalidTransition)
	}
	next := cloneRisk(current)
	next.State = RiskExpired
	next.Version++
	next.UpdatedAt = at
	return next, nil
}

func validateAcceptedRisk(risk Risk, at time.Time) error {
	if risk.Treatment != RiskTreatmentAccept || strings.TrimSpace(risk.OwnerID) == "" || strings.TrimSpace(risk.Rationale) == "" || len(risk.CompensatingControls) == 0 {
		return fmt.Errorf("%w: accepted risk requires owner, rationale, compensating controls, and accept treatment", ErrInvalidRisk)
	}
	if err := validateApproval(risk.Approval); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidRisk, err)
	}
	if risk.Approval.ApprovedAt.After(at) {
		return fmt.Errorf("%w: approval cannot postdate acceptance", ErrInvalidRisk)
	}
	if risk.ExpiresAt.IsZero() || !risk.ExpiresAt.After(at) {
		return fmt.Errorf("%w: accepted risk requires a future expiry", ErrInvalidRisk)
	}
	return nil
}

func validateRiskClosure(risk Risk) error {
	if !risk.VerificationRequired {
		return nil
	}
	if len(risk.VerificationEvidenceIDs) == 0 || strings.TrimSpace(risk.VerifiedBy) == "" {
		return fmt.Errorf("%w: risk closure requires verification evidence and verifier", ErrInvalidRisk)
	}
	if risk.VerifiedBy == risk.OwnerID || (risk.Approval != nil && risk.VerifiedBy == risk.Approval.ApprovedBy) {
		return ErrIndependentReview
	}
	return nil
}

func normalizeApproval(value Approval) Approval {
	value.ID = strings.TrimSpace(value.ID)
	value.ApprovedBy = strings.TrimSpace(value.ApprovedBy)
	value.ApprovedAt = CanonicalTime(value.ApprovedAt)
	return value
}

func validateApproval(value *Approval) error {
	if value == nil || strings.TrimSpace(value.ID) == "" || strings.TrimSpace(value.ApprovedBy) == "" || value.ApprovedAt.IsZero() {
		return errors.New("approval id, approver, and approval time are required")
	}
	return nil
}

func validateRenewalApproval(current, proposed *Approval, notBefore time.Time) error {
	if current == nil {
		return nil
	}
	if err := validateApproval(proposed); err != nil {
		return errors.New("renewal requires a new approval")
	}
	next := normalizeApproval(*proposed)
	if next.ID == strings.TrimSpace(current.ID) {
		return errors.New("renewal requires a new approval id")
	}
	if next.ApprovedAt.Before(CanonicalTime(notBefore)) {
		return errors.New("renewal approval predates the current review")
	}
	return nil
}

func cloneRisk(value Risk) Risk {
	value.CompensatingControls = append([]string(nil), value.CompensatingControls...)
	value.VerificationEvidenceIDs = append([]string(nil), value.VerificationEvidenceIDs...)
	if value.Approval != nil {
		approval := *value.Approval
		value.Approval = &approval
	}
	return value
}

func riskTransitionAllowed(from, to RiskState) bool {
	if from == to {
		return validRiskState(to)
	}
	switch from {
	case RiskOpen:
		return to == RiskAssessing || to == RiskRejected
	case RiskAssessing:
		return to == RiskTreatmentPlanned || to == RiskAccepted || to == RiskRejected
	case RiskTreatmentPlanned:
		return to == RiskAccepted || to == RiskMitigated || to == RiskRejected
	case RiskAccepted:
		return to == RiskMitigated || to == RiskClosed
	case RiskMitigated:
		return to == RiskClosed || to == RiskOpen
	case RiskExpired:
		return to == RiskAssessing || to == RiskTreatmentPlanned
	default:
		return false
	}
}

func validRiskState(value RiskState) bool {
	switch value {
	case RiskOpen, RiskAssessing, RiskTreatmentPlanned, RiskAccepted, RiskRejected, RiskMitigated, RiskClosed, RiskExpired:
		return true
	default:
		return false
	}
}

func validRiskTreatment(value RiskTreatment) bool {
	switch value {
	case RiskTreatmentNone, RiskTreatmentAvoid, RiskTreatmentMitigate, RiskTreatmentTransfer,
		RiskTreatmentAccept, RiskTreatmentShare, RiskTreatmentContingency:
		return true
	default:
		return false
	}
}
