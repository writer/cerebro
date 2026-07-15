package grcaudit

import (
	"fmt"
	"strings"
	"time"
)

// EvidenceRequestStatus is the current state of an audit evidence request.
type EvidenceRequestStatus string

const (
	EvidenceRequestStatusOpen             EvidenceRequestStatus = "open"
	EvidenceRequestStatusInProgress       EvidenceRequestStatus = "in_progress"
	EvidenceRequestStatusSubmitted        EvidenceRequestStatus = "submitted"
	EvidenceRequestStatusChangesRequested EvidenceRequestStatus = "changes_requested"
	EvidenceRequestStatusAccepted         EvidenceRequestStatus = "accepted"
	EvidenceRequestStatusRejected         EvidenceRequestStatus = "rejected"
	EvidenceRequestStatusWithdrawn        EvidenceRequestStatus = "withdrawn"
	EvidenceRequestStatusClosed           EvidenceRequestStatus = "closed"
)

// EvidenceRequest is the mutable pointer for a stable request identity.
type EvidenceRequest struct {
	ID                string                `json:"id"`
	TenantID          string                `json:"tenant_id"`
	EngagementID      string                `json:"engagement_id"`
	Version           uint64                `json:"version"`
	CurrentRevision   uint64                `json:"current_revision"`
	CurrentRevisionID string                `json:"current_revision_id"`
	Status            EvidenceRequestStatus `json:"status"`
}

// EvidenceRequestRevision is one immutable statement of requested evidence.
type EvidenceRequestRevision struct {
	ID                   string                `json:"id"`
	TenantID             string                `json:"tenant_id"`
	EngagementID         string                `json:"engagement_id"`
	RequestID            string                `json:"request_id"`
	Revision             uint64                `json:"revision"`
	PredecessorID        string                `json:"predecessor_id,omitempty"`
	ObjectiveID          string                `json:"objective_id"`
	SubjectIDs           []string              `json:"subject_ids,omitempty"`
	PeriodStart          time.Time             `json:"period_start"`
	PeriodEnd            time.Time             `json:"period_end"`
	SampleRevisionID     string                `json:"sample_revision_id,omitempty"`
	RequesterPrincipalID string                `json:"requester_principal_id"`
	OwnerPrincipalID     string                `json:"owner_principal_id"`
	DueAt                time.Time             `json:"due_at"`
	ExpectedFormats      []string              `json:"expected_formats,omitempty"`
	Instructions         string                `json:"instructions,omitempty"`
	Status               EvidenceRequestStatus `json:"status"`
	ChangeSummary        string                `json:"change_summary,omitempty"`
	CreatedBy            string                `json:"created_by"`
	CreatedAt            time.Time             `json:"created_at"`
	RevisionHash         string                `json:"revision_hash"`
}

// EvidenceRequestRevisionInput contains the semantic fields of a request revision.
type EvidenceRequestRevisionInput struct {
	ObjectiveID          string
	SubjectIDs           []string
	PeriodStart          time.Time
	PeriodEnd            time.Time
	SampleRevisionID     string
	RequesterPrincipalID string
	OwnerPrincipalID     string
	DueAt                time.Time
	ExpectedFormats      []string
	Instructions         string
	Status               EvidenceRequestStatus
	ChangeSummary        string
}

// CreateEvidenceRequestRequest creates a request and immutable revision one.
type CreateEvidenceRequestRequest struct {
	ID           string
	TenantID     string
	EngagementID string
	Revision     EvidenceRequestRevisionInput
	CreatedBy    string
	CreatedAt    time.Time
}

// EvidenceSubmission is an immutable response to one exact request version.
type EvidenceSubmission struct {
	ID                 string    `json:"id"`
	TenantID           string    `json:"tenant_id"`
	EngagementID       string    `json:"engagement_id"`
	RequestID          string    `json:"request_id"`
	RequestVersion     uint64    `json:"request_version"`
	ClaimIDs           []string  `json:"claim_ids,omitempty"`
	ArtifactVersionIDs []string  `json:"artifact_version_ids,omitempty"`
	PackageRevisionID  string    `json:"package_revision_id,omitempty"`
	Message            string    `json:"message,omitempty"`
	SubmittedBy        string    `json:"submitted_by"`
	SubmittedAt        time.Time `json:"submitted_at"`
	SubmissionHash     string    `json:"submission_hash"`
}

// EvidenceSubmissionInput supplies the immutable references in a submission.
type EvidenceSubmissionInput struct {
	ClaimIDs           []string
	ArtifactVersionIDs []string
	PackageRevisionID  string
	Message            string
}

// NewEvidenceRequest creates one request and immutable revision one.
func NewEvidenceRequest(request CreateEvidenceRequestRequest) (EvidenceRequest, EvidenceRequestRevision, error) {
	id, err := required(request.ID, "evidence request id")
	if err != nil {
		return EvidenceRequest{}, EvidenceRequestRevision{}, err
	}
	tenantID, err := required(request.TenantID, "tenant id")
	if err != nil {
		return EvidenceRequest{}, EvidenceRequestRevision{}, err
	}
	engagementID, err := required(request.EngagementID, "engagement id")
	if err != nil {
		return EvidenceRequest{}, EvidenceRequestRevision{}, err
	}
	actor, err := required(request.CreatedBy, "created by")
	if err != nil {
		return EvidenceRequest{}, EvidenceRequestRevision{}, err
	}
	createdAt := request.CreatedAt.UTC()
	if createdAt.IsZero() {
		return EvidenceRequest{}, EvidenceRequestRevision{}, fmt.Errorf("%w: created at is required", ErrInvalidRequest)
	}
	if request.Revision.Status == "" {
		request.Revision.Status = EvidenceRequestStatusOpen
	}
	if request.Revision.Status != EvidenceRequestStatusOpen {
		return EvidenceRequest{}, EvidenceRequestRevision{}, fmt.Errorf("%w: initial request status must be open", ErrInvalidRequest)
	}
	revision, err := buildEvidenceRequestRevision(tenantID, engagementID, id, 1, "", request.Revision, actor, createdAt)
	if err != nil {
		return EvidenceRequest{}, EvidenceRequestRevision{}, err
	}
	return EvidenceRequest{ID: id, TenantID: tenantID, EngagementID: engagementID, Version: 1, CurrentRevision: 1, CurrentRevisionID: revision.ID, Status: revision.Status}, revision, nil
}

// ReviseEvidenceRequest creates a new immutable request revision.
func ReviseEvidenceRequest(current EvidenceRequest, expectedVersion uint64, input EvidenceRequestRevisionInput, actor string, createdAt time.Time) (EvidenceRequest, EvidenceRequestRevision, error) {
	if current.Version != expectedVersion {
		return EvidenceRequest{}, EvidenceRequestRevision{}, fmt.Errorf("%w: expected %d, current %d", ErrVersionConflict, expectedVersion, current.Version)
	}
	if input.Status == "" {
		input.Status = current.Status
	}
	if !requestTransitionAllowed(current.Status, input.Status) {
		return EvidenceRequest{}, EvidenceRequestRevision{}, fmt.Errorf("%w: request transition %q to %q is invalid", ErrInvalidRequest, current.Status, input.Status)
	}
	actor, err := required(actor, "created by")
	if err != nil {
		return EvidenceRequest{}, EvidenceRequestRevision{}, err
	}
	createdAt = createdAt.UTC()
	if createdAt.IsZero() {
		return EvidenceRequest{}, EvidenceRequestRevision{}, fmt.Errorf("%w: created at is required", ErrInvalidRequest)
	}
	revision, err := buildEvidenceRequestRevision(current.TenantID, current.EngagementID, current.ID, current.CurrentRevision+1, current.CurrentRevisionID, input, actor, createdAt)
	if err != nil {
		return EvidenceRequest{}, EvidenceRequestRevision{}, err
	}
	next := current
	next.Version++
	next.CurrentRevision++
	next.CurrentRevisionID = revision.ID
	next.Status = revision.Status
	return next, revision, nil
}

// RecordEvidenceSubmission creates an immutable submission and moves the request
// to submitted without changing the supplied request value.
func RecordEvidenceSubmission(current EvidenceRequest, expectedVersion uint64, input EvidenceSubmissionInput, actor string, submittedAt time.Time) (EvidenceRequest, EvidenceSubmission, error) {
	if current.Version != expectedVersion {
		return EvidenceRequest{}, EvidenceSubmission{}, fmt.Errorf("%w: expected %d, current %d", ErrVersionConflict, expectedVersion, current.Version)
	}
	switch current.Status {
	case EvidenceRequestStatusOpen, EvidenceRequestStatusInProgress, EvidenceRequestStatusChangesRequested:
	default:
		return EvidenceRequest{}, EvidenceSubmission{}, fmt.Errorf("%w: request in state %q cannot accept a submission", ErrInvalidRequest, current.Status)
	}
	actor, err := required(actor, "submitted by")
	if err != nil {
		return EvidenceRequest{}, EvidenceSubmission{}, err
	}
	submittedAt = submittedAt.UTC()
	if submittedAt.IsZero() {
		return EvidenceRequest{}, EvidenceSubmission{}, fmt.Errorf("%w: submitted at is required", ErrInvalidRequest)
	}
	input.ClaimIDs = normalizedStrings(input.ClaimIDs)
	input.ArtifactVersionIDs = normalizedStrings(input.ArtifactVersionIDs)
	input.PackageRevisionID = strings.TrimSpace(input.PackageRevisionID)
	if len(input.ClaimIDs) == 0 && len(input.ArtifactVersionIDs) == 0 && input.PackageRevisionID == "" {
		return EvidenceRequest{}, EvidenceSubmission{}, fmt.Errorf("%w: submission requires a claim, artifact version, or package revision", ErrInvalidRequest)
	}
	submission := EvidenceSubmission{
		TenantID:           strings.TrimSpace(current.TenantID),
		EngagementID:       strings.TrimSpace(current.EngagementID),
		RequestID:          strings.TrimSpace(current.ID),
		RequestVersion:     current.Version,
		ClaimIDs:           input.ClaimIDs,
		ArtifactVersionIDs: input.ArtifactVersionIDs,
		PackageRevisionID:  input.PackageRevisionID,
		Message:            strings.TrimSpace(input.Message),
		SubmittedBy:        actor,
		SubmittedAt:        submittedAt,
	}
	hash, err := canonicalDigest(submission)
	if err != nil {
		return EvidenceRequest{}, EvidenceSubmission{}, fmt.Errorf("hash evidence submission: %w", err)
	}
	submission.SubmissionHash = hash
	submission.ID = digestID("audit-submission-", hash)
	next := current
	next.Version++
	next.Status = EvidenceRequestStatusSubmitted
	return next, submission, nil
}

// AuthorizeEvidenceRequestAccess verifies request and engagement object scope.
func AuthorizeEvidenceRequestAccess(principal Principal, engagement Engagement, request EvidenceRequest, permission EngagementPermission) error {
	if strings.TrimSpace(request.ID) == "" || request.TenantID != engagement.TenantID || request.EngagementID != engagement.ID {
		return ErrEvidenceRequestNotFound
	}
	if err := AuthorizeEngagementAccess(principal, engagement, permission); err != nil {
		return ErrEvidenceRequestNotFound
	}
	return nil
}

func buildEvidenceRequestRevision(tenantID, engagementID, requestID string, revisionNumber uint64, predecessorID string, input EvidenceRequestRevisionInput, actor string, createdAt time.Time) (EvidenceRequestRevision, error) {
	objectiveID, err := required(input.ObjectiveID, "objective id")
	if err != nil {
		return EvidenceRequestRevision{}, err
	}
	requesterID, err := required(input.RequesterPrincipalID, "requester principal id")
	if err != nil {
		return EvidenceRequestRevision{}, err
	}
	ownerID, err := required(input.OwnerPrincipalID, "owner principal id")
	if err != nil {
		return EvidenceRequestRevision{}, err
	}
	periodStart := input.PeriodStart.UTC()
	periodEnd := input.PeriodEnd.UTC()
	if periodStart.IsZero() || periodEnd.IsZero() || periodEnd.Before(periodStart) {
		return EvidenceRequestRevision{}, fmt.Errorf("%w: evidence request period is invalid", ErrInvalidRequest)
	}
	dueAt := input.DueAt.UTC()
	if dueAt.IsZero() {
		return EvidenceRequestRevision{}, fmt.Errorf("%w: due at is required", ErrInvalidRequest)
	}
	if !validEvidenceRequestStatus(input.Status) {
		return EvidenceRequestRevision{}, fmt.Errorf("%w: evidence request status %q is invalid", ErrInvalidRequest, input.Status)
	}
	revision := EvidenceRequestRevision{
		TenantID:             strings.TrimSpace(tenantID),
		EngagementID:         strings.TrimSpace(engagementID),
		RequestID:            strings.TrimSpace(requestID),
		Revision:             revisionNumber,
		PredecessorID:        strings.TrimSpace(predecessorID),
		ObjectiveID:          objectiveID,
		SubjectIDs:           normalizedStrings(input.SubjectIDs),
		PeriodStart:          periodStart,
		PeriodEnd:            periodEnd,
		SampleRevisionID:     strings.TrimSpace(input.SampleRevisionID),
		RequesterPrincipalID: requesterID,
		OwnerPrincipalID:     ownerID,
		DueAt:                dueAt,
		ExpectedFormats:      normalizedStrings(input.ExpectedFormats),
		Instructions:         strings.TrimSpace(input.Instructions),
		Status:               input.Status,
		ChangeSummary:        strings.TrimSpace(input.ChangeSummary),
		CreatedBy:            actor,
		CreatedAt:            createdAt,
	}
	hash, err := canonicalDigest(revision)
	if err != nil {
		return EvidenceRequestRevision{}, fmt.Errorf("hash evidence request revision: %w", err)
	}
	revision.RevisionHash = hash
	revision.ID = digestID("audit-request-revision-", hash)
	return revision, nil
}

func validEvidenceRequestStatus(status EvidenceRequestStatus) bool {
	switch status {
	case EvidenceRequestStatusOpen, EvidenceRequestStatusInProgress, EvidenceRequestStatusSubmitted, EvidenceRequestStatusChangesRequested, EvidenceRequestStatusAccepted, EvidenceRequestStatusRejected, EvidenceRequestStatusWithdrawn, EvidenceRequestStatusClosed:
		return true
	default:
		return false
	}
}

func requestTransitionAllowed(from, to EvidenceRequestStatus) bool {
	if from == to {
		return true
	}
	switch from {
	case EvidenceRequestStatusOpen:
		return to == EvidenceRequestStatusInProgress || to == EvidenceRequestStatusWithdrawn || to == EvidenceRequestStatusClosed
	case EvidenceRequestStatusInProgress:
		return to == EvidenceRequestStatusSubmitted || to == EvidenceRequestStatusChangesRequested || to == EvidenceRequestStatusWithdrawn || to == EvidenceRequestStatusClosed
	case EvidenceRequestStatusSubmitted:
		return to == EvidenceRequestStatusAccepted || to == EvidenceRequestStatusRejected || to == EvidenceRequestStatusChangesRequested
	case EvidenceRequestStatusChangesRequested:
		return to == EvidenceRequestStatusInProgress || to == EvidenceRequestStatusSubmitted || to == EvidenceRequestStatusWithdrawn
	case EvidenceRequestStatusAccepted, EvidenceRequestStatusRejected, EvidenceRequestStatusWithdrawn:
		return to == EvidenceRequestStatusClosed
	default:
		return false
	}
}
