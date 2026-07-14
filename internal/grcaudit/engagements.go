package grcaudit

import (
	"fmt"
	"strings"
	"time"
)

// EngagementStatus is the operating state of an audit engagement revision.
type EngagementStatus string

const (
	EngagementStatusPlanning      EngagementStatus = "planning"
	EngagementStatusFieldwork     EngagementStatus = "fieldwork"
	EngagementStatusClarification EngagementStatus = "clarification"
	EngagementStatusComplete      EngagementStatus = "complete"
	EngagementStatusClosed        EngagementStatus = "closed"
)

// ParticipantRole identifies an engagement participant's bounded authority.
type ParticipantRole string

const (
	ParticipantRoleAuditLead     ParticipantRole = "audit_lead"
	ParticipantRoleAuditor       ParticipantRole = "auditor"
	ParticipantRoleClientOwner   ParticipantRole = "client_owner"
	ParticipantRoleEvidenceOwner ParticipantRole = "evidence_owner"
	ParticipantRoleObserver      ParticipantRole = "observer"
)

// ParticipantStatus is the current assignment state for an engagement participant.
type ParticipantStatus string

const (
	ParticipantStatusActive  ParticipantStatus = "active"
	ParticipantStatusRemoved ParticipantStatus = "removed"
)

// EngagementPermission is one domain-level object permission.
type EngagementPermission string

const (
	EngagementPermissionRead     EngagementPermission = "read"
	EngagementPermissionManage   EngagementPermission = "manage"
	EngagementPermissionReview   EngagementPermission = "review"
	EngagementPermissionDisclose EngagementPermission = "disclose"
	EngagementPermissionDeliver  EngagementPermission = "deliver"
)

// Principal is the server-derived identity passed into audit object authorization.
// TenantWide must only be set after transport authorization has established the
// corresponding tenant-wide permission.
type Principal struct {
	TenantID   string
	ID         string
	TenantWide bool
}

// Participant is the current assignment of one principal to one engagement.
type Participant struct {
	ID           string            `json:"id"`
	TenantID     string            `json:"tenant_id"`
	EngagementID string            `json:"engagement_id"`
	PrincipalID  string            `json:"principal_id"`
	Role         ParticipantRole   `json:"role"`
	Status       ParticipantStatus `json:"status"`
	Version      uint64            `json:"version"`
	UpdatedAt    time.Time         `json:"updated_at"`
}

// ParticipantInput assigns one principal during engagement creation or update.
type ParticipantInput struct {
	PrincipalID string
	Role        ParticipantRole
}

// Engagement is the current pointer for a stable audit engagement identity.
// Semantic scope and period data live only in immutable EngagementRevision values.
type Engagement struct {
	ID                string           `json:"id"`
	TenantID          string           `json:"tenant_id"`
	Version           uint64           `json:"version"`
	CurrentRevision   uint64           `json:"current_revision"`
	CurrentRevisionID string           `json:"current_revision_id"`
	Status            EngagementStatus `json:"status"`
	Participants      []Participant    `json:"participants,omitempty"`
}

// EngagementRevision is one immutable engagement scope and period decision.
type EngagementRevision struct {
	ID                   string           `json:"id"`
	TenantID             string           `json:"tenant_id"`
	EngagementID         string           `json:"engagement_id"`
	Revision             uint64           `json:"revision"`
	PredecessorID        string           `json:"predecessor_id,omitempty"`
	ProgramID            string           `json:"program_id"`
	ProgramScopeRevision string           `json:"program_scope_revision_id"`
	FrameworkRevisionIDs []string         `json:"framework_revision_ids,omitempty"`
	PlanRevisionID       string           `json:"plan_revision_id,omitempty"`
	PeriodStart          time.Time        `json:"period_start"`
	PeriodEnd            time.Time        `json:"period_end"`
	Deadline             time.Time        `json:"deadline"`
	DisclosurePolicyID   string           `json:"disclosure_policy_id"`
	Status               EngagementStatus `json:"status"`
	ChangeSummary        string           `json:"change_summary,omitempty"`
	CreatedBy            string           `json:"created_by"`
	CreatedAt            time.Time        `json:"created_at"`
	RevisionHash         string           `json:"revision_hash"`
}

// EngagementRevisionInput contains the semantic fields for a new revision.
type EngagementRevisionInput struct {
	ProgramID            string
	ProgramScopeRevision string
	FrameworkRevisionIDs []string
	PlanRevisionID       string
	PeriodStart          time.Time
	PeriodEnd            time.Time
	Deadline             time.Time
	DisclosurePolicyID   string
	Status               EngagementStatus
	ChangeSummary        string
}

// CreateEngagementRequest creates a stable engagement and its first revision.
type CreateEngagementRequest struct {
	ID           string
	TenantID     string
	Revision     EngagementRevisionInput
	Participants []ParticipantInput
	CreatedBy    string
	CreatedAt    time.Time
}

// NewEngagement creates one engagement and immutable revision one.
func NewEngagement(request CreateEngagementRequest) (Engagement, EngagementRevision, error) {
	id, err := required(request.ID, "engagement id")
	if err != nil {
		return Engagement{}, EngagementRevision{}, err
	}
	tenantID, err := required(request.TenantID, "tenant id")
	if err != nil {
		return Engagement{}, EngagementRevision{}, err
	}
	actor, err := required(request.CreatedBy, "created by")
	if err != nil {
		return Engagement{}, EngagementRevision{}, err
	}
	createdAt := request.CreatedAt.UTC()
	if createdAt.IsZero() {
		return Engagement{}, EngagementRevision{}, fmt.Errorf("%w: created at is required", ErrInvalidRequest)
	}
	if request.Revision.Status == "" {
		request.Revision.Status = EngagementStatusPlanning
	}
	if request.Revision.Status != EngagementStatusPlanning {
		return Engagement{}, EngagementRevision{}, fmt.Errorf("%w: initial engagement status must be planning", ErrInvalidRequest)
	}
	revision, err := buildEngagementRevision(tenantID, id, 1, "", request.Revision, actor, createdAt)
	if err != nil {
		return Engagement{}, EngagementRevision{}, err
	}
	participants, err := buildParticipants(tenantID, id, request.Participants, createdAt)
	if err != nil {
		return Engagement{}, EngagementRevision{}, err
	}
	return Engagement{ID: id, TenantID: tenantID, Version: 1, CurrentRevision: 1, CurrentRevisionID: revision.ID, Status: revision.Status, Participants: participants}, revision, nil
}

// ReviseEngagement creates a new immutable revision without changing the supplied aggregate.
func ReviseEngagement(current Engagement, expectedVersion uint64, input EngagementRevisionInput, actor string, createdAt time.Time) (Engagement, EngagementRevision, error) {
	if current.Version != expectedVersion {
		return Engagement{}, EngagementRevision{}, fmt.Errorf("%w: expected %d, current %d", ErrVersionConflict, expectedVersion, current.Version)
	}
	if input.Status == "" {
		input.Status = current.Status
	}
	if !engagementTransitionAllowed(current.Status, input.Status) {
		return Engagement{}, EngagementRevision{}, fmt.Errorf("%w: engagement transition %q to %q is invalid", ErrInvalidRequest, current.Status, input.Status)
	}
	actor, err := required(actor, "created by")
	if err != nil {
		return Engagement{}, EngagementRevision{}, err
	}
	createdAt = createdAt.UTC()
	if createdAt.IsZero() {
		return Engagement{}, EngagementRevision{}, fmt.Errorf("%w: created at is required", ErrInvalidRequest)
	}
	revision, err := buildEngagementRevision(current.TenantID, current.ID, current.CurrentRevision+1, current.CurrentRevisionID, input, actor, createdAt)
	if err != nil {
		return Engagement{}, EngagementRevision{}, err
	}
	next := cloneEngagement(current)
	next.Version++
	next.CurrentRevision++
	next.CurrentRevisionID = revision.ID
	next.Status = revision.Status
	return next, revision, nil
}

// GrantParticipant creates or replaces one current participant assignment without
// changing any immutable engagement revision.
func GrantParticipant(current Engagement, expectedVersion uint64, input ParticipantInput, updatedAt time.Time) (Engagement, Participant, error) {
	if current.Version != expectedVersion {
		return Engagement{}, Participant{}, fmt.Errorf("%w: expected %d, current %d", ErrVersionConflict, expectedVersion, current.Version)
	}
	participant, err := buildParticipant(current.TenantID, current.ID, input, updatedAt.UTC())
	if err != nil {
		return Engagement{}, Participant{}, err
	}
	next := cloneEngagement(current)
	participant.Version = 1
	replaced := false
	for idx := range next.Participants {
		if next.Participants[idx].PrincipalID != participant.PrincipalID {
			continue
		}
		participant.Version = next.Participants[idx].Version + 1
		next.Participants[idx] = participant
		replaced = true
		break
	}
	if !replaced {
		next.Participants = append(next.Participants, participant)
	}
	sortParticipants(next.Participants)
	next.Version++
	return next, participant, nil
}

// RemoveParticipant records a removed assignment without changing any immutable
// engagement revision. The removed assignment remains available for audit history.
func RemoveParticipant(current Engagement, expectedVersion uint64, principalID string, updatedAt time.Time) (Engagement, Participant, error) {
	if current.Version != expectedVersion {
		return Engagement{}, Participant{}, fmt.Errorf("%w: expected %d, current %d", ErrVersionConflict, expectedVersion, current.Version)
	}
	principalID, err := required(principalID, "participant principal id")
	if err != nil {
		return Engagement{}, Participant{}, err
	}
	updatedAt = updatedAt.UTC()
	if updatedAt.IsZero() {
		return Engagement{}, Participant{}, fmt.Errorf("%w: participant updated at is required", ErrInvalidRequest)
	}
	next := cloneEngagement(current)
	for index := range next.Participants {
		participant := next.Participants[index]
		if participant.PrincipalID != principalID || participant.Status != ParticipantStatusActive {
			continue
		}
		participant.Status = ParticipantStatusRemoved
		participant.Version++
		participant.UpdatedAt = updatedAt
		next.Participants[index] = participant
		next.Version++
		return next, participant, nil
	}
	return Engagement{}, Participant{}, ErrEngagementNotFound
}

// AuthorizeEngagementAccess applies tenant and participant scope without revealing
// whether an inaccessible engagement exists.
func AuthorizeEngagementAccess(principal Principal, engagement Engagement, permission EngagementPermission) error {
	if strings.TrimSpace(principal.TenantID) == "" || strings.TrimSpace(principal.ID) == "" || strings.TrimSpace(engagement.ID) == "" {
		return ErrEngagementNotFound
	}
	if !validEngagementPermission(permission) {
		return ErrEngagementNotFound
	}
	if strings.TrimSpace(principal.TenantID) != strings.TrimSpace(engagement.TenantID) {
		return ErrEngagementNotFound
	}
	if principal.TenantWide {
		return nil
	}
	for _, participant := range engagement.Participants {
		if strings.TrimSpace(participant.TenantID) != strings.TrimSpace(engagement.TenantID) ||
			strings.TrimSpace(participant.EngagementID) != strings.TrimSpace(engagement.ID) ||
			participant.Status != ParticipantStatusActive || participant.PrincipalID != strings.TrimSpace(principal.ID) {
			continue
		}
		if roleAllows(participant.Role, permission) {
			return nil
		}
	}
	return ErrEngagementNotFound
}

func buildEngagementRevision(tenantID, engagementID string, revisionNumber uint64, predecessorID string, input EngagementRevisionInput, actor string, createdAt time.Time) (EngagementRevision, error) {
	programID, err := required(input.ProgramID, "program id")
	if err != nil {
		return EngagementRevision{}, err
	}
	scopeRevision, err := required(input.ProgramScopeRevision, "program scope revision id")
	if err != nil {
		return EngagementRevision{}, err
	}
	disclosurePolicyID, err := required(input.DisclosurePolicyID, "disclosure policy id")
	if err != nil {
		return EngagementRevision{}, err
	}
	periodStart := input.PeriodStart.UTC()
	periodEnd := input.PeriodEnd.UTC()
	if periodStart.IsZero() || periodEnd.IsZero() || periodEnd.Before(periodStart) {
		return EngagementRevision{}, fmt.Errorf("%w: audit period is invalid", ErrInvalidRequest)
	}
	deadline := input.Deadline.UTC()
	if deadline.IsZero() {
		return EngagementRevision{}, fmt.Errorf("%w: deadline is required", ErrInvalidRequest)
	}
	status := input.Status
	if status == "" {
		status = EngagementStatusPlanning
	}
	if !validEngagementStatus(status) {
		return EngagementRevision{}, fmt.Errorf("%w: engagement status %q is invalid", ErrInvalidRequest, status)
	}
	revision := EngagementRevision{
		TenantID:             strings.TrimSpace(tenantID),
		EngagementID:         strings.TrimSpace(engagementID),
		Revision:             revisionNumber,
		PredecessorID:        strings.TrimSpace(predecessorID),
		ProgramID:            programID,
		ProgramScopeRevision: scopeRevision,
		FrameworkRevisionIDs: normalizedStrings(input.FrameworkRevisionIDs),
		PlanRevisionID:       strings.TrimSpace(input.PlanRevisionID),
		PeriodStart:          periodStart,
		PeriodEnd:            periodEnd,
		Deadline:             deadline,
		DisclosurePolicyID:   disclosurePolicyID,
		Status:               status,
		ChangeSummary:        strings.TrimSpace(input.ChangeSummary),
		CreatedBy:            actor,
		CreatedAt:            createdAt,
	}
	hash, err := canonicalDigest(revision)
	if err != nil {
		return EngagementRevision{}, fmt.Errorf("hash engagement revision: %w", err)
	}
	revision.RevisionHash = hash
	revision.ID = digestID("audit-engagement-revision-", hash)
	return revision, nil
}

func buildParticipants(tenantID, engagementID string, inputs []ParticipantInput, updatedAt time.Time) ([]Participant, error) {
	participants := make([]Participant, 0, len(inputs))
	seen := map[string]struct{}{}
	for _, input := range inputs {
		participant, err := buildParticipant(tenantID, engagementID, input, updatedAt)
		if err != nil {
			return nil, err
		}
		if _, ok := seen[participant.PrincipalID]; ok {
			return nil, fmt.Errorf("%w: participant %q is duplicated", ErrInvalidRequest, participant.PrincipalID)
		}
		seen[participant.PrincipalID] = struct{}{}
		participant.Version = 1
		participants = append(participants, participant)
	}
	sortParticipants(participants)
	return participants, nil
}

func buildParticipant(tenantID, engagementID string, input ParticipantInput, updatedAt time.Time) (Participant, error) {
	principalID, err := required(input.PrincipalID, "participant principal id")
	if err != nil {
		return Participant{}, err
	}
	if !validParticipantRole(input.Role) {
		return Participant{}, fmt.Errorf("%w: participant role %q is invalid", ErrInvalidRequest, input.Role)
	}
	if updatedAt.IsZero() {
		return Participant{}, fmt.Errorf("%w: participant updated at is required", ErrInvalidRequest)
	}
	digest := DigestBytes([]byte(strings.Join([]string{tenantID, engagementID, principalID}, "\x00")))
	return Participant{
		ID:           digestID("audit-participant-", digest),
		TenantID:     strings.TrimSpace(tenantID),
		EngagementID: strings.TrimSpace(engagementID),
		PrincipalID:  principalID,
		Role:         input.Role,
		Status:       ParticipantStatusActive,
		UpdatedAt:    updatedAt,
	}, nil
}

func cloneEngagement(value Engagement) Engagement {
	value.Participants = append([]Participant(nil), value.Participants...)
	return value
}

func sortParticipants(participants []Participant) {
	for i := 1; i < len(participants); i++ {
		for j := i; j > 0 && participants[j].PrincipalID < participants[j-1].PrincipalID; j-- {
			participants[j], participants[j-1] = participants[j-1], participants[j]
		}
	}
}

func validEngagementStatus(status EngagementStatus) bool {
	switch status {
	case EngagementStatusPlanning, EngagementStatusFieldwork, EngagementStatusClarification, EngagementStatusComplete, EngagementStatusClosed:
		return true
	default:
		return false
	}
}

func engagementTransitionAllowed(from, to EngagementStatus) bool {
	if from == to {
		return validEngagementStatus(to)
	}
	switch from {
	case EngagementStatusPlanning:
		return to == EngagementStatusFieldwork || to == EngagementStatusClosed
	case EngagementStatusFieldwork:
		return to == EngagementStatusClarification || to == EngagementStatusComplete || to == EngagementStatusClosed
	case EngagementStatusClarification:
		return to == EngagementStatusFieldwork || to == EngagementStatusComplete || to == EngagementStatusClosed
	case EngagementStatusComplete:
		return to == EngagementStatusClarification || to == EngagementStatusClosed
	default:
		return false
	}
}

func validEngagementPermission(permission EngagementPermission) bool {
	switch permission {
	case EngagementPermissionRead, EngagementPermissionManage, EngagementPermissionReview, EngagementPermissionDisclose, EngagementPermissionDeliver:
		return true
	default:
		return false
	}
}

func validParticipantRole(role ParticipantRole) bool {
	switch role {
	case ParticipantRoleAuditLead, ParticipantRoleAuditor, ParticipantRoleClientOwner, ParticipantRoleEvidenceOwner, ParticipantRoleObserver:
		return true
	default:
		return false
	}
}

func roleAllows(role ParticipantRole, permission EngagementPermission) bool {
	switch role {
	case ParticipantRoleAuditLead, ParticipantRoleClientOwner:
		return true
	case ParticipantRoleAuditor:
		return permission == EngagementPermissionRead || permission == EngagementPermissionReview || permission == EngagementPermissionDisclose
	case ParticipantRoleEvidenceOwner:
		return permission == EngagementPermissionRead || permission == EngagementPermissionDisclose
	case ParticipantRoleObserver:
		return permission == EngagementPermissionRead
	default:
		return false
	}
}
