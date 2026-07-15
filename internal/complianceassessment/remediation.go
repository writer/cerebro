package complianceassessment

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

var ErrInvalidRemediation = errors.New("invalid compliance remediation")

// RemediationState is the explicit lifecycle of a remediation plan.
type RemediationState string

const (
	RemediationDraft               RemediationState = "draft"
	RemediationActive              RemediationState = "active"
	RemediationVerificationPending RemediationState = "verification_pending"
	RemediationClosed              RemediationState = "closed"
	RemediationReopened            RemediationState = "reopened"
	RemediationCanceled            RemediationState = "canceled"
)

// MilestoneState is the explicit lifecycle of one remediation milestone.
type MilestoneState string

const (
	MilestonePending    MilestoneState = "pending"
	MilestoneInProgress MilestoneState = "in_progress"
	MilestoneBlocked    MilestoneState = "blocked"
	MilestoneCompleted  MilestoneState = "completed"
	MilestoneVerified   MilestoneState = "verified"
	MilestoneCanceled   MilestoneState = "canceled"
)

// RemediationMilestone is one owned, dependency-aware unit of planned work.
type RemediationMilestone struct {
	ID                      string         `json:"id"`
	Title                   string         `json:"title"`
	OwnerID                 string         `json:"owner_id"`
	TargetAt                time.Time      `json:"target_at"`
	DependsOnIDs            []string       `json:"depends_on_ids,omitempty"`
	PlannedAction           string         `json:"planned_action"`
	CompletedAction         string         `json:"completed_action,omitempty"`
	CompletionEvidenceIDs   []string       `json:"completion_evidence_ids,omitempty"`
	VerificationEvidenceIDs []string       `json:"verification_evidence_ids,omitempty"`
	State                   MilestoneState `json:"state"`
	CompletedBy             string         `json:"completed_by,omitempty"`
	CompletedAt             time.Time      `json:"completed_at,omitempty"`
	VerifiedBy              string         `json:"verified_by,omitempty"`
	VerifiedAt              time.Time      `json:"verified_at,omitempty"`
}

// RemediationPlan is the current projection for a risk response implementation.
type RemediationPlan struct {
	ID                      string                 `json:"id"`
	TenantID                string                 `json:"tenant_id"`
	ProgramID               string                 `json:"program_id"`
	ScopeRevisionID         string                 `json:"scope_revision_id"`
	RiskID                  string                 `json:"risk_id"`
	WorkItemID              string                 `json:"work_item_id"`
	Treatment               RiskTreatment          `json:"treatment"`
	OwnerID                 string                 `json:"owner_id"`
	TargetAt                time.Time              `json:"target_at"`
	CompensatingControls    []string               `json:"compensating_controls,omitempty"`
	RetestRequired          bool                   `json:"retest_required"`
	VerificationRequired    bool                   `json:"verification_required"`
	State                   RemediationState       `json:"state"`
	Milestones              []RemediationMilestone `json:"milestones"`
	VerificationEvidenceIDs []string               `json:"verification_evidence_ids,omitempty"`
	VerifiedBy              string                 `json:"verified_by,omitempty"`
	LastReopenTrigger       WorkReopenTrigger      `json:"last_reopen_trigger,omitempty"`
	Version                 uint64                 `json:"version"`
	UpdatedAt               time.Time              `json:"updated_at"`
}

// RemediationMilestoneInput creates one pending milestone.
type RemediationMilestoneInput struct {
	ID            string    `json:"id"`
	Title         string    `json:"title"`
	OwnerID       string    `json:"owner_id"`
	TargetAt      time.Time `json:"target_at"`
	DependsOnIDs  []string  `json:"depends_on_ids,omitempty"`
	PlannedAction string    `json:"planned_action"`
}

// RemediationPlanInput creates a draft remediation plan.
type RemediationPlanInput struct {
	ID                   string
	TenantID             string
	ProgramID            string
	ScopeRevisionID      string
	RiskID               string
	WorkItemID           string
	Treatment            RiskTreatment
	OwnerID              string
	TargetAt             time.Time
	CompensatingControls []string
	RetestRequired       bool
	VerificationRequired bool
	Milestones           []RemediationMilestoneInput
	CreatedAt            time.Time
}

// RemediationReopenRecord is the immutable reason verified remediation reopened.
type RemediationReopenRecord struct {
	ID         string            `json:"id"`
	PlanID     string            `json:"plan_id"`
	Trigger    WorkReopenTrigger `json:"trigger"`
	SourceRef  string            `json:"source_ref"`
	ActorID    string            `json:"actor_id"`
	CreatedAt  time.Time         `json:"created_at"`
	RecordHash string            `json:"record_hash"`
}

// NewRemediationPlan creates a draft plan with pending milestones.
func NewRemediationPlan(input RemediationPlanInput) (RemediationPlan, error) {
	for name, value := range map[string]string{
		"plan id": input.ID, "tenant id": input.TenantID, "program id": input.ProgramID,
		"scope revision id": input.ScopeRevisionID, "risk id": input.RiskID,
		"work item id": input.WorkItemID, "owner id": input.OwnerID,
	} {
		if strings.TrimSpace(value) == "" {
			return RemediationPlan{}, fmt.Errorf("%w: %s is required", ErrInvalidRemediation, name)
		}
	}
	if !validRiskTreatment(input.Treatment) || input.Treatment == RiskTreatmentNone || len(input.Milestones) == 0 {
		return RemediationPlan{}, fmt.Errorf("%w: treatment and milestones are required", ErrInvalidRemediation)
	}
	createdAt := CanonicalTime(input.CreatedAt)
	targetAt := CanonicalTime(input.TargetAt)
	if createdAt.IsZero() || targetAt.IsZero() || targetAt.Before(createdAt) {
		return RemediationPlan{}, fmt.Errorf("%w: valid creation and target times are required", ErrInvalidRemediation)
	}
	milestones, err := buildMilestones(input.Milestones, createdAt)
	if err != nil {
		return RemediationPlan{}, err
	}
	return RemediationPlan{
		ID:                   strings.TrimSpace(input.ID),
		TenantID:             strings.TrimSpace(input.TenantID),
		ProgramID:            strings.TrimSpace(input.ProgramID),
		ScopeRevisionID:      strings.TrimSpace(input.ScopeRevisionID),
		RiskID:               strings.TrimSpace(input.RiskID),
		WorkItemID:           strings.TrimSpace(input.WorkItemID),
		Treatment:            input.Treatment,
		OwnerID:              strings.TrimSpace(input.OwnerID),
		TargetAt:             targetAt,
		CompensatingControls: normalizedStrings(input.CompensatingControls),
		RetestRequired:       input.RetestRequired,
		VerificationRequired: input.VerificationRequired,
		State:                RemediationDraft,
		Milestones:           milestones,
		Version:              1,
		UpdatedAt:            createdAt,
	}, nil
}

// ActivateRemediationPlan moves a validated draft or reopened plan into execution.
func ActivateRemediationPlan(current RemediationPlan, expectedVersion uint64, actorID string, at time.Time) (RemediationPlan, error) {
	if current.Version != expectedVersion {
		return RemediationPlan{}, versionConflict(expectedVersion, current.Version)
	}
	if current.State != RemediationDraft && current.State != RemediationReopened {
		return RemediationPlan{}, fmt.Errorf("%w: plan state %q cannot activate", ErrInvalidTransition, current.State)
	}
	if strings.TrimSpace(actorID) == "" || CanonicalTime(at).IsZero() {
		return RemediationPlan{}, fmt.Errorf("%w: actor and action time are required", ErrInvalidRemediation)
	}
	next := cloneRemediationPlan(current)
	next.State = RemediationActive
	next.Version++
	next.UpdatedAt = CanonicalTime(at)
	return next, nil
}

// StartRemediationMilestone moves an unblocked milestone into progress.
func StartRemediationMilestone(current RemediationPlan, expectedVersion uint64, milestoneID, actorID string, at time.Time) (RemediationPlan, error) {
	if current.Version != expectedVersion {
		return RemediationPlan{}, versionConflict(expectedVersion, current.Version)
	}
	if current.State != RemediationActive && current.State != RemediationReopened {
		return RemediationPlan{}, fmt.Errorf("%w: remediation plan is not active", ErrInvalidTransition)
	}
	if strings.TrimSpace(actorID) == "" || CanonicalTime(at).IsZero() {
		return RemediationPlan{}, fmt.Errorf("%w: actor and action time are required", ErrInvalidRemediation)
	}
	next := cloneRemediationPlan(current)
	index, err := milestoneIndex(next.Milestones, milestoneID)
	if err != nil {
		return RemediationPlan{}, err
	}
	if next.Milestones[index].State != MilestonePending && next.Milestones[index].State != MilestoneBlocked {
		return RemediationPlan{}, fmt.Errorf("%w: milestone state %q cannot start", ErrInvalidTransition, next.Milestones[index].State)
	}
	if !milestoneDependenciesComplete(next.Milestones, next.Milestones[index]) {
		return RemediationPlan{}, fmt.Errorf("%w: milestone dependencies are incomplete", ErrInvalidTransition)
	}
	next.Milestones[index].State = MilestoneInProgress
	next.Version++
	next.UpdatedAt = CanonicalTime(at)
	return next, nil
}

// CompleteRemediationMilestone records implementation evidence separately from verification.
func CompleteRemediationMilestone(current RemediationPlan, expectedVersion uint64, milestoneID, completedAction string, evidenceIDs []string, actorID string, at time.Time) (RemediationPlan, error) {
	if current.Version != expectedVersion {
		return RemediationPlan{}, versionConflict(expectedVersion, current.Version)
	}
	next := cloneRemediationPlan(current)
	index, err := milestoneIndex(next.Milestones, milestoneID)
	if err != nil {
		return RemediationPlan{}, err
	}
	at = CanonicalTime(at)
	if next.Milestones[index].State != MilestoneInProgress || strings.TrimSpace(completedAction) == "" || len(normalizedStrings(evidenceIDs)) == 0 || strings.TrimSpace(actorID) == "" || at.IsZero() {
		return RemediationPlan{}, fmt.Errorf("%w: in-progress milestone requires action, evidence, actor, and time", ErrInvalidRemediation)
	}
	milestone := &next.Milestones[index]
	milestone.State = MilestoneCompleted
	milestone.CompletedAction = strings.TrimSpace(completedAction)
	milestone.CompletionEvidenceIDs = normalizedStrings(evidenceIDs)
	milestone.CompletedBy = strings.TrimSpace(actorID)
	milestone.CompletedAt = at
	if allMilestonesImplemented(next.Milestones) && next.VerificationRequired {
		next.State = RemediationVerificationPending
	}
	next.Version++
	next.UpdatedAt = at
	return next, nil
}

// VerifyRemediationMilestone requires evidence from a verifier independent of implementation.
func VerifyRemediationMilestone(current RemediationPlan, expectedVersion uint64, milestoneID string, evidenceIDs []string, verifierID string, at time.Time) (RemediationPlan, error) {
	if current.Version != expectedVersion {
		return RemediationPlan{}, versionConflict(expectedVersion, current.Version)
	}
	if current.State != RemediationActive && current.State != RemediationReopened && current.State != RemediationVerificationPending {
		return RemediationPlan{}, fmt.Errorf("%w: plan state %q cannot verify milestones", ErrInvalidTransition, current.State)
	}
	next := cloneRemediationPlan(current)
	index, err := milestoneIndex(next.Milestones, milestoneID)
	if err != nil {
		return RemediationPlan{}, err
	}
	milestone := &next.Milestones[index]
	at = CanonicalTime(at)
	verifierID = strings.TrimSpace(verifierID)
	if milestone.State != MilestoneCompleted || len(normalizedStrings(evidenceIDs)) == 0 || verifierID == "" || at.IsZero() {
		return RemediationPlan{}, fmt.Errorf("%w: completed milestone requires verification evidence, verifier, and time", ErrInvalidRemediation)
	}
	if verifierID == milestone.CompletedBy || verifierID == next.OwnerID {
		return RemediationPlan{}, ErrIndependentReview
	}
	milestone.State = MilestoneVerified
	milestone.VerificationEvidenceIDs = normalizedStrings(evidenceIDs)
	milestone.VerifiedBy = verifierID
	milestone.VerifiedAt = at
	next.Version++
	next.UpdatedAt = at
	return next, nil
}

// CloseRemediationPlan requires every milestone and any configured independent verification.
func CloseRemediationPlan(current RemediationPlan, expectedVersion uint64, evidenceIDs []string, verifierID string, at time.Time) (RemediationPlan, error) {
	if current.Version != expectedVersion {
		return RemediationPlan{}, versionConflict(expectedVersion, current.Version)
	}
	if current.State != RemediationActive && current.State != RemediationVerificationPending {
		return RemediationPlan{}, fmt.Errorf("%w: plan state %q cannot close", ErrInvalidTransition, current.State)
	}
	for _, milestone := range current.Milestones {
		if current.VerificationRequired && milestone.State != MilestoneVerified {
			return RemediationPlan{}, fmt.Errorf("%w: milestone %q is not verified", ErrInvalidRemediation, milestone.ID)
		}
		if !current.VerificationRequired && milestone.State != MilestoneCompleted && milestone.State != MilestoneVerified {
			return RemediationPlan{}, fmt.Errorf("%w: milestone %q is incomplete", ErrInvalidRemediation, milestone.ID)
		}
	}
	next := cloneRemediationPlan(current)
	at = CanonicalTime(at)
	if at.IsZero() {
		return RemediationPlan{}, fmt.Errorf("%w: closure time is required", ErrInvalidRemediation)
	}
	if current.VerificationRequired {
		verifierID = strings.TrimSpace(verifierID)
		if len(normalizedStrings(evidenceIDs)) == 0 || verifierID == "" {
			return RemediationPlan{}, fmt.Errorf("%w: closure verification evidence and verifier are required", ErrInvalidRemediation)
		}
		if verifierID == current.OwnerID || verifierImplementedMilestone(current.Milestones, verifierID) {
			return RemediationPlan{}, ErrIndependentReview
		}
		next.VerificationEvidenceIDs = normalizedStrings(evidenceIDs)
		next.VerifiedBy = verifierID
	}
	next.State = RemediationClosed
	next.Version++
	next.UpdatedAt = at
	return next, nil
}

// ReopenRemediationPlan records the condition that invalidated verified closure.
func ReopenRemediationPlan(current RemediationPlan, expectedVersion uint64, trigger WorkReopenTrigger, sourceRef, actorID string, at time.Time) (RemediationPlan, RemediationReopenRecord, error) {
	if current.Version != expectedVersion {
		return RemediationPlan{}, RemediationReopenRecord{}, versionConflict(expectedVersion, current.Version)
	}
	if current.State != RemediationClosed || !validReopenTrigger(trigger) || strings.TrimSpace(sourceRef) == "" || strings.TrimSpace(actorID) == "" || CanonicalTime(at).IsZero() {
		return RemediationPlan{}, RemediationReopenRecord{}, fmt.Errorf("%w: closed plan, trigger, source, actor, and time are required", ErrInvalidTransition)
	}
	next := cloneRemediationPlan(current)
	next.State = RemediationReopened
	next.LastReopenTrigger = trigger
	next.VerificationEvidenceIDs = nil
	next.VerifiedBy = ""
	for index := range next.Milestones {
		milestone := &next.Milestones[index]
		if milestone.State != MilestoneVerified {
			continue
		}
		milestone.State = MilestoneCompleted
		milestone.VerificationEvidenceIDs = nil
		milestone.VerifiedBy = ""
		milestone.VerifiedAt = time.Time{}
	}
	next.Version++
	next.UpdatedAt = CanonicalTime(at)
	record := RemediationReopenRecord{
		PlanID:    current.ID,
		Trigger:   trigger,
		SourceRef: strings.TrimSpace(sourceRef),
		ActorID:   strings.TrimSpace(actorID),
		CreatedAt: CanonicalTime(at),
	}
	hash, err := hashDomainValue(record)
	if err != nil {
		return RemediationPlan{}, RemediationReopenRecord{}, err
	}
	record.RecordHash = hash
	record.ID = stableDomainID("compliance-remediation-reopen-", hash)
	return next, record, nil
}

func buildMilestones(inputs []RemediationMilestoneInput, createdAt time.Time) ([]RemediationMilestone, error) {
	result := make([]RemediationMilestone, 0, len(inputs))
	seen := map[string]struct{}{}
	for _, input := range inputs {
		id := strings.TrimSpace(input.ID)
		targetAt := CanonicalTime(input.TargetAt)
		if id == "" || strings.TrimSpace(input.Title) == "" || strings.TrimSpace(input.OwnerID) == "" || strings.TrimSpace(input.PlannedAction) == "" || targetAt.IsZero() || targetAt.Before(createdAt) {
			return nil, fmt.Errorf("%w: milestone identity, owner, action, and target are required", ErrInvalidRemediation)
		}
		if _, exists := seen[id]; exists {
			return nil, fmt.Errorf("%w: duplicate milestone %q", ErrInvalidRemediation, id)
		}
		seen[id] = struct{}{}
		result = append(result, RemediationMilestone{
			ID: id, Title: strings.TrimSpace(input.Title), OwnerID: strings.TrimSpace(input.OwnerID),
			TargetAt: targetAt, DependsOnIDs: normalizedStrings(input.DependsOnIDs),
			PlannedAction: strings.TrimSpace(input.PlannedAction), State: MilestonePending,
		})
	}
	for _, milestone := range result {
		for _, dependencyID := range milestone.DependsOnIDs {
			if dependencyID == milestone.ID {
				return nil, fmt.Errorf("%w: milestone %q depends on itself", ErrInvalidRemediation, milestone.ID)
			}
			if _, exists := seen[dependencyID]; !exists {
				return nil, fmt.Errorf("%w: milestone %q has unknown dependency %q", ErrInvalidRemediation, milestone.ID, dependencyID)
			}
		}
	}
	if hasMilestoneDependencyCycle(result) {
		return nil, fmt.Errorf("%w: milestone dependency cycle", ErrInvalidRemediation)
	}
	return result, nil
}

func hasMilestoneDependencyCycle(milestones []RemediationMilestone) bool {
	dependencies := make(map[string][]string, len(milestones))
	for _, milestone := range milestones {
		dependencies[milestone.ID] = milestone.DependsOnIDs
	}
	visiting := map[string]bool{}
	visited := map[string]bool{}
	var visit func(string) bool
	visit = func(id string) bool {
		if visiting[id] {
			return true
		}
		if visited[id] {
			return false
		}
		visiting[id] = true
		for _, dependencyID := range dependencies[id] {
			if visit(dependencyID) {
				return true
			}
		}
		visiting[id] = false
		visited[id] = true
		return false
	}
	for id := range dependencies {
		if visit(id) {
			return true
		}
	}
	return false
}

func milestoneIndex(milestones []RemediationMilestone, milestoneID string) (int, error) {
	milestoneID = strings.TrimSpace(milestoneID)
	for index := range milestones {
		if milestones[index].ID == milestoneID {
			return index, nil
		}
	}
	return 0, fmt.Errorf("%w: milestone %q was not found", ErrInvalidRemediation, milestoneID)
}

func milestoneDependenciesComplete(milestones []RemediationMilestone, candidate RemediationMilestone) bool {
	for _, dependencyID := range candidate.DependsOnIDs {
		for _, milestone := range milestones {
			if milestone.ID == dependencyID && milestone.State != MilestoneCompleted && milestone.State != MilestoneVerified {
				return false
			}
		}
	}
	return true
}

func allMilestonesImplemented(milestones []RemediationMilestone) bool {
	for _, milestone := range milestones {
		if milestone.State != MilestoneCompleted && milestone.State != MilestoneVerified {
			return false
		}
	}
	return true
}

func verifierImplementedMilestone(milestones []RemediationMilestone, verifierID string) bool {
	for _, milestone := range milestones {
		if milestone.CompletedBy == verifierID {
			return true
		}
	}
	return false
}

func cloneRemediationPlan(value RemediationPlan) RemediationPlan {
	value.CompensatingControls = append([]string(nil), value.CompensatingControls...)
	value.VerificationEvidenceIDs = append([]string(nil), value.VerificationEvidenceIDs...)
	value.Milestones = append([]RemediationMilestone(nil), value.Milestones...)
	for index := range value.Milestones {
		milestone := &value.Milestones[index]
		milestone.DependsOnIDs = append([]string(nil), milestone.DependsOnIDs...)
		milestone.CompletionEvidenceIDs = append([]string(nil), milestone.CompletionEvidenceIDs...)
		milestone.VerificationEvidenceIDs = append([]string(nil), milestone.VerificationEvidenceIDs...)
	}
	return value
}
