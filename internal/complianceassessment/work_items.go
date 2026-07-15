package complianceassessment

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

const WorkFingerprintVersion = "compliance-work-fingerprint/v1"

var (
	ErrInvalidWorkItem     = errors.New("invalid compliance work item")
	ErrDuplicateOccurrence = errors.New("duplicate compliance work occurrence")
)

// WorkItemKind identifies the concrete operating job represented by an item.
type WorkItemKind string

const (
	WorkRemediateFinding     WorkItemKind = "remediate_finding"
	WorkCollectEvidence      WorkItemKind = "collect_evidence"
	WorkRefreshEvidence      WorkItemKind = "refresh_evidence"
	WorkResolveConflict      WorkItemKind = "resolve_conflict"
	WorkReviewManualEvidence WorkItemKind = "review_manual_evidence"
	WorkRepairSource         WorkItemKind = "repair_source"
	WorkAssignOwner          WorkItemKind = "assign_owner"
	WorkMapControl           WorkItemKind = "map_control"
	WorkRenewException       WorkItemKind = "renew_exception"
	WorkResolvePolicyGap     WorkItemKind = "resolve_policy_gap"
	WorkCompleteAccessChange WorkItemKind = "complete_access_change"
	WorkAnswerAuditRequest   WorkItemKind = "answer_audit_request"
	WorkReviewVendor         WorkItemKind = "review_vendor"
)

// WorkItemState is the explicit current-state projection for operating work.
type WorkItemState string

const (
	WorkOpen       WorkItemState = "open"
	WorkInProgress WorkItemState = "in_progress"
	WorkBlocked    WorkItemState = "blocked"
	WorkResolved   WorkItemState = "resolved"
	WorkAccepted   WorkItemState = "accepted"
	WorkSnoozed    WorkItemState = "snoozed"
	WorkSuperseded WorkItemState = "superseded"
)

// WorkAction is an auditable operating action rather than an implicit state write.
type WorkAction string

const (
	WorkActionAssign          WorkAction = "assign"
	WorkActionRequestEvidence WorkAction = "request_evidence"
	WorkActionBlock           WorkAction = "block"
	WorkActionSnooze          WorkAction = "snooze"
	WorkActionAccept          WorkAction = "accept"
	WorkActionRemediate       WorkAction = "remediate"
	WorkActionVerify          WorkAction = "verify"
	WorkActionClose           WorkAction = "close"
	WorkActionSupersede       WorkAction = "supersede"
)

// WorkReopenTrigger identifies the external condition that invalidated closure.
type WorkReopenTrigger string

const (
	ReopenExceptionExpired   WorkReopenTrigger = "exception_expired"
	ReopenEvidenceStale      WorkReopenTrigger = "evidence_stale"
	ReopenEvidenceRevoked    WorkReopenTrigger = "evidence_revoked"
	ReopenFindingReopened    WorkReopenTrigger = "finding_reopened"
	ReopenSourceCoverageLost WorkReopenTrigger = "source_coverage_lost"
	ReopenScopeSubjectAdded  WorkReopenTrigger = "scope_subject_added"
)

// WorkFingerprintInput is the versioned identity basis shared across assessment runs.
type WorkFingerprintInput struct {
	TenantID        string       `json:"tenant_id"`
	ProgramID       string       `json:"program_id"`
	ScopeRevisionID string       `json:"scope_revision_id"`
	ControlID       string       `json:"control_id"`
	ObjectiveID     string       `json:"objective_id"`
	Kind            WorkItemKind `json:"kind"`
	SubjectID       string       `json:"subject_id"`
	Reason          ReasonCode   `json:"reason"`
	SourceID        string       `json:"source_id"`
}

// WorkOccurrence is one immutable observation of the work condition in a run.
type WorkOccurrence struct {
	ID                  string    `json:"id"`
	WorkItemID          string    `json:"work_item_id"`
	AssessmentRunID     string    `json:"assessment_run_id"`
	ObjectiveResultID   string    `json:"objective_result_id"`
	AutomatedResultHash string    `json:"automated_result_hash"`
	EvidenceIDs         []string  `json:"evidence_ids,omitempty"`
	FindingIDs          []string  `json:"finding_ids,omitempty"`
	OccurredAt          time.Time `json:"occurred_at"`
	OccurrenceHash      string    `json:"occurrence_hash"`
}

// WorkOccurrenceInput supplies one exact run occurrence.
type WorkOccurrenceInput struct {
	AssessmentRunID     string
	ObjectiveResultID   string
	AutomatedResultHash string
	EvidenceIDs         []string
	FindingIDs          []string
	OccurredAt          time.Time
}

// WorkItem is the stable cross-run operating queue projection.
type WorkItem struct {
	ID                      string               `json:"id"`
	FingerprintVersion      string               `json:"fingerprint_version"`
	Fingerprint             string               `json:"fingerprint"`
	Basis                   WorkFingerprintInput `json:"basis"`
	State                   WorkItemState        `json:"state"`
	OwnerID                 string               `json:"owner_id"`
	DueAt                   time.Time            `json:"due_at"`
	Priority                string               `json:"priority"`
	BlockerReason           string               `json:"blocker_reason,omitempty"`
	SnoozeUntil             time.Time            `json:"snooze_until,omitempty"`
	RiskID                  string               `json:"risk_id,omitempty"`
	ExceptionID             string               `json:"exception_id,omitempty"`
	VerificationRequired    bool                 `json:"verification_required"`
	VerificationEvidenceIDs []string             `json:"verification_evidence_ids,omitempty"`
	VerifiedBy              string               `json:"verified_by,omitempty"`
	LastRemediatedBy        string               `json:"last_remediated_by,omitempty"`
	Occurrences             []WorkOccurrence     `json:"occurrences"`
	LastReopenTrigger       WorkReopenTrigger    `json:"last_reopen_trigger,omitempty"`
	Version                 uint64               `json:"version"`
	UpdatedAt               time.Time            `json:"updated_at"`
}

// WorkItemInput creates one item and its first occurrence.
type WorkItemInput struct {
	Basis                WorkFingerprintInput
	OwnerID              string
	DueAt                time.Time
	Priority             string
	RiskID               string
	ExceptionID          string
	VerificationRequired bool
	Occurrence           WorkOccurrenceInput
}

// WorkActionInput contains the basis for one explicit work action.
type WorkActionInput struct {
	Action        WorkAction
	OwnerID       string
	Rationale     string
	BlockerReason string
	SnoozeUntil   time.Time
	EvidenceIDs   []string
	ActorID       string
	At            time.Time
}

// WorkActionRecord is an immutable action record emitted with a work transition.
type WorkActionRecord struct {
	ID         string        `json:"id"`
	WorkItemID string        `json:"work_item_id"`
	Action     WorkAction    `json:"action"`
	From       WorkItemState `json:"from"`
	To         WorkItemState `json:"to"`
	OwnerID    string        `json:"owner_id"`
	Rationale  string        `json:"rationale"`
	ActorID    string        `json:"actor_id"`
	CreatedAt  time.Time     `json:"created_at"`
	ActionHash string        `json:"action_hash"`
}

// WorkReopenRecord is the immutable reason a terminal item became active again.
type WorkReopenRecord struct {
	ID         string            `json:"id"`
	WorkItemID string            `json:"work_item_id"`
	Trigger    WorkReopenTrigger `json:"trigger"`
	SourceRef  string            `json:"source_ref"`
	ActorID    string            `json:"actor_id"`
	CreatedAt  time.Time         `json:"created_at"`
	RecordHash string            `json:"record_hash"`
}

// ComputeWorkFingerprint returns the stable, versioned cross-run work identity.
func ComputeWorkFingerprint(input WorkFingerprintInput) (string, error) {
	input = normalizeWorkFingerprintInput(input)
	if input.TenantID == "" || input.ProgramID == "" || input.ScopeRevisionID == "" || input.ControlID == "" || input.ObjectiveID == "" ||
		input.SubjectID == "" || input.SourceID == "" || !validWorkKind(input.Kind) || !knownReasonCode(input.Reason) {
		return "", fmt.Errorf("%w: fingerprint basis is incomplete", ErrInvalidWorkItem)
	}
	payload := struct {
		Version string               `json:"version"`
		Basis   WorkFingerprintInput `json:"basis"`
	}{Version: WorkFingerprintVersion, Basis: input}
	return hashDomainValue(payload)
}

// NewWorkItem creates one stable work item and first immutable run occurrence.
func NewWorkItem(input WorkItemInput) (WorkItem, WorkOccurrence, error) {
	fingerprint, err := ComputeWorkFingerprint(input.Basis)
	if err != nil {
		return WorkItem{}, WorkOccurrence{}, err
	}
	ownerID := strings.TrimSpace(input.OwnerID)
	dueAt := CanonicalTime(input.DueAt)
	if ownerID == "" || dueAt.IsZero() || strings.TrimSpace(input.Priority) == "" {
		return WorkItem{}, WorkOccurrence{}, fmt.Errorf("%w: owner, due date, and priority are required", ErrInvalidWorkItem)
	}
	item := WorkItem{
		ID:                   stableDomainID("compliance-work-item-", fingerprint),
		FingerprintVersion:   WorkFingerprintVersion,
		Fingerprint:          fingerprint,
		Basis:                normalizeWorkFingerprintInput(input.Basis),
		State:                WorkOpen,
		OwnerID:              ownerID,
		DueAt:                dueAt,
		Priority:             strings.TrimSpace(input.Priority),
		RiskID:               strings.TrimSpace(input.RiskID),
		ExceptionID:          strings.TrimSpace(input.ExceptionID),
		VerificationRequired: input.VerificationRequired,
		Version:              1,
	}
	occurrence, err := buildWorkOccurrence(item.ID, input.Occurrence)
	if err != nil {
		return WorkItem{}, WorkOccurrence{}, err
	}
	item.Occurrences = []WorkOccurrence{occurrence}
	item.UpdatedAt = occurrence.OccurredAt
	return item, occurrence, nil
}

// RecordWorkOccurrence attaches one new run to the stable work item.
func RecordWorkOccurrence(current WorkItem, expectedVersion uint64, input WorkOccurrenceInput) (WorkItem, WorkOccurrence, error) {
	if current.Version != expectedVersion {
		return WorkItem{}, WorkOccurrence{}, versionConflict(expectedVersion, current.Version)
	}
	for _, occurrence := range current.Occurrences {
		if occurrence.AssessmentRunID == strings.TrimSpace(input.AssessmentRunID) {
			return WorkItem{}, WorkOccurrence{}, ErrDuplicateOccurrence
		}
	}
	occurrence, err := buildWorkOccurrence(current.ID, input)
	if err != nil {
		return WorkItem{}, WorkOccurrence{}, err
	}
	next := cloneWorkItem(current)
	next.Occurrences = append(next.Occurrences, occurrence)
	next.Version++
	next.UpdatedAt = occurrence.OccurredAt
	return next, occurrence, nil
}

// ApplyWorkAction applies a named action and returns its immutable audit record.
func ApplyWorkAction(current WorkItem, expectedVersion uint64, input WorkActionInput) (WorkItem, WorkActionRecord, error) {
	if current.Version != expectedVersion {
		return WorkItem{}, WorkActionRecord{}, versionConflict(expectedVersion, current.Version)
	}
	actorID := strings.TrimSpace(input.ActorID)
	rationale := strings.TrimSpace(input.Rationale)
	at := CanonicalTime(input.At)
	if actorID == "" || rationale == "" || at.IsZero() {
		return WorkItem{}, WorkActionRecord{}, fmt.Errorf("%w: actor, rationale, and action time are required", ErrInvalidWorkItem)
	}
	next := cloneWorkItem(current)
	to, err := workActionTarget(current, input, at)
	if err != nil {
		return WorkItem{}, WorkActionRecord{}, err
	}
	next.State = to
	if next.State != WorkBlocked {
		next.BlockerReason = ""
	}
	if next.State != WorkSnoozed {
		next.SnoozeUntil = time.Time{}
	}
	if value := strings.TrimSpace(input.OwnerID); value != "" {
		next.OwnerID = value
	}
	if input.Action == WorkActionBlock || input.Action == WorkActionRequestEvidence {
		next.BlockerReason = strings.TrimSpace(input.BlockerReason)
	}
	if input.Action == WorkActionSnooze {
		next.SnoozeUntil = CanonicalTime(input.SnoozeUntil)
	}
	if input.Action == WorkActionRemediate {
		next.LastRemediatedBy = actorID
		next.VerificationEvidenceIDs = nil
		next.VerifiedBy = ""
	}
	if input.Action == WorkActionVerify {
		next.VerificationEvidenceIDs = normalizedStrings(input.EvidenceIDs)
		next.VerifiedBy = actorID
	}
	next.Version++
	next.UpdatedAt = at
	record := WorkActionRecord{
		WorkItemID: current.ID,
		Action:     input.Action,
		From:       current.State,
		To:         next.State,
		OwnerID:    next.OwnerID,
		Rationale:  rationale,
		ActorID:    actorID,
		CreatedAt:  at,
	}
	hash, err := hashDomainValue(record)
	if err != nil {
		return WorkItem{}, WorkActionRecord{}, err
	}
	record.ActionHash = hash
	record.ID = stableDomainID("compliance-work-action-", hash)
	return next, record, nil
}

// ReopenWorkItem creates concrete owned work when a prior disposition becomes invalid.
func ReopenWorkItem(current WorkItem, expectedVersion uint64, trigger WorkReopenTrigger, sourceRef, ownerID, actorID string, dueAt, at time.Time) (WorkItem, WorkReopenRecord, error) {
	if current.Version != expectedVersion {
		return WorkItem{}, WorkReopenRecord{}, versionConflict(expectedVersion, current.Version)
	}
	if current.State != WorkResolved && current.State != WorkAccepted && current.State != WorkSnoozed && current.State != WorkSuperseded {
		return WorkItem{}, WorkReopenRecord{}, fmt.Errorf("%w: state %q cannot reopen", ErrInvalidTransition, current.State)
	}
	if !validReopenTrigger(trigger) || strings.TrimSpace(sourceRef) == "" || strings.TrimSpace(ownerID) == "" || strings.TrimSpace(actorID) == "" {
		return WorkItem{}, WorkReopenRecord{}, fmt.Errorf("%w: trigger, source, owner, and actor are required", ErrInvalidWorkItem)
	}
	dueAt = CanonicalTime(dueAt)
	at = CanonicalTime(at)
	if dueAt.IsZero() || at.IsZero() || dueAt.Before(at) {
		return WorkItem{}, WorkReopenRecord{}, fmt.Errorf("%w: reopen requires a current action time and due date", ErrInvalidWorkItem)
	}
	next := cloneWorkItem(current)
	next.State = WorkOpen
	next.OwnerID = strings.TrimSpace(ownerID)
	next.DueAt = dueAt
	next.BlockerReason = ""
	next.SnoozeUntil = time.Time{}
	next.VerificationEvidenceIDs = nil
	next.VerifiedBy = ""
	next.LastReopenTrigger = trigger
	next.Version++
	next.UpdatedAt = at
	record := WorkReopenRecord{
		WorkItemID: current.ID,
		Trigger:    trigger,
		SourceRef:  strings.TrimSpace(sourceRef),
		ActorID:    strings.TrimSpace(actorID),
		CreatedAt:  at,
	}
	hash, err := hashDomainValue(record)
	if err != nil {
		return WorkItem{}, WorkReopenRecord{}, err
	}
	record.RecordHash = hash
	record.ID = stableDomainID("compliance-work-reopen-", hash)
	return next, record, nil
}

func buildWorkOccurrence(workItemID string, input WorkOccurrenceInput) (WorkOccurrence, error) {
	runID := strings.TrimSpace(input.AssessmentRunID)
	resultID := strings.TrimSpace(input.ObjectiveResultID)
	hash := strings.TrimSpace(input.AutomatedResultHash)
	occurredAt := CanonicalTime(input.OccurredAt)
	if runID == "" || resultID == "" || occurredAt.IsZero() || !validDigestString(hash) {
		return WorkOccurrence{}, fmt.Errorf("%w: run, result, automated hash, and occurrence time are required", ErrInvalidWorkItem)
	}
	occurrence := WorkOccurrence{
		WorkItemID:          strings.TrimSpace(workItemID),
		AssessmentRunID:     runID,
		ObjectiveResultID:   resultID,
		AutomatedResultHash: hash,
		EvidenceIDs:         normalizedStrings(input.EvidenceIDs),
		FindingIDs:          normalizedStrings(input.FindingIDs),
		OccurredAt:          occurredAt,
	}
	occurrenceHash, err := hashDomainValue(occurrence)
	if err != nil {
		return WorkOccurrence{}, err
	}
	occurrence.OccurrenceHash = occurrenceHash
	identityHash := digestBytes([]byte(strings.Join([]string{occurrence.WorkItemID, runID, resultID, hash}, "\x00")))
	occurrence.ID = stableDomainID("compliance-work-occurrence-", identityHash)
	return occurrence, nil
}

func workActionTarget(current WorkItem, input WorkActionInput, at time.Time) (WorkItemState, error) {
	switch input.Action {
	case WorkActionAssign:
		if strings.TrimSpace(input.OwnerID) == "" || current.State == WorkSuperseded {
			return "", fmt.Errorf("%w: assign requires owner on active work", ErrInvalidTransition)
		}
		return current.State, nil
	case WorkActionRequestEvidence, WorkActionBlock:
		if strings.TrimSpace(input.BlockerReason) == "" || (current.State != WorkOpen && current.State != WorkInProgress) {
			return "", fmt.Errorf("%w: block requires active work and blocker reason", ErrInvalidTransition)
		}
		return WorkBlocked, nil
	case WorkActionSnooze:
		if CanonicalTime(input.SnoozeUntil).IsZero() || !CanonicalTime(input.SnoozeUntil).After(at) || current.State == WorkResolved || current.State == WorkSuperseded {
			return "", fmt.Errorf("%w: snooze requires active work and future wake time", ErrInvalidTransition)
		}
		return WorkSnoozed, nil
	case WorkActionAccept:
		if strings.TrimSpace(current.RiskID) == "" && strings.TrimSpace(current.ExceptionID) == "" {
			return "", fmt.Errorf("%w: accept requires linked risk or exception", ErrInvalidTransition)
		}
		if current.State != WorkOpen && current.State != WorkInProgress && current.State != WorkBlocked {
			return "", fmt.Errorf("%w: work is not accept-ready", ErrInvalidTransition)
		}
		return WorkAccepted, nil
	case WorkActionRemediate:
		if current.State == WorkResolved || current.State == WorkAccepted || current.State == WorkSuperseded {
			return "", fmt.Errorf("%w: terminal work cannot enter remediation", ErrInvalidTransition)
		}
		return WorkInProgress, nil
	case WorkActionVerify:
		if current.State != WorkInProgress && current.State != WorkBlocked {
			return "", fmt.Errorf("%w: only active work can resolve", ErrInvalidTransition)
		}
		if current.VerificationRequired {
			if len(normalizedStrings(input.EvidenceIDs)) == 0 {
				return "", fmt.Errorf("%w: verification evidence is required", ErrInvalidTransition)
			}
			actorID := strings.TrimSpace(input.ActorID)
			if actorID == current.OwnerID || actorID == current.LastRemediatedBy {
				return "", ErrIndependentReview
			}
		}
		return WorkResolved, nil
	case WorkActionClose:
		if current.VerificationRequired {
			return "", fmt.Errorf("%w: verification-required work must use verify", ErrInvalidTransition)
		}
		if current.State != WorkInProgress && current.State != WorkBlocked {
			return "", fmt.Errorf("%w: only active work can resolve", ErrInvalidTransition)
		}
		return WorkResolved, nil
	case WorkActionSupersede:
		if current.State == WorkSuperseded {
			return "", fmt.Errorf("%w: work is already superseded", ErrInvalidTransition)
		}
		return WorkSuperseded, nil
	default:
		return "", fmt.Errorf("%w: unknown work action %q", ErrInvalidTransition, input.Action)
	}
}

func normalizeWorkFingerprintInput(input WorkFingerprintInput) WorkFingerprintInput {
	input.TenantID = strings.TrimSpace(input.TenantID)
	input.ProgramID = strings.TrimSpace(input.ProgramID)
	input.ScopeRevisionID = strings.TrimSpace(input.ScopeRevisionID)
	input.ControlID = strings.TrimSpace(input.ControlID)
	input.ObjectiveID = strings.TrimSpace(input.ObjectiveID)
	input.SubjectID = strings.TrimSpace(input.SubjectID)
	input.SourceID = strings.TrimSpace(input.SourceID)
	return input
}

func cloneWorkItem(value WorkItem) WorkItem {
	value.VerificationEvidenceIDs = append([]string(nil), value.VerificationEvidenceIDs...)
	value.Occurrences = append([]WorkOccurrence(nil), value.Occurrences...)
	for index := range value.Occurrences {
		value.Occurrences[index].EvidenceIDs = append([]string(nil), value.Occurrences[index].EvidenceIDs...)
		value.Occurrences[index].FindingIDs = append([]string(nil), value.Occurrences[index].FindingIDs...)
	}
	return value
}

func validWorkKind(value WorkItemKind) bool {
	switch value {
	case WorkRemediateFinding, WorkCollectEvidence, WorkRefreshEvidence, WorkResolveConflict,
		WorkReviewManualEvidence, WorkRepairSource, WorkAssignOwner, WorkMapControl,
		WorkRenewException, WorkResolvePolicyGap, WorkCompleteAccessChange,
		WorkAnswerAuditRequest, WorkReviewVendor:
		return true
	default:
		return false
	}
}

func validReopenTrigger(value WorkReopenTrigger) bool {
	switch value {
	case ReopenExceptionExpired, ReopenEvidenceStale, ReopenEvidenceRevoked,
		ReopenFindingReopened, ReopenSourceCoverageLost, ReopenScopeSubjectAdded:
		return true
	default:
		return false
	}
}

func validDigestString(value string) bool {
	return len(value) == len("sha256:")+64 && strings.HasPrefix(value, "sha256:") && strings.Trim(value[len("sha256:"):], "0123456789abcdef") == ""
}
