package complianceremediation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/complianceassessment"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/workflowevents"
)

var (
	ErrUnavailable    = errors.New("compliance remediation runtime is unavailable")
	ErrNotFound       = errors.New("compliance remediation record not found")
	ErrInvalidRequest = errors.New("invalid compliance remediation request")
)

// ProjectionMetadata identifies one append-log event applied to current state.
type ProjectionMetadata struct {
	EventID         string
	ExpectedVersion uint64
	OccurredAt      time.Time
}

// WorkItemRecord is one current work item with its immutable operating history.
type WorkItemRecord struct {
	Item        complianceassessment.WorkItem           `json:"item"`
	Occurrences []complianceassessment.WorkOccurrence   `json:"occurrences"`
	Actions     []complianceassessment.WorkActionRecord `json:"actions"`
}

// Store is the tenant-scoped current-state read boundary.
type Store interface {
	GetWorkItem(context.Context, string, string) (WorkItemRecord, error)
	GetRemediationPlan(context.Context, string, string) (complianceassessment.RemediationPlan, error)
}

// Projector applies replay-safe current-state projections after append succeeds.
type Projector interface {
	ProjectWorkOccurrence(context.Context, ProjectionMetadata, complianceassessment.WorkItem, complianceassessment.WorkOccurrence) error
	ProjectWorkAction(context.Context, ProjectionMetadata, complianceassessment.WorkItem, complianceassessment.WorkActionRecord) error
	ProjectWorkReopen(context.Context, ProjectionMetadata, complianceassessment.WorkItem, complianceassessment.WorkReopenRecord) error
	ProjectRemediationPlan(context.Context, ProjectionMetadata, complianceassessment.RemediationPlan) error
	ProjectRemediationReopen(context.Context, ProjectionMetadata, complianceassessment.RemediationPlan, complianceassessment.RemediationReopenRecord) error
}

// Service owns append-first work and remediation transitions.
type Service struct {
	store     Store
	projector Projector
	log       ports.AppendLog
	replayer  ports.EventReplayPager
	now       func() time.Time
}

// New constructs a remediation runtime from durable capabilities.
func New(store Store, projector Projector, log ports.AppendLog, replayer ports.EventReplayPager) *Service {
	return &Service{store: store, projector: projector, log: log, replayer: replayer, now: time.Now}
}

// DeriveWorkInput binds one failed assessment result to stable, owned work.
type DeriveWorkInput struct {
	TenantID            string                               `json:"tenant_id"`
	ProgramID           string                               `json:"program_id"`
	ScopeRevisionID     string                               `json:"scope_revision_id"`
	SubjectID           string                               `json:"subject_id"`
	SourceID            string                               `json:"source_id"`
	OwnerID             string                               `json:"owner_id"`
	DueAt               time.Time                            `json:"due_at"`
	Priority            string                               `json:"priority"`
	AssessmentRunID     string                               `json:"assessment_run_id"`
	AutomatedResultHash string                               `json:"automated_result_hash"`
	Result              complianceassessment.ObjectiveResult `json:"result"`
}

// DeriveWork creates or extends stable work for one failed assessment result.
func (s *Service) DeriveWork(ctx context.Context, input DeriveWorkInput, actorID string) (WorkItemRecord, error) {
	if err := s.ready(); err != nil {
		return WorkItemRecord{}, err
	}
	itemInput, err := workItemInput(input)
	if err != nil {
		return WorkItemRecord{}, err
	}
	item, occurrence, err := complianceassessment.NewWorkItem(itemInput)
	if err != nil {
		return WorkItemRecord{}, err
	}
	existing, getErr := s.store.GetWorkItem(ctx, item.Basis.TenantID, item.ID)
	switch {
	case getErr == nil:
		for _, recorded := range existing.Occurrences {
			if recorded.AssessmentRunID == occurrence.AssessmentRunID {
				return existing, nil
			}
		}
		item, occurrence, err = complianceassessment.RecordWorkOccurrence(existing.Item, existing.Item.Version, itemInput.Occurrence)
		if err != nil {
			return WorkItemRecord{}, err
		}
	case !errors.Is(getErr, ErrNotFound):
		return WorkItemRecord{}, getErr
	}
	payload := workOccurrencePayload{Item: item, Occurrence: occurrence}
	metadata, event, err := s.append(ctx, workflowevents.EventKindComplianceWorkItemUpdated, "work_occurrence", item.ID, item.Version, "failed_result_recorded", actorID, item.UpdatedAt, payload)
	if err != nil {
		return WorkItemRecord{}, err
	}
	if err := s.projector.ProjectWorkOccurrence(ctx, metadata, item, occurrence); err != nil {
		return WorkItemRecord{}, fmt.Errorf("project work event %q: %w", event.GetId(), err)
	}
	return s.store.GetWorkItem(ctx, item.Basis.TenantID, item.ID)
}

// GetWorkItem reads one tenant-scoped work item.
func (s *Service) GetWorkItem(ctx context.Context, tenantID, workItemID string) (WorkItemRecord, error) {
	if err := s.ready(); err != nil {
		return WorkItemRecord{}, err
	}
	return s.store.GetWorkItem(ctx, strings.TrimSpace(tenantID), strings.TrimSpace(workItemID))
}

// WorkCommand applies an explicit operating action or invalidation.
type WorkCommand struct {
	Operation       string                                 `json:"operation"`
	ExpectedVersion uint64                                 `json:"expected_version"`
	Action          complianceassessment.WorkAction        `json:"action,omitempty"`
	OwnerID         string                                 `json:"owner_id,omitempty"`
	Rationale       string                                 `json:"rationale,omitempty"`
	BlockerReason   string                                 `json:"blocker_reason,omitempty"`
	SnoozeUntil     time.Time                              `json:"snooze_until,omitempty"`
	EvidenceIDs     []string                               `json:"evidence_ids,omitempty"`
	Trigger         complianceassessment.WorkReopenTrigger `json:"trigger,omitempty"`
	SourceRef       string                                 `json:"source_ref,omitempty"`
	DueAt           time.Time                              `json:"due_at,omitempty"`
	ActorID         string                                 `json:"actor_id"`
	At              time.Time                              `json:"at"`
}

// ApplyWorkCommand records a state transition without executing an external action.
func (s *Service) ApplyWorkCommand(ctx context.Context, tenantID, workItemID string, command WorkCommand) (WorkItemRecord, error) {
	if err := s.ready(); err != nil {
		return WorkItemRecord{}, err
	}
	record, err := s.store.GetWorkItem(ctx, strings.TrimSpace(tenantID), strings.TrimSpace(workItemID))
	if err != nil {
		return WorkItemRecord{}, err
	}
	if command.At.IsZero() {
		command.At = s.now().UTC()
	}
	switch strings.TrimSpace(command.Operation) {
	case "action":
		next, action, err := complianceassessment.ApplyWorkAction(record.Item, command.ExpectedVersion, complianceassessment.WorkActionInput{
			Action: command.Action, OwnerID: command.OwnerID, Rationale: command.Rationale,
			BlockerReason: command.BlockerReason, SnoozeUntil: command.SnoozeUntil,
			EvidenceIDs: command.EvidenceIDs, ActorID: command.ActorID, At: command.At,
		})
		if err != nil {
			return WorkItemRecord{}, err
		}
		payload := workActionPayload{Item: next, Action: action}
		metadata, event, err := s.append(ctx, workflowevents.EventKindComplianceWorkItemUpdated, "work_action", next.ID, next.Version, string(action.Action), command.ActorID, action.CreatedAt, payload)
		if err != nil {
			return WorkItemRecord{}, err
		}
		if err := s.projector.ProjectWorkAction(ctx, metadata, next, action); err != nil {
			return WorkItemRecord{}, fmt.Errorf("project work event %q: %w", event.GetId(), err)
		}
	case "invalidate":
		if !supportedInvalidation(command.Trigger) {
			return WorkItemRecord{}, fmt.Errorf("%w: unsupported invalidation trigger %q", ErrInvalidRequest, command.Trigger)
		}
		next, reopen, err := complianceassessment.ReopenWorkItem(record.Item, command.ExpectedVersion, command.Trigger, command.SourceRef, command.OwnerID, command.ActorID, command.DueAt, command.At)
		if err != nil {
			return WorkItemRecord{}, err
		}
		payload := workReopenPayload{Item: next, Reopen: reopen}
		metadata, event, err := s.append(ctx, workflowevents.EventKindComplianceWorkItemUpdated, "work_reopen", next.ID, next.Version, "invalidated", command.ActorID, reopen.CreatedAt, payload)
		if err != nil {
			return WorkItemRecord{}, err
		}
		if err := s.projector.ProjectWorkReopen(ctx, metadata, next, reopen); err != nil {
			return WorkItemRecord{}, fmt.Errorf("project work event %q: %w", event.GetId(), err)
		}
	default:
		return WorkItemRecord{}, fmt.Errorf("%w: operation must be action or invalidate", ErrInvalidRequest)
	}
	return s.store.GetWorkItem(ctx, strings.TrimSpace(tenantID), strings.TrimSpace(workItemID))
}

// CreateRemediationPlan creates an owned plan with mandatory independent verification.
func (s *Service) CreateRemediationPlan(ctx context.Context, input complianceassessment.RemediationPlanInput, actorID string) (complianceassessment.RemediationPlan, error) {
	if err := s.ready(); err != nil {
		return complianceassessment.RemediationPlan{}, err
	}
	input.VerificationRequired = true
	if input.CreatedAt.IsZero() {
		input.CreatedAt = s.now().UTC()
	}
	plan, err := complianceassessment.NewRemediationPlan(input)
	if err != nil {
		return complianceassessment.RemediationPlan{}, err
	}
	metadata, event, err := s.append(ctx, workflowevents.EventKindComplianceRemediationMilestoneUpdated, "remediation_plan", plan.ID, plan.Version, "created", actorID, plan.UpdatedAt, remediationPayload{Plan: plan})
	if err != nil {
		return complianceassessment.RemediationPlan{}, err
	}
	if err := s.projector.ProjectRemediationPlan(ctx, metadata, plan); err != nil {
		return complianceassessment.RemediationPlan{}, fmt.Errorf("project remediation event %q: %w", event.GetId(), err)
	}
	return s.store.GetRemediationPlan(ctx, plan.TenantID, plan.ID)
}

// GetRemediationPlan reads one tenant-scoped remediation plan.
func (s *Service) GetRemediationPlan(ctx context.Context, tenantID, planID string) (complianceassessment.RemediationPlan, error) {
	if err := s.ready(); err != nil {
		return complianceassessment.RemediationPlan{}, err
	}
	return s.store.GetRemediationPlan(ctx, strings.TrimSpace(tenantID), strings.TrimSpace(planID))
}

// RemediationCommand applies one plan or milestone transition.
type RemediationCommand struct {
	Operation       string                                 `json:"operation"`
	ExpectedVersion uint64                                 `json:"expected_version"`
	MilestoneID     string                                 `json:"milestone_id,omitempty"`
	CompletedAction string                                 `json:"completed_action,omitempty"`
	EvidenceIDs     []string                               `json:"evidence_ids,omitempty"`
	Trigger         complianceassessment.WorkReopenTrigger `json:"trigger,omitempty"`
	SourceRef       string                                 `json:"source_ref,omitempty"`
	ActorID         string                                 `json:"actor_id"`
	At              time.Time                              `json:"at"`
}

// ApplyRemediationCommand records plan progress, verification, closure, or invalidation.
func (s *Service) ApplyRemediationCommand(ctx context.Context, tenantID, planID string, command RemediationCommand) (complianceassessment.RemediationPlan, error) {
	if err := s.ready(); err != nil {
		return complianceassessment.RemediationPlan{}, err
	}
	current, err := s.store.GetRemediationPlan(ctx, strings.TrimSpace(tenantID), strings.TrimSpace(planID))
	if err != nil {
		return complianceassessment.RemediationPlan{}, err
	}
	if command.At.IsZero() {
		command.At = s.now().UTC()
	}
	var next complianceassessment.RemediationPlan
	operation := strings.TrimSpace(command.Operation)
	switch operation {
	case "activate":
		next, err = complianceassessment.ActivateRemediationPlan(current, command.ExpectedVersion, command.ActorID, command.At)
	case "start_milestone":
		next, err = complianceassessment.StartRemediationMilestone(current, command.ExpectedVersion, command.MilestoneID, command.ActorID, command.At)
	case "complete_milestone":
		next, err = complianceassessment.CompleteRemediationMilestone(current, command.ExpectedVersion, command.MilestoneID, command.CompletedAction, command.EvidenceIDs, command.ActorID, command.At)
	case "verify_milestone":
		next, err = complianceassessment.VerifyRemediationMilestone(current, command.ExpectedVersion, command.MilestoneID, command.EvidenceIDs, command.ActorID, command.At)
	case "close":
		next, err = complianceassessment.CloseRemediationPlan(current, command.ExpectedVersion, command.EvidenceIDs, command.ActorID, command.At)
	case "invalidate":
		if !supportedInvalidation(command.Trigger) {
			return complianceassessment.RemediationPlan{}, fmt.Errorf("%w: unsupported invalidation trigger %q", ErrInvalidRequest, command.Trigger)
		}
		var reopen complianceassessment.RemediationReopenRecord
		next, reopen, err = complianceassessment.ReopenRemediationPlan(current, command.ExpectedVersion, command.Trigger, command.SourceRef, command.ActorID, command.At)
		if err == nil {
			return s.persistRemediationReopen(ctx, next, command.ActorID, reopen)
		}
	default:
		return complianceassessment.RemediationPlan{}, fmt.Errorf("%w: unknown remediation operation %q", ErrInvalidRequest, operation)
	}
	if err != nil {
		return complianceassessment.RemediationPlan{}, err
	}
	return s.persistRemediation(ctx, next, operation, command.ActorID, remediationPayload{Plan: next})
}

func (s *Service) persistRemediationReopen(ctx context.Context, plan complianceassessment.RemediationPlan, actorID string, reopen complianceassessment.RemediationReopenRecord) (complianceassessment.RemediationPlan, error) {
	payload := remediationPayload{Plan: plan, Reopen: &reopen}
	metadata, event, err := s.append(ctx, workflowevents.EventKindComplianceRemediationMilestoneUpdated, "remediation_plan", plan.ID, plan.Version, "invalidate", actorID, plan.UpdatedAt, payload)
	if err != nil {
		return complianceassessment.RemediationPlan{}, err
	}
	if err := s.projector.ProjectRemediationReopen(ctx, metadata, plan, reopen); err != nil {
		return complianceassessment.RemediationPlan{}, fmt.Errorf("project remediation event %q: %w", event.GetId(), err)
	}
	return s.store.GetRemediationPlan(ctx, plan.TenantID, plan.ID)
}

func (s *Service) persistRemediation(ctx context.Context, plan complianceassessment.RemediationPlan, operation, actorID string, payload remediationPayload) (complianceassessment.RemediationPlan, error) {
	metadata, event, err := s.append(ctx, workflowevents.EventKindComplianceRemediationMilestoneUpdated, "remediation_plan", plan.ID, plan.Version, operation, actorID, plan.UpdatedAt, payload)
	if err != nil {
		return complianceassessment.RemediationPlan{}, err
	}
	if err := s.projector.ProjectRemediationPlan(ctx, metadata, plan); err != nil {
		return complianceassessment.RemediationPlan{}, fmt.Errorf("project remediation event %q: %w", event.GetId(), err)
	}
	return s.store.GetRemediationPlan(ctx, plan.TenantID, plan.ID)
}

func (s *Service) append(ctx context.Context, kind, aggregateType, aggregateID string, version uint64, operation, actorID string, at time.Time, payload any) (ProjectionMetadata, *cerebrov1.EventEnvelope, error) {
	if err := s.ready(); err != nil {
		return ProjectionMetadata{}, nil, err
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return ProjectionMetadata{}, nil, fmt.Errorf("encode compliance remediation event: %w", err)
	}
	digest := sha256.Sum256(body)
	tenantID := tenantIDForPayload(payload)
	event, err := workflowevents.NewComplianceAggregateEvent(workflowevents.ComplianceAggregateRecorded{
		Kind: kind, TenantID: tenantID, AggregateType: aggregateType, AggregateID: aggregateID,
		AggregateVersion: int64(version), Operation: operation,
		ContentDigest: "sha256:" + hex.EncodeToString(digest[:]), PayloadJSON: string(body),
		ActorID: strings.TrimSpace(actorID), RecordedAt: at.UTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		return ProjectionMetadata{}, nil, err
	}
	if err := s.log.Append(ctx, event); err != nil {
		return ProjectionMetadata{}, nil, err
	}
	return ProjectionMetadata{EventID: event.GetId(), ExpectedVersion: version - 1, OccurredAt: at.UTC()}, event, nil
}

func (s *Service) ready() error {
	if s == nil || s.store == nil || s.projector == nil || s.log == nil {
		return ErrUnavailable
	}
	return nil
}

type workOccurrencePayload struct {
	Item       complianceassessment.WorkItem       `json:"item"`
	Occurrence complianceassessment.WorkOccurrence `json:"occurrence"`
}

type workActionPayload struct {
	Item   complianceassessment.WorkItem         `json:"item"`
	Action complianceassessment.WorkActionRecord `json:"action"`
}

type workReopenPayload struct {
	Item   complianceassessment.WorkItem         `json:"item"`
	Reopen complianceassessment.WorkReopenRecord `json:"reopen"`
}

type remediationPayload struct {
	Plan   complianceassessment.RemediationPlan          `json:"plan"`
	Reopen *complianceassessment.RemediationReopenRecord `json:"reopen,omitempty"`
}

func tenantIDForPayload(payload any) string {
	switch value := payload.(type) {
	case workOccurrencePayload:
		return value.Item.Basis.TenantID
	case workActionPayload:
		return value.Item.Basis.TenantID
	case workReopenPayload:
		return value.Item.Basis.TenantID
	case remediationPayload:
		return value.Plan.TenantID
	default:
		return ""
	}
}

func supportedInvalidation(trigger complianceassessment.WorkReopenTrigger) bool {
	switch trigger {
	case complianceassessment.ReopenEvidenceStale, complianceassessment.ReopenEvidenceRevoked,
		complianceassessment.ReopenFindingReopened, complianceassessment.ReopenSourceCoverageLost:
		return true
	default:
		return false
	}
}
