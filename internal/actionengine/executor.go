package actionengine

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

type StepRunner interface {
	RunStep(ctx context.Context, step Step, signal Signal, execution *Execution) (string, error)
}

const stepMetadataTriggerPrefix = "_step_metadata:"

type Executor struct {
	store Store
	now   func() time.Time
}

func NewExecutor(store Store) *Executor {
	return &Executor{
		store: store,
		now: func() time.Time {
			return time.Now().UTC()
		},
	}
}

func (e *Executor) RequiresApproval(playbook Playbook) bool {
	if playbook.RequireApproval {
		return true
	}
	for _, step := range playbook.Steps {
		if step.RequiresApproval {
			return true
		}
	}
	return false
}

func (e *Executor) NewExecution(playbook Playbook, signal Signal) *Execution {
	triggerData := cloneAnyMap(signal.Data)
	if triggerData == nil {
		triggerData = map[string]any{}
	}
	for key, value := range signal.Attributes {
		if _, exists := triggerData[key]; !exists {
			triggerData[key] = value
		}
	}
	if signal.Kind != "" {
		triggerData["signal_kind"] = signal.Kind
	}
	if signal.Severity != "" {
		triggerData["severity"] = signal.Severity
	}
	if signal.PolicyID != "" {
		triggerData["policy_id"] = signal.PolicyID
	}
	if signal.Category != "" {
		triggerData["category"] = signal.Category
	}
	if signal.RuleID != "" {
		triggerData["rule_id"] = signal.RuleID
	}
	if signal.ResourceID != "" {
		triggerData["resource_id"] = signal.ResourceID
	}
	if signal.ResourceType != "" {
		triggerData["resource_type"] = signal.ResourceType
	}
	if len(signal.Tags) > 0 {
		triggerData["tags"] = append([]string(nil), signal.Tags...)
	}
	now := e.now()
	execution := &Execution{
		ID:           uuid.NewString(),
		PlaybookID:   playbook.ID,
		PlaybookName: playbook.Name,
		SignalID:     signal.ID,
		Status:       StatusPending,
		ResourceID:   signal.ResourceID,
		ResourceType: signal.ResourceType,
		TriggerData:  triggerData,
		Results:      make([]ActionResult, 0, len(playbook.Steps)),
		StartedAt:    now,
	}
	e.persist(context.Background(), execution)
	e.appendEvent(context.Background(), Event{
		Type:        "execution.created",
		ExecutionID: execution.ID,
		RecordedAt:  now,
		Data: map[string]any{
			"playbook_id": playbook.ID,
			"signal_id":   signal.ID,
			"status":      execution.Status,
		},
	})
	return execution
}

func (e *Executor) Execute(ctx context.Context, execution *Execution, playbook Playbook, signal Signal, runner StepRunner) error {
	if execution == nil {
		return fmt.Errorf("execution is nil")
	}
	if runner == nil {
		return fmt.Errorf("step runner is nil")
	}
	if execution.StartedAt.IsZero() {
		execution.StartedAt = e.now()
	}
	if e.RequiresApproval(playbook) && execution.ApprovedAt == nil {
		execution.Status = StatusAwaitingApproval
		execution.Error = ""
		now := e.now()
		e.persist(ctx, execution)
		e.appendEvent(ctx, Event{
			Type:        "execution.awaiting_approval",
			ExecutionID: execution.ID,
			RecordedAt:  now,
			Data: map[string]any{
				"playbook_id": playbook.ID,
				"status":      execution.Status,
			},
		})
		return nil
	}
	execution.Status = StatusRunning
	execution.Error = ""
	e.persist(ctx, execution)
	e.appendEvent(ctx, Event{
		Type:        "execution.started",
		ExecutionID: execution.ID,
		RecordedAt:  e.now(),
		Data: map[string]any{
			"playbook_id": playbook.ID,
			"status":      execution.Status,
		},
	})

	for _, step := range playbook.Steps {
		if step.ID == "" {
			step.ID = step.Type
		}
		result := ActionResult{
			StepID:    step.ID,
			Type:      step.Type,
			Status:    StatusRunning,
			StartedAt: e.now(),
		}
		e.appendEvent(ctx, Event{
			Type:        "step.started",
			ExecutionID: execution.ID,
			RecordedAt:  result.StartedAt,
			Data: map[string]any{
				"step_id": step.ID,
				"type":    step.Type,
			},
		})

		stepCtx := ctx
		cancel := func() {}
		if step.TimeoutSeconds > 0 {
			stepCtx, cancel = context.WithTimeout(ctx, time.Duration(step.TimeoutSeconds)*time.Second)
		}
		output, err := runner.RunStep(stepCtx, step, signal, execution)
		cancel()

		completedAt := e.now()
		result.CompletedAt = &completedAt
		result.Duration = completedAt.Sub(result.StartedAt).String()
		result.Metadata = ConsumeStepMetadata(execution, step.ID)
		if err != nil {
			result.Status = StatusFailed
			result.Error = err.Error()
			execution.Results = append(execution.Results, result)
			execution.Status = StatusFailed
			execution.Error = err.Error()
			execution.CompletedAt = &completedAt
			e.persist(ctx, execution)
			e.appendEvent(ctx, Event{
				Type:        "step.failed",
				ExecutionID: execution.ID,
				RecordedAt:  completedAt,
				Data: map[string]any{
					"step_id":  step.ID,
					"type":     step.Type,
					"error":    err.Error(),
					"metadata": result.Metadata,
				},
			})
			if step.OnFailure != FailurePolicyContinue {
				e.appendEvent(ctx, Event{
					Type:        "execution.failed",
					ExecutionID: execution.ID,
					RecordedAt:  completedAt,
					Data: map[string]any{
						"playbook_id": playbook.ID,
						"status":      execution.Status,
						"error":       execution.Error,
					},
				})
				return err
			}
		} else {
			result.Status = StatusCompleted
			result.Output = output
			execution.Results = append(execution.Results, result)
			e.appendEvent(ctx, Event{
				Type:        "step.completed",
				ExecutionID: execution.ID,
				RecordedAt:  completedAt,
				Data: map[string]any{
					"step_id":  step.ID,
					"type":     step.Type,
					"output":   output,
					"metadata": result.Metadata,
				},
			})
		}
	}

	completedAt := e.now()
	execution.Status = StatusCompleted
	execution.Error = ""
	execution.CompletedAt = &completedAt
	e.persist(ctx, execution)
	e.appendEvent(ctx, Event{
		Type:        "execution.completed",
		ExecutionID: execution.ID,
		RecordedAt:  completedAt,
		Data: map[string]any{
			"playbook_id": playbook.ID,
			"status":      execution.Status,
		},
	})
	return nil
}

func (e *Executor) Approve(ctx context.Context, execution *Execution, approver string, playbook Playbook, signal Signal, runner StepRunner) error {
	if execution == nil {
		return fmt.Errorf("execution is nil")
	}
	now := e.now()
	execution.ApprovedBy = approver
	execution.ApprovedAt = &now
	e.persist(ctx, execution)
	e.appendEvent(ctx, Event{
		Type:        "execution.approved",
		ExecutionID: execution.ID,
		RecordedAt:  now,
		Data: map[string]any{
			"approved_by": approver,
		},
	})
	return e.Execute(ctx, execution, playbook, signal, runner)
}

func (e *Executor) Reject(ctx context.Context, execution *Execution, rejecter, reason string) error {
	if execution == nil {
		return fmt.Errorf("execution is nil")
	}
	now := e.now()
	execution.Status = StatusCanceled
	execution.Error = fmt.Sprintf("Rejected by %s: %s", rejecter, reason)
	execution.CompletedAt = &now
	e.persist(ctx, execution)
	e.appendEvent(ctx, Event{
		Type:        "execution.rejected",
		ExecutionID: execution.ID,
		RecordedAt:  now,
		Data: map[string]any{
			"rejected_by": rejecter,
			"reason":      reason,
		},
	})
	return nil
}

func (e *Executor) persist(ctx context.Context, execution *Execution) {
	if e == nil || e.store == nil || execution == nil {
		return
	}
	_ = e.store.SaveExecution(ctx, execution)
}

func (e *Executor) appendEvent(ctx context.Context, event Event) {
	if e == nil || e.store == nil {
		return
	}
	_, _ = e.store.AppendEvent(ctx, event)
}

func cloneAnyMap(input map[string]any) map[string]any {
	if len(input) == 0 {
		return nil
	}
	cloned := make(map[string]any, len(input))
	for key, value := range input {
		cloned[key] = value
	}
	return cloned
}

func SetStepMetadata(execution *Execution, stepID string, metadata map[string]any) {
	if execution == nil || len(metadata) == 0 {
		return
	}
	stepID = strings.TrimSpace(stepID)
	if stepID == "" {
		return
	}
	if execution.TriggerData == nil {
		execution.TriggerData = map[string]any{}
	}
	execution.TriggerData[stepMetadataTriggerPrefix+stepID] = cloneAnyMap(metadata)
}

func ConsumeStepMetadata(execution *Execution, stepID string) map[string]any {
	if execution == nil || len(execution.TriggerData) == 0 {
		return nil
	}
	stepID = strings.TrimSpace(stepID)
	if stepID == "" {
		return nil
	}
	key := stepMetadataTriggerPrefix + stepID
	raw, ok := execution.TriggerData[key]
	if !ok {
		return nil
	}
	delete(execution.TriggerData, key)
	values, ok := raw.(map[string]any)
	if !ok {
		return nil
	}
	return cloneAnyMap(values)
}
