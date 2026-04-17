package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/writer/cerebro/internal/actionengine"
	"github.com/writer/cerebro/internal/autonomous"
	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/runtime"
)

const autonomousCredentialWorkflowName = "Credential Exposure Response"

type autonomousCredentialAnalysis struct {
	SecretNodeID      string
	WorkloadID        string
	PrincipalID       string
	Provider          string
	ImpactedTargetIDs []string
	Summary           string
}

func (a *Runtime) toolCerebroAutonomousCredentialResponse(ctx context.Context, args json.RawMessage) (string, error) {
	g, err := a.requireReadableSecurityGraph()
	if err != nil {
		return "", err
	}

	var req struct {
		SecretNodeID string `json:"secret_node_id"`
		RequestedBy  string `json:"requested_by"`
	}
	if err := decodeToolArgs(args, &req); err != nil {
		return "", err
	}
	req.SecretNodeID = strings.TrimSpace(req.SecretNodeID)
	if req.SecretNodeID == "" {
		return "", fmt.Errorf("secret_node_id is required")
	}

	analysis, err := analyzeAutonomousCredentialExposure(g, req.SecretNodeID)
	if err != nil {
		return "", err
	}

	// Approval policy is owned by the server, not caller-controlled tool input.
	requireApproval := true
	now := time.Now().UTC()
	run := &autonomous.RunRecord{
		ID:                "autonomous:" + uuid.NewString(),
		WorkflowID:        autonomous.WorkflowCredentialExposureResponse,
		WorkflowName:      autonomousCredentialWorkflowName,
		Status:            autonomous.RunStatusPending,
		Stage:             autonomous.RunStageAnalyze,
		RequestedBy:       toolDurableActorID(ctx),
		SubmittedAt:       now,
		StartedAt:         timePointer(now),
		UpdatedAt:         now,
		Summary:           analysis.Summary,
		SecretNodeID:      analysis.SecretNodeID,
		WorkloadID:        analysis.WorkloadID,
		PrincipalID:       analysis.PrincipalID,
		Provider:          analysis.Provider,
		ImpactedTargetIDs: append([]string(nil), analysis.ImpactedTargetIDs...),
		RequireApproval:   requireApproval,
		Inputs:            map[string]any{"secret_node_id": req.SecretNodeID, "require_approval": requireApproval},
		Metadata:          map[string]any{"requested_by_hint": strings.TrimSpace(req.RequestedBy)},
	}
	store, err := a.autonomousRunStore()
	if err != nil {
		return "", err
	}
	defer func() { _ = store.Close() }()
	if err := store.SaveRun(ctx, run); err != nil {
		return "", fmt.Errorf("save autonomous workflow run: %w", err)
	}
	a.appendAutonomousRunEventBestEffort(ctx, store, run.ID, autonomous.RunEvent{
		Status:     run.Status,
		Stage:      run.Stage,
		Message:    "credential exposure analysis started",
		RecordedAt: now,
		Data:       map[string]any{"secret_node_id": run.SecretNodeID},
	})

	observationID, detectionClaimID, decisionID, err := a.writeAutonomousCredentialArtifacts(ctx, run, analysis)
	if err != nil {
		run.Status = autonomous.RunStatusFailed
		run.Stage = autonomous.RunStageClosed
		run.Error = err.Error()
		run.CompletedAt = timePointer(time.Now().UTC())
		run.UpdatedAt = *run.CompletedAt
		a.saveAutonomousRunBestEffort(ctx, store, run)
		a.appendAutonomousRunEventBestEffort(ctx, store, run.ID, autonomous.RunEvent{
			Status:     run.Status,
			Stage:      run.Stage,
			Message:    "failed to write graph artifacts",
			RecordedAt: run.UpdatedAt,
			Data:       map[string]any{"error": run.Error},
		})
		return "", err
	}
	run.ObservationID = observationID
	run.DetectionClaimID = detectionClaimID
	run.DecisionID = decisionID

	execution, err := a.startAutonomousCredentialAction(ctx, run)
	if err != nil {
		run.Status = autonomous.RunStatusFailed
		run.Stage = autonomous.RunStageClosed
		run.Error = err.Error()
		run.CompletedAt = timePointer(time.Now().UTC())
		run.UpdatedAt = *run.CompletedAt
		a.saveAutonomousRunBestEffort(ctx, store, run)
		a.appendAutonomousRunEventBestEffort(ctx, store, run.ID, autonomous.RunEvent{
			Status:     run.Status,
			Stage:      run.Stage,
			Message:    "failed to start autonomous action execution",
			RecordedAt: run.UpdatedAt,
			Data:       map[string]any{"error": run.Error},
		})
		return "", err
	}
	run.ActionExecutionID = execution.ID

	if execution.Status == actionengine.StatusAwaitingApproval {
		run.Status = autonomous.RunStatusAwaitingApproval
		run.Stage = autonomous.RunStageAwaitingApproval
		run.UpdatedAt = time.Now().UTC()
		if err := store.SaveRun(ctx, run); err != nil {
			return "", fmt.Errorf("save pending autonomous workflow run: %w", err)
		}
		a.appendAutonomousRunEventBestEffort(ctx, store, run.ID, autonomous.RunEvent{
			Status:     run.Status,
			Stage:      run.Stage,
			Message:    "awaiting approval before revoking credentials",
			RecordedAt: run.UpdatedAt,
			Data: map[string]any{
				"action_execution_id": run.ActionExecutionID,
				"principal_id":        run.PrincipalID,
				"provider":            run.Provider,
			},
		})
		return marshalToolResponse(a.autonomousWorkflowResponse(ctx, run, nil, nil))
	}

	if err := a.finalizeAutonomousCredentialResponse(ctx, run, execution, store); err != nil {
		return "", err
	}
	return marshalToolResponse(a.autonomousWorkflowResponse(ctx, run, execution, nil))
}

func (a *Runtime) toolCerebroAutonomousWorkflowApprove(ctx context.Context, args json.RawMessage) (string, error) {
	var req struct {
		RunID      string `json:"run_id"`
		ApprovedBy string `json:"approved_by"`
		Approve    *bool  `json:"approve"`
		Reason     string `json:"reason"`
	}
	if err := decodeToolArgs(args, &req); err != nil {
		return "", err
	}
	req.RunID = strings.TrimSpace(req.RunID)
	if req.RunID == "" {
		return "", fmt.Errorf("run_id is required")
	}
	approve := true
	if req.Approve != nil {
		approve = *req.Approve
	}
	store, err := a.autonomousRunStore()
	if err != nil {
		return "", err
	}
	defer func() { _ = store.Close() }()
	run, err := store.LoadRun(ctx, req.RunID)
	if err != nil {
		return "", err
	}
	if run == nil {
		return "", fmt.Errorf("autonomous workflow run not found: %s", req.RunID)
	}
	if run.WorkflowID != autonomous.WorkflowCredentialExposureResponse {
		return "", fmt.Errorf("unsupported workflow: %s", run.WorkflowID)
	}
	if run.ActionExecutionID == "" {
		return "", fmt.Errorf("workflow run %s has no action execution", req.RunID)
	}
	if run.Status != autonomous.RunStatusAwaitingApproval || run.Stage != autonomous.RunStageAwaitingApproval {
		return "", fmt.Errorf("workflow run %s is not awaiting approval", req.RunID)
	}

	actionStore, err := a.autonomousActionStore()
	if err != nil {
		return "", err
	}
	defer func() { _ = actionStore.Close() }()
	execution, err := actionStore.LoadExecution(ctx, run.ActionExecutionID)
	if err != nil {
		return "", err
	}
	if execution == nil {
		return "", fmt.Errorf("action execution not found: %s", run.ActionExecutionID)
	}
	if execution.Status != actionengine.StatusAwaitingApproval || execution.CompletedAt != nil {
		return "", fmt.Errorf("action execution %s is not awaiting approval", run.ActionExecutionID)
	}
	executor := a.newSharedActionExecutor()
	defer func() { _ = executor.Close() }()
	playbook := autonomousCredentialPlaybook(run)
	signal := autonomousCredentialSignal(run)
	approver := toolDurableActorID(ctx)
	runner := autonomousCredentialStepRunner{
		handler: a.autonomousActionHandler(),
	}
	if approve {
		execution, claimed, err := actionStore.ClaimApproval(ctx, run.ActionExecutionID, approver, time.Now().UTC())
		if err != nil {
			return "", err
		}
		if !claimed {
			return "", fmt.Errorf("action execution %s is not awaiting approval", run.ActionExecutionID)
		}
		if err := executor.Approve(ctx, execution, approver, playbook, signal, runner); err != nil {
			run.Status = autonomous.RunStatusFailed
			run.Stage = autonomous.RunStageClosed
			run.Error = err.Error()
			now := time.Now().UTC()
			run.CompletedAt = timePointer(now)
			run.UpdatedAt = now
			a.saveAutonomousRunBestEffort(ctx, store, run)
			a.appendAutonomousRunEventBestEffort(ctx, store, run.ID, autonomous.RunEvent{
				Status:     run.Status,
				Stage:      run.Stage,
				Message:    "workflow approval failed during execution",
				RecordedAt: now,
				Data:       map[string]any{"error": err.Error()},
			})
			return "", err
		}
		if err := a.finalizeAutonomousCredentialResponse(ctx, run, execution, store); err != nil {
			return "", err
		}
		return marshalToolResponse(a.autonomousWorkflowResponse(ctx, run, execution, nil))
	}

	reason := strings.TrimSpace(req.Reason)
	if reason == "" {
		reason = "workflow approval rejected"
	}
	if err := executor.Reject(ctx, execution, approver, reason); err != nil {
		return "", err
	}
	now := time.Now().UTC()
	run.Status = autonomous.RunStatusCanceled
	run.Stage = autonomous.RunStageClosed
	run.Error = reason
	run.CompletedAt = timePointer(now)
	run.UpdatedAt = now
	if err := store.SaveRun(ctx, run); err != nil {
		return "", err
	}
	a.appendAutonomousRunEventBestEffort(ctx, store, run.ID, autonomous.RunEvent{
		Status:     run.Status,
		Stage:      run.Stage,
		Message:    "workflow approval rejected",
		RecordedAt: now,
		Data:       map[string]any{"reason": reason},
	})
	return marshalToolResponse(a.autonomousWorkflowResponse(ctx, run, execution, nil))
}

func (a *Runtime) toolCerebroAutonomousWorkflowStatus(ctx context.Context, args json.RawMessage) (string, error) {
	var req struct {
		RunID string `json:"run_id"`
	}
	if err := decodeToolArgs(args, &req); err != nil {
		return "", err
	}
	req.RunID = strings.TrimSpace(req.RunID)
	if req.RunID == "" {
		return "", fmt.Errorf("run_id is required")
	}
	store, err := a.autonomousRunStore()
	if err != nil {
		return "", err
	}
	defer func() { _ = store.Close() }()
	run, err := store.LoadRun(ctx, req.RunID)
	if err != nil {
		return "", err
	}
	if run == nil {
		return "", fmt.Errorf("autonomous workflow run not found: %s", req.RunID)
	}
	events, err := store.LoadEvents(ctx, req.RunID)
	if err != nil {
		return "", err
	}
	response := a.autonomousWorkflowResponse(ctx, run, nil, events)
	if run.ActionExecutionID != "" {
		actionStore, actionErr := a.autonomousActionStore()
		if actionErr == nil {
			defer func() { _ = actionStore.Close() }()
			if execution, loadErr := actionStore.LoadExecution(ctx, run.ActionExecutionID); loadErr == nil && execution != nil {
				response["action_execution"] = execution
				if actionEvents, eventErr := actionStore.LoadEvents(ctx, run.ActionExecutionID); eventErr == nil {
					response["action_events"] = actionEvents
				}
			}
		}
	}
	return marshalToolResponse(response)
}

func (a *Runtime) writeAutonomousCredentialArtifacts(ctx context.Context, run *autonomous.RunRecord, analysis autonomousCredentialAnalysis) (string, string, string, error) {
	observationPayload := map[string]any{
		"entity_id":       run.SecretNodeID,
		"observation":     "credential_exposure_response_started",
		"summary":         analysis.Summary,
		"source_system":   "autonomous_workflow",
		"source_event_id": run.ID + ":observe",
		"metadata": map[string]any{
			"workflow_run_id":     run.ID,
			"principal_id":        run.PrincipalID,
			"workload_id":         run.WorkloadID,
			"impacted_target_ids": append([]string(nil), run.ImpactedTargetIDs...),
		},
	}
	observationResult, err := invokeToolHandler(ctx, a.toolCerebroRecordObservation, observationPayload)
	if err != nil {
		return "", "", "", err
	}
	observationID := mapString(observationResult, "observation_id")

	claimPayload := map[string]any{
		"subject_id":      run.SecretNodeID,
		"claim_type":      "security_posture",
		"predicate":       "credential_exposure_status",
		"object_value":    "detected",
		"summary":         analysis.Summary,
		"source_system":   "autonomous_workflow",
		"source_event_id": run.ID + ":claim:detected",
		"metadata": map[string]any{
			"workflow_run_id": run.ID,
			"principal_id":    run.PrincipalID,
			"workload_id":     run.WorkloadID,
		},
	}
	claimResult, err := invokeToolHandler(ctx, a.toolCerebroWriteClaim, claimPayload)
	if err != nil {
		return "", "", "", err
	}
	claimID := mapString(claimResult, "claim_id")

	decisionTargets := uniqueToolNormalizedIDs(append([]string{run.SecretNodeID, run.WorkloadID, run.PrincipalID}, run.ImpactedTargetIDs...))
	decisionPayload := map[string]any{
		"decision_type":   "credential_exposure_response",
		"status":          "planned",
		"made_by":         toolDurableActorID(ctx),
		"rationale":       analysis.Summary,
		"target_ids":      decisionTargets,
		"source_system":   "autonomous_workflow",
		"source_event_id": run.ID + ":decision",
		"metadata": map[string]any{
			"workflow_run_id":  run.ID,
			"require_approval": run.RequireApproval,
		},
	}
	decisionResult, err := invokeToolHandler(ctx, a.toolCerebroRecordDecision, decisionPayload)
	if err != nil {
		return "", "", "", err
	}
	return observationID, claimID, mapString(decisionResult, "decision_id"), nil
}

func (a *Runtime) startAutonomousCredentialAction(ctx context.Context, run *autonomous.RunRecord) (*actionengine.Execution, error) {
	if run == nil {
		return nil, fmt.Errorf("workflow run is required")
	}
	if strings.TrimSpace(run.PrincipalID) == "" {
		return nil, fmt.Errorf("credential exposure did not resolve to a revocable principal")
	}
	executor := a.newSharedActionExecutor()
	defer func() { _ = executor.Close() }()
	playbook := autonomousCredentialPlaybook(run)
	signal := autonomousCredentialSignal(run)
	execution := executor.NewExecution(playbook, signal)
	runner := autonomousCredentialStepRunner{
		handler: a.autonomousActionHandler(),
	}
	if err := executor.Execute(ctx, execution, playbook, signal, runner); err != nil {
		return execution, err
	}
	return execution, nil
}

func (a *Runtime) finalizeAutonomousCredentialResponse(ctx context.Context, run *autonomous.RunRecord, execution *actionengine.Execution, store autonomous.RunStore) error {
	if run == nil {
		return fmt.Errorf("workflow run is required")
	}
	now := time.Now().UTC()
	run.UpdatedAt = now
	if execution == nil {
		run.Status = autonomous.RunStatusFailed
		run.Stage = autonomous.RunStageClosed
		run.Error = "missing action execution"
		run.CompletedAt = timePointer(now)
		if err := store.SaveRun(ctx, run); err != nil {
			return err
		}
		return nil
	}
	switch execution.Status {
	case actionengine.StatusCompleted:
		remediationClaimID, outcomeID, err := a.writeAutonomousCredentialRemediation(ctx, run)
		if err != nil {
			run.Status = autonomous.RunStatusFailed
			run.Stage = autonomous.RunStageClosed
			run.Error = err.Error()
			run.CompletedAt = timePointer(now)
			a.saveAutonomousRunBestEffort(ctx, store, run)
			a.appendAutonomousRunEventBestEffort(ctx, store, run.ID, autonomous.RunEvent{
				Status:     run.Status,
				Stage:      run.Stage,
				Message:    "credential revocation succeeded but graph closeout failed",
				RecordedAt: now,
				Data:       map[string]any{"error": err.Error()},
			})
			return err
		}
		run.RemediationClaimID = remediationClaimID
		run.OutcomeID = outcomeID
		run.Status = autonomous.RunStatusCompleted
		run.Stage = autonomous.RunStageClosed
		run.Error = ""
		run.CompletedAt = timePointer(now)
		if err := store.SaveRun(ctx, run); err != nil {
			return err
		}
		a.appendAutonomousRunEventBestEffort(ctx, store, run.ID, autonomous.RunEvent{
			Status:     run.Status,
			Stage:      run.Stage,
			Message:    "credential exposure workflow completed",
			RecordedAt: now,
			Data: map[string]any{
				"action_execution_id":  run.ActionExecutionID,
				"outcome_id":           run.OutcomeID,
				"remediation_claim_id": run.RemediationClaimID,
			},
		})
	case actionengine.StatusFailed:
		run.Status = autonomous.RunStatusFailed
		run.Stage = autonomous.RunStageClosed
		run.Error = strings.TrimSpace(execution.Error)
		run.CompletedAt = timePointer(now)
		if err := store.SaveRun(ctx, run); err != nil {
			return err
		}
		a.appendAutonomousRunEventBestEffort(ctx, store, run.ID, autonomous.RunEvent{
			Status:     run.Status,
			Stage:      run.Stage,
			Message:    "credential exposure workflow failed during actuation",
			RecordedAt: now,
			Data:       map[string]any{"error": run.Error},
		})
	default:
		run.Status = autonomous.RunStatusRunning
		run.Stage = autonomous.RunStageExecute
		if err := store.SaveRun(ctx, run); err != nil {
			return err
		}
	}
	return nil
}

func (a *Runtime) writeAutonomousCredentialRemediation(ctx context.Context, run *autonomous.RunRecord) (string, string, error) {
	claimPayload := map[string]any{
		"subject_id":          run.SecretNodeID,
		"claim_type":          "security_posture",
		"predicate":           "credential_exposure_status",
		"object_value":        "remediated",
		"summary":             "Credential exposure was remediated by revoking the affected credential.",
		"source_system":       "autonomous_workflow",
		"source_event_id":     run.ID + ":claim:remediated",
		"supersedes_claim_id": run.DetectionClaimID,
		"metadata": map[string]any{
			"workflow_run_id":     run.ID,
			"action_execution_id": run.ActionExecutionID,
		},
	}
	claimResult, err := invokeToolHandler(ctx, a.toolCerebroWriteClaim, claimPayload)
	if err != nil {
		return "", "", err
	}
	outcomePayload := map[string]any{
		"decision_id":     run.DecisionID,
		"outcome_type":    "credential_revocation",
		"verdict":         "positive",
		"target_ids":      uniqueToolNormalizedIDs(append([]string{run.SecretNodeID, run.WorkloadID, run.PrincipalID}, run.ImpactedTargetIDs...)),
		"source_system":   "autonomous_workflow",
		"source_event_id": run.ID + ":outcome",
		"metadata": map[string]any{
			"workflow_run_id":     run.ID,
			"action_execution_id": run.ActionExecutionID,
		},
	}
	outcomeResult, err := invokeToolHandler(ctx, a.toolCerebroRecordOutcome, outcomePayload)
	if err != nil {
		return "", "", err
	}
	return mapString(claimResult, "claim_id"), mapString(outcomeResult, "outcome_id"), nil
}

func (a *Runtime) autonomousWorkflowResponse(ctx context.Context, run *autonomous.RunRecord, execution *actionengine.Execution, events []autonomous.RunEvent) map[string]any {
	response := map[string]any{
		"run_id":               run.ID,
		"workflow_id":          run.WorkflowID,
		"workflow_name":        run.WorkflowName,
		"status":               run.Status,
		"stage":                run.Stage,
		"requested_by":         run.RequestedBy,
		"summary":              run.Summary,
		"secret_node_id":       run.SecretNodeID,
		"workload_id":          run.WorkloadID,
		"principal_id":         run.PrincipalID,
		"provider":             run.Provider,
		"impacted_target_ids":  append([]string(nil), run.ImpactedTargetIDs...),
		"observation_id":       run.ObservationID,
		"detection_claim_id":   run.DetectionClaimID,
		"remediation_claim_id": run.RemediationClaimID,
		"decision_id":          run.DecisionID,
		"outcome_id":           run.OutcomeID,
		"action_execution_id":  run.ActionExecutionID,
		"require_approval":     run.RequireApproval,
		"submitted_at":         run.SubmittedAt,
		"started_at":           run.StartedAt,
		"completed_at":         run.CompletedAt,
		"updated_at":           run.UpdatedAt,
		"error":                run.Error,
	}
	if events != nil {
		response["events"] = events
	}
	if execution != nil {
		response["action_execution"] = execution
	}
	if run.RequireApproval && run.Status == autonomous.RunStatusAwaitingApproval {
		response["next_step"] = "approve the workflow with cerebro.autonomous_workflow_approve"
	}
	_ = ctx
	return response
}

func (a *Runtime) autonomousRunStore() (autonomous.RunStore, error) {
	if a != nil && a.executionStore() != nil {
		return autonomous.NewSQLiteRunStoreWithExecutionStore(a.executionStore()), nil
	}
	if a == nil || a.config() == nil {
		return nil, fmt.Errorf("execution store is not configured")
	}
	store, err := autonomous.NewSQLiteRunStore(a.config().ExecutionStoreFile)
	if err != nil {
		return nil, fmt.Errorf("open autonomous workflow store: %w", err)
	}
	return store, nil
}

func (a *Runtime) autonomousRuntimeBlocklist() *runtime.Blocklist {
	if a == nil || a.runtimeRespond() == nil {
		return nil
	}
	return a.runtimeRespond().Blocklist()
}

func (a *Runtime) saveAutonomousRunBestEffort(ctx context.Context, store autonomous.RunStore, run *autonomous.RunRecord) {
	if store == nil || run == nil {
		return
	}
	if err := store.SaveRun(ctx, run); err != nil {
		a.warnAutonomousRunPersistence("persist autonomous workflow run failed", run.ID, err)
	}
}

func (a *Runtime) appendAutonomousRunEventBestEffort(ctx context.Context, store autonomous.RunStore, runID string, event autonomous.RunEvent) {
	if store == nil {
		return
	}
	if _, err := store.AppendEvent(ctx, runID, event); err != nil {
		a.warnAutonomousRunPersistence("persist autonomous workflow event failed", runID, err)
	}
}

func (a *Runtime) warnAutonomousRunPersistence(message, runID string, err error) {
	if err == nil || a == nil || a.logger() == nil {
		return
	}
	a.logger().Warn(message, "run_id", strings.TrimSpace(runID), "error", err)
}

func (a *Runtime) autonomousActionHandler() runtime.ActionHandler {
	if a != nil && a.runtimeRespond() != nil && a.runtimeRespond().ActionHandler() != nil {
		return a.runtimeRespond().ActionHandler()
	}
	return runtime.NewDefaultActionHandler(runtime.DefaultActionHandlerOptions{
		Blocklist:    a.autonomousRuntimeBlocklist(),
		RemoteCaller: a.remoteTools(),
	})
}

func (a *Runtime) autonomousActionStore() (*actionengine.SQLiteStore, error) {
	if a != nil && a.executionStore() != nil {
		return actionengine.NewSQLiteStoreWithExecutionStore(a.executionStore(), actionengine.DefaultNamespace), nil
	}
	if a == nil || a.config() == nil {
		return nil, fmt.Errorf("execution store is not configured")
	}
	store, err := actionengine.NewSQLiteStore(a.config().ExecutionStoreFile, actionengine.DefaultNamespace)
	if err != nil {
		return nil, fmt.Errorf("open action execution store: %w", err)
	}
	return store, nil
}

func autonomousCredentialPlaybook(run *autonomous.RunRecord) actionengine.Playbook {
	now := time.Now().UTC()
	return actionengine.Playbook{
		ID:              "autonomous.credential_exposure_response",
		Name:            autonomousCredentialWorkflowName,
		Description:     "Revoke exposed credentials after graph-based impact analysis.",
		Enabled:         true,
		Priority:        1,
		RequireApproval: run.RequireApproval,
		Steps: []actionengine.Step{
			{
				ID:               "revoke_credentials",
				Type:             string(runtime.ActionRevokeCredentials),
				RequiresApproval: run.RequireApproval,
				OnFailure:        actionengine.FailurePolicyAbort,
			},
		},
		CreatedAt: now,
		UpdatedAt: now,
	}
}

func autonomousCredentialSignal(run *autonomous.RunRecord) actionengine.Signal {
	return actionengine.Signal{
		ID:           run.ID,
		Kind:         "autonomous_workflow",
		Severity:     "high",
		Category:     "credential_exposure",
		ResourceID:   firstNonEmpty(run.PrincipalID, run.WorkloadID, run.SecretNodeID),
		ResourceType: "credential",
		Data: map[string]any{
			"run_id":              run.ID,
			"workflow_id":         run.WorkflowID,
			"secret_node_id":      run.SecretNodeID,
			"workload_id":         run.WorkloadID,
			"principal_id":        run.PrincipalID,
			"provider":            run.Provider,
			"impacted_target_ids": append([]string(nil), run.ImpactedTargetIDs...),
		},
		CreatedAt: time.Now().UTC(),
	}
}

type autonomousCredentialStepRunner struct {
	handler runtime.ActionHandler
}

func (r autonomousCredentialStepRunner) RunStep(ctx context.Context, step actionengine.Step, signal actionengine.Signal, execution *actionengine.Execution) (string, error) {
	if r.handler == nil {
		return "", fmt.Errorf("runtime action handler is nil")
	}
	if step.Type != string(runtime.ActionRevokeCredentials) {
		return "", fmt.Errorf("unsupported autonomous workflow step: %s", step.Type)
	}
	principalID := strings.TrimSpace(fmt.Sprintf("%v", signal.Data["principal_id"]))
	provider := strings.TrimSpace(fmt.Sprintf("%v", signal.Data["provider"]))
	if principalID == "" {
		return "", fmt.Errorf("principal_id is required for revoke_credentials")
	}
	actuationCtx := runtime.WithTrustedActuationScope(ctx, runtime.TrustedActuationScope{
		AllowedPrincipalIDs: []string{principalID},
	})
	if err := r.handler.RevokeCredentials(actuationCtx, principalID, provider); err != nil {
		return "", err
	}
	return fmt.Sprintf("revoked credentials for %s via %s", principalID, firstNonEmpty(provider, "unknown")), nil
}

func analyzeAutonomousCredentialExposure(g *graph.Graph, secretNodeID string) (autonomousCredentialAnalysis, error) {
	secretNodeID = strings.TrimSpace(secretNodeID)
	if secretNodeID == "" {
		return autonomousCredentialAnalysis{}, fmt.Errorf("secret_node_id is required")
	}
	secretNode, ok := g.GetNode(secretNodeID)
	if !ok || secretNode == nil {
		return autonomousCredentialAnalysis{}, fmt.Errorf("secret node not found: %s", secretNodeID)
	}
	if secretNode.Kind != graph.NodeKindSecret {
		return autonomousCredentialAnalysis{}, fmt.Errorf("node %s is not a discovered secret", secretNodeID)
	}

	analysis := autonomousCredentialAnalysis{
		SecretNodeID: secretNodeID,
		Provider:     firstNonEmpty(secretNode.Provider, mapValue(secretNode.Properties, "provider")),
	}
	if workloadID := mapValue(secretNode.Properties, "workload_target_id"); workloadID != "" {
		analysis.WorkloadID = workloadID
		if workload, ok := g.GetNode(workloadID); ok && workload != nil {
			analysis.Provider = firstNonEmpty(analysis.Provider, workload.Provider)
		}
	}

	findingID := mapValue(secretNode.Properties, "finding_id")
	seenTargets := map[string]struct{}{}
	if analysis.WorkloadID != "" {
		for _, edge := range g.GetOutEdges(analysis.WorkloadID) {
			if edge == nil || edge.Kind != graph.EdgeKindHasCredentialFor {
				continue
			}
			if edgeMatchesSecret(edge, secretNodeID, findingID) {
				if _, ok := seenTargets[edge.Target]; !ok {
					seenTargets[edge.Target] = struct{}{}
					analysis.ImpactedTargetIDs = append(analysis.ImpactedTargetIDs, edge.Target)
				}
				if analysis.PrincipalID == "" {
					analysis.PrincipalID = mapValue(edge.Properties, "via_principal_id")
				}
			}
		}
	}

	for _, edge := range g.GetOutEdges(secretNodeID) {
		if edge == nil || edge.Kind != graph.EdgeKindTargets {
			continue
		}
		target, ok := g.GetNode(edge.Target)
		if !ok || target == nil {
			continue
		}
		if analysis.PrincipalID == "" && isRevocablePrincipalNode(target) {
			analysis.PrincipalID = target.ID
			analysis.Provider = firstNonEmpty(analysis.Provider, target.Provider)
		}
		if _, ok := seenTargets[target.ID]; !ok {
			seenTargets[target.ID] = struct{}{}
			analysis.ImpactedTargetIDs = append(analysis.ImpactedTargetIDs, target.ID)
		}
	}

	if analysis.Provider == "" && analysis.PrincipalID != "" {
		if principal, ok := g.GetNode(analysis.PrincipalID); ok && principal != nil {
			analysis.Provider = principal.Provider
		}
	}
	if analysis.Provider == "" {
		analysis.Provider = "unknown"
	}
	analysis.Summary = fmt.Sprintf(
		"Detected exposed credential %s on workload %s with %d impacted graph targets; principal=%s provider=%s.",
		secretNodeID,
		firstNonEmpty(analysis.WorkloadID, "unknown"),
		len(analysis.ImpactedTargetIDs),
		firstNonEmpty(analysis.PrincipalID, "unresolved"),
		analysis.Provider,
	)
	return analysis, nil
}

func edgeMatchesSecret(edge *graph.Edge, secretNodeID, findingID string) bool {
	if edge == nil {
		return false
	}
	if mapValue(edge.Properties, "secret_node_id") == secretNodeID {
		return true
	}
	return findingID != "" && mapValue(edge.Properties, "credential_finding_id") == findingID
}

func isRevocablePrincipalNode(node *graph.Node) bool {
	if node == nil {
		return false
	}
	return node.Kind == graph.NodeKindUser || node.Kind == graph.NodeKindServiceAccount
}

func mapValue(values map[string]any, key string) string {
	if len(values) == 0 {
		return ""
	}
	value, ok := values[key]
	if !ok || value == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprintf("%v", value))
}

func invokeToolHandler(ctx context.Context, handler func(context.Context, json.RawMessage) (string, error), payload any) (map[string]any, error) {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("encode workflow payload: %w", err)
	}
	result, err := handler(ctx, encoded)
	if err != nil {
		return nil, err
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(result), &decoded); err != nil {
		return nil, fmt.Errorf("decode workflow tool response: %w", err)
	}
	return decoded, nil
}

func mapString(values map[string]any, key string) string {
	if len(values) == 0 {
		return ""
	}
	value, ok := values[key]
	if !ok || value == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprintf("%v", value))
}

func timePointer(value time.Time) *time.Time {
	if value.IsZero() {
		return nil
	}
	copy := value.UTC()
	return &copy
}
