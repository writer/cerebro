package bootstrap

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/complianceassessment"
	"github.com/writer/cerebro/internal/mcpoperations"
)

func (app *App) mcpAssessmentPlanCreate(r *http.Request, args map[string]any) (any, error) {
	service, err := app.mcpAssessmentService()
	if err != nil {
		return nil, err
	}
	var plan complianceassessment.AssessmentPlanRevision
	if err := mcpAssessmentObjectArg(args, "plan", &plan); err != nil {
		return nil, err
	}
	tenantID, err := effectiveTenantFilter(r.Context(), plan.TenantID)
	if err != nil {
		return nil, err
	}
	plan, err = service.CreatePlanForAgent(r.Context(), tenantID, customDashboardActorID(r.Context()), plan)
	if err != nil {
		return nil, err
	}
	return map[string]any{"plan": plan, "created": true}, nil
}

func (app *App) mcpAssessmentPlanPublish(r *http.Request, args map[string]any) (any, error) {
	service, tenantID, err := app.mcpAssessmentContext(r, args)
	if err != nil {
		return nil, err
	}
	planID := mcpStringArg(args, "plan_id")
	expectedVersion, err := mcpAssessmentUint64Arg(args, "expected_version")
	if planID == "" || err != nil {
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("%w: plan_id is required", complianceassessment.ErrInvalidResult)
	}
	plan, err := service.PublishPlanForAgent(r.Context(), tenantID, planID, customDashboardActorID(r.Context()), expectedVersion)
	if err != nil {
		return nil, err
	}
	return map[string]any{"plan": plan, "published": true}, nil
}

func (app *App) mcpAssessmentPlanGet(r *http.Request, args map[string]any) (any, error) {
	service, tenantID, err := app.mcpAssessmentContext(r, args)
	if err != nil {
		return nil, err
	}
	planID := mcpStringArg(args, "plan_id")
	if planID == "" {
		return nil, fmt.Errorf("%w: plan_id is required", complianceassessment.ErrInvalidResult)
	}
	plan, err := service.GetPlan(r.Context(), tenantID, planID)
	if err != nil {
		return nil, err
	}
	return map[string]any{"plan": plan}, nil
}

func (app *App) mcpAssessmentRunRequest(r *http.Request, args map[string]any) (any, error) {
	service, tenantID, err := app.mcpAssessmentContext(r, args)
	if err != nil {
		return nil, err
	}
	periodStart, err := mcpAssessmentTimeArg(args, "period_start")
	if err != nil {
		return nil, err
	}
	periodEnd, err := mcpAssessmentTimeArg(args, "period_end")
	if err != nil {
		return nil, err
	}
	run, created, err := service.RequestRunForAgent(r.Context(), complianceassessment.AgentRunRequest{
		TenantID: tenantID, PlanRevisionID: mcpStringArg(args, "plan_revision_id"),
		PeriodStart: periodStart, PeriodEnd: periodEnd, BaselineRunID: mcpStringArg(args, "baseline_run_id"),
		IdempotencyKey: mcpStringArg(args, "idempotency_key"), ActorID: customDashboardActorID(r.Context()),
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{"run": run, "created": created}, nil
}

func (app *App) mcpAssessmentRunGet(r *http.Request, args map[string]any) (any, error) {
	service, tenantID, err := app.mcpAssessmentContext(r, args)
	if err != nil {
		return nil, err
	}
	runID := mcpStringArg(args, "run_id")
	if runID == "" {
		return nil, fmt.Errorf("%w: run_id is required", complianceassessment.ErrInvalidResult)
	}
	run, err := service.GetRun(r.Context(), tenantID, runID)
	if err != nil {
		return nil, err
	}
	return map[string]any{"run": run, "terminal": complianceassessment.AgentRunTerminal(run.State), "results_available": run.State == complianceassessment.RunComplete}, nil
}

func (app *App) mcpAssessmentResultsList(r *http.Request, args map[string]any) (any, error) {
	service, tenantID, err := app.mcpAssessmentContext(r, args)
	if err != nil {
		return nil, err
	}
	afterSequence, err := mcpAssessmentOptionalUint32Arg(args, "after_sequence")
	if err != nil {
		return nil, err
	}
	limit, err := mcpBoundedLimit(args, "limit", 25, 100)
	if err != nil {
		return nil, err
	}
	// #nosec G115 -- mcpBoundedLimit caps this value at 100.
	verified, err := service.VerifiedResultsPage(r.Context(), tenantID, mcpStringArg(args, "run_id"), afterSequence, uint32(limit), mcpStringArg(args, "expected_previous_digest"))
	if err != nil {
		return nil, err
	}
	returnedResults := 0
	for _, chunk := range verified.Page.Chunks {
		returnedResults += len(chunk.Results)
	}
	return map[string]any{
		"run_id": verified.Run.ID, "state": verified.Run.State, "result_count": verified.Run.ResultCount,
		"input_hash": verified.Run.InputHash, "automated_result_hash": verified.Run.AutomatedResultHash,
		"chunks": verified.Page.Chunks, "next_sequence": verified.Page.NextSequence, "has_more": verified.Page.HasMore,
		"verification": verified.Verification, "metadata": mcpResponseMetadata(limit, returnedResults, nil),
	}, nil
}

func (app *App) mcpAssessmentRunDiff(r *http.Request, args map[string]any) (any, error) {
	service, tenantID, err := app.mcpAssessmentContext(r, args)
	if err != nil {
		return nil, err
	}
	diff, err := service.DiffRunsForAgent(r.Context(), tenantID, mcpStringArg(args, "run_id"), mcpStringArg(args, "baseline_run_id"), complianceassessment.DefaultAgentResultBound)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"run_id": diff.Run.ID, "baseline_run_id": diff.Baseline.ID,
		"current_result_hash": diff.Run.AutomatedResultHash, "baseline_result_hash": diff.Baseline.AutomatedResultHash,
		"current_verification": diff.CurrentVerification, "baseline_verification": diff.BaselineVerification, "diff": diff.Diff,
	}, nil
}

func (app *App) mcpAssessmentResultExplain(r *http.Request, args map[string]any) (any, error) {
	service, tenantID, err := app.mcpAssessmentContext(r, args)
	if err != nil {
		return nil, err
	}
	run, result, verification, err := service.FindVerifiedResult(r.Context(), tenantID, mcpStringArg(args, "run_id"), mcpStringArg(args, "result_id"), complianceassessment.DefaultAgentResultBound)
	if err != nil {
		return nil, err
	}
	partialErrors := []string{}
	evidence := make([]any, 0, len(result.EvidenceIDs))
	findings := make([]any, 0, len(result.FindingIDs))
	handoffs := make([]map[string]any, 0, len(result.EvidenceIDs)+len(result.FindingIDs)+len(result.SourceRuntimeIDs))
	for _, id := range boundedAssessmentRefs(result.EvidenceIDs, 20) {
		value, getErr := app.mcpGetEvidence(r, map[string]any{"evidence_id": id})
		if getErr != nil {
			partialErrors = append(partialErrors, "evidence "+id+": "+safeMCPToolError(getErr))
		} else {
			evidence = append(evidence, value)
		}
		handoffs = append(handoffs, map[string]any{"tool": "cerebro.evidence.get", "arguments": map[string]any{"evidence_id": id}})
	}
	for _, id := range boundedAssessmentRefs(result.FindingIDs, 20) {
		value, getErr := app.mcpGetFinding(r, map[string]any{"finding_id": id})
		if getErr != nil {
			partialErrors = append(partialErrors, "finding "+id+": "+safeMCPToolError(getErr))
		} else {
			findings = append(findings, value)
		}
		handoffs = append(handoffs, map[string]any{"tool": "cerebro.findings.get", "arguments": map[string]any{"finding_id": id}})
	}
	for _, id := range boundedAssessmentRefs(result.SourceRuntimeIDs, 20) {
		handoffs = append(handoffs, map[string]any{"tool": "cerebro.runtimes.status", "arguments": map[string]any{"runtime_id": id}})
	}
	return map[string]any{
		"run": run, "result": result, "input_manifest": run.InputManifest, "verification": verification,
		"evidence": evidence, "findings": findings, "provenance_handoffs": handoffs,
		"metadata": mcpResponseMetadata(20, len(evidence)+len(findings), partialErrors),
	}, nil
}

func (app *App) mcpAssessmentRemediationPropose(r *http.Request, args map[string]any) (any, error) {
	service, tenantID, err := app.mcpAssessmentContext(r, args)
	if err != nil {
		return nil, err
	}
	proposal, err := service.ProposeRemediationForAgent(r.Context(), tenantID, mcpStringArg(args, "run_id"), mcpStringArg(args, "result_id"), mcpStringArg(args, "subject_id"), mcpStringArg(args, "source_id"), mcpStringArg(args, "owner_id"), mcpStringArg(args, "due_at"), mcpStringArg(args, "priority"), complianceassessment.DefaultAgentResultBound)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"dry_run": true, "would_mutate": false, "approval_required": true,
		"required_scope": scopeFindingLifecycleWrite, "operation": "POST /grc/work-items",
		"ready": proposal.Ready, "missing_fields": proposal.MissingFields, "request": proposal.Request, "verification": proposal.Verification,
	}, nil
}

func (app *App) mcpAssessmentService() (*complianceassessment.Service, error) {
	if app == nil || app.services.assessments == nil {
		return nil, complianceassessment.ErrResultPagingUnavailable
	}
	return app.services.assessments, nil
}

func (app *App) mcpAssessmentContext(r *http.Request, args map[string]any) (*complianceassessment.Service, string, error) {
	service, err := app.mcpAssessmentService()
	if err != nil {
		return nil, "", err
	}
	tenantID, err := effectiveTenantFilter(r.Context(), mcpStringArg(args, "tenant_id"))
	return service, tenantID, err
}

func mcpAssessmentObjectArg(args map[string]any, key string, target any) error {
	value, ok := args[key]
	if !ok || value == nil {
		return fmt.Errorf("%w: %s is required", complianceassessment.ErrInvalidResult, key)
	}
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("%w: encode %s: %w", complianceassessment.ErrInvalidResult, key, err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("%w: decode %s: %w", complianceassessment.ErrInvalidResult, key, err)
	}
	return nil
}

func mcpAssessmentTimeArg(args map[string]any, key string) (time.Time, error) {
	value, err := time.Parse(time.RFC3339Nano, mcpStringArg(args, key))
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: %s must be an RFC3339 timestamp", complianceassessment.ErrInvalidResult, key)
	}
	return value, nil
}

func mcpAssessmentUint64Arg(args map[string]any, key string) (uint64, error) {
	value, err := strconv.ParseUint(mcpStringArg(args, key), 10, 64)
	if err != nil || value == 0 {
		return 0, fmt.Errorf("%w: %s must be a positive integer", complianceassessment.ErrInvalidResult, key)
	}
	return value, nil
}

func mcpAssessmentOptionalUint32Arg(args map[string]any, key string) (uint32, error) {
	raw := mcpStringArg(args, key)
	if raw == "" {
		return 0, nil
	}
	value, err := strconv.ParseUint(raw, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("%w: %s must be an unsigned integer", complianceassessment.ErrInvalidResult, key)
	}
	return uint32(value), nil
}

func boundedAssessmentRefs(values []string, limit int) []string {
	if len(values) > limit {
		return values[:limit]
	}
	return values
}

func mcpAssessmentTools() []mcpTool {
	definitions := mcpoperations.AssessmentToolDefinitions()
	tools := make([]mcpTool, 0, len(definitions))
	for _, definition := range definitions {
		annotations := mcpReadOnlyAnnotations(definition.Title)
		if operation, ok := mcpoperations.Lookup(definition.Name); ok && operation.Behavior == mcpoperations.BehaviorExecute {
			annotations = mcpWriteAnnotations(definition.Title, definition.Idempotent)
		}
		tools = append(tools, mcpTool{Name: definition.Name, Title: definition.Title, Description: definition.Description, InputSchema: definition.InputSchema, OutputSchema: definition.OutputSchema, Annotations: annotations})
	}
	return tools
}
