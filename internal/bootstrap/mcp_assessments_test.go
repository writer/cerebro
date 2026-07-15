package bootstrap

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/compliance"
	"github.com/writer/cerebro/internal/complianceassessment"
	platformjobs "github.com/writer/cerebro/internal/jobs"
)

func TestMCPAssessmentExecutionToolsRequireWriteScope(t *testing.T) {
	readOnly := context.WithValue(context.Background(), authContextKey{}, authContext{principal: authPrincipal{
		TenantID: "tenant-1", Scopes: []string{scopeCosmoSecurityRead},
	}})
	if err := authorizeMCPToolScope(readOnly, "cerebro.assessments.plan.create"); err == nil {
		t.Fatal("read-only principal authorized to create an assessment plan")
	}
	readWrite := context.WithValue(context.Background(), authContextKey{}, authContext{principal: authPrincipal{
		TenantID: "tenant-1", Scopes: []string{scopeCosmoSecurityRead, scopeGRCInventoryWrite},
	}})
	if err := authorizeMCPToolScope(readWrite, "cerebro.assessments.plan.create"); err != nil {
		t.Fatalf("read-write principal rejected: %v", err)
	}
	if err := authorizeMCPToolScope(readOnly, "cerebro.assessments.run.get"); err != nil {
		t.Fatalf("read-only principal rejected for assessment read: %v", err)
	}
}

func TestMCPAssessmentPlanLifecycleAndIdempotentRunRequest(t *testing.T) {
	store := newAssessmentHTTPStore()
	app := &App{}
	app.services.jobs = platformjobs.New(store.a2ATestJobStore)
	app.services.assessments = complianceassessment.NewAssessmentService(store, &assessmentHTTPLog{}, app.services.jobs, nil)
	app.services.jobs.WithRunner(complianceassessment.JobKindComplianceAssessment, app.services.assessments.Runner())

	request := mcpAssessmentRequest(t, []string{scopeCosmoSecurityRead, scopeGRCInventoryWrite})
	created, err := app.mcpAssessmentPlanCreate(request, map[string]any{"plan": mcpAssessmentTestPlan()})
	if err != nil {
		t.Fatalf("mcpAssessmentPlanCreate() error = %v", err)
	}
	plan := created.(map[string]any)["plan"].(complianceassessment.AssessmentPlanRevision)
	if plan.Status != complianceassessment.PlanDraft || plan.Version != 1 || plan.TenantID != "tenant-1" {
		t.Fatalf("created plan = %#v", plan)
	}
	published, err := app.mcpAssessmentPlanPublish(request, map[string]any{"plan_id": plan.ID, "expected_version": plan.Version})
	if err != nil {
		t.Fatalf("mcpAssessmentPlanPublish() error = %v", err)
	}
	plan = published.(map[string]any)["plan"].(complianceassessment.AssessmentPlanRevision)
	if plan.Status != complianceassessment.PlanPublished || plan.Version != 2 {
		t.Fatalf("published plan = %#v", plan)
	}

	args := map[string]any{
		"plan_revision_id": plan.RevisionID, "period_start": "2026-07-01T00:00:00Z", "period_end": "2026-07-15T00:00:00Z",
		"idempotency_key": "agent-assessment-1",
	}
	first, err := app.mcpAssessmentRunRequest(request, args)
	if err != nil {
		t.Fatalf("mcpAssessmentRunRequest() error = %v", err)
	}
	second, err := app.mcpAssessmentRunRequest(request, args)
	if err != nil {
		t.Fatalf("replayed mcpAssessmentRunRequest() error = %v", err)
	}
	firstRun := first.(map[string]any)["run"].(complianceassessment.AssessmentRun)
	secondRun := second.(map[string]any)["run"].(complianceassessment.AssessmentRun)
	if !first.(map[string]any)["created"].(bool) || second.(map[string]any)["created"].(bool) || firstRun.ID != secondRun.ID {
		t.Fatalf("idempotent runs = first %#v second %#v", first, second)
	}
}

func TestMCPAssessmentResultsDiffExplainAndRemediationProposal(t *testing.T) {
	store := newAssessmentHTTPStore()
	app := &App{}
	app.services.assessments = complianceassessment.NewAssessmentService(store, &assessmentHTTPLog{}, nil, nil)
	request := mcpAssessmentRequest(t, []string{scopeCosmoSecurityRead})

	baselineResult := mcpAssessmentTestResult("result-baseline", "objective-1", complianceassessment.OutcomeNotSatisfied)
	currentResult := mcpAssessmentTestResult("result-current", "objective-1", complianceassessment.OutcomeIndeterminate)
	baselineChunk := mcpAssessmentTestChunk(t, "run-baseline", baselineResult)
	currentChunk := mcpAssessmentTestChunk(t, "run-current", currentResult)
	store.mu.Lock()
	store.runs[assessmentHTTPKey("tenant-1", "run-baseline")] = complianceassessment.AssessmentRun{
		ID: "run-baseline", TenantID: "tenant-1", State: complianceassessment.RunComplete,
		ProgramID: "program-1", ScopeRevisionID: "scope-1", ResultCount: 1, AutomatedResultHash: "sha256:baseline",
	}
	store.runs[assessmentHTTPKey("tenant-1", "run-current")] = complianceassessment.AssessmentRun{
		ID: "run-current", TenantID: "tenant-1", State: complianceassessment.RunComplete,
		ProgramID: "program-1", ScopeRevisionID: "scope-1", BaselineRunID: "run-baseline",
		ResultCount: 1, AutomatedResultHash: "sha256:current", InputHash: "sha256:input",
	}
	store.chunks[assessmentHTTPKey("tenant-1", "run-baseline")] = []complianceassessment.ResultChunk{baselineChunk}
	store.chunks[assessmentHTTPKey("tenant-1", "run-current")] = []complianceassessment.ResultChunk{currentChunk}
	store.mu.Unlock()

	listed, err := app.mcpAssessmentResultsList(request, map[string]any{"run_id": "run-current", "limit": 1})
	if err != nil {
		t.Fatalf("mcpAssessmentResultsList() error = %v", err)
	}
	verification := listed.(map[string]any)["verification"].(complianceassessment.ResultPageVerification)
	if !verification.Verified || verification.ResultCount != 1 || verification.NextPreviousDigest != currentChunk.Digest {
		t.Fatalf("verification = %#v", verification)
	}

	diff, err := app.mcpAssessmentRunDiff(request, map[string]any{"run_id": "run-current"})
	if err != nil {
		t.Fatalf("mcpAssessmentRunDiff() error = %v", err)
	}
	diffBody := diff.(map[string]any)["diff"].(complianceassessment.AgentResultDiff)
	if len(diffBody.Changed) != 1 || len(diffBody.Added) != 0 || len(diffBody.Removed) != 0 {
		t.Fatalf("diff = %#v", diffBody)
	}

	explained, err := app.mcpAssessmentResultExplain(request, map[string]any{"run_id": "run-current", "result_id": "result-current"})
	if err != nil {
		t.Fatalf("mcpAssessmentResultExplain() error = %v", err)
	}
	if explained.(map[string]any)["result"].(complianceassessment.ObjectiveResult).ID != "result-current" {
		t.Fatalf("explanation = %#v", explained)
	}

	proposal, err := app.mcpAssessmentRemediationPropose(request, map[string]any{"run_id": "run-current", "result_id": "result-current"})
	if err != nil {
		t.Fatalf("mcpAssessmentRemediationPropose() error = %v", err)
	}
	proposalBody := proposal.(map[string]any)
	if proposalBody["would_mutate"] != false || proposalBody["approval_required"] != true || proposalBody["ready"] != false {
		t.Fatalf("proposal = %#v", proposalBody)
	}
}

func mcpAssessmentRequest(t *testing.T, scopes []string) *http.Request {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, mcpEndpointPath, nil)
	return request.WithContext(context.WithValue(request.Context(), authContextKey{}, authContext{principal: authPrincipal{
		Name: "assessment-agent", TenantID: "tenant-1", Scopes: scopes,
	}}))
}

func mcpAssessmentTestPlan() complianceassessment.AssessmentPlanRevision {
	return complianceassessment.AssessmentPlanRevision{
		TenantID: "tenant-1", Name: "Access review",
		Scope: complianceassessment.PlanScope{ProgramID: "program-1", ScopeRevisionID: "scope-1", ImplementationRevisions: []string{"implementation-1"}, ObjectiveIDs: []string{"objective-1"}},
		Execution: complianceassessment.PlanExecution{
			Methods: []string{"automated_test"}, Depth: "moderate", CoverageTarget: "complete", AssuranceTarget: "high",
			Tasks:          []complianceassessment.PlanTask{{ID: "task-1", ObjectiveID: "objective-1", ControlRef: compliance.ControlRef{FrameworkID: "framework-1", ControlID: "control-1"}, Kind: complianceassessment.PlanTaskKindFindingEvaluation, RuleID: "rule-1", RuntimeIDs: []string{"runtime-1"}, MaxAge: "24h", EvaluationMode: complianceassessment.EvaluationModePointInTime}},
			OrderedTaskIDs: []string{"task-1"}, CancellationRule: "stop_after_checkpoint",
		},
		Governance: complianceassessment.PlanGovernance{OwnerID: "owner-1", ApproverIDs: []string{"approver-1"}, RulesOfEngagement: "Read source records only."},
	}
}

func mcpAssessmentTestResult(id, objectiveID string, outcome complianceassessment.AutomatedOutcome) complianceassessment.ObjectiveResult {
	return complianceassessment.ObjectiveResult{
		ID: id, ObjectiveID: objectiveID, ControlRef: compliance.ControlRef{FrameworkID: "framework-1", ControlID: "control-1"},
		ScopeState: complianceassessment.ScopeInScope, AutomatedOutcome: outcome,
		DesignState: complianceassessment.DesignUnknown, OperatingEffectivenessState: complianceassessment.OperatingUnknown,
		EvidenceState: complianceassessment.EvidenceIncomplete, DispositionState: complianceassessment.DispositionNone,
		Assurance: complianceassessment.AssuranceLow, AuditorState: complianceassessment.AuditorNotReviewed,
		ReasonCodes: []complianceassessment.ReasonCode{complianceassessment.ReasonCoverageIncomplete}, NextActions: []complianceassessment.NextAction{complianceassessment.ActionCollectEvidence},
		EvaluatorRevision: "evaluator-v1", EvaluatedAt: time.Date(2026, 7, 15, 0, 0, 0, 0, time.UTC),
	}
}

func mcpAssessmentTestChunk(t *testing.T, runID string, result complianceassessment.ObjectiveResult) complianceassessment.ResultChunk {
	t.Helper()
	results := []complianceassessment.ObjectiveResult{result}
	digest, err := complianceassessment.CanonicalResultChunkDigest("", results)
	if err != nil {
		t.Fatal(err)
	}
	return complianceassessment.ResultChunk{
		RunID: runID, Sequence: 1, FirstResultID: result.ID, LastResultID: result.ID, Count: 1,
		Digest: digest, Results: results,
	}
}
