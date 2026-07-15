package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"sync"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/compliance"
	"github.com/writer/cerebro/internal/complianceassessment"
	platformjobs "github.com/writer/cerebro/internal/jobs"
	"github.com/writer/cerebro/internal/ports"
)

type testAssessmentPlanResponse struct {
	Plan complianceassessment.AssessmentPlanRevision `json:"plan"`
}

type testPublishAssessmentPlanRequest struct {
	ExpectedVersion uint64 `json:"expected_version"`
}

type testRequestAssessmentRunRequest struct {
	TenantID       string    `json:"tenant_id"`
	PlanRevisionID string    `json:"plan_revision_id"`
	PeriodStart    time.Time `json:"period_start"`
	PeriodEnd      time.Time `json:"period_end"`
	BaselineRunID  string    `json:"baseline_run_id,omitempty"`
}

type testAssessmentRunResponse struct {
	Run struct {
		ID    string `json:"id"`
		JobID string `json:"job_id"`
	} `json:"run"`
	Created bool `json:"created"`
}

type testAssessmentResultPageResponse struct {
	RunID               string                             `json:"run_id"`
	State               string                             `json:"state"`
	ResultCount         uint64                             `json:"result_count"`
	AutomatedResultHash string                             `json:"automated_result_hash"`
	Chunks              []complianceassessment.ResultChunk `json:"chunks"`
	NextSequence        uint32                             `json:"next_sequence"`
	HasMore             bool                               `json:"has_more"`
}

func TestGRCAssessmentPlanRunAndPagedResults(t *testing.T) {
	now := time.Date(2026, 7, 14, 16, 30, 0, 0, time.UTC)
	store := newAssessmentHTTPStore()
	jobs := platformjobs.New(store.a2ATestJobStore)
	service := complianceassessment.NewAssessmentService(store, &assessmentHTTPLog{}, jobs, nil)
	jobs.WithRunner(complianceassessment.JobKindComplianceAssessment, service.Runner())
	app := &App{}
	app.services.assessments = service
	mux := http.NewServeMux()
	app.registerGRCRoutes(mux)
	server := httptest.NewServer(mux)
	defer func() {
		server.Close()
		waitCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = jobs.Wait(waitCtx)
	}()

	planInput := complianceassessment.AssessmentPlanRevision{
		TenantID: "tenant-1", Name: "Quarterly access review",
		Scope: complianceassessment.PlanScope{
			ProgramID: "program-1", ScopeRevisionID: "scope-revision-1",
			ImplementationRevisions: []string{"implementation-revision-1"},
			ObjectiveIDs:            []string{"objective-1"},
		},
		Execution: complianceassessment.PlanExecution{
			Methods: []string{"automated_test"}, Depth: "moderate", CoverageTarget: "complete", AssuranceTarget: "high",
			Tasks: []complianceassessment.PlanTask{{
				ID: "task-1", ObjectiveID: "objective-1", Kind: complianceassessment.PlanTaskKindFindingEvaluation,
				ControlRef: compliance.ControlRef{FrameworkID: "framework-1", ControlID: "control-1"},
				RuleID:     "rule-1", RuntimeIDs: []string{"runtime-1"}, MaxAge: "24h", EvaluationMode: complianceassessment.EvaluationModePointInTime,
			}},
			OrderedTaskIDs: []string{"task-1"}, CancellationRule: "stop_after_checkpoint",
		},
		Governance: complianceassessment.PlanGovernance{
			OwnerID: "owner-1", ApproverIDs: []string{"approver-1"},
			RulesOfEngagement: "Read source records only.",
		},
	}
	unsupportedPlan := planInput
	unsupportedPlan.Execution.Tasks = append([]complianceassessment.PlanTask(nil), planInput.Execution.Tasks...)
	unsupportedPlan.Execution.Tasks[0].Kind = complianceassessment.PlanTaskKindProcedure
	doAssessmentStatus(t, server.Client(), http.MethodPost, server.URL+"/grc/assessment-plans", unsupportedPlan, "", http.StatusBadRequest)
	createResponse := doAssessmentRequest[testAssessmentPlanResponse](t, server.Client(), http.MethodPost, server.URL+"/grc/assessment-plans", planInput, "", http.StatusCreated)
	if createResponse.Plan.Status != complianceassessment.PlanDraft || createResponse.Plan.Version != 1 || createResponse.Plan.ID == "" {
		t.Fatalf("created plan = %#v", createResponse.Plan)
	}
	publishResponse := doAssessmentRequest[testAssessmentPlanResponse](t, server.Client(), http.MethodPost,
		server.URL+"/grc/assessment-plans/"+createResponse.Plan.ID+"/publish?tenant_id=tenant-1",
		testPublishAssessmentPlanRequest{ExpectedVersion: createResponse.Plan.Version}, "", http.StatusOK)
	if publishResponse.Plan.Status != complianceassessment.PlanPublished || publishResponse.Plan.Version != 2 {
		t.Fatalf("published plan = %#v", publishResponse.Plan)
	}

	runRequest := testRequestAssessmentRunRequest{
		TenantID: "tenant-1", PlanRevisionID: publishResponse.Plan.RevisionID,
		PeriodStart: now.Add(-24 * time.Hour), PeriodEnd: now,
	}
	runResponse := doAssessmentRequest[testAssessmentRunResponse](t, server.Client(), http.MethodPost,
		server.URL+"/grc/assessment-runs", runRequest, "assessment-run-key-1", http.StatusAccepted)
	if !runResponse.Created || runResponse.Run.ID == "" || runResponse.Run.JobID == "" {
		t.Fatalf("requested run = %#v", runResponse)
	}
	replayed := doAssessmentRequest[testAssessmentRunResponse](t, server.Client(), http.MethodPost,
		server.URL+"/grc/assessment-runs", runRequest, "assessment-run-key-1", http.StatusOK)
	if replayed.Created || replayed.Run.ID != runResponse.Run.ID {
		t.Fatalf("replayed run = %#v", replayed)
	}
	if err := jobs.Wait(context.Background()); err != nil {
		t.Fatalf("Wait() error = %v", err)
	}
	doAssessmentStatus(t, server.Client(), http.MethodGet,
		server.URL+"/grc/assessment-runs/"+runResponse.Run.ID+"/results?tenant_id=tenant-1&limit=1", nil, "", http.StatusConflict)

	store.setChunks("tenant-1", runResponse.Run.ID, []complianceassessment.ResultChunk{
		{RunID: runResponse.Run.ID, Sequence: 1, FirstResultID: "result-1", LastResultID: "result-1", Count: 1, Digest: "sha256:first", Results: []complianceassessment.ObjectiveResult{{ID: "result-1"}}},
		{RunID: runResponse.Run.ID, Sequence: 2, FirstResultID: "result-2", LastResultID: "result-2", Count: 1, PreviousDigest: "sha256:first", Digest: "sha256:second", Results: []complianceassessment.ObjectiveResult{{ID: "result-2"}}},
	})
	store.setRunComplete("tenant-1", runResponse.Run.ID, 2, "sha256:complete-result-set")
	firstPage := doAssessmentRequest[testAssessmentResultPageResponse](t, server.Client(), http.MethodGet,
		server.URL+"/grc/assessment-runs/"+runResponse.Run.ID+"/results?tenant_id=tenant-1&limit=1", nil, "", http.StatusOK)
	if len(firstPage.Chunks) != 1 || !firstPage.HasMore || firstPage.NextSequence != 1 || firstPage.State != complianceassessment.RunComplete || firstPage.ResultCount != 2 || firstPage.AutomatedResultHash != "sha256:complete-result-set" {
		t.Fatalf("first result page = %#v", firstPage)
	}
	secondPage := doAssessmentRequest[testAssessmentResultPageResponse](t, server.Client(), http.MethodGet,
		server.URL+"/grc/assessment-runs/"+runResponse.Run.ID+"/results?tenant_id=tenant-1&limit=1&after_sequence=1", nil, "", http.StatusOK)
	if len(secondPage.Chunks) != 1 || secondPage.HasMore || secondPage.Chunks[0].Sequence != 2 {
		t.Fatalf("second result page = %#v", secondPage)
	}

	wrongTenant, err := server.Client().Get(server.URL + "/grc/assessment-runs/" + runResponse.Run.ID + "?tenant_id=tenant-2")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = wrongTenant.Body.Close() }()
	if wrongTenant.StatusCode != http.StatusNotFound {
		t.Fatalf("wrong-tenant run status = %d, want 404", wrongTenant.StatusCode)
	}
}

func doAssessmentRequest[T any](t *testing.T, client *http.Client, method, url string, body any, idempotencyKey string, wantStatus int) T {
	t.Helper()
	var payload []byte
	var err error
	if body != nil {
		payload, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	request, err := http.NewRequest(method, url, bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if idempotencyKey != "" {
		request.Header.Set("Idempotency-Key", idempotencyKey)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != wantStatus {
		var errorBody bytes.Buffer
		_, _ = errorBody.ReadFrom(response.Body)
		t.Fatalf("%s %s status = %d, want %d: %s", method, url, response.StatusCode, wantStatus, errorBody.String())
	}
	var result T
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	return result
}

func doAssessmentStatus(t *testing.T, client *http.Client, method, url string, body any, idempotencyKey string, wantStatus int) {
	t.Helper()
	var payload []byte
	var err error
	if body != nil {
		payload, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	request, err := http.NewRequest(method, url, bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if idempotencyKey != "" {
		request.Header.Set("Idempotency-Key", idempotencyKey)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != wantStatus {
		var errorBody bytes.Buffer
		_, _ = errorBody.ReadFrom(response.Body)
		t.Fatalf("%s %s status = %d, want %d: %s", method, url, response.StatusCode, wantStatus, errorBody.String())
	}
}

type assessmentHTTPLog struct{}

func (*assessmentHTTPLog) Ping(context.Context) error { return nil }
func (*assessmentHTTPLog) Append(context.Context, *cerebrov1.EventEnvelope) error {
	return nil
}

type assessmentHTTPStore struct {
	*a2ATestJobStore
	mu     sync.Mutex
	plans  map[string]complianceassessment.AssessmentPlanRevision
	runs   map[string]complianceassessment.AssessmentRun
	byKey  map[string]string
	chunks map[string][]complianceassessment.ResultChunk
}

func newAssessmentHTTPStore() *assessmentHTTPStore {
	return &assessmentHTTPStore{
		a2ATestJobStore: newA2ATestJobStore(),
		plans:           map[string]complianceassessment.AssessmentPlanRevision{},
		runs:            map[string]complianceassessment.AssessmentRun{},
		byKey:           map[string]string{},
		chunks:          map[string][]complianceassessment.ResultChunk{},
	}
}

func assessmentHTTPKey(tenantID, id string) string { return tenantID + "\x00" + id }

func (s *assessmentHTTPStore) ApplyPlan(_ context.Context, _ string, plan complianceassessment.AssessmentPlanRevision, expectedVersion uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := assessmentHTTPKey(plan.TenantID, plan.ID)
	current, exists := s.plans[key]
	if (exists && current.Version != expectedVersion) || (!exists && expectedVersion != 0) {
		return complianceassessment.ErrAssessmentConflict
	}
	s.plans[key] = plan
	s.plans[assessmentHTTPKey(plan.TenantID, plan.RevisionID)] = plan
	return nil
}

func (s *assessmentHTTPStore) GetPlan(_ context.Context, tenantID, id string) (complianceassessment.AssessmentPlanRevision, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	plan, ok := s.plans[assessmentHTTPKey(tenantID, id)]
	if !ok {
		return complianceassessment.AssessmentPlanRevision{}, complianceassessment.ErrPlanNotFound
	}
	return plan, nil
}

func (s *assessmentHTTPStore) ApplyRun(_ context.Context, _ string, run complianceassessment.AssessmentRun, expectedVersion uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := assessmentHTTPKey(run.TenantID, run.ID)
	current, exists := s.runs[key]
	if (exists && current.Version != expectedVersion) || (!exists && expectedVersion != 0) {
		return complianceassessment.ErrAssessmentConflict
	}
	s.runs[key] = run
	s.byKey[assessmentHTTPKey(run.TenantID, run.IdempotencyKey)] = run.ID
	return nil
}

func (s *assessmentHTTPStore) GetRun(_ context.Context, tenantID, id string) (complianceassessment.AssessmentRun, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	run, ok := s.runs[assessmentHTTPKey(tenantID, id)]
	if !ok {
		return complianceassessment.AssessmentRun{}, complianceassessment.ErrRunNotFound
	}
	return run, nil
}

func (s *assessmentHTTPStore) FindRunByIdempotency(_ context.Context, tenantID, key string) (complianceassessment.AssessmentRun, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := s.byKey[assessmentHTTPKey(tenantID, key)]
	if id == "" {
		return complianceassessment.AssessmentRun{}, complianceassessment.ErrRunNotFound
	}
	return s.runs[assessmentHTTPKey(tenantID, id)], nil
}

func (*assessmentHTTPStore) ListUnboundRuns(context.Context, uint32) ([]complianceassessment.AssessmentRun, error) {
	return nil, nil
}

func (s *assessmentHTTPStore) ApplyResultChunk(_ context.Context, _ string, tenantID string, chunk complianceassessment.ResultChunk) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := assessmentHTTPKey(tenantID, chunk.RunID)
	for _, existing := range s.chunks[key] {
		if existing.Sequence == chunk.Sequence && existing.Digest != chunk.Digest {
			return complianceassessment.ErrAssessmentConflict
		}
	}
	s.chunks[key] = append(s.chunks[key], chunk)
	return nil
}

func (s *assessmentHTTPStore) ListResultChunks(_ context.Context, tenantID, runID string) ([]complianceassessment.ResultChunk, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]complianceassessment.ResultChunk(nil), s.chunks[assessmentHTTPKey(tenantID, runID)]...), nil
}

func (s *assessmentHTTPStore) ListResultChunksPage(_ context.Context, tenantID, runID string, afterSequence, limit uint32) (complianceassessment.ResultChunkPage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if limit == 0 {
		return complianceassessment.ResultChunkPage{}, errors.New("limit is required")
	}
	chunks := append([]complianceassessment.ResultChunk(nil), s.chunks[assessmentHTTPKey(tenantID, runID)]...)
	sort.Slice(chunks, func(i, j int) bool { return chunks[i].Sequence < chunks[j].Sequence })
	page := complianceassessment.ResultChunkPage{}
	for _, chunk := range chunks {
		if chunk.Sequence <= afterSequence {
			continue
		}
		if int64(len(page.Chunks)) == int64(limit) {
			page.HasMore = true
			page.NextSequence = page.Chunks[len(page.Chunks)-1].Sequence
			break
		}
		page.Chunks = append(page.Chunks, chunk)
	}
	return page, nil
}

func (s *assessmentHTTPStore) setChunks(tenantID, runID string, chunks []complianceassessment.ResultChunk) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.chunks[assessmentHTTPKey(tenantID, runID)] = append([]complianceassessment.ResultChunk(nil), chunks...)
}

func (s *assessmentHTTPStore) setRunComplete(tenantID, runID string, resultCount uint64, resultHash string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := assessmentHTTPKey(tenantID, runID)
	run := s.runs[key]
	run.State = complianceassessment.RunComplete
	run.ResultCount = resultCount
	run.AutomatedResultHash = resultHash
	s.runs[key] = run
}

func (*assessmentHTTPStore) ListSourceRuntimes(context.Context, ports.SourceRuntimeFilter) ([]*cerebrov1.SourceRuntime, error) {
	return nil, nil
}

func (*assessmentHTTPStore) ListFindingEvaluationRuns(context.Context, ports.ListFindingEvaluationRunsRequest) ([]*cerebrov1.FindingEvaluationRun, error) {
	return nil, nil
}

var _ complianceassessment.Store = (*assessmentHTTPStore)(nil)
var _ complianceassessment.ResultChunkPageStore = (*assessmentHTTPStore)(nil)

func (s *assessmentHTTPStore) String() string {
	return fmt.Sprintf("assessmentHTTPStore(%d plans, %d runs)", len(s.plans), len(s.runs))
}
