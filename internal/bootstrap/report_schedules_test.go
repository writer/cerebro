package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/ports"
)

type stubReportScheduleStore struct {
	schedules       map[string]*ports.ReportSchedule
	due             []*ports.ReportSchedule
	runs            []*cerebrov1.ReportRun
	createdJobs     []ports.CreateJobRequest
	claimLimit      uint32
	claimOwner      string
	claimTTL        time.Duration
	completedClaims []string
	releasedClaims  []string
	createJobErr    error
}

func newStubReportScheduleStore() *stubReportScheduleStore {
	return &stubReportScheduleStore{schedules: map[string]*ports.ReportSchedule{}}
}

func (s *stubReportScheduleStore) Ping(context.Context) error { return nil }

func (s *stubReportScheduleStore) PutReportSchedule(_ context.Context, schedule *ports.ReportSchedule) error {
	copied := *schedule
	s.schedules[schedule.ID] = &copied
	return nil
}

func (s *stubReportScheduleStore) GetReportSchedule(_ context.Context, id string) (*ports.ReportSchedule, error) {
	schedule, ok := s.schedules[strings.TrimSpace(id)]
	if !ok {
		return nil, ports.ErrReportScheduleNotFound
	}
	copied := *schedule
	return &copied, nil
}

func (s *stubReportScheduleStore) ListReportSchedules(_ context.Context, filter ports.ReportScheduleFilter) ([]*ports.ReportSchedule, error) {
	out := []*ports.ReportSchedule{}
	for _, schedule := range s.schedules {
		if filter.TenantID != "" && schedule.TenantID != filter.TenantID {
			continue
		}
		copied := *schedule
		out = append(out, &copied)
	}
	return out, nil
}

func (s *stubReportScheduleStore) DeleteReportSchedule(_ context.Context, id string) error {
	delete(s.schedules, strings.TrimSpace(id))
	return nil
}

func (s *stubReportScheduleStore) ClaimDueReportSchedules(_ context.Context, _ time.Time, owner string, ttl time.Duration, limit uint32) ([]*ports.ReportSchedule, error) {
	s.claimLimit = limit
	s.claimOwner = owner
	s.claimTTL = ttl
	return s.due, nil
}

func (s *stubReportScheduleStore) CompleteReportScheduleClaim(_ context.Context, id string, owner string, _ time.Time, _ time.Time) error {
	s.completedClaims = append(s.completedClaims, id+":"+owner)
	return nil
}

func (s *stubReportScheduleStore) ReleaseReportScheduleClaim(_ context.Context, id string, owner string) error {
	s.releasedClaims = append(s.releasedClaims, id+":"+owner)
	return nil
}

func (s *stubReportScheduleStore) ListReportRuns(_ context.Context, _ ports.ReportRunFilter) ([]*cerebrov1.ReportRun, error) {
	return s.runs, nil
}

func (s *stubReportScheduleStore) CreateJob(_ context.Context, request ports.CreateJobRequest) (*ports.Job, bool, error) {
	s.createdJobs = append(s.createdJobs, request)
	if s.createJobErr != nil {
		return nil, false, s.createJobErr
	}
	return &ports.Job{ID: "job-stub", Kind: request.Kind, Status: "queued"}, false, nil
}

func (s *stubReportScheduleStore) GetJob(context.Context, string) (*ports.Job, error) {
	return nil, ports.ErrJobNotFound
}

func (s *stubReportScheduleStore) ListJobs(context.Context, ports.JobFilter) ([]*ports.Job, error) {
	return nil, nil
}

func (s *stubReportScheduleStore) CountJobs(context.Context, ports.JobFilter) (uint64, error) {
	return 0, nil
}

func (s *stubReportScheduleStore) UpdateJob(context.Context, string, ports.JobUpdate) (*ports.Job, error) {
	return nil, ports.ErrJobNotFound
}

func (s *stubReportScheduleStore) AppendJobEvent(context.Context, ports.JobEvent) (*ports.JobEvent, error) {
	return &ports.JobEvent{}, nil
}

func (s *stubReportScheduleStore) ListJobEvents(context.Context, string, uint32) ([]*ports.JobEvent, error) {
	return nil, nil
}

func reportScheduleTestApp(store ports.StateStore) *App {
	return New(config.Config{HTTPAddr: "127.0.0.1:0"}, Dependencies{StateStore: store}, nil)
}

func reportScheduleTestRequest(method, target, body string) *http.Request {
	var reader *strings.Reader
	if body != "" {
		reader = strings.NewReader(body)
	} else {
		reader = strings.NewReader("")
	}
	request := httptest.NewRequest(method, target, reader)
	return request.WithContext(context.WithValue(request.Context(), authContextKey{}, authContext{
		principal: authPrincipal{TenantID: "local"},
	}))
}

func TestHandleCreateReportScheduleValidatesAndPersists(t *testing.T) {
	store := newStubReportScheduleStore()
	app := reportScheduleTestApp(store)

	recorder := httptest.NewRecorder()
	body := `{"report_id":"finding-summary","interval_seconds":3600,"parameters":{"runtime_ids":"rt-1"}}`
	app.handleCreateReportSchedule(recorder, reportScheduleTestRequest(http.MethodPost, "/report-schedules", body))
	if recorder.Code != http.StatusCreated {
		t.Fatalf("create status = %d, want %d (body %s)", recorder.Code, http.StatusCreated, recorder.Body.String())
	}
	var response reportScheduleResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	if response.Schedule.TenantID != "local" || response.Schedule.ReportID != "finding-summary" {
		t.Fatalf("unexpected schedule %+v", response.Schedule)
	}
	if !response.Schedule.Enabled {
		t.Fatal("schedule should default to enabled")
	}
	if response.Schedule.Parameters["tenant_id"] != "local" || response.Schedule.Parameters["runtime_ids"] != "rt-1" {
		t.Fatalf("unexpected parameters %+v", response.Schedule.Parameters)
	}
	if response.Schedule.NextRunAt == "" {
		t.Fatal("next_run_at should be set")
	}
	if len(store.schedules) != 1 {
		t.Fatalf("stored schedules = %d, want 1", len(store.schedules))
	}
}

func TestHandleCreateReportScheduleRejectsInvalidInput(t *testing.T) {
	cases := []struct {
		name string
		body string
		want int
	}{
		{name: "missing required parameter", body: `{"report_id":"finding-summary","interval_seconds":3600}`, want: http.StatusBadRequest},
		{name: "unknown report", body: `{"report_id":"nope","interval_seconds":3600,"parameters":{"runtime_ids":"rt-1"}}`, want: http.StatusNotFound},
		{name: "interval too small", body: `{"report_id":"finding-summary","interval_seconds":5,"parameters":{"runtime_ids":"rt-1"}}`, want: http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := newStubReportScheduleStore()
			app := reportScheduleTestApp(store)
			recorder := httptest.NewRecorder()
			app.handleCreateReportSchedule(recorder, reportScheduleTestRequest(http.MethodPost, "/report-schedules", tc.body))
			if recorder.Code != tc.want {
				t.Fatalf("status = %d, want %d (body %s)", recorder.Code, tc.want, recorder.Body.String())
			}
			if len(store.schedules) != 0 {
				t.Fatalf("invalid input should not persist, stored %d", len(store.schedules))
			}
		})
	}
}

func TestHandleListReportSchedulesScopesToTenant(t *testing.T) {
	store := newStubReportScheduleStore()
	store.schedules["a"] = &ports.ReportSchedule{ID: "a", TenantID: "local", ReportID: "finding-summary", IntervalSeconds: 3600}
	store.schedules["b"] = &ports.ReportSchedule{ID: "b", TenantID: "other", ReportID: "finding-summary", IntervalSeconds: 3600}
	app := reportScheduleTestApp(store)

	recorder := httptest.NewRecorder()
	app.handleListReportSchedules(recorder, reportScheduleTestRequest(http.MethodGet, "/report-schedules", ""))
	if recorder.Code != http.StatusOK {
		t.Fatalf("list status = %d, want 200 (body %s)", recorder.Code, recorder.Body.String())
	}
	var response reportScheduleListResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode list response: %v", err)
	}
	if len(response.Schedules) != 1 || response.Schedules[0].ID != "a" {
		t.Fatalf("expected only tenant-scoped schedule, got %+v", response.Schedules)
	}
}

func TestHandleUpdateReportScheduleAppliesPatchAndScopesTenant(t *testing.T) {
	store := newStubReportScheduleStore()
	store.schedules["a"] = &ports.ReportSchedule{ID: "a", TenantID: "local", ReportID: "finding-summary", IntervalSeconds: 3600, Enabled: true, Parameters: map[string]string{"tenant_id": "local", "runtime_ids": "rt-1"}}
	store.schedules["b"] = &ports.ReportSchedule{ID: "b", TenantID: "other", ReportID: "finding-summary", IntervalSeconds: 3600, Enabled: true}
	app := reportScheduleTestApp(store)

	recorder := httptest.NewRecorder()
	request := reportScheduleTestRequest(http.MethodPatch, "/report-schedules/a", `{"enabled":false}`)
	request.SetPathValue("scheduleID", "a")
	app.handleUpdateReportSchedule(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("update status = %d, want 200 (body %s)", recorder.Code, recorder.Body.String())
	}
	if store.schedules["a"].Enabled {
		t.Fatal("schedule a should be disabled after patch")
	}

	crossRecorder := httptest.NewRecorder()
	crossRequest := reportScheduleTestRequest(http.MethodPatch, "/report-schedules/b", `{"enabled":false}`)
	crossRequest.SetPathValue("scheduleID", "b")
	app.handleUpdateReportSchedule(crossRecorder, crossRequest)
	if crossRecorder.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant update status = %d, want 404", crossRecorder.Code)
	}
	if !store.schedules["b"].Enabled {
		t.Fatal("cross-tenant schedule must not be modified")
	}
}

func TestHandleDeleteReportScheduleScopesTenant(t *testing.T) {
	store := newStubReportScheduleStore()
	store.schedules["a"] = &ports.ReportSchedule{ID: "a", TenantID: "local", ReportID: "finding-summary", IntervalSeconds: 3600}
	store.schedules["b"] = &ports.ReportSchedule{ID: "b", TenantID: "other", ReportID: "finding-summary", IntervalSeconds: 3600}
	app := reportScheduleTestApp(store)

	recorder := httptest.NewRecorder()
	request := reportScheduleTestRequest(http.MethodDelete, "/report-schedules/a", "")
	request.SetPathValue("scheduleID", "a")
	app.handleDeleteReportSchedule(recorder, request)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d, want 204 (body %s)", recorder.Code, recorder.Body.String())
	}
	if _, ok := store.schedules["a"]; ok {
		t.Fatal("schedule a should be deleted")
	}

	crossRecorder := httptest.NewRecorder()
	crossRequest := reportScheduleTestRequest(http.MethodDelete, "/report-schedules/b", "")
	crossRequest.SetPathValue("scheduleID", "b")
	app.handleDeleteReportSchedule(crossRecorder, crossRequest)
	if crossRecorder.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant delete status = %d, want 404", crossRecorder.Code)
	}
	if _, ok := store.schedules["b"]; !ok {
		t.Fatal("cross-tenant schedule must not be deleted")
	}
}

func TestRunDueReportSchedulesEnqueuesReportRunJobs(t *testing.T) {
	store := newStubReportScheduleStore()
	store.due = []*ports.ReportSchedule{
		{ID: "a", TenantID: "local", ReportID: "finding-summary", IntervalSeconds: 3600, Enabled: true, NextRunAt: time.Date(2026, 7, 11, 8, 0, 0, 0, time.UTC), Parameters: map[string]string{"tenant_id": "local", "runtime_ids": "rt-1"}},
	}
	app := reportScheduleTestApp(store)

	enqueued, err := app.RunDueReportSchedules(context.Background())
	if err != nil {
		t.Fatalf("RunDueReportSchedules() error = %v", err)
	}
	if enqueued != 1 {
		t.Fatalf("enqueued = %d, want 1", enqueued)
	}
	if len(store.createdJobs) != 1 {
		t.Fatalf("created jobs = %d, want 1", len(store.createdJobs))
	}
	job := store.createdJobs[0]
	if job.Kind != "report_run" || job.TenantID != "local" {
		t.Fatalf("unexpected job %+v", job)
	}
	if job.IdempotencyKey != "report-schedule:a:2026-07-11T08:00:00Z" {
		t.Fatalf("unexpected idempotency key %q", job.IdempotencyKey)
	}
	if len(store.completedClaims) != 1 || len(store.releasedClaims) != 0 {
		t.Fatalf("completed=%v released=%v, want one completion and no release", store.completedClaims, store.releasedClaims)
	}
	if job.Payload["report_id"] != "finding-summary" {
		t.Fatalf("unexpected job report_id %v", job.Payload["report_id"])
	}
	parameters, ok := job.Payload["parameters"].(map[string]any)
	if !ok {
		t.Fatalf("job parameters type = %T, want map", job.Payload["parameters"])
	}
	if parameters["tenant_id"] != "local" || parameters["runtime_ids"] != "rt-1" {
		t.Fatalf("unexpected job parameters %+v", parameters)
	}
}

func TestRunDueReportSchedulesReleasesClaimWhenEnqueueFails(t *testing.T) {
	store := newStubReportScheduleStore()
	store.createJobErr = errors.New("job store unavailable")
	store.due = []*ports.ReportSchedule{{
		ID: "a", TenantID: "local", ReportID: "finding-summary", IntervalSeconds: 3600,
		Enabled: true, NextRunAt: time.Date(2026, 7, 11, 8, 0, 0, 0, time.UTC),
		Parameters: map[string]string{"tenant_id": "local", "runtime_ids": "rt-1"},
	}}
	app := reportScheduleTestApp(store)

	enqueued, err := app.RunDueReportSchedules(context.Background())
	if err == nil {
		t.Fatal("RunDueReportSchedules() error = nil, want enqueue failure")
	}
	if enqueued != 0 || len(store.completedClaims) != 0 || len(store.releasedClaims) != 1 {
		t.Fatalf("enqueued=%d completed=%v released=%v", enqueued, store.completedClaims, store.releasedClaims)
	}
}

func TestHandleListReportRunsReturnsRecentRuns(t *testing.T) {
	store := newStubReportScheduleStore()
	store.runs = []*cerebrov1.ReportRun{
		{Id: "run-1", ReportId: "finding-summary", Status: "completed"},
		{Id: "run-2", ReportId: "risk-delta", Status: "completed"},
	}
	app := reportScheduleTestApp(store)

	recorder := httptest.NewRecorder()
	app.handleListReportRuns(recorder, reportScheduleTestRequest(http.MethodGet, "/report-runs", ""))
	if recorder.Code != http.StatusOK {
		t.Fatalf("list runs status = %d, want 200 (body %s)", recorder.Code, recorder.Body.String())
	}
	var response struct {
		Runs []json.RawMessage `json:"runs"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode runs response: %v", err)
	}
	if len(response.Runs) != 2 {
		t.Fatalf("runs = %d, want 2", len(response.Runs))
	}
	if !strings.Contains(string(response.Runs[0]), "run-1") {
		t.Fatalf("first run missing id: %s", response.Runs[0])
	}
}
