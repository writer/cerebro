package grcuploadhttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/grcupload"
	"github.com/writer/cerebro/internal/ports"
)

func TestHandlerRejectsDivergentFormTenant(t *testing.T) {
	appendLog := &recordingAppendLog{}
	projector := &recordingProjector{}
	parserCalled := false
	handler := NewHandler(Options{
		Target: grcupload.TargetPolicy,
		ParserFactory: func() (grcupload.Parser, error) {
			parserCalled = true
			return stubParser{}, nil
		},
		AppendLog: appendLog,
		Projector: projector,
		ResolveScope: func(r *http.Request) (Scope, error) {
			return Scope{TenantID: r.URL.Query().Get("tenant_id"), SourceID: "grc", RuntimeID: "runtime-1"}, nil
		},
		AuthorizeTenant: func(context.Context, string) error {
			t.Fatal("AuthorizeTenant called for mismatched tenant")
			return nil
		},
		Now: fixedUploadTime,
	})
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, uploadRequest(t, "?tenant_id=query-tenant", map[string]string{"tenant_id": "form-tenant"}))

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if parserCalled {
		t.Fatal("parser was called for mismatched tenant")
	}
	if len(appendLog.events) != 0 || len(projector.events) != 0 {
		t.Fatalf("append/project counts = %d/%d, want 0/0", len(appendLog.events), len(projector.events))
	}
}

func TestHandlerAppendsAllEventsBeforeProjecting(t *testing.T) {
	appendLog := &recordingAppendLog{failAt: 2}
	projector := &recordingProjector{}
	handler := NewHandler(Options{
		Target: grcupload.TargetPolicy,
		ParserFactory: func() (grcupload.Parser, error) {
			return stubParser{parsed: grcupload.ParsedDocument{ProviderFileID: "file-1", ParseID: "parse-1", Status: "completed"}}, nil
		},
		AppendLog: appendLog,
		Projector: projector,
		ResolveScope: func(r *http.Request) (Scope, error) {
			return Scope{TenantID: r.URL.Query().Get("tenant_id"), SourceID: "grc", RuntimeID: "runtime-1"}, nil
		},
		AuthorizeTenant: func(context.Context, string) error { return nil },
		Now:             fixedUploadTime,
	})
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, uploadRequest(t, "?tenant_id=tenant-1", map[string]string{"policy_id": "access"}))

	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusServiceUnavailable)
	}
	if len(appendLog.events) != 2 {
		t.Fatalf("appended events = %d, want 2 attempts", len(appendLog.events))
	}
	if len(projector.events) != 0 {
		t.Fatalf("projected events = %d, want 0 before all appends succeed", len(projector.events))
	}
}

func TestHandlerAcceptsUploadWithEncodedRecordIDs(t *testing.T) {
	appendLog := &recordingAppendLog{}
	projector := &recordingProjector{}
	cacheBumps := 0
	handler := NewHandler(Options{
		Target: grcupload.TargetPolicy,
		ParserFactory: func() (grcupload.Parser, error) {
			return stubParser{parsed: grcupload.ParsedDocument{ProviderFileID: "file-1", ParseID: "parse-1", Status: "completed"}}, nil
		},
		AppendLog: appendLog,
		Projector: projector,
		ResolveScope: func(r *http.Request) (Scope, error) {
			return Scope{TenantID: r.URL.Query().Get("tenant_id"), SourceID: "grc", RuntimeID: "runtime-1"}, nil
		},
		AuthorizeTenant: func(context.Context, string) error { return nil },
		BumpCache: func(context.Context, string) {
			cacheBumps++
		},
		Now: fixedUploadTime,
	})
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, uploadRequest(t, "?tenant_id=tenant-1", map[string]string{
		"policy_id":   "ISO:27001/2022",
		"document_id": "Access Policy:v2",
	}))

	if response.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusAccepted)
	}
	var payload grcupload.Response
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got, want := payload.ProjectionStatus, "projected"; got != want {
		t.Fatalf("projection_status = %q, want %q", got, want)
	}
	if len(payload.Events) != 2 {
		t.Fatalf("response events = %d, want 2", len(payload.Events))
	}
	if got, want := payload.Events[0].RecordID, "ISO:27001/2022"; got != want {
		t.Fatalf("policy record_id = %q, want %q", got, want)
	}
	if got, want := payload.Events[0].RecordURN, "urn:cerebro:tenant-1:policy:cerebro_upload:ISO%3A27001%2F2022"; got != want {
		t.Fatalf("policy record_urn = %q, want %q", got, want)
	}
	if got, want := payload.Events[1].RecordURN, "urn:cerebro:tenant-1:document:cerebro_upload:Access%20Policy%3Av2"; got != want {
		t.Fatalf("document record_urn = %q, want %q", got, want)
	}
	if got, want := payload.Events[1].LegacyRecordURN, "urn:cerebro:tenant-1:document:cerebro_upload:Access+Policy%3Av2"; got != want {
		t.Fatalf("document legacy_record_urn = %q, want %q", got, want)
	}
	if len(appendLog.events) != 2 || len(projector.events) != 2 {
		t.Fatalf("append/project counts = %d/%d, want 2/2", len(appendLog.events), len(projector.events))
	}
	if got, want := appendLog.events[0].GetAttributes()["policy_id"], "ISO:27001/2022"; got != want {
		t.Fatalf("policy_id attribute = %q, want %q", got, want)
	}
	if got, want := appendLog.events[0].GetAttributes()["record_urn"], payload.Events[0].RecordURN; got != want {
		t.Fatalf("record_urn attribute = %q, want %q", got, want)
	}
	if got, want := appendLog.events[1].GetAttributes()["legacy_record_urn"], payload.Events[1].LegacyRecordURN; got != want {
		t.Fatalf("legacy_record_urn attribute = %q, want %q", got, want)
	}
	if cacheBumps != 1 {
		t.Fatalf("cache bumps = %d, want 1", cacheBumps)
	}
}

func TestHandlerAcceptsUploadWhenProjectionFailsAfterAppend(t *testing.T) {
	appendLog := &recordingAppendLog{}
	projector := &recordingProjector{failAt: 1}
	cacheBumps := 0
	handler := NewHandler(Options{
		Target: grcupload.TargetPolicy,
		ParserFactory: func() (grcupload.Parser, error) {
			return stubParser{parsed: grcupload.ParsedDocument{ProviderFileID: "file-1", ParseID: "parse-1", Status: "completed"}}, nil
		},
		AppendLog: appendLog,
		Projector: projector,
		ResolveScope: func(r *http.Request) (Scope, error) {
			return Scope{TenantID: r.URL.Query().Get("tenant_id"), SourceID: "grc", RuntimeID: "runtime-1"}, nil
		},
		AuthorizeTenant: func(context.Context, string) error { return nil },
		BumpCache: func(context.Context, string) {
			cacheBumps++
		},
		Now: fixedUploadTime,
	})
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, uploadRequest(t, "?tenant_id=tenant-1", map[string]string{"policy_id": "access"}))

	if response.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusAccepted)
	}
	var payload grcupload.Response
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got, want := payload.ProjectionStatus, "projection_partial"; got != want {
		t.Fatalf("projection_status = %q, want %q", got, want)
	}
	if got, want := payload.ProjectionFailures, 1; got != want {
		t.Fatalf("projection_failures = %d, want %d", got, want)
	}
	if len(appendLog.events) != 2 {
		t.Fatalf("appended events = %d, want 2", len(appendLog.events))
	}
	if len(projector.events) != 2 {
		t.Fatalf("projected events = %d, want both events attempted", len(projector.events))
	}
	if cacheBumps != 1 {
		t.Fatalf("cache bumps = %d, want 1 for the successful projection", cacheBumps)
	}
}

func TestHandlerRecordsUploadJobTimeline(t *testing.T) {
	appendLog := &recordingAppendLog{}
	projector := &recordingProjector{}
	jobs := newRecordingJobStore()
	handler := NewHandler(Options{
		Target: grcupload.TargetPolicy,
		ParserFactory: func() (grcupload.Parser, error) {
			return stubParser{parsed: grcupload.ParsedDocument{
				ProviderFileID: "file-1",
				ParseID:        "parse-1",
				Status:         "completed",
				TextPreview:    "Access policy review evidence",
				ChunkCount:     1,
				PageCount:      2,
				Chunks:         []grcupload.ParsedChunk{{Index: 1, Page: 1, TextPreview: "Access policy review evidence"}},
			}}, nil
		},
		AppendLog: appendLog,
		Projector: projector,
		JobStore:  jobs,
		ResolveScope: func(r *http.Request) (Scope, error) {
			return Scope{TenantID: r.URL.Query().Get("tenant_id"), RuntimeID: "runtime-1"}, nil
		},
		AuthorizeTenant: func(context.Context, string) error { return nil },
		Now:             fixedUploadTime,
	})
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, uploadRequest(t, "?tenant_id=tenant-1", map[string]string{
		"policy_id":                "access",
		"owner_id":                 "owner-1",
		"approving_authority":      "Security Steering Committee",
		"next_review_due_at":       "2026-12-31",
		"acknowledgement_evidence": "campaign-1",
		"exception_path":           "Submit a waiver request",
		"control_ids":              "CC6.1",
	}))

	if response.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusAccepted)
	}
	var payload grcupload.Response
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload.Job == nil || payload.Job.ID == "" || payload.Job.Status != ports.JobStatusCompleted {
		t.Fatalf("job ref = %#v", payload.Job)
	}
	if payload.FileSHA256 == "" {
		t.Fatal("file_sha256 is empty")
	}
	if payload.Status != "projected" {
		t.Fatalf("upload status = %q, want projected", payload.Status)
	}
	gotTypes := []string{}
	for _, event := range jobs.events {
		gotTypes = append(gotTypes, event.Type)
	}
	wantTypes := []string{"received", "parsing", "parsed", "events_appended", "projected"}
	if len(gotTypes) != len(wantTypes) {
		t.Fatalf("job event types = %#v, want %#v", gotTypes, wantTypes)
	}
	for index, want := range wantTypes {
		if gotTypes[index] != want {
			t.Fatalf("job event types = %#v, want %#v", gotTypes, wantTypes)
		}
	}
	job := jobs.jobs[payload.Job.ID]
	if job == nil || job.Result["status"] != "projected" || job.ResultRefs["upload_id"] != payload.UploadID {
		t.Fatalf("stored job = %#v", job)
	}
	if job.SubjectID != payload.UploadID || job.IdempotencyKey != "grc_upload:"+payload.UploadID {
		t.Fatalf("job upload identity = subject %q idempotency %q, want upload %q", job.SubjectID, job.IdempotencyKey, payload.UploadID)
	}
}

func uploadRequest(t *testing.T, query string, fields map[string]string) *http.Request {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("file", "Access Policy.pdf")
	if err != nil {
		t.Fatalf("CreateFormFile() error = %v", err)
	}
	if _, err := part.Write([]byte("policy body")); err != nil {
		t.Fatalf("write file part: %v", err)
	}
	for key, value := range fields {
		if err := writer.WriteField(key, value); err != nil {
			t.Fatalf("WriteField(%s) error = %v", key, err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("multipart close: %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, "/upload"+query, &body)
	request.Header.Set("Content-Type", writer.FormDataContentType())
	return request
}

func fixedUploadTime() time.Time {
	return time.Date(2026, 6, 28, 10, 30, 0, 0, time.UTC)
}

type stubParser struct {
	parsed grcupload.ParsedDocument
	err    error
}

func (p stubParser) Parse(context.Context, string, string, io.Reader) (grcupload.ParsedDocument, error) {
	return p.parsed, p.err
}

type recordingAppendLog struct {
	events []*cerebrov1.EventEnvelope
	failAt int
}

func (l *recordingAppendLog) Ping(context.Context) error {
	return nil
}

func (l *recordingAppendLog) Append(_ context.Context, event *cerebrov1.EventEnvelope) error {
	l.events = append(l.events, event)
	if l.failAt > 0 && len(l.events) == l.failAt {
		return errors.New("append failed")
	}
	return nil
}

type recordingProjector struct {
	events []*cerebrov1.EventEnvelope
	failAt int
}

func (p *recordingProjector) Project(_ context.Context, event *cerebrov1.EventEnvelope) (ports.ProjectionResult, error) {
	p.events = append(p.events, event)
	if p.failAt > 0 && len(p.events) == p.failAt {
		return ports.ProjectionResult{}, errors.New("project failed")
	}
	return ports.ProjectionResult{}, nil
}

type recordingJobStore struct {
	jobs   map[string]*ports.Job
	events []*ports.JobEvent
	nextID int
}

func newRecordingJobStore() *recordingJobStore {
	return &recordingJobStore{jobs: map[string]*ports.Job{}, nextID: 1}
}

func (s *recordingJobStore) Ping(context.Context) error {
	return nil
}

func (s *recordingJobStore) CreateJob(_ context.Context, request ports.CreateJobRequest) (*ports.Job, bool, error) {
	for _, job := range s.jobs {
		if job.TenantID == request.TenantID && job.IdempotencyKey != "" && job.IdempotencyKey == request.IdempotencyKey {
			return cloneTestJob(job), false, nil
		}
	}
	id := "job-" + strconv.Itoa(s.nextID)
	s.nextID++
	job := &ports.Job{
		ID:             id,
		Kind:           request.Kind,
		Status:         ports.JobStatusQueued,
		TenantID:       request.TenantID,
		SubjectType:    request.SubjectType,
		SubjectID:      request.SubjectID,
		IdempotencyKey: request.IdempotencyKey,
		Payload:        request.Payload,
	}
	s.jobs[id] = cloneTestJob(job)
	return cloneTestJob(job), true, nil
}

func (s *recordingJobStore) GetJob(_ context.Context, id string) (*ports.Job, error) {
	job := s.jobs[id]
	if job == nil {
		return nil, ports.ErrJobNotFound
	}
	return cloneTestJob(job), nil
}

func (s *recordingJobStore) ListJobs(context.Context, ports.JobFilter) ([]*ports.Job, error) {
	return nil, nil
}

func (s *recordingJobStore) CountJobs(context.Context, ports.JobFilter) (uint64, error) {
	return 0, nil
}

func (s *recordingJobStore) UpdateJob(_ context.Context, id string, update ports.JobUpdate) (*ports.Job, error) {
	job := s.jobs[id]
	if job == nil {
		return nil, ports.ErrJobNotFound
	}
	if update.Status != "" {
		job.Status = update.Status
	}
	if update.Progress != nil {
		job.Progress = *update.Progress
	}
	if update.Message != "" {
		job.Message = update.Message
	}
	if update.Error != "" {
		job.Error = update.Error
	}
	if update.Result != nil {
		job.Result = update.Result
	}
	if update.ResultRefs != nil {
		job.ResultRefs = update.ResultRefs
	}
	if update.StartedAt != nil {
		job.StartedAt = *update.StartedAt
	}
	if update.FinishedAt != nil {
		job.FinishedAt = *update.FinishedAt
	}
	if update.CancelRequested != nil {
		job.CancelRequested = *update.CancelRequested
	}
	return cloneTestJob(job), nil
}

func (s *recordingJobStore) AppendJobEvent(_ context.Context, event ports.JobEvent) (*ports.JobEvent, error) {
	event.Sequence = uint64(len(s.events) + 1)
	s.events = append(s.events, &event)
	return &event, nil
}

func (s *recordingJobStore) ListJobEvents(context.Context, string, uint32) ([]*ports.JobEvent, error) {
	return nil, nil
}

func cloneTestJob(job *ports.Job) *ports.Job {
	if job == nil {
		return nil
	}
	clone := *job
	if job.Payload != nil {
		clone.Payload = map[string]any{}
		for key, value := range job.Payload {
			clone.Payload[key] = value
		}
	}
	if job.Result != nil {
		clone.Result = map[string]any{}
		for key, value := range job.Result {
			clone.Result[key] = value
		}
	}
	if job.ResultRefs != nil {
		clone.ResultRefs = map[string]string{}
		for key, value := range job.ResultRefs {
			clone.ResultRefs[key] = value
		}
	}
	return &clone
}
