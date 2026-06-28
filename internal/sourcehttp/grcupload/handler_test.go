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
	if len(appendLog.events) != 2 || len(projector.events) != 2 {
		t.Fatalf("append/project counts = %d/%d, want 2/2", len(appendLog.events), len(projector.events))
	}
	if got, want := appendLog.events[0].GetAttributes()["policy_id"], "ISO:27001/2022"; got != want {
		t.Fatalf("policy_id attribute = %q, want %q", got, want)
	}
	if got, want := appendLog.events[0].GetAttributes()["record_urn"], payload.Events[0].RecordURN; got != want {
		t.Fatalf("record_urn attribute = %q, want %q", got, want)
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
	if got, want := payload.ProjectionStatus, "accepted_with_projection_errors"; got != want {
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
