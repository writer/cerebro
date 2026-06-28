package grcuploadhttp

import (
	"bytes"
	"context"
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
