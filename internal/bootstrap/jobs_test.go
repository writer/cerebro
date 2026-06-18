package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/config"
	platformjobs "github.com/writer/cerebro/internal/jobs"
	"github.com/writer/cerebro/internal/ports"
)

func TestAuthorizeJobCreateAllowsSourceRuntimeOrchestrate(t *testing.T) {
	store := &stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
		"runtime-1": {Id: "runtime-1", SourceId: "github", TenantId: "writer"},
	}}
	tenantID, err := authorizeJobCreate(context.Background(), store, createJobHTTPRequest{
		Kind:     platformjobs.KindSourceRuntimeOrchestrate,
		TenantID: "writer",
		Payload:  map[string]any{"runtime_id": "runtime-1"},
	})
	if err != nil {
		t.Fatalf("authorizeJobCreate() error = %v", err)
	}
	if tenantID != "writer" {
		t.Fatalf("authorizeJobCreate() tenantID = %q, want writer", tenantID)
	}
}

func TestNewCachesJobServiceForAsyncLifecycle(t *testing.T) {
	app := New(config.Config{HTTPAddr: "127.0.0.1:0"}, Dependencies{StateStore: &stubRuntimeStore{}}, nil)
	if app.services.jobs == nil {
		t.Fatal("jobsService = nil, want cached service")
	}
	first := app.jobService()
	second := app.jobService()
	if first != second {
		t.Fatal("jobService() returned different instances")
	}
}

func TestJobDirectIDHandlersNormalizeForeignTenantLookup(t *testing.T) {
	store := newA2ATestJobStore()
	store.jobs["foreign-job"] = &ports.Job{
		ID:       "foreign-job",
		TenantID: "tenant-b",
		Status:   ports.JobStatusRunning,
	}
	app := New(config.Config{HTTPAddr: "127.0.0.1:0"}, Dependencies{StateStore: store}, nil)

	for _, tt := range []struct {
		name    string
		method  string
		target  string
		handler http.HandlerFunc
	}{
		{name: "get", method: http.MethodGet, target: "/platform/jobs/foreign-job", handler: app.handleGetJob},
		{name: "events", method: http.MethodGet, target: "/platform/jobs/foreign-job/events", handler: app.handleListJobEvents},
		{name: "cancel", method: http.MethodPost, target: "/platform/jobs/foreign-job/cancel", handler: app.handleCancelJob},
	} {
		t.Run(tt.name, func(t *testing.T) {
			request := httptest.NewRequest(tt.method, tt.target, nil)
			request.SetPathValue("jobID", "foreign-job")
			request = request.WithContext(context.WithValue(request.Context(), authContextKey{}, authContext{
				principal: authPrincipal{TenantID: "tenant-a"},
			}))
			recorder := httptest.NewRecorder()
			tt.handler(recorder, request)
			if recorder.Code != http.StatusNotFound {
				t.Fatalf("%s status = %d, want %d", tt.name, recorder.Code, http.StatusNotFound)
			}
		})
	}
}

func TestWriteJobErrorSanitizesInternalErrors(t *testing.T) {
	recorder := httptest.NewRecorder()
	writeJobError(recorder, errors.New("postgres query failed: secret DSN"))

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", recorder.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["error"] != "internal server error" {
		t.Fatalf("error body = %q, want sanitized internal server error", body["error"])
	}
}

func TestWriteJobErrorKeepsClientErrorsActionable(t *testing.T) {
	recorder := httptest.NewRecorder()
	writeJobError(recorder, fmt.Errorf("%w: missing tenant_id", platformjobs.ErrInvalidRequest))

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", recorder.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["error"] == "" || body["error"] == "bad request" {
		t.Fatalf("error body = %q, want actionable client error", body["error"])
	}
}
