package grcvendorcreate

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/grcvendor"
	"github.com/writer/cerebro/internal/ports"
)

func TestHandlerPreservesScopeAuthorizationWriteOrdering(t *testing.T) {
	operations := []string{}
	appendLog := &recordingAppendLog{operations: &operations}
	projector := &recordingProjector{operations: &operations}
	handler := NewHandler(Options{
		AppendLog: appendLog,
		Projector: projector,
		ResolveScope: func(request *http.Request) (Scope, error) {
			operations = append(operations, "scope")
			if got := request.URL.Query().Get("tenant_id"); got != "writer" {
				t.Fatalf("resolved tenant query = %q, want writer", got)
			}
			return Scope{TenantID: "writer", ApplicationWorkspaceID: "workspace-a"}, nil
		},
		AuthorizeTenant: func(_ context.Context, tenantID string) error {
			operations = append(operations, "authorize")
			if tenantID != "writer" {
				t.Fatalf("authorized tenant = %q, want writer", tenantID)
			}
			return nil
		},
		BumpCache: func(_ context.Context, tenantID string) {
			operations = append(operations, "write_stamp")
			if tenantID != "writer" {
				t.Fatalf("write-stamped tenant = %q, want writer", tenantID)
			}
		},
		WriteError: testErrorWriter,
		Now:        testNow,
	})
	request := httptest.NewRequest(http.MethodPost, "/grc/vendors?workspace_id=workspace-a", strings.NewReader(
		`{"tenant_id":"writer","workspace_id":"workspace-a","name":"Acme Vendor"}`,
	))
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusCreated, response.Body.String())
	}
	if got, want := strings.Join(operations, ","), "scope,authorize,append,project,write_stamp"; got != want {
		t.Fatalf("operations = %q, want %q", got, want)
	}
	if appendLog.event == nil {
		t.Fatal("appended event is nil")
	}
	if got := appendLog.event.GetTenantId(); got != "writer" {
		t.Fatalf("event tenant = %q, want writer", got)
	}
	if got := appendLog.event.GetAttributes()[ports.EventAttributeApplicationWorkspaceID]; got != "workspace-a" {
		t.Fatalf("event workspace = %q, want workspace-a", got)
	}
}

func TestHandlerRejectsInvalidResolvedScopeBeforeAuthorizationOrWrite(t *testing.T) {
	tests := []struct {
		name  string
		url   string
		body  string
		scope Scope
	}{
		{
			name:  "workspace mismatch",
			url:   "/grc/vendors?tenant_id=writer&workspace_id=workspace-b",
			body:  `{"tenant_id":"writer","workspace_id":"workspace-a","name":"Acme Vendor"}`,
			scope: Scope{TenantID: "writer", ApplicationWorkspaceID: "workspace-b"},
		},
		{
			name:  "tenant mismatch",
			url:   "/grc/vendors?tenant_id=tenant-b",
			body:  `{"tenant_id":"tenant-a","name":"Acme Vendor"}`,
			scope: Scope{TenantID: "tenant-b"},
		},
		{
			name:  "empty tenant",
			url:   "/grc/vendors",
			body:  `{"name":"Acme Vendor"}`,
			scope: Scope{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			operations := []string{}
			handler := NewHandler(Options{
				AppendLog: &recordingAppendLog{operations: &operations},
				Projector: &recordingProjector{operations: &operations},
				ResolveScope: func(*http.Request) (Scope, error) {
					operations = append(operations, "scope")
					return tt.scope, nil
				},
				AuthorizeTenant: func(context.Context, string) error {
					operations = append(operations, "authorize")
					return nil
				},
				BumpCache: func(context.Context, string) {
					operations = append(operations, "write_stamp")
				},
				WriteError: testErrorWriter,
			})
			request := httptest.NewRequest(http.MethodPost, tt.url, strings.NewReader(tt.body))
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)

			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d", response.Code, http.StatusBadRequest)
			}
			if got, want := strings.Join(operations, ","), "scope"; got != want {
				t.Fatalf("operations = %q, want %q", got, want)
			}
		})
	}
}

func TestHandlerDoesNotAdvanceWriteStampOnWriteFailure(t *testing.T) {
	tests := []struct {
		name           string
		authorizeErr   error
		appendErr      error
		projectErr     error
		wantOperations string
	}{
		{name: "authorization failure", authorizeErr: errors.New("authorization failed"), wantOperations: "scope,authorize"},
		{name: "append failure", appendErr: errors.New("append failed"), wantOperations: "scope,authorize,append"},
		{name: "projection failure", projectErr: errors.New("projection failed"), wantOperations: "scope,authorize,append,project"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			operations := []string{}
			handler := NewHandler(Options{
				AppendLog: &recordingAppendLog{operations: &operations, err: tt.appendErr},
				Projector: &recordingProjector{operations: &operations, err: tt.projectErr},
				ResolveScope: func(*http.Request) (Scope, error) {
					operations = append(operations, "scope")
					return Scope{TenantID: "writer", ApplicationWorkspaceID: "workspace-a"}, nil
				},
				AuthorizeTenant: func(context.Context, string) error {
					operations = append(operations, "authorize")
					return tt.authorizeErr
				},
				BumpCache: func(context.Context, string) {
					operations = append(operations, "write_stamp")
				},
				WriteError: testErrorWriter,
				Now:        testNow,
			})
			request := httptest.NewRequest(http.MethodPost, "/grc/vendors?tenant_id=writer&workspace_id=workspace-a", strings.NewReader(
				`{"tenant_id":"writer","workspace_id":"workspace-a","name":"Acme Vendor"}`,
			))
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)

			if response.Code != http.StatusInternalServerError {
				t.Fatalf("status = %d, want %d", response.Code, http.StatusInternalServerError)
			}
			if got := strings.Join(operations, ","); got != tt.wantOperations {
				t.Fatalf("operations = %q, want %q", got, tt.wantOperations)
			}
		})
	}
}

func TestHandlerAcceptsTrailingWhitespaceAndRejectsSecondJSONObject(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		wantStatus int
	}{
		{name: "trailing whitespace", body: "{\"name\":\"Acme Vendor\"} \n\t", wantStatus: http.StatusCreated},
		{name: "second object", body: `{"name":"Acme Vendor"}{"name":"Other Vendor"}`, wantStatus: http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			operations := []string{}
			handler := NewHandler(Options{
				AppendLog: &recordingAppendLog{operations: &operations},
				Projector: &recordingProjector{operations: &operations},
				ResolveScope: func(*http.Request) (Scope, error) {
					return Scope{TenantID: "writer"}, nil
				},
				AuthorizeTenant: func(context.Context, string) error { return nil },
				WriteError:      testErrorWriter,
				Now:             testNow,
			})
			request := httptest.NewRequest(http.MethodPost, "/grc/vendors?tenant_id=writer", strings.NewReader(tt.body))
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)

			if response.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body = %s", response.Code, tt.wantStatus, response.Body.String())
			}
		})
	}
}

func TestBuildGRCVendorCreateEventDoesNotAllowStandardAttributeOverrides(t *testing.T) {
	event, vendor, err := buildGRCVendorCreateEvent(grcVendorCreateRequest{
		Name: "Acme Vendor",
		Attributes: map[string]string{
			"source_status": "disabled",
			"owner":         "untrusted-owner",
			"custom_field":  "kept",
		},
	}, Scope{TenantID: "writer"}, testNow())
	if err != nil {
		t.Fatalf("buildGRCVendorCreateEvent() error = %v", err)
	}
	if got := event.GetAttributes()["source_status"]; got != "active" {
		t.Fatalf("source_status = %q, want active", got)
	}
	if got := event.GetAttributes()["owner"]; got != "" {
		t.Fatalf("owner = %q, want reserved attribute omitted", got)
	}
	if got := event.GetAttributes()["custom_field"]; got != "kept" {
		t.Fatalf("custom_field = %q, want kept", got)
	}
	if vendor.Owner != "" {
		t.Fatalf("vendor owner = %q, want empty", vendor.Owner)
	}
}

type recordingAppendLog struct {
	operations *[]string
	event      *cerebrov1.EventEnvelope
	err        error
}

func (*recordingAppendLog) Ping(context.Context) error {
	return nil
}

func (l *recordingAppendLog) Append(_ context.Context, event *cerebrov1.EventEnvelope) error {
	*l.operations = append(*l.operations, "append")
	l.event = event
	return l.err
}

type recordingProjector struct {
	operations *[]string
	err        error
}

func (p *recordingProjector) Project(context.Context, *cerebrov1.EventEnvelope) (ports.ProjectionResult, error) {
	*p.operations = append(*p.operations, "project")
	return ports.ProjectionResult{}, p.err
}

func testErrorWriter(w http.ResponseWriter, err error) {
	statusCode := http.StatusInternalServerError
	if errors.Is(err, grcvendor.ErrInvalidRequest) {
		statusCode = http.StatusBadRequest
	}
	http.Error(w, http.StatusText(statusCode), statusCode)
}

func testNow() time.Time {
	return time.Date(2026, time.August, 26, 0, 0, 0, 0, time.UTC)
}
