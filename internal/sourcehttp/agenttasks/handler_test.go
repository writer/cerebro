package agenttasks

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestReadTaskRequestUsesInboundBodyLimit(t *testing.T) {
	body := `{"reason":"` + strings.Repeat("a", 2<<20) + `"}`
	request := httptest.NewRequest(http.MethodPost, "/api/v1/agent/tasks/findings/finding-1/explain", strings.NewReader(body))
	recorder := httptest.NewRecorder()

	_, err := readTaskRequest(recorder, request)
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("readTaskRequest() error = %v, want ErrInvalidRequest", err)
	}
	var maxBytesErr *http.MaxBytesError
	if !errors.As(err, &maxBytesErr) {
		t.Fatalf("readTaskRequest() error = %v, want MaxBytesError", err)
	}
}

func TestTaskParametersNormalizesTenantToAuthorizedValue(t *testing.T) {
	request := TaskRequest{
		TenantID: " authorized-tenant ",
		Parameters: map[string]string{
			"tenant_id": "other-tenant",
			"format":    "packet",
		},
	}

	parameters := taskParameters(request, strings.TrimSpace(request.TenantID))

	if parameters["tenant_id"] != "authorized-tenant" {
		t.Fatalf("tenant_id = %q, want authorized tenant", parameters["tenant_id"])
	}
	if parameters["format"] != "packet" {
		t.Fatalf("format = %q, want existing parameter preserved", parameters["format"])
	}
	if request.Parameters["tenant_id"] != "other-tenant" {
		t.Fatalf("request parameters were mutated: %+v", request.Parameters)
	}
}
