package agenttasks

import (
	"encoding/json"
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

func TestReadTaskRequestNormalizesIdempotencyHeader(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/api/v1/agent/tasks/source-runtimes/runtime-1/retry", strings.NewReader(`{"dry_run":true}`))
	request.Header.Set(idempotencyHeader, " retry-1 ")
	recorder := httptest.NewRecorder()

	task, err := readTaskRequest(recorder, request)
	if err != nil {
		t.Fatalf("readTaskRequest() error = %v", err)
	}
	if task.Idempotency != "retry-1" {
		t.Fatalf("idempotency = %q, want trimmed header key", task.Idempotency)
	}
}

func TestReadTaskRequestNormalizesIdempotencyHeaderWithEmptyBody(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/api/v1/agent/tasks/source-runtimes/runtime-1/retry", strings.NewReader(""))
	request.Header.Set(idempotencyHeader, "retry-empty-body")
	recorder := httptest.NewRecorder()

	task, err := readTaskRequest(recorder, request)
	if err != nil {
		t.Fatalf("readTaskRequest() error = %v", err)
	}
	if task.Idempotency != "retry-empty-body" {
		t.Fatalf("idempotency = %q, want header key", task.Idempotency)
	}
}

func TestReadTaskRequestRejectsMismatchedIdempotencySources(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/api/v1/agent/tasks/source-runtimes/runtime-1/retry", strings.NewReader(`{"idempotency_key":"body-key"}`))
	request.Header.Set(idempotencyHeader, "header-key")
	recorder := httptest.NewRecorder()

	_, err := readTaskRequest(recorder, request)
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("readTaskRequest() error = %v, want ErrInvalidRequest", err)
	}
}

func TestReadTaskRequestRejectsLongIdempotencyKey(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/api/v1/agent/tasks/source-runtimes/runtime-1/retry", strings.NewReader(`{}`))
	request.Header.Set(idempotencyHeader, strings.Repeat("a", maxIdempotencyKeyBytes+1))
	recorder := httptest.NewRecorder()

	_, err := readTaskRequest(recorder, request)
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("readTaskRequest() error = %v, want ErrInvalidRequest", err)
	}
}

func TestRuntimeRetryDryRunEchoesIdempotencyMetadata(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/api/v1/agent/tasks/source-runtimes/runtime-1/retry", strings.NewReader(`{"dry_run":true}`))
	request.SetPathValue("runtimeID", "runtime-1")
	request.Header.Set(idempotencyHeader, "retry-runtime-1")
	recorder := httptest.NewRecorder()

	New(Dependencies{Scopes: ScopeSet{SourceRuntimesWrite: "source.runtimes.write"}}).SourceRuntimeRetry(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	var response TaskResponse
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.IdempotencyKey != "retry-runtime-1" {
		t.Fatalf("response idempotency_key = %q, want request key", response.IdempotencyKey)
	}
	if response.Mutation == nil || response.Mutation.IdempotencyKey != "retry-runtime-1" {
		t.Fatalf("mutation = %+v, want idempotency key", response.Mutation)
	}
	if response.Mutation.Headers[idempotencyHeader] != "retry-runtime-1" {
		t.Fatalf("mutation headers = %+v, want Idempotency-Key", response.Mutation.Headers)
	}
	if response.Attempt.ID == "" || strings.Contains(response.Attempt.ID, "retry-runtime-1") {
		t.Fatalf("attempt id = %q, want hashed attempt id without raw key", response.Attempt.ID)
	}
	if !response.Attempt.IdempotencyKeyPresent || response.Attempt.DuplicateDetection != taskDuplicateDetectionCallerKey {
		t.Fatalf("attempt = %+v, want caller-key duplicate detection", response.Attempt)
	}
	if response.Attempt.ReplaySupported || response.Attempt.CancellationSupported {
		t.Fatalf("attempt = %+v, want no replay or cancellation support", response.Attempt)
	}
	if len(response.Attempt.Audit) != 1 || response.Attempt.Audit[0].Event != "cerebro.api.access" {
		t.Fatalf("attempt audit = %+v, want platform access audit", response.Attempt.Audit)
	}
}

func TestTaskAttemptIDIsStableForSameRetryKey(t *testing.T) {
	request := TaskRequest{Idempotency: " retry-runtime-1 "}
	first := New(Dependencies{}).baseTaskResponse("source_runtime_retry", "source_runtime", "runtime-1", "/source-runtimes/runtime-1", request)
	replay := New(Dependencies{}).baseTaskResponse("source_runtime_retry", "source_runtime", "runtime-1", "/source-runtimes/runtime-1", request)
	other := New(Dependencies{}).baseTaskResponse("source_runtime_retry", "source_runtime", "runtime-1", "/source-runtimes/runtime-1", TaskRequest{Idempotency: "retry-runtime-2"})

	if first.Attempt.ID == "" {
		t.Fatal("attempt id is empty, want stable id")
	}
	if first.Attempt.ID != replay.Attempt.ID {
		t.Fatalf("attempt id changed across replay: %q != %q", first.Attempt.ID, replay.Attempt.ID)
	}
	if first.Attempt.ID == other.Attempt.ID {
		t.Fatalf("attempt id = %q for different idempotency keys", first.Attempt.ID)
	}
	if strings.Contains(first.Attempt.ID, "retry-runtime-1") {
		t.Fatalf("attempt id = %q, want no raw idempotency key", first.Attempt.ID)
	}
}

func TestTaskAttemptWithoutIdempotencyKeyMarksDuplicateDetectionUnavailable(t *testing.T) {
	response := New(Dependencies{}).baseTaskResponse("report_run", "report", "risk-summary", "/reports/risk-summary/runs", TaskRequest{})

	if response.Attempt.ID != "" {
		t.Fatalf("attempt id = %q, want empty without idempotency key", response.Attempt.ID)
	}
	if response.Attempt.IdempotencyKeyPresent {
		t.Fatalf("attempt = %+v, want idempotency_key_present=false", response.Attempt)
	}
	if response.Attempt.DuplicateDetection != taskDuplicateDetectionUnavailable {
		t.Fatalf("duplicate detection = %q, want unavailable", response.Attempt.DuplicateDetection)
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
