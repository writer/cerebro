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
