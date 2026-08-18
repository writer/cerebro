package bootstrap

import (
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/writer/cerebro/internal/parityrun"
)

func TestWithParityCorrelationPropagatesValidatedHeaders(t *testing.T) {
	request := httptest.NewRequest("GET", "/platform/graph/neighborhood", nil)
	request.Header.Set(parityrun.HeaderName, "cutover-run-2026-08-13")
	request.Header.Set(parityrun.ObservationHeaderName, "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")

	got, err := withParityCorrelation(request)
	if err != nil {
		t.Fatalf("withParityCorrelation() error = %v", err)
	}
	if values := parityrun.FromContext(got); values.RunID != "cutover-run-2026-08-13" || values.ObservationID == "" {
		t.Fatalf("parityrun.FromContext() = %#v", values)
	}
}

func TestWithParityCorrelationRejectsInvalidOrRepeatedHeader(t *testing.T) {
	for _, values := range [][]string{{"short"}, {"cutover-run-one", "cutover-run-two"}} {
		request := httptest.NewRequest("GET", "/grc/findings", nil)
		request.Header.Set(parityrun.ObservationHeaderName, "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
		for _, value := range values {
			request.Header.Add(parityrun.HeaderName, value)
		}
		if _, err := withParityCorrelation(request); !errors.Is(err, errInvalidHTTPRequest) {
			t.Fatalf("withParityCorrelation(%q) error = %v, want invalid request", values, err)
		}
	}
}
