package telemetry

import (
	"errors"
	"fmt"
	"net/url"
	"testing"
)

func TestErrorKindReportsSingleJoinedCause(t *testing.T) {
	cause := &url.Error{Op: "Get", URL: "http://example.invalid", Err: errors.New("dial failed")}
	var nilErr error

	if got := ErrorKind(errors.Join(cause, nilErr, nilErr)); got != ErrorKind(cause) {
		t.Fatalf("ErrorKind(single join) = %q, want %q", got, ErrorKind(cause))
	}
	if got := ErrorKind(fmt.Errorf("sync: %w", errors.Join(errors.New("boom"), nilErr))); got != "error" {
		t.Fatalf("ErrorKind(wrapped single join) = %q, want error", got)
	}
}

func TestErrorKindKeepsJoinKindForMultipleCauses(t *testing.T) {
	err := errors.Join(errors.New("sync failed"), errors.New("release failed"))
	if got := ErrorKind(err); got != "errors_join_error" {
		t.Fatalf("ErrorKind(multi join) = %q, want errors_join_error", got)
	}
}
