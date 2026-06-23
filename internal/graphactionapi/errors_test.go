package graphactionapi

import (
	"errors"
	"testing"

	"connectrpc.com/connect"

	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/graphactions"
	"github.com/writer/cerebro/internal/ports"
)

func TestErrorSentinelsFor(t *testing.T) {
	a := errors.New("invalid request")
	b := errors.New("tenant forbidden")
	c := errors.New("scope forbidden")
	s := ErrorSentinelsFor(a, b, c)
	if !errors.Is(s.InvalidHTTPRequest, a) {
		t.Fatal("InvalidHTTPRequest mismatch")
	}
	if !errors.Is(s.TenantForbidden, b) {
		t.Fatal("TenantForbidden mismatch")
	}
	if !errors.Is(s.ScopeForbidden, c) {
		t.Fatal("ScopeForbidden mismatch")
	}
}

func TestHTTPStatusMapsErrors(t *testing.T) {
	sentinels := ErrorSentinels{
		InvalidHTTPRequest: errors.New("bad http"),
		TenantForbidden:    errors.New("tenant"),
		ScopeForbidden:     errors.New("scope"),
	}
	tests := []struct {
		name string
		err  error
		want int
	}{
		{"invalid_request", graphactions.ErrInvalidRequest, statusBadRequest},
		{"invalid_http", sentinels.InvalidHTTPRequest, statusBadRequest},
		{"not_configured", graphactions.ErrNotConfigured, statusServiceUnavailable},
		{"runtime_unavailable", findings.ErrRuntimeUnavailable, statusServiceUnavailable},
		{"finding_not_found", ports.ErrFindingNotFound, statusNotFound},
		{"tenant_forbidden", sentinels.TenantForbidden, statusForbidden},
		{"scope_forbidden", sentinels.ScopeForbidden, statusForbidden},
		{"remote_error", graphactions.ErrRemote, statusBadGateway},
		{"unknown_error", errors.New("unknown"), statusInternalServer},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := HTTPStatus(tt.err, sentinels); got != tt.want {
				t.Fatalf("HTTPStatus() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestHTTPStatusWrappedErrors(t *testing.T) {
	sentinels := ErrorSentinels{
		InvalidHTTPRequest: errors.New("bad http"),
		TenantForbidden:    errors.New("tenant"),
		ScopeForbidden:     errors.New("scope"),
	}
	wrapped := errors.Join(graphactions.ErrInvalidRequest, errors.New("details"))
	if got := HTTPStatus(wrapped, sentinels); got != statusBadRequest {
		t.Fatalf("HTTPStatus(wrapped) = %d, want %d", got, statusBadRequest)
	}
}

func TestConnectErrorMapsToCorrectCodes(t *testing.T) {
	sentinels := ErrorSentinels{
		InvalidHTTPRequest: errors.New("bad http"),
		TenantForbidden:    errors.New("tenant"),
		ScopeForbidden:     errors.New("scope"),
	}
	tests := []struct {
		name string
		err  error
		want connect.Code
	}{
		{"invalid_request", graphactions.ErrInvalidRequest, connect.CodeInvalidArgument},
		{"not_found", ports.ErrFindingNotFound, connect.CodeNotFound},
		{"tenant_forbidden", sentinels.TenantForbidden, connect.CodePermissionDenied},
		{"not_configured", graphactions.ErrNotConfigured, connect.CodeUnavailable},
		{"remote", graphactions.ErrRemote, connect.CodeUnavailable},
		{"unknown", errors.New("unknown"), connect.CodeInternal},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			connErr := ConnectError(tt.err, sentinels)
			var ce *connect.Error
			if !errors.As(connErr, &ce) {
				t.Fatalf("ConnectError() did not return *connect.Error")
			}
			if ce.Code() != tt.want {
				t.Fatalf("connect code = %v, want %v", ce.Code(), tt.want)
			}
		})
	}
}

func TestConnectErrorForbiddenHidesMessage(t *testing.T) {
	sentinels := ErrorSentinels{
		InvalidHTTPRequest: errors.New("bad http"),
		TenantForbidden:    errors.New("tenant"),
		ScopeForbidden:     errors.New("scope"),
	}
	connErr := ConnectError(sentinels.TenantForbidden, sentinels)
	var ce *connect.Error
	if !errors.As(connErr, &ce) {
		t.Fatal("ConnectError() did not return *connect.Error")
	}
	if ce.Message() != "" {
		t.Fatalf("forbidden error should hide message, got %q", ce.Message())
	}
}
