package graphactionapi

import (
	"errors"

	"connectrpc.com/connect"

	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/graphactions"
	"github.com/writer/cerebro/internal/ports"
)

const (
	statusBadRequest         = 400
	statusForbidden          = 403
	statusNotFound           = 404
	statusBadGateway         = 502
	statusServiceUnavailable = 503
	statusInternalServer     = 500
)

type ErrorSentinels struct {
	InvalidHTTPRequest error
	TenantForbidden    error
	ScopeForbidden     error
}

func HTTPStatus(err error, sentinels ErrorSentinels) int {
	switch {
	case errors.Is(err, graphactions.ErrInvalidRequest), errors.Is(err, sentinels.InvalidHTTPRequest):
		return statusBadRequest
	case errors.Is(err, graphactions.ErrNotConfigured), errors.Is(err, findings.ErrRuntimeUnavailable):
		return statusServiceUnavailable
	case errors.Is(err, ports.ErrFindingNotFound):
		return statusNotFound
	case errors.Is(err, sentinels.TenantForbidden), errors.Is(err, sentinels.ScopeForbidden):
		return statusForbidden
	case errors.Is(err, graphactions.ErrRemote):
		return statusBadGateway
	default:
		return statusInternalServer
	}
}

func ConnectError(err error, sentinels ErrorSentinels) error {
	switch HTTPStatus(err, sentinels) {
	case statusBadRequest:
		return connect.NewError(connect.CodeInvalidArgument, err)
	case statusNotFound:
		return connect.NewError(connect.CodeNotFound, err)
	case statusForbidden:
		return connect.NewError(connect.CodePermissionDenied, nil)
	case statusServiceUnavailable, statusBadGateway:
		return connect.NewError(connect.CodeUnavailable, nil)
	default:
		return connect.NewError(connect.CodeInternal, nil)
	}
}
