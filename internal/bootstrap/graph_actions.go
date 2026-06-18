package bootstrap

import (
	"context"
	"errors"
	"net/http"

	"connectrpc.com/connect"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/graphactionapi"
	"github.com/writer/cerebro/internal/graphactions"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourcehttp/accessapprovalsclient"
)

func (a *App) handleExecuteGraphAction(w http.ResponseWriter, r *http.Request) {
	request := &cerebrov1.ExecuteGraphActionRequest{}
	if err := readProtoJSON(r, request); err != nil {
		writeGraphActionError(w, err)
		return
	}
	result, err := a.executeGraphAction(r.Context(), graphactions.Input{
		FindingID:      request.GetFindingId(),
		Action:         request.GetAction(),
		Target:         request.GetTarget(),
		Reason:         request.GetReason(),
		TicketURL:      request.GetTicketUrl(),
		IdempotencyKey: request.GetIdempotencyKey(),
	})
	if err != nil {
		writeGraphActionError(w, err)
		return
	}
	writeProtoJSON(w, http.StatusAccepted, graphActionResponseProto(result))
}

func (s *bootstrapService) ExecuteGraphAction(ctx context.Context, req *connect.Request[cerebrov1.ExecuteGraphActionRequest]) (*connect.Response[cerebrov1.ExecuteGraphActionResponse], error) {
	app := &App{cfg: s.cfg, deps: s.deps, sources: s.sources}
	result, err := app.executeGraphAction(ctx, graphactions.Input{
		FindingID:      req.Msg.GetFindingId(),
		Action:         req.Msg.GetAction(),
		Target:         req.Msg.GetTarget(),
		Reason:         req.Msg.GetReason(),
		TicketURL:      req.Msg.GetTicketUrl(),
		IdempotencyKey: req.Msg.GetIdempotencyKey(),
	})
	if err != nil {
		return nil, graphActionConnectError(err)
	}
	return connect.NewResponse(graphActionResponseProto(result)), nil
}

func (a *App) executeGraphAction(ctx context.Context, input graphactions.Input) (*graphactions.Result, error) {
	if input.FindingID != "" {
		if err := authorizeFindingIDTenant(ctx, findingStore(a.deps.StateStore), input.FindingID); err != nil {
			return nil, normalizeIDLookupError(err, ports.ErrFindingNotFound)
		}
	}
	client, err := accessapprovalsclient.New(a.cfg.GraphActions.AccessApprovals)
	if err != nil {
		return nil, err
	}
	result, err := (graphactions.Service{Findings: a.findingService(), Client: client}).Execute(ctx, input)
	if err != nil {
		return nil, err
	}
	if result.Finding != nil {
		bumpGRCCacheForFinding(ctx, a.deps.QueryCache, result.Finding)
	}
	return result, nil
}

func graphActionResponseProto(result *graphactions.Result) *cerebrov1.ExecuteGraphActionResponse {
	var finding *cerebrov1.Finding
	if result != nil {
		finding = findingMessage(result.Finding)
	}
	return graphactionapi.ResponseMessage(result, finding)
}

func writeGraphActionError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, graphactions.ErrInvalidRequest), errors.Is(err, errInvalidHTTPRequest):
		status = http.StatusBadRequest
	case errors.Is(err, graphactions.ErrNotConfigured), errors.Is(err, findings.ErrRuntimeUnavailable):
		status = http.StatusServiceUnavailable
	case errors.Is(err, ports.ErrFindingNotFound):
		status = http.StatusNotFound
	case errors.Is(err, errTenantForbidden), errors.Is(err, errScopeForbidden):
		status = http.StatusForbidden
	case errors.Is(err, graphactions.ErrRemote):
		status = http.StatusBadGateway
	}
	writeJSON(w, status, map[string]string{"error": safeHTTPErrorMessage(status, err)})
}

func graphActionConnectError(err error) error {
	switch {
	case errors.Is(err, graphactions.ErrInvalidRequest), errors.Is(err, errInvalidHTTPRequest):
		return connect.NewError(connect.CodeInvalidArgument, err)
	case errors.Is(err, graphactions.ErrNotConfigured), errors.Is(err, findings.ErrRuntimeUnavailable):
		return connect.NewError(connect.CodeUnavailable, nil)
	case errors.Is(err, ports.ErrFindingNotFound):
		return connect.NewError(connect.CodeNotFound, err)
	case errors.Is(err, errTenantForbidden), errors.Is(err, errScopeForbidden):
		return connect.NewError(connect.CodePermissionDenied, nil)
	case errors.Is(err, graphactions.ErrRemote):
		return connect.NewError(connect.CodeUnavailable, nil)
	default:
		return connect.NewError(connect.CodeInternal, nil)
	}
}
