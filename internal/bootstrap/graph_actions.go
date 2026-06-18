package bootstrap

import (
	"context"
	"net/http"

	"connectrpc.com/connect"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/graphactionapi"
	"github.com/writer/cerebro/internal/graphactions"
	"github.com/writer/cerebro/internal/ports"
)

func (a *App) handleExecuteGraphAction(w http.ResponseWriter, r *http.Request) {
	request := &cerebrov1.ExecuteGraphActionRequest{}
	if err := readProtoJSON(r, request); err != nil {
		writeGraphActionError(w, err)
		return
	}
	result, err := a.executeGraphAction(r.Context(), graphactionapi.InputFromRequest(request))
	if err != nil {
		writeGraphActionError(w, err)
		return
	}
	writeProtoJSON(w, http.StatusAccepted, graphactionapi.ResponseMessage(result, findingMessage(result.Finding)))
}

func (s *bootstrapService) ExecuteGraphAction(ctx context.Context, req *connect.Request[cerebrov1.ExecuteGraphActionRequest]) (*connect.Response[cerebrov1.ExecuteGraphActionResponse], error) {
	app := s.app
	if app == nil {
		app = &App{cfg: s.cfg, deps: s.deps, sources: s.sources}
	}
	result, err := app.executeGraphAction(ctx, graphactionapi.InputFromRequest(req.Msg))
	if err != nil {
		return nil, graphActionConnectError(err)
	}
	return connect.NewResponse(graphactionapi.ResponseMessage(result, findingMessage(result.Finding))), nil
}

func (a *App) executeGraphAction(ctx context.Context, input graphactions.Input) (*graphactions.Result, error) {
	return graphactionapi.Executor{
		Service: a.services.graphActions,
		NewService: func() (*graphactions.Service, error) {
			return graphactionapi.NewAccessApprovalsService(a.cfg.GraphActions.AccessApprovals, a.findingService())
		},
		AuthorizeFinding: func(ctx context.Context, findingID string) error {
			return normalizeIDLookupError(authorizeFindingIDTenant(ctx, findingStore(a.deps.StateStore), findingID), ports.ErrFindingNotFound)
		},
		BumpFinding: func(ctx context.Context, finding *ports.FindingRecord) {
			bumpGRCCacheForFinding(ctx, a.deps.QueryCache, finding)
		},
	}.Execute(ctx, input)
}

func writeGraphActionError(w http.ResponseWriter, err error) {
	status := graphactionapi.HTTPStatus(err, graphActionErrorSentinels())
	writeJSON(w, status, map[string]string{"error": safeHTTPErrorMessage(status, err)})
}

func graphActionConnectError(err error) error {
	return graphactionapi.ConnectError(err, graphActionErrorSentinels())
}

func graphActionErrorSentinels() graphactionapi.ErrorSentinels {
	return graphactionapi.ErrorSentinels{
		InvalidHTTPRequest: errInvalidHTTPRequest,
		TenantForbidden:    errTenantForbidden,
		ScopeForbidden:     errScopeForbidden,
	}
}
