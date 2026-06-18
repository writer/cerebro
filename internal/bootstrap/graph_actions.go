package bootstrap

import (
	"context"
	"net/http"

	"connectrpc.com/connect"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
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
	result, err := a.executeGraphAction(r.Context(), graphactionapi.InputFromRequest(request))
	if err != nil {
		writeGraphActionError(w, err)
		return
	}
	writeProtoJSON(w, http.StatusAccepted, graphActionResponseProto(result))
}

func (s *bootstrapService) ExecuteGraphAction(ctx context.Context, req *connect.Request[cerebrov1.ExecuteGraphActionRequest]) (*connect.Response[cerebrov1.ExecuteGraphActionResponse], error) {
	app := &App{cfg: s.cfg, deps: s.deps, sources: s.sources}
	result, err := app.executeGraphAction(ctx, graphactionapi.InputFromRequest(req.Msg))
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
