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
	result, err := executeGraphAction(r.Context(), graphactionapi.InputFromRequest(request), a.services.graphActions, a.deps)
	if err != nil {
		writeGraphActionError(w, err)
		return
	}
	writeProtoJSON(w, http.StatusAccepted, graphactionapi.ResponseMessage(result, findingMessage(result.Finding)))
}

func (s *bootstrapService) ExecuteGraphAction(ctx context.Context, req *connect.Request[cerebrov1.ExecuteGraphActionRequest]) (*connect.Response[cerebrov1.ExecuteGraphActionResponse], error) {
	result, err := executeGraphAction(ctx, graphactionapi.InputFromRequest(req.Msg), s.graphActions, s.deps)
	if err != nil {
		return nil, graphactionapi.ConnectError(err, graphActionErrors)
	}
	return connect.NewResponse(graphactionapi.ResponseMessage(result, findingMessage(result.Finding))), nil
}

func executeGraphAction(ctx context.Context, input graphactions.Input, service *graphactions.Service, deps Dependencies) (*graphactions.Result, error) {
	return graphactionapi.Executor{
		Service: service,
		AuthorizeFinding: func(ctx context.Context, findingID string) error {
			return normalizeIDLookupError(authorizeFindingIDTenant(ctx, findingStore(deps.StateStore), findingID), ports.ErrFindingNotFound)
		},
		BumpFinding: func(ctx context.Context, finding *ports.FindingRecord) {
			bumpGRCCacheForFinding(ctx, deps.QueryCache, finding)
		},
	}.Execute(ctx, input)
}

func writeGraphActionError(w http.ResponseWriter, err error) {
	status := graphactionapi.HTTPStatus(err, graphActionErrors)
	writeJSON(w, status, map[string]string{"error": safeHTTPErrorMessage(status, err)})
}

var graphActionErrors = graphactionapi.ErrorSentinels{
	InvalidHTTPRequest: errInvalidHTTPRequest,
	TenantForbidden:    errTenantForbidden,
	ScopeForbidden:     errScopeForbidden,
}
