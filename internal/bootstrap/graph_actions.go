package bootstrap

import (
	"context"
	"net/http"

	"connectrpc.com/connect"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/graphactionapi"
	"github.com/writer/cerebro/internal/graphactions"
	"github.com/writer/cerebro/internal/graphactionworkflow"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourcehttp/graphactionhandler"
)

func (a *App) handleExecuteGraphAction(w http.ResponseWriter, r *http.Request) {
	graphActionHandler(a.services.graphActions, a.deps).HandleExecute(w, r)
}

func (s *bootstrapService) ExecuteGraphAction(ctx context.Context, req *connect.Request[cerebrov1.ExecuteGraphActionRequest]) (*connect.Response[cerebrov1.ExecuteGraphActionResponse], error) {
	return graphActionHandler(s.graphActions, s.deps).ExecuteConnect(ctx, req.Msg)
}

func (a *App) handleReconcileGraphAction(w http.ResponseWriter, r *http.Request) {
	graphActionHandler(a.services.graphActions, a.deps).HandleReconcile(w, r)
}

func (s *bootstrapService) ReconcileGraphAction(ctx context.Context, req *connect.Request[cerebrov1.ReconcileGraphActionRequest]) (*connect.Response[cerebrov1.ReconcileGraphActionResponse], error) {
	return graphActionHandler(s.graphActions, s.deps).ReconcileConnect(ctx, req.Msg)
}

func graphActionHandler(service *graphactions.Service, deps Dependencies) graphactionhandler.Handler {
	return graphactionhandler.Handler{
		Executor:       graphActionExecutor(service, deps),
		ErrorSentinels: graphactionapi.ErrorSentinelsFor(errInvalidHTTPRequest, errTenantForbidden, errScopeForbidden),
		ReadProtoJSON:  readProtoJSON,
		WriteProtoJSON: writeProtoJSON,
		ErrorMessage:   safeHTTPErrorMessage,
		FindingMessage: findingMessage,
	}
}

func graphActionExecutor(service *graphactions.Service, deps Dependencies) graphactionapi.Executor {
	return graphactionapi.Executor{
		Service: service,
		AuthorizeFinding: func(ctx context.Context, findingID string) error {
			return normalizeIDLookupError(authorizeFindingIDTenant(ctx, findingStore(deps.StateStore), findingID), ports.ErrFindingNotFound)
		},
		BumpFinding: func(ctx context.Context, finding *ports.FindingRecord) {
			bumpGRCCacheForFinding(ctx, deps.QueryCache, finding)
		},
		BeforeLink: graphactionworkflow.BeforeLink(deps.AppendLog),
	}
}
