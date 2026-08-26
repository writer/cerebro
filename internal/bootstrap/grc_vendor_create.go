package bootstrap

import (
	"context"
	"net/http"

	grcvendorcreate "github.com/writer/cerebro/internal/sourcehttp/grcvendorcreate"
)

func (a *App) handleCreateGRCVendor(w http.ResponseWriter, r *http.Request) {
	grcvendorcreate.NewHandler(grcvendorcreate.Options{
		AppendLog:       a.deps.AppendLog,
		Projector:       appendLogSourceProjector(a.deps),
		AuthorizeTenant: authorizeTenantID,
		WriteError:      writeGRCError,
		ResolveScope: func(request *http.Request) (grcvendorcreate.Scope, error) {
			scope, err := grcScopeFromRequest(request)
			return grcvendorcreate.Scope{
				TenantID: scope.TenantID, ApplicationWorkspaceID: scope.ApplicationWorkspaceID,
				RuntimeID: scope.RuntimeID, SourceID: scope.SourceID,
			}, err
		},
		BumpCache: func(ctx context.Context, tenantID string) {
			a.bumpGRCCacheVersions(ctx, tenantID, grcCacheScopeGraph)
		},
	}).ServeHTTP(w, r)
}
