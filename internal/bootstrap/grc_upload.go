package bootstrap

import (
	"context"
	"net/http"

	"github.com/writer/cerebro/internal/grcupload"
	grcuploadhttp "github.com/writer/cerebro/internal/sourcehttp/grcupload"
	"github.com/writer/cerebro/internal/sourcehttp/reducto"
)

func (a *App) handleGRCPolicyUpload(w http.ResponseWriter, r *http.Request) {
	a.grcUploadHandler(grcupload.TargetPolicy).ServeHTTP(w, r)
}

func (a *App) handleGRCVendorUpload(w http.ResponseWriter, r *http.Request) {
	a.grcUploadHandler(grcupload.TargetVendor).ServeHTTP(w, r)
}

func (a *App) grcUploadHandler(target grcupload.Target) http.Handler {
	return grcuploadhttp.NewHandler(grcuploadhttp.Options{
		Target:        target,
		ParserFactory: a.grcUploadParser,
		AppendLog:     a.deps.AppendLog,
		Projector:     sourceProjector(a.deps.StateStore, a.deps.GraphStore),
		ResolveScope: func(r *http.Request) (grcuploadhttp.Scope, error) {
			scope, err := grcScopeFromRequest(r)
			return grcuploadhttp.Scope{
				TenantID:  scope.TenantID,
				SourceID:  scope.SourceID,
				RuntimeID: scope.RuntimeID,
			}, err
		},
		AuthorizeTenant: authorizeTenantID,
		ActorUserID:     customDashboardActorID,
		BumpCache: func(ctx context.Context, tenantID string) {
			a.bumpGRCCacheVersions(ctx, tenantID, grcCacheScopeGraph)
		},
		WriteError: writeGRCError,
		WriteJSON:  writeJSON,
	})
}

func (a *App) grcUploadParser() (grcupload.Parser, error) {
	return reducto.NewClient(reducto.Config{
		APIKey:  a.cfg.DocumentParsing.Reducto.APIKey,
		BaseURL: a.cfg.DocumentParsing.Reducto.BaseURL,
		Timeout: a.cfg.DocumentParsing.Reducto.Timeout,
	})
}
