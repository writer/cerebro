package bootstrap

import (
	"context"
	"net/http"

	"github.com/writer/cerebro/internal/grcupload"
	grcuploadhttp "github.com/writer/cerebro/internal/sourcehttp/grcupload"
	"github.com/writer/cerebro/internal/sourcehttp/reducto"
)

func (a *App) grcUploadReplayHandler() http.Handler {
	return grcuploadhttp.NewReplayHandler(grcuploadhttp.ReplayOptions{
		Replayer:  eventReplayer(a.deps.AppendLog),
		Projector: sourceProjector(a.deps.StateStore, a.deps.GraphStore),
		ResolveTenant: func(r *http.Request) (string, error) {
			return effectiveTenantFilter(r.Context(), r.URL.Query().Get("tenant_id"))
		},
		AuthorizeTenant: authorizeTenantID,
		BumpCache:       func(ctx context.Context, tenantID string) { a.bumpGRCCacheVersions(ctx, tenantID, grcCacheScopeGraph) },
		WriteError:      writeGRCError,
		WriteJSON:       writeJSON,
	})
}

func (a *App) grcUploadHandler(target grcupload.Target) http.Handler {
	return grcuploadhttp.NewHandler(grcuploadhttp.Options{
		Target: target,
		ParserFactory: func() (grcupload.Parser, error) {
			return reducto.NewClient(reducto.Config{APIKey: a.cfg.DocumentParsing.Reducto.APIKey, BaseURL: a.cfg.DocumentParsing.Reducto.BaseURL, Timeout: a.cfg.DocumentParsing.Reducto.Timeout})
		},
		AppendLog: a.deps.AppendLog,
		Projector: sourceProjector(a.deps.StateStore, a.deps.GraphStore),
		JobStore:  jobStore(a.deps.StateStore),
		ResolveScope: func(r *http.Request) (grcuploadhttp.Scope, error) {
			scope, err := grcScopeFromRequest(r)
			return grcuploadhttp.Scope(scope), err
		},
		AuthorizeTenant: authorizeTenantID,
		ActorUserID:     customDashboardActorID,
		BumpCache:       func(ctx context.Context, tenantID string) { a.bumpGRCCacheVersions(ctx, tenantID, grcCacheScopeGraph) },
		WriteError:      writeGRCError,
		WriteJSON:       writeJSON,
	})
}
