package bootstrap

import (
	"context"
	"errors"
	"net/http"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/reports"
	"github.com/writer/cerebro/internal/sourcehttp/agenttasks"
	"github.com/writer/cerebro/internal/sourceruntime"
)

const agentContextPath = agenttasks.ContextPath

func (a *App) agentTaskHandler() agenttasks.Handler {
	return agenttasks.New(agenttasks.Dependencies{
		Origin:                       func(r *http.Request) string { return externalOrigin(r, a.cfg.Auth.RequestOrigin) },
		Caller:                       agentCallerContextForRequest,
		SupportedScopes:              supportedOAuthScopes,
		OAuthProtectedResourcePath:   oauthProtectedResourceMetadataPath,
		OAuthAuthorizationServerPath: oauthAuthorizationServerMetadataPath,
		OAuthTokenPath:               oauthTokenPath,
		Scopes: agenttasks.ScopeSet{
			SecurityRead:          scopeCosmoSecurityRead,
			GraphActionsWrite:     scopeGraphActionsWrite,
			FindingLifecycleWrite: scopeFindingLifecycleWrite,
			SourceRuntimesWrite:   scopeSourceRuntimesWrite,
			ReportsRun:            scopeReportsRun,
		},
		AuthorizeFinding: func(ctx context.Context, findingID string) error {
			return normalizeIDLookupError(authorizeFindingIDTenant(ctx, findingStore(a.deps.StateStore), findingID), ports.ErrFindingNotFound)
		},
		AuthorizeSourceRuntime: func(ctx context.Context, runtimeID string) error {
			return normalizeIDLookupError(authorizeSourceRuntimeIDTenant(ctx, sourceRuntimeStore(a.deps.StateStore), runtimeID), ports.ErrSourceRuntimeNotFound)
		},
		AuthorizeTenant:         authorizeTenantID,
		AuthorizeExecutionScope: authorizeAgentTaskExecutionScope,
		SyncRuntime:             a.syncAgentTaskRuntime,
		RunReport:               a.runAgentTaskReport,
		ErrorStatus:             agentTaskErrorStatus,
	})
}

func agentCallerContextForRequest(r *http.Request) agenttasks.CallerContext {
	userAgent := requestHeaderValue(r, "User-Agent")
	ctx := agenttasks.CallerContext{
		ActorType: agenttasks.ActorTypeFromUserAgent(userAgent),
		UserAgent: agenttasks.UserAgentFamily(userAgent),
	}
	if r == nil {
		return ctx
	}
	auth, ok := r.Context().Value(authContextKey{}).(authContext)
	if !ok {
		return ctx
	}
	ctx.Authenticated = true
	ctx.TenantID = strings.TrimSpace(auth.principal.TenantID)
	ctx.ActorID = agentPlatformPrincipalActorID(auth.principal, "")
	ctx.AuthMode = strings.TrimSpace(auth.principal.AuthMode)
	ctx.Scopes = expandedPrincipalScopes(auth.principal)
	if ctx.ActorType == "unknown" || ctx.ActorType == "automation" {
		ctx.ActorType = agentActorTypeFromPrincipal(auth.principal, userAgent)
	}
	return ctx
}

func agentActorTypeFromPrincipal(principal authPrincipal, userAgent string) string {
	switch strings.TrimSpace(principal.AuthMode) {
	case "device_jwt":
		return "agent"
	case "api_credential", "capability_token":
		return "service"
	}
	return agenttasks.ActorTypeFromUserAgent(userAgent)
}

func requestHeaderValue(r *http.Request, key string) string {
	if r == nil {
		return ""
	}
	return r.Header.Get(key)
}

func authorizeAgentTaskExecutionScope(ctx context.Context, required string) error {
	auth, ok := ctx.Value(authContextKey{}).(authContext)
	if !ok || !principalScopeRestricted(auth.principal) {
		return nil
	}
	return authorizePrincipalScope(auth.principal, required)
}

func (a *App) syncAgentTaskRuntime(ctx context.Context, runtimeID string, pageLimit uint32) (agenttasks.RuntimeSyncResult, error) {
	syncResp, err := a.runtimeService().SyncWithLease(ctx, &cerebrov1.SyncSourceRuntimeRequest{Id: runtimeID, PageLimit: pageLimit}, sourceruntime.SyncWithLeaseOptions{
		LeaseStore: sourceRuntimeLeaseStore(a.deps.StateStore),
	})
	if err != nil {
		return agenttasks.RuntimeSyncResult{}, err
	}
	return agenttasks.RuntimeSyncResult{
		RuntimeID:         syncResp.GetRuntime().GetId(),
		PagesRead:         syncResp.GetPagesRead(),
		EventsAppended:    syncResp.GetEventsAppended(),
		EntitiesProjected: syncResp.GetEntitiesProjected(),
		LinksProjected:    syncResp.GetLinksProjected(),
	}, nil
}

func (a *App) runAgentTaskReport(ctx context.Context, reportID string, parameters map[string]string) (agenttasks.ReportRunResult, error) {
	runResp, err := a.reportService().Run(ctx, &cerebrov1.RunReportRequest{ReportId: reportID, Parameters: parameters})
	if err != nil {
		return agenttasks.ReportRunResult{}, err
	}
	run := runResp.GetRun()
	if err := authorizeTenantID(ctx, run.GetParameters()["tenant_id"]); err != nil {
		return agenttasks.ReportRunResult{}, err
	}
	result := agenttasks.ReportRunResult{
		ReportID: run.GetReportId(),
		RunID:    run.GetId(),
		Status:   run.GetStatus(),
	}
	if generatedAt := run.GetGeneratedAt(); generatedAt != nil {
		result.GeneratedAt = generatedAt.AsTime()
	}
	return result, nil
}

func agentTaskErrorStatus(err error) int {
	switch {
	case errors.Is(err, agenttasks.ErrInvalidRequest), errors.Is(err, reports.ErrInvalidRequest), errors.Is(err, sourceruntime.ErrInvalidRequest):
		return http.StatusBadRequest
	case errors.Is(err, errTenantForbidden), errors.Is(err, errScopeForbidden):
		return http.StatusForbidden
	case errors.Is(err, ports.ErrFindingNotFound), errors.Is(err, ports.ErrSourceRuntimeNotFound):
		return http.StatusNotFound
	case errors.Is(err, sourceruntime.ErrRuntimeUnavailable), errors.Is(err, reports.ErrRuntimeUnavailable), errors.Is(err, findings.ErrRuntimeUnavailable):
		return http.StatusServiceUnavailable
	default:
		return 0
	}
}
