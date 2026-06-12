package bootstrap

import (
	"net/http"

	"connectrpc.com/connect"

	cerebrov1connect "github.com/writer/cerebro/gen/cerebro/v1/cerebrov1connect"
	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/sourcecdk"
)

type bootstrapRouteSurface string

const (
	routeSurfacePublicHTTP   bootstrapRouteSurface = "public-http"
	routeSurfacePlatformHTTP bootstrapRouteSurface = "platform-http"
	routeSurfaceInternalHTTP bootstrapRouteSurface = "internal-http"
)

func (app *App) registerRoutes(mux *http.ServeMux, cfg config.Config, deps Dependencies, sources *sourcecdk.Registry) {
	app.registerConnectRoutes(mux, cfg, deps, sources)
	app.registerPublicRoutes(mux)
	app.registerOAuthRoutes(mux)
	app.registerReportRoutes(mux)
	app.registerGRCRoutes(mux)
	app.registerFindingRoutes(mux)
	app.registerSourceRoutes(mux)
	app.registerKnowledgeRoutes(mux)
	app.registerGraphRoutes(mux)
	app.registerJobRoutes(mux)
	app.registerRuntimeResponseRoutes(mux)
	app.registerSourceRuntimeRoutes(mux)
	app.registerMCPRoutes(mux)
	app.registerDeviceRoutes(mux)
}

func (app *App) registerConnectRoutes(mux *http.ServeMux, cfg config.Config, deps Dependencies, sources *sourcecdk.Registry) {
	service := &bootstrapService{cfg: cfg, deps: deps, sources: sources}
	path, handler := cerebrov1connect.NewBootstrapServiceHandler(service, connect.WithInterceptors(authInterceptor(cfg.Auth)))
	mux.Handle(path, handler)
}

func (app *App) registerPublicRoutes(mux *http.ServeMux) {
	registerHTTPRoute(mux, "GET /health", routeSurfacePublicHTTP, app.handleHealth)
	registerHTTPRoute(mux, "GET /healthz", routeSurfacePublicHTTP, app.handleLiveness)
	registerHTTPRoute(mux, "GET /livez", routeSurfacePublicHTTP, app.handleLiveness)
	registerHTTPRoute(mux, "GET /metrics", routeSurfacePlatformHTTP, app.handleMetrics)
	registerHTTPRoute(mux, "GET /openapi.yaml", routeSurfacePublicHTTP, app.handleOpenAPI)
}

func (app *App) registerOAuthRoutes(mux *http.ServeMux) {
	registerHTTPRoute(mux, "GET /.well-known/oauth-protected-resource", routeSurfacePublicHTTP, app.handleOAuthProtectedResourceMetadata)
	registerHTTPRoute(mux, "GET /.well-known/oauth-protected-resource/api/v1/mcp", routeSurfacePublicHTTP, app.handleOAuthProtectedResourceMetadata)
	registerHTTPRoute(mux, "GET /.well-known/oauth-authorization-server", routeSurfacePublicHTTP, app.handleOAuthAuthorizationServerMetadata)
	registerHTTPRoute(mux, "GET /oauth/authorize", routeSurfacePublicHTTP, app.handleOAuthAuthorize)
	registerHTTPRoute(mux, "GET /oauth/callback", routeSurfacePublicHTTP, app.handleOAuthCallback)
	registerHTTPRoute(mux, "POST /oauth/token", routeSurfacePublicHTTP, app.handleOAuthToken)
	registerHTTPRoute(mux, "POST /oauth/revoke", routeSurfacePublicHTTP, app.handleOAuthRevoke)
	registerHTTPRoute(mux, "POST /oauth/register", routeSurfacePublicHTTP, app.handleOAuthRegister)
}

func (app *App) registerReportRoutes(mux *http.ServeMux) {
	registerHTTPRoute(mux, "GET /reports", routeSurfacePlatformHTTP, app.handleListReportDefinitions)
	registerHTTPRoute(mux, "POST /reports/{reportID}/runs", routeSurfacePlatformHTTP, app.handleRunReport)
	registerHTTPRoute(mux, "GET /report-runs/{runID}", routeSurfacePlatformHTTP, app.handleGetReportRun)
}

func (app *App) registerGRCRoutes(mux *http.ServeMux) {
	registerHTTPRoute(mux, "GET /grc/dashboard", routeSurfacePlatformHTTP, app.handleGRCDashboard)
	registerHTTPRoute(mux, "POST /grc/ask", routeSurfacePlatformHTTP, app.handleGRCAsk)
	registerHTTPRoute(mux, "GET /grc/findings", routeSurfacePlatformHTTP, app.handleGRCFindings)
	registerHTTPRoute(mux, "GET /grc/controls", routeSurfacePlatformHTTP, app.handleGRCControls)
	registerHTTPRoute(mux, "GET /grc/evidence", routeSurfacePlatformHTTP, app.handleGRCEvidence)
	registerHTTPRoute(mux, "GET /grc/inventory/categories", routeSurfacePlatformHTTP, app.handleGRCInventoryCategories)
	registerHTTPRoute(mux, "GET /grc/inventory/assets", routeSurfacePlatformHTTP, app.handleGRCInventoryAssets)
	registerHTTPRoute(mux, "GET /grc/inventory/assets/detail", routeSurfacePlatformHTTP, app.handleGRCInventoryAssetDetail)
	registerHTTPRoute(mux, "GET /grc/inventory/resource-scope", routeSurfacePlatformHTTP, app.handleGRCResourceScope)
	registerHTTPRoute(mux, "POST /grc/inventory/resource-scope", routeSurfacePlatformHTTP, app.handleUpdateGRCResourceScope)
	registerHTTPRoute(mux, "GET /grc/entities/{entityID}/impact", routeSurfacePlatformHTTP, app.handleGRCEntityImpact)
	registerHTTPRoute(mux, "GET /grc/audit-packets/{packetID}", routeSurfacePlatformHTTP, app.handleGRCAuditPacket)
}

func (app *App) registerFindingRoutes(mux *http.ServeMux) {
	registerHTTPRoute(mux, "GET /finding-rules", routeSurfacePlatformHTTP, app.handleListFindingRules)
	registerHTTPRoute(mux, "GET /findings/{findingID}", routeSurfacePlatformHTTP, app.handleGetFinding)
	registerHTTPRoute(mux, "POST /findings/{findingID}/resolve", routeSurfacePlatformHTTP, app.handleResolveFinding)
	registerHTTPRoute(mux, "POST /findings/{findingID}/suppress", routeSurfacePlatformHTTP, app.handleSuppressFinding)
	registerHTTPRoute(mux, "PUT /findings/{findingID}/assign", routeSurfacePlatformHTTP, app.handleAssignFinding)
	registerHTTPRoute(mux, "PUT /findings/{findingID}/due", routeSurfacePlatformHTTP, app.handleSetFindingDueDate)
	registerHTTPRoute(mux, "POST /findings/{findingID}/notes", routeSurfacePlatformHTTP, app.handleAddFindingNote)
	registerHTTPRoute(mux, "POST /findings/{findingID}/tickets", routeSurfacePlatformHTTP, app.handleLinkFindingTicket)
	registerHTTPRoute(mux, "GET /finding-candidates/{candidateID}", routeSurfacePlatformHTTP, app.handleGetFindingCandidate)
	registerHTTPRoute(mux, "POST /finding-candidates/{candidateID}/promote", routeSurfacePlatformHTTP, app.handlePromoteFindingCandidate)
	registerHTTPRoute(mux, "POST /finding-candidates/{candidateID}/reject", routeSurfacePlatformHTTP, app.handleRejectFindingCandidate)
	registerHTTPRoute(mux, "GET /endpoint-vulnerability-findings", routeSurfacePlatformHTTP, app.handleListEndpointVulnerabilityFindings)
	registerHTTPRoute(mux, "GET /finding-evaluation-runs/{runID}", routeSurfacePlatformHTTP, app.handleGetFindingEvaluationRun)
	registerHTTPRoute(mux, "GET /finding-evidence/{evidenceID}", routeSurfacePlatformHTTP, app.handleGetFindingEvidence)
	registerHTTPRoute(mux, "GET /platform/endpoints/{deviceKey}/vulnerability-findings", routeSurfacePlatformHTTP, app.handleListEndpointVulnerabilityFindings)
}

func (app *App) registerSourceRoutes(mux *http.ServeMux) {
	registerHTTPRoute(mux, "GET /sources", routeSurfacePlatformHTTP, app.handleSources)
	registerHTTPRoute(mux, "GET /sources/{sourceID}/check", routeSurfacePlatformHTTP, app.handleCheckSource)
	registerHTTPRoute(mux, "GET /sources/{sourceID}/discover", routeSurfacePlatformHTTP, app.handleDiscoverSource)
	registerHTTPRoute(mux, "GET /sources/{sourceID}/read", routeSurfacePlatformHTTP, app.handleReadSource)
}

func (app *App) registerKnowledgeRoutes(mux *http.ServeMux) {
	registerHTTPRoute(mux, "POST /platform/knowledge/decisions", routeSurfacePlatformHTTP, app.handleWriteDecision)
	registerHTTPRoute(mux, "POST /platform/knowledge/actions", routeSurfacePlatformHTTP, app.handleWriteAction)
	registerHTTPRoute(mux, "POST /platform/knowledge/actions/recommendation", routeSurfacePlatformHTTP, app.handleWriteAction)
	registerHTTPRoute(mux, "POST /platform/knowledge/outcomes", routeSurfacePlatformHTTP, app.handleWriteOutcome)
	registerHTTPRoute(mux, "POST /platform/workflow/replay", routeSurfacePlatformHTTP, app.handleReplayWorkflowEvents)
}

func (app *App) registerGraphRoutes(mux *http.ServeMux) {
	registerHTTPRoute(mux, "GET /platform/graph/neighborhood", routeSurfacePlatformHTTP, app.handleGetEntityNeighborhood)
	registerHTTPRoute(mux, "GET /platform/graph/impact/vulnerability/{id}", routeSurfacePlatformHTTP, app.handleGetVulnerabilityImpact)
	registerHTTPRoute(mux, "GET /platform/graph/impact/package", routeSurfacePlatformHTTP, app.handleGetPackageImpact)
	registerHTTPRoute(mux, "GET /platform/graph/impact/asset", routeSurfacePlatformHTTP, app.handleGetAssetImpact)
	registerHTTPRoute(mux, "GET /platform/graph/person-access-paths", routeSurfacePlatformHTTP, app.handleGetPersonAccessPaths)
	registerHTTPRoute(mux, "GET /platform/graph/attack-paths", routeSurfacePlatformHTTP, app.handleGetAttackPaths)
	registerHTTPRoute(mux, "GET /platform/graph/crown-jewel-rankings", routeSurfacePlatformHTTP, app.handleGetCrownJewelRankings)
	registerHTTPRoute(mux, "GET /platform/graph/aws-public-endpoint-insights", routeSurfacePlatformHTTP, app.handleGetAWSPublicEndpointInsights)
	registerHTTPRoute(mux, "GET /platform/graph/ingest-health", routeSurfacePlatformHTTP, app.handleCheckGraphIngestHealth)
	registerHTTPRoute(mux, "GET /platform/graph/ingest-runs", routeSurfacePlatformHTTP, app.handleListGraphIngestRuns)
	registerHTTPRoute(mux, "GET /platform/graph/ingest-runs/{runID}", routeSurfacePlatformHTTP, app.handleGetGraphIngestRun)
}

func (app *App) registerJobRoutes(mux *http.ServeMux) {
	registerHTTPRoute(mux, "POST /platform/jobs", routeSurfacePlatformHTTP, app.handleCreateJob)
	registerHTTPRoute(mux, "GET /platform/jobs", routeSurfacePlatformHTTP, app.handleListJobs)
	registerHTTPRoute(mux, "GET /platform/jobs/{jobID}", routeSurfacePlatformHTTP, app.handleGetJob)
	registerHTTPRoute(mux, "GET /platform/jobs/{jobID}/events", routeSurfacePlatformHTTP, app.handleListJobEvents)
	registerHTTPRoute(mux, "POST /platform/jobs/{jobID}/cancel", routeSurfacePlatformHTTP, app.handleCancelJob)
}

func (app *App) registerRuntimeResponseRoutes(mux *http.ServeMux) {
	registerHTTPRoute(mux, "GET /platform/runtime-response/capabilities", routeSurfacePlatformHTTP, app.handleRuntimeResponseCapabilities)
	registerHTTPRoute(mux, "POST /platform/runtime-response/actions", routeSurfacePlatformHTTP, app.handleExecuteRuntimeResponse)
	registerHTTPRoute(mux, "GET /platform/runtime-response/blocklist", routeSurfacePlatformHTTP, app.handleListRuntimeBlocklist)
	registerHTTPRoute(mux, "POST /platform/runtime-response/blocklist/{entryID}/revoke", routeSurfacePlatformHTTP, app.handleRevokeRuntimeBlocklistEntry)
}

func (app *App) registerSourceRuntimeRoutes(mux *http.ServeMux) {
	registerHTTPRoute(mux, "GET /source-runtimes", routeSurfacePlatformHTTP, app.handleListSourceRuntimes)
	registerHTTPRoute(mux, "GET /source-runtimes/health", routeSurfacePlatformHTTP, app.handleListSourceRuntimeHealth)
	registerHTTPRoute(mux, "PUT /source-runtimes/{runtimeID}", routeSurfacePlatformHTTP, app.handlePutSourceRuntime)
	registerHTTPRoute(mux, "GET /source-runtimes/{runtimeID}", routeSurfacePlatformHTTP, app.handleGetSourceRuntime)
	registerHTTPRoute(mux, "POST /source-runtimes/{runtimeID}/sync", routeSurfacePlatformHTTP, app.handleSyncSourceRuntime)
	registerHTTPRoute(mux, "GET /source-runtimes/{runtimeID}/invalid-events", routeSurfacePlatformHTTP, app.handleListSourceRuntimeInvalidEvents)
	registerHTTPRoute(mux, "POST /source-runtimes/{runtimeID}/graph-ingest-runs", routeSurfacePlatformHTTP, app.handleRunGraphIngestRuntime)
	registerHTTPRoute(mux, "GET /source-runtimes/{runtimeID}/claims", routeSurfacePlatformHTTP, app.handleListClaims)
	registerHTTPRoute(mux, "POST /source-runtimes/{runtimeID}/claims", routeSurfacePlatformHTTP, app.handleWriteClaims)
	registerHTTPRoute(mux, "GET /source-runtimes/{runtimeID}/findings", routeSurfacePlatformHTTP, app.handleListFindings)
	registerHTTPRoute(mux, "GET /source-runtimes/{runtimeID}/finding-candidates", routeSurfacePlatformHTTP, app.handleListFindingCandidates)
	registerHTTPRoute(mux, "GET /source-runtimes/{runtimeID}/finding-evidence", routeSurfacePlatformHTTP, app.handleListFindingEvidence)
	registerHTTPRoute(mux, "GET /source-runtimes/{runtimeID}/finding-evaluation-runs", routeSurfacePlatformHTTP, app.handleListFindingEvaluationRuns)
	registerHTTPRoute(mux, "POST /source-runtimes/{runtimeID}/finding-candidates/evaluate", routeSurfacePlatformHTTP, app.handleEvaluateSourceRuntimeFindingCandidates)
	registerHTTPRoute(mux, "POST /source-runtimes/{runtimeID}/finding-rules/evaluate", routeSurfacePlatformHTTP, app.handleEvaluateSourceRuntimeFindingRules)
	registerHTTPRoute(mux, "POST /source-runtimes/{runtimeID}/findings/evaluate", routeSurfacePlatformHTTP, app.handleEvaluateSourceRuntimeFindings)
}

func (app *App) registerMCPRoutes(mux *http.ServeMux) {
	registerHTTPRoute(mux, "GET /api/v1/mcp", routeSurfacePlatformHTTP, app.handleMCPStream)
	registerHTTPRoute(mux, "POST /api/v1/mcp", routeSurfacePlatformHTTP, app.handleMCP)
}

func (app *App) registerDeviceRoutes(mux *http.ServeMux) {
	if app.deviceHandler == nil {
		return
	}
	registerHTTPRoute(mux, "POST /platform/devices/enroll", routeSurfacePlatformHTTP, app.deviceHandler.handleEnroll)
	registerHTTPRoute(mux, "POST /platform/devices/token", routeSurfacePlatformHTTP, app.deviceHandler.handleToken)
	registerHTTPRoute(mux, "POST /platform/devices/bootstrap-tokens", routeSurfacePlatformHTTP, app.deviceHandler.handleIssueBootstrapToken)
	registerHTTPRoute(mux, "POST /platform/devices/{deviceID}/revoke", routeSurfacePlatformHTTP, app.deviceHandler.handleRevoke)
	registerHTTPRoute(mux, "POST /platform/telemetry/ingest", routeSurfacePlatformHTTP, app.deviceHandler.handleIngestTelemetry)
	registerHTTPRoute(mux, "GET /.well-known/device-jwks.json", routeSurfacePublicHTTP, app.deviceHandler.handleJWKS)
}

func registerHTTPRoute(mux *http.ServeMux, pattern string, _ bootstrapRouteSurface, handler http.HandlerFunc) {
	mux.HandleFunc(pattern, handler)
}
