package bootstrap

import (
	"context"
	"net/http"
	"time"

	"connectrpc.com/connect"

	cerebrov1connect "github.com/writer/cerebro/gen/cerebro/v1/cerebrov1connect"
	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/connectorcredentials"
	"github.com/writer/cerebro/internal/connectordefinitionrecords"
	"github.com/writer/cerebro/internal/connectordefinitions"
	"github.com/writer/cerebro/internal/grcupload"
	"github.com/writer/cerebro/internal/sourcecdk"
	credentialstoreshttp "github.com/writer/cerebro/internal/sourcehttp/credentialstores"
	"github.com/writer/cerebro/internal/sourcehttp/customdashboards"
	"github.com/writer/cerebro/internal/sourcehttp/identitydirectory"
	"github.com/writer/cerebro/internal/sourcehttp/userpreferences"
	"github.com/writer/cerebro/internal/sourceplanapi"
	"github.com/writer/cerebro/internal/sourceruntime"
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
	app.registerAgentPlatformRoutes(mux)
	app.registerReportRoutes(mux)
	app.registerAskQueryRoutes(mux)
	preferencesHandler := userpreferences.NewHandler(app.deps.StateStore, effectiveTenantFilter, userPreferenceActorID)
	registerHTTPRoute(mux, "GET /user/preferences", routeSurfacePlatformHTTP, preferencesHandler.Get)
	registerHTTPRoute(mux, "PUT /user/preferences", routeSurfacePlatformHTTP, preferencesHandler.Put)
	identityHandler := identitydirectory.NewHandler(app.deps.StateStore, cfg.Auth, effectiveTenantFilter, authorizeTenantID)
	registerHTTPRoute(mux, "GET /identity/orgs", routeSurfacePlatformHTTP, identityHandler.ListOrganizations)
	registerHTTPRoute(mux, "GET /identity/users", routeSurfacePlatformHTTP, identityHandler.ListUsers)
	app.registerGRCRoutes(mux)
	app.registerFindingRoutes(mux)
	app.registerSourceRoutes(mux)
	app.registerConnectorRoutes(mux)
	app.registerKnowledgeRoutes(mux)
	app.registerGraphRoutes(mux)
	app.registerJobRoutes(mux)
	app.registerRuntimeResponseRoutes(mux)
	app.registerSourceRuntimeRoutes(mux)
	app.registerMCPRoutes(mux)
	app.registerDeviceRoutes(mux)
}
func (app *App) registerConnectRoutes(mux *http.ServeMux, cfg config.Config, deps Dependencies, sources *sourcecdk.Registry) {
	service := &bootstrapService{cfg: cfg, deps: deps, sources: sources, graphActions: app.services.graphActions}
	path, handler := cerebrov1connect.NewBootstrapServiceHandler(service, connect.WithInterceptors(authInterceptor(cfg.Auth)))
	mux.Handle(path, handler)
}
func (app *App) registerPublicRoutes(mux *http.ServeMux) {
	registerHTTPRoute(mux, "GET /health", routeSurfacePublicHTTP, app.handleHealth)
	registerHTTPRoute(mux, "GET /healthz", routeSurfacePublicHTTP, app.handleLiveness)
	registerHTTPRoute(mux, "GET /livez", routeSurfacePublicHTTP, app.handleLiveness)
	registerHTTPRoute(mux, "GET /metrics", routeSurfacePlatformHTTP, app.handleMetrics)
	registerHTTPRoute(mux, "GET /openapi.yaml", routeSurfacePublicHTTP, app.handleOpenAPI)
	registerHTTPRoute(mux, "GET /.well-known/agent-card.json", routeSurfacePublicHTTP, app.handleA2AAgentCard)
	registerHTTPRoute(mux, "GET /.well-known/agent.json", routeSurfacePublicHTTP, app.handleA2AAgentCard)
}
func (app *App) registerAgentPlatformRoutes(mux *http.ServeMux) {
	agentTasks := app.agentTaskHandler()
	registerHTTPRoute(mux, "POST /api/v1/a2a", routeSurfacePlatformHTTP, app.handleA2AJSONRPC)
	registerHTTPRoute(mux, "GET /api/v1/agent/context", routeSurfacePlatformHTTP, agentTasks.Context)
	registerHTTPRoute(mux, "GET /api/v1/agent-platform/contract", routeSurfacePlatformHTTP, app.handleAgentPlatformContract)
	registerHTTPRoute(mux, "GET /api/v1/agent-platform/capabilities", routeSurfacePlatformHTTP, app.handleAgentPlatformCapabilities)
	registerHTTPRoute(mux, "GET /api/v1/agent-platform/security-control-plane", routeSurfacePlatformHTTP, app.handleAgentPlatformSecurityControlPlane)
	registerHTTPRoute(mux, "GET /api/v1/event-subscriptions/contract", routeSurfacePlatformHTTP, app.handleEventSubscriptionContract)
	registerHTTPRoute(mux, "GET /api/v1/idempotency-contract", routeSurfacePlatformHTTP, app.handleIdempotencyContract)
	registerHTTPRoute(mux, "POST /api/v1/agent-platform/capability-decisions", routeSurfacePlatformHTTP, app.handleAgentPlatformCapabilityDecision)
	registerHTTPRoute(mux, "POST /api/v1/agent-platform/preflight", routeSurfacePlatformHTTP, app.handleAgentPlatformPreflight)
	registerHTTPRoute(mux, "POST /api/v1/agent-platform/evidence-packets", routeSurfacePlatformHTTP, app.handleAgentPlatformEvidencePacket)
	registerHTTPRoute(mux, "POST /api/v1/agent-platform/claims/verify", routeSurfacePlatformHTTP, app.handleAgentPlatformClaimVerification)
	registerHTTPRoute(mux, "POST /api/v1/agent-platform/graph/reason", routeSurfacePlatformHTTP, app.handleAgentPlatformGraphReason)
	registerHTTPRoute(mux, "POST /api/v1/agent/tasks/findings/{findingID}/explain", routeSurfacePlatformHTTP, agentTasks.FindingExplain)
	registerHTTPRoute(mux, "POST /api/v1/agent/tasks/findings/{findingID}/triage", routeSurfacePlatformHTTP, agentTasks.FindingTriage)
	registerHTTPRoute(mux, "POST /api/v1/agent/tasks/findings/{findingID}/audit-packet", routeSurfacePlatformHTTP, agentTasks.FindingAuditPacket)
	registerHTTPRoute(mux, "POST /api/v1/agent/tasks/source-runtimes/{runtimeID}/retry", routeSurfacePlatformHTTP, agentTasks.SourceRuntimeRetry)
	registerHTTPRoute(mux, "POST /api/v1/agent/tasks/reports/{reportID}/run", routeSurfacePlatformHTTP, agentTasks.ReportRun)
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
	registerHTTPRoute(mux, "GET /report-runs", routeSurfacePlatformHTTP, app.handleListReportRuns)
	registerHTTPRoute(mux, "GET /report-runs/{runID}", routeSurfacePlatformHTTP, app.handleGetReportRun)
	registerHTTPRoute(mux, "GET /report-schedules", routeSurfacePlatformHTTP, app.handleListReportSchedules)
	registerHTTPRoute(mux, "POST /report-schedules", routeSurfacePlatformHTTP, app.handleCreateReportSchedule)
	registerHTTPRoute(mux, "PATCH /report-schedules/{scheduleID}", routeSurfacePlatformHTTP, app.handleUpdateReportSchedule)
	registerHTTPRoute(mux, "DELETE /report-schedules/{scheduleID}", routeSurfacePlatformHTTP, app.handleDeleteReportSchedule)
}
func (app *App) registerAskQueryRoutes(mux *http.ServeMux) {
	registerHTTPRoute(mux, "GET /ask-queries", routeSurfacePlatformHTTP, app.handleListAskQueries)
	registerHTTPRoute(mux, "POST /ask-queries", routeSurfacePlatformHTTP, app.handleCreateAskQuery)
	registerHTTPRoute(mux, "PATCH /ask-queries/{queryID}", routeSurfacePlatformHTTP, app.handleUpdateAskQuery)
	registerHTTPRoute(mux, "DELETE /ask-queries/{queryID}", routeSurfacePlatformHTTP, app.handleDeleteAskQuery)
}
func (app *App) registerGRCRoutes(mux *http.ServeMux) {
	dashboards := customdashboards.NewHandler(app.deps.StateStore, effectiveTenantFilter, authorizeTenantID, customDashboardActorID)
	registerHTTPRoute(mux, "GET /grc/dashboards", routeSurfacePlatformHTTP, dashboards.List)
	registerHTTPRoute(mux, "POST /grc/dashboards", routeSurfacePlatformHTTP, dashboards.Create)
	registerHTTPRoute(mux, "GET /grc/dashboards/{dashboardID}", routeSurfacePlatformHTTP, dashboards.Get)
	registerHTTPRoute(mux, "PATCH /grc/dashboards/{dashboardID}", routeSurfacePlatformHTTP, dashboards.Update)
	registerHTTPRoute(mux, "DELETE /grc/dashboards/{dashboardID}", routeSurfacePlatformHTTP, dashboards.Delete)
	registerHTTPRoute(mux, "POST /grc/dashboards/{dashboardID}/clone", routeSurfacePlatformHTTP, dashboards.Clone)
	registerHTTPRoute(mux, "GET /grc/program-readiness", routeSurfacePlatformHTTP, app.cacheGRCJSON(app.grcCachePolicy("program.readiness", time.Minute, grcCacheScopeFindings, grcCacheScopeEvidence, grcCacheScopeRuntime, grcCacheScopeGraph), app.handleGRCProgramReadiness))
	registerHTTPRoute(mux, "GET /grc/report-catalog", routeSurfacePlatformHTTP, app.cacheGRCJSON(app.grcCachePolicy("report.catalog", 5*time.Minute), app.handleGRCReportCatalog))
	registerHTTPRoute(mux, "POST /grc/query", routeSurfacePlatformHTTP, app.handleGRCQuery)
	registerHTTPRoute(mux, "GET /grc/dashboard", routeSurfacePlatformHTTP, app.cacheGRCJSON(app.grcCachePolicy("dashboard", 30*time.Second, grcCacheScopeFindings, grcCacheScopeEvidence, grcCacheScopeRuntime, grcCacheScopeGraph), app.handleGRCDashboard))
	registerHTTPRoute(mux, "GET /grc/policy-lifecycle", routeSurfacePlatformHTTP, app.cacheGRCJSON(app.grcCachePolicy("policy.lifecycle", time.Minute, grcCacheScopeGraph), app.handleGRCPolicyLifecycle))
	registerHTTPRoute(mux, "POST /grc/policy-lifecycle/actions", routeSurfacePlatformHTTP, app.handleGRCPolicyLifecycleAction)
	registerHTTPRoute(mux, "POST /grc/policy-lifecycle/uploads", routeSurfacePlatformHTTP, app.grcUploadHandler(grcupload.TargetPolicy).ServeHTTP)
	registerHTTPRoute(mux, "POST /grc/policy-lifecycle/uploads/{uploadID}/replay", routeSurfacePlatformHTTP, app.grcUploadReplayHandler().ServeHTTP)
	registerHTTPRoute(mux, "GET /grc/policy-lifecycle/export", routeSurfacePlatformHTTP, app.handleGRCPolicyLifecycleExport)
	registerHTTPRoute(mux, "GET /grc/trends", routeSurfacePlatformHTTP, app.cacheGRCJSON(app.grcCachePolicy("trends", time.Minute, grcCacheScopeFindings, grcCacheScopeRuntime), app.handleGRCTrends))
	registerHTTPRoute(mux, "POST /grc/ask", routeSurfacePlatformHTTP, app.handleGRCAsk)
	registerHTTPRoute(mux, "GET /grc/risk-scoring-config", routeSurfacePlatformHTTP, app.handleGetRiskScoringConfig)
	registerHTTPRoute(mux, "PUT /grc/risk-scoring-config", routeSurfacePlatformHTTP, app.handlePutRiskScoringConfig)
	registerHTTPRoute(mux, "DELETE /grc/risk-scoring-config", routeSurfacePlatformHTTP, app.handleDeleteRiskScoringConfig)
	registerHTTPRoute(mux, "GET /grc/findings", routeSurfacePlatformHTTP, app.cacheGRCJSON(app.grcCachePolicy("findings", time.Minute, grcCacheScopeFindings, grcCacheScopeEvidence, grcCacheScopeRuntime), app.handleGRCFindings))
	registerHTTPRoute(mux, "POST /grc/work-items", routeSurfacePlatformHTTP, app.handleDeriveComplianceWork)
	registerHTTPRoute(mux, "GET /grc/work-items/{workItemID}", routeSurfacePlatformHTTP, app.handleGetComplianceWorkItem)
	registerHTTPRoute(mux, "POST /grc/work-items/{workItemID}/commands", routeSurfacePlatformHTTP, app.handleComplianceWorkCommand)
	registerHTTPRoute(mux, "POST /grc/remediation-plans", routeSurfacePlatformHTTP, app.handleCreateComplianceRemediationPlan)
	registerHTTPRoute(mux, "GET /grc/remediation-plans/{planID}", routeSurfacePlatformHTTP, app.handleGetComplianceRemediationPlan)
	registerHTTPRoute(mux, "POST /grc/remediation-plans/{planID}/commands", routeSurfacePlatformHTTP, app.handleComplianceRemediationCommand)
	registerHTTPRoute(mux, "POST /grc/findings/triage", routeSurfacePlatformHTTP, app.handleUpdateGRCFindingDispositions)
	registerHTTPRoute(mux, "GET /grc/findings/export", routeSurfacePlatformHTTP, app.handleGRCFindingsExport)
	registerHTTPRoute(mux, "GET /grc/controls", routeSurfacePlatformHTTP, app.cacheGRCJSON(app.grcCachePolicy("controls", time.Minute, grcCacheScopeFindings, grcCacheScopeEvidence, grcCacheScopeRuntime), app.handleGRCControls))
	registerHTTPRoute(mux, "GET /grc/controls/export", routeSurfacePlatformHTTP, app.handleGRCControlsExport)
	registerHTTPRoute(mux, "GET /grc/evidence", routeSurfacePlatformHTTP, app.cacheGRCJSON(app.grcCachePolicy("evidence", time.Minute, grcCacheScopeEvidence, grcCacheScopeFindings, grcCacheScopeRuntime), app.handleGRCEvidence))
	registerHTTPRoute(mux, "GET /grc/frameworks", routeSurfacePlatformHTTP, app.cacheGRCJSON(app.grcCachePolicy("frameworks", 5*time.Minute), app.handleGRCFrameworks))
	registerHTTPRoute(mux, "GET /grc/control-archetypes", routeSurfacePlatformHTTP, app.cacheGRCJSON(app.grcCachePolicy("control.archetypes", 5*time.Minute), app.handleGRCControlArchetypes))
	registerHTTPRoute(mux, "GET /grc/control-profiles", routeSurfacePlatformHTTP, app.cacheGRCJSON(app.grcCachePolicy("control.profiles", 5*time.Minute), app.handleGRCControlProfiles))
	registerHTTPRoute(mux, "GET /grc/control-coverage", routeSurfacePlatformHTTP, app.cacheGRCJSON(app.grcCachePolicy("control.coverage", 5*time.Minute), app.handleGRCControlCoverage))
	registerHTTPRoute(mux, "GET /grc/control-packets", routeSurfacePlatformHTTP, app.cacheGRCJSON(app.grcCachePolicy("control.packets", time.Minute, grcCacheScopeFindings, grcCacheScopeEvidence, grcCacheScopeRuntime), app.handleGRCControlEvidencePacket))
	registerHTTPRoute(mux, "GET /grc/evidence-packets", routeSurfacePlatformHTTP, app.cacheGRCJSON(app.grcCachePolicy("evidence.packets", time.Minute, grcCacheScopeFindings, grcCacheScopeEvidence, grcCacheScopeRuntime), app.handleGRCControlEvidencePacket))
	registerHTTPRoute(mux, "POST /grc/control-packets", routeSurfacePlatformHTTP, app.handleGRCCustomControlEvidencePacket)
	registerHTTPRoute(mux, "GET /grc/control-packets/detail", routeSurfacePlatformHTTP, app.cacheGRCJSON(app.grcCachePolicy("control.packet.detail", time.Minute, grcCacheScopeFindings, grcCacheScopeEvidence, grcCacheScopeRuntime), app.handleGRCControlEvidencePacketDetail))
	registerHTTPRoute(mux, "GET /grc/control-packets/export", routeSurfacePlatformHTTP, app.handleGRCControlEvidencePacketExport)
	registerHTTPRoute(mux, "POST /grc/control-packets/export", routeSurfacePlatformHTTP, app.handleGRCCustomControlEvidencePacketExport)
	registerHTTPRoute(mux, "POST /grc/control-packs/preview", routeSurfacePlatformHTTP, app.handleGRCControlPackPreview)
	registerHTTPRoute(mux, "POST /grc/control-packs", routeSurfacePlatformHTTP, app.handleGRCControlPackCreate)
	questionnaireRuns := app.grcQuestionnaireRunHandler()
	registerHTTPRoute(mux, "GET /grc/questionnaire-runs", routeSurfacePlatformHTTP, app.cacheGRCJSON(app.grcCachePolicy("questionnaire.runs", time.Minute, grcCacheScopeEvidence, grcCacheScopeFindings, grcCacheScopeGraph, grcCacheScopeRuntime), questionnaireRuns.ListRuns))
	registerHTTPRoute(mux, "POST /grc/questionnaire-runs", routeSurfacePlatformHTTP, questionnaireRuns.CreateRun)
	registerHTTPRoute(mux, "GET /grc/questionnaire-runs/{runID}", routeSurfacePlatformHTTP, app.cacheGRCJSON(app.grcCachePolicy("questionnaire.run", time.Minute, grcCacheScopeEvidence, grcCacheScopeFindings, grcCacheScopeGraph, grcCacheScopeRuntime), questionnaireRuns.GetRun))
	registerHTTPRoute(mux, "POST /grc/questionnaire-runs/{runID}/process", routeSurfacePlatformHTTP, questionnaireRuns.ProcessRun)
	registerHTTPRoute(mux, "POST /grc/questionnaire-runs/{runID}/assignments", routeSurfacePlatformHTTP, questionnaireRuns.AssignRun)
	registerHTTPRoute(mux, "POST /grc/questionnaire-runs/{runID}/questions", routeSurfacePlatformHTTP, questionnaireRuns.UpdateQuestion)
	registerHTTPRoute(mux, "POST /grc/questionnaire-runs/{runID}/vendor-link", routeSurfacePlatformHTTP, questionnaireRuns.LinkVendor)
	registerHTTPRoute(mux, "POST /grc/questionnaire-runs/{runID}/decisions", routeSurfacePlatformHTTP, questionnaireRuns.DecideRun)
	registerHTTPRoute(mux, "POST /grc/questionnaire-runs/{runID}/comments", routeSurfacePlatformHTTP, questionnaireRuns.CommentRun)
	registerHTTPRoute(mux, "GET /grc/inventory/categories", routeSurfacePlatformHTTP, app.cacheGRCJSON(app.grcCachePolicy("inventory.categories", 5*time.Minute, grcCacheScopeGraph, grcCacheScopeInventory), app.handleGRCInventoryCategories))
	registerHTTPRoute(mux, "GET /grc/inventory/assets", routeSurfacePlatformHTTP, app.cacheGRCJSON(app.grcCachePolicy("inventory.assets", 2*time.Minute, grcCacheScopeGraph, grcCacheScopeInventory, grcCacheScopeFindings, grcCacheScopeEvidence), app.handleGRCInventoryAssets))
	registerHTTPRoute(mux, "GET /grc/inventory/assets/detail", routeSurfacePlatformHTTP, app.cacheGRCJSON(app.grcCachePolicy("inventory.asset.detail", 5*time.Minute, grcCacheScopeGraph, grcCacheScopeInventory, grcCacheScopeFindings, grcCacheScopeEvidence), app.handleGRCInventoryAssetDetail))
	registerHTTPRoute(mux, "GET /grc/vendors", routeSurfacePlatformHTTP, app.cacheGRCJSON(app.grcCachePolicy("vendors", 2*time.Minute, grcCacheScopeGraph, grcCacheScopeFindings, grcCacheScopeEvidence, grcCacheScopeRuntime), app.handleGRCVendors))
	registerHTTPRoute(mux, "POST /grc/vendors/uploads", routeSurfacePlatformHTTP, app.grcUploadHandler(grcupload.TargetVendor).ServeHTTP)
	registerHTTPRoute(mux, "POST /grc/vendors/uploads/{uploadID}/replay", routeSurfacePlatformHTTP, app.grcUploadReplayHandler().ServeHTTP)
	registerHTTPRoute(mux, "GET /grc/vendors/{vendorID}", routeSurfacePlatformHTTP, app.cacheGRCJSON(app.grcCachePolicy("vendor.detail", 5*time.Minute, grcCacheScopeGraph, grcCacheScopeFindings, grcCacheScopeEvidence, grcCacheScopeRuntime), app.handleGRCVendorDetail))
	registerHTTPRoute(mux, "GET /grc/vendors/{vendorID}/packet", routeSurfacePlatformHTTP, app.cacheGRCJSON(app.grcCachePolicy("vendor.packet", 5*time.Minute, grcCacheScopeGraph, grcCacheScopeFindings, grcCacheScopeEvidence, grcCacheScopeRuntime), app.handleGRCVendorPacket))
	registerHTTPRoute(mux, "GET /grc/vendor-discoveries", routeSurfacePlatformHTTP, app.cacheGRCJSON(app.grcCachePolicy("vendor.discoveries", time.Minute, grcCacheScopeGraph, grcCacheScopeInventory, grcCacheScopeRuntime), app.handleGRCVendorDiscoveries))
	registerHTTPRoute(mux, "POST /grc/vendor-discoveries/{discoveryID}/decision", routeSurfacePlatformHTTP, app.handleUpdateGRCVendorDiscoveryDecision)
	registerHTTPRoute(mux, "GET /grc/vendor-risk/vendors", routeSurfacePlatformHTTP, app.cacheGRCJSON(app.grcCachePolicy("vendor_risk.vendors", 2*time.Minute, grcCacheScopeGraph, grcCacheScopeFindings, grcCacheScopeEvidence, grcCacheScopeRuntime), app.handleGRCVendorRiskVendors))
	registerHTTPRoute(mux, "GET /grc/vendor-risk/vendors/detail", routeSurfacePlatformHTTP, app.cacheGRCJSON(app.grcCachePolicy("vendor_risk.vendor.detail", 5*time.Minute, grcCacheScopeGraph, grcCacheScopeFindings, grcCacheScopeEvidence, grcCacheScopeRuntime), app.handleGRCVendorRiskVendorDetail))
	registerHTTPRoute(mux, "GET /grc/inventory/resource-scope", routeSurfacePlatformHTTP, app.cacheGRCJSON(app.grcCachePolicy("inventory.resource_scope", time.Minute, grcCacheScopeInventory, grcCacheScopeGraph), app.handleGRCResourceScope))
	registerHTTPRoute(mux, "POST /grc/inventory/resource-scope", routeSurfacePlatformHTTP, app.handleUpdateGRCResourceScope)
	registerHTTPRoute(mux, "POST /grc/inventory/accountability", routeSurfacePlatformHTTP, app.handleUpdateGRCInventoryAccountability)
	registerHTTPRoute(mux, "GET /grc/inventory/asset-reports", routeSurfacePlatformHTTP, app.cacheGRCJSON(app.grcCachePolicy("inventory.asset_reports", time.Minute, grcCacheScopeInventory), app.handleListGRCInventoryAssetReports))
	registerHTTPRoute(mux, "POST /grc/inventory/asset-reports", routeSurfacePlatformHTTP, app.handleCreateGRCInventoryAssetReport)
	registerHTTPRoute(mux, "GET /grc/inventory/asset-reports/{reportID}", routeSurfacePlatformHTTP, app.cacheGRCJSON(app.grcCachePolicy("inventory.asset_report", time.Minute, grcCacheScopeInventory), app.handleGetGRCInventoryAssetReport))
	registerHTTPRoute(mux, "PATCH /grc/inventory/asset-reports/{reportID}/triage", routeSurfacePlatformHTTP, app.handleUpdateGRCInventoryAssetReportTriage)
	registerHTTPRoute(mux, "GET /grc/entities/{entityID}/impact", routeSurfacePlatformHTTP, app.cacheGRCJSON(app.grcCachePolicy("entity.impact", 5*time.Minute, grcCacheScopeGraph, grcCacheScopeFindings, grcCacheScopeEvidence), app.handleGRCEntityImpact))
	registerHTTPRoute(mux, "GET /grc/audit-packets/{packetID}", routeSurfacePlatformHTTP, app.cacheGRCJSON(app.grcCachePolicy("audit.packet", 5*time.Minute, grcCacheScopeGraph, grcCacheScopeFindings, grcCacheScopeEvidence), app.handleGRCAuditPacket))
	registerHTTPRoute(mux, "GET /grc/audit-packets/{packetID}/export", routeSurfacePlatformHTTP, app.handleGRCAuditPacketExport)
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
	registerHTTPRoute(mux, "POST /findings/{findingID}/external-refs", routeSurfacePlatformHTTP, app.handleLinkFindingExternalRef)
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
func (app *App) registerConnectorRoutes(mux *http.ServeMux) {
	credentialStores := credentialstoreshttp.New(credentialstoreshttp.Dependencies{Config: app.cfg, StateStore: app.deps.StateStore, TransitKey: app.connectorTransitKey, SourceService: app.sourceService(), EffectiveTenant: effectiveTenantFilter, RequiresTenantFilter: requiresTenantFilter, TenantAllowed: tenantAllowedByContext, WriteError: writeConnectorError})
	registerHTTPRoute(mux, "GET /credential-stores", routeSurfacePlatformHTTP, credentialStores.List)
	registerHTTPRoute(mux, "GET /credential-stores/{storeID}", routeSurfacePlatformHTTP, credentialStores.Get)
	registerHTTPRoute(mux, "GET /connectors", routeSurfacePlatformHTTP, app.handleListConnectors)
	registerHTTPRoute(mux, "GET /connectors/coverage", routeSurfacePlatformHTTP, app.handleGetConnectorCoverage)
	registerHTTPRoute(mux, "GET /connectors/credential-key", routeSurfacePlatformHTTP, app.handleConnectorCredentialKey)
	registerHTTPRoute(mux, "GET /connector-definitions", routeSurfacePlatformHTTP, app.handleListConnectorDefinitions)
	registerHTTPRoute(mux, "POST /connector-definitions", routeSurfacePlatformHTTP, app.handleCreateConnectorDefinition)
	registerHTTPRoute(mux, "POST /connector-definitions/plan", routeSurfacePlatformHTTP, sourceplanapi.HandleDefinitionPlan(app.sourcePlanAPIDeps()))
	registerHTTPRoute(mux, "POST /connector-definitions/preview", routeSurfacePlatformHTTP, app.handlePreviewConnectorDefinition)
	registerHTTPRoute(mux, "POST /connector-definitions/validate", routeSurfacePlatformHTTP, app.handleValidateConnectorDefinition)
	registerHTTPRoute(mux, "GET /connector-definitions/{definitionID}", routeSurfacePlatformHTTP, app.handleGetConnectorDefinition)
	registerHTTPRoute(mux, "GET /connector-definitions/{definitionID}/versions", routeSurfacePlatformHTTP, app.handleListConnectorDefinitionVersions)
	registerHTTPRoute(mux, "PUT /connector-definitions/{definitionID}", routeSurfacePlatformHTTP, app.handlePutConnectorDefinition)
	registerHTTPRoute(mux, "GET /connector-definitions/{definitionID}/promotion-plan", routeSurfacePlatformHTTP, sourceplanapi.HandleStoredPromotionPlan(app.sourcePlanAPIDeps()))
	registerHTTPRoute(mux, "POST /connector-definitions/{definitionID}/promote", routeSurfacePlatformHTTP, app.handlePromoteConnectorDefinition)
	registerHTTPRoute(mux, "GET /connectors/{sourceID}", routeSurfacePlatformHTTP, app.handleGetConnector)
	registerHTTPRoute(mux, "GET /connectors/{sourceID}/activity", routeSurfacePlatformHTTP, app.handleListConnectorActivity)
	registerHTTPRoute(mux, "GET /connectors/{sourceID}/credentials", routeSurfacePlatformHTTP, app.handleListConnectorCredentials)
	registerHTTPRoute(mux, "POST /connectors/{sourceID}/credentials", routeSurfacePlatformHTTP, app.handleCreateConnectorCredential)
	registerHTTPRoute(mux, "GET /connectors/{sourceID}/credentials/{credentialID}", routeSurfacePlatformHTTP, app.handleGetConnectorCredential)
	registerHTTPRoute(mux, "POST /connectors/{sourceID}/credentials/{credentialID}/rotate", routeSurfacePlatformHTTP, app.handleRotateConnectorCredential)
	registerHTTPRoute(mux, "POST /connectors/{sourceID}/credentials/{credentialID}/revoke", routeSurfacePlatformHTTP, app.handleRevokeConnectorCredential)
	registerHTTPRoute(mux, "POST /connectors/{sourceID}/preflight", routeSurfacePlatformHTTP, app.handlePreflightConnectorConnection)
	registerHTTPRoute(mux, "POST /connectors/{sourceID}/connections", routeSurfacePlatformHTTP, app.handleCreateConnectorConnection)
	registerHTTPRoute(mux, "POST /connectors/{sourceID}/deposits", routeSurfacePlatformHTTP, app.handleDepositConnectorRecords)
}
func (app *App) sourcePlanAPIDeps() sourceplanapi.Dependencies {
	return sourceplanapi.Dependencies{EffectiveTenant: effectiveTenantFilter, GetDefinition: app.connectorDefinitionForPlan, WriteJSON: writeJSON, WriteError: writeConnectorError, InvalidRequest: connectorcredentials.ErrInvalidRequest}
}
func (app *App) connectorDefinitionForPlan(ctx context.Context, definitionID string) (connectordefinitions.Definition, error) {
	store := connectorDefinitionStore(app.deps.StateStore)
	if store == nil {
		return connectordefinitions.Definition{}, sourceruntime.ErrRuntimeUnavailable
	}
	record, err := store.GetConnectorDefinition(ctx, definitionID)
	if err != nil {
		return connectordefinitions.Definition{}, err
	}
	definition, err := connectordefinitionrecords.FromRecord(record)
	if err != nil {
		return connectordefinitions.Definition{}, err
	}
	if err := authorizeTenantID(ctx, definition.TenantID); err != nil {
		return connectordefinitions.Definition{}, err
	}
	return definition, nil
}
func (app *App) registerKnowledgeRoutes(mux *http.ServeMux) {
	registerHTTPRoute(mux, "POST /platform/knowledge/decisions", routeSurfacePlatformHTTP, app.handleWriteDecision)
	registerHTTPRoute(mux, "POST /platform/knowledge/actions", routeSurfacePlatformHTTP, app.handleWriteAction)
	registerHTTPRoute(mux, "POST /platform/knowledge/actions/recommendation", routeSurfacePlatformHTTP, app.handleWriteAction)
	registerHTTPRoute(mux, "POST /platform/knowledge/outcomes", routeSurfacePlatformHTTP, app.handleWriteOutcome)
	registerHTTPRoute(mux, "POST /platform/workflow/replay", routeSurfacePlatformHTTP, app.handleReplayWorkflowEvents)
}
func (app *App) registerGraphRoutes(mux *http.ServeMux) {
	registerHTTPRoute(mux, "GET /platform/runtime-freshness", routeSurfacePlatformHTTP, app.handleListRuntimeFreshness)
	registerHTTPRoute(mux, "GET /platform/graph/neighborhood", routeSurfacePlatformHTTP, app.handleGetEntityNeighborhood)
	registerHTTPRoute(mux, "POST /platform/graph/actions", routeSurfacePlatformHTTP, app.handleExecuteGraphAction)
	registerHTTPRoute(mux, "POST /platform/graph/actions/reconcile", routeSurfacePlatformHTTP, app.handleReconcileGraphAction)
	registerHTTPRoute(mux, "GET /platform/graph/provenance", routeSurfacePlatformHTTP, app.handleGetGraphProvenance)
	registerHTTPRoute(mux, "GET /platform/graph/impact/vulnerability/{id}", routeSurfacePlatformHTTP, app.handleGetVulnerabilityImpact)
	registerHTTPRoute(mux, "GET /platform/graph/impact/package", routeSurfacePlatformHTTP, app.handleGetPackageImpact)
	registerHTTPRoute(mux, "GET /platform/graph/impact/asset", routeSurfacePlatformHTTP, app.handleGetAssetImpact)
	registerHTTPRoute(mux, "GET /platform/graph/person-access-paths", routeSurfacePlatformHTTP, app.handleGetPersonAccessPaths)
	registerHTTPRoute(mux, "GET /platform/graph/effective-access-paths", routeSurfacePlatformHTTP, app.handleGetEffectiveAccessPaths)
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
