package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	apicontract "github.com/writer/cerebro/api"
	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/buildinfo"
	"github.com/writer/cerebro/internal/claims"
	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/connectorcredentials"
	"github.com/writer/cerebro/internal/connectorsecretstores"
	"github.com/writer/cerebro/internal/deviceauth"
	"github.com/writer/cerebro/internal/deviceauth/risk"
	"github.com/writer/cerebro/internal/findingapi"
	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/graphactionapi"
	"github.com/writer/cerebro/internal/graphactions"
	"github.com/writer/cerebro/internal/graphagent"
	"github.com/writer/cerebro/internal/graphfacts"
	"github.com/writer/cerebro/internal/graphingest"
	"github.com/writer/cerebro/internal/graphquery"
	"github.com/writer/cerebro/internal/graphstore"
	platformjobs "github.com/writer/cerebro/internal/jobs"
	"github.com/writer/cerebro/internal/knowledge"
	"github.com/writer/cerebro/internal/mcpoauth"
	"github.com/writer/cerebro/internal/observability"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/querycache"
	"github.com/writer/cerebro/internal/reports"
	linktransport "github.com/writer/cerebro/internal/resourcelinks/transport"
	"github.com/writer/cerebro/internal/resourcescope"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourceconfig"
	"github.com/writer/cerebro/internal/sourceops"
	"github.com/writer/cerebro/internal/sourceprojection"
	"github.com/writer/cerebro/internal/sourceruntime"
	"github.com/writer/cerebro/internal/workflowprojection"
)

// Dependencies are the future store/log boundaries that will be wired into the rewrite.
type Dependencies struct {
	AppendLog     ports.AppendLog
	StateStore    ports.StateStore
	GraphStore    ports.GraphStore
	GraphAgentLLM graphagent.LLMClient
	QueryCache    querycache.Cache
}

// App is the minimal Connect/bootstrap composition root for the rewrite skeleton.
type App struct {
	cfg                   config.Config
	deps                  Dependencies
	sources               *sourcecdk.Registry
	mux                   *http.ServeMux
	handler               http.Handler
	server                *http.Server
	deviceService         *deviceauth.Service
	deviceHandler         *deviceAuthHTTPHandler
	deviceVerifier        *deviceauth.JWTVerifier
	dpopVerifier          *deviceauth.DPoPVerifier
	riskScorer            *risk.Scorer
	observationStore      risk.ObservationStore
	services              appServices
	mcpOAuthService       *mcpoauth.Service
	mcpOAuthRegisterLimit *deviceauth.TokenBucket
	oauthEndpointLimit    *deviceauth.TokenBucket
	connectorTransitKey   *connectorcredentials.TransitKey
	queryCacheGroup       queryCacheRefreshGroup
}

type appServices struct {
	sourceOps      *sourceops.Service
	reports        *reports.Service
	runtimeOps     *sourceruntime.Service
	claims         *claims.Service
	findings       *findings.Service
	knowledgeOps   *knowledge.Service
	graphQueries   *graphquery.Service
	graphFacts     *graphfacts.Service
	graphActions   *graphactions.Service
	graphIngestOps *graphingest.Service
	workflowReplay *workflowprojection.Replayer
	jobs           *platformjobs.Service
}

type bootstrapService struct {
	cfg          config.Config
	deps         Dependencies
	sources      *sourcecdk.Registry
	graphActions *graphactions.Service
}

const (
	maxProtoJSONBodyBytes              = 1 << 20
	healthCheckTimeout                 = 2 * time.Second
	sourceRuntimeProgressConfigHashKey = "__cerebro_resolved_progress_config_hash"
	redactedAttributeValue             = "[redacted]"
)

var (
	errInvalidHTTPRequest                 = errors.New("invalid http request")
	errProtoJSONBodyTooLarge              = errors.New("request JSON body exceeds maximum size")
	errDeviceAuthRequiresAPIAuth          = errors.New("device-auth requires CEREBRO_API_AUTH_ENABLED=true")
	errDeviceAuthRequiresStore            = errors.New("device-auth requires a device-auth capable state store")
	errDeviceAuthRequiresSharedDPoPReplay = errors.New("device-auth DPoP replay protection requires shared state for multiple replicas")
	errMCPOAuthRequiresAPIAuth            = errors.New("MCP OAuth requires CEREBRO_API_AUTH_ENABLED=true")
	errMCPOAuthRequiresStore              = errors.New("MCP OAuth requires an OAuth-capable state store")
	errMCPOAuthRequiresCapabilitySecrets  = errors.New("MCP OAuth requires CEREBRO_CAPABILITY_TOKEN_SECRETS")
)

// New constructs the minimal bootstrap app and registers the Connect handlers.
func New(cfg config.Config, deps Dependencies, sources *sourcecdk.Registry) *App {
	app, err := NewWithError(cfg, deps, sources)
	if err != nil {
		log.Printf("bootstrap: app initialization error: %v", err)
	}
	return app
}

// NewWithError constructs the minimal bootstrap app and returns configuration
// errors instead of panicking. Production startup should use this form so
// security-sensitive surfaces fail closed when misconfigured.
func NewWithError(cfg config.Config, deps Dependencies, sources *sourcecdk.Registry) (*App, error) {
	app := &App{cfg: cfg, deps: deps, sources: sources}
	transitKey, err := connectorTransitKeyFromConfig(cfg.ConnectorCredentials)
	if err != nil {
		return nil, err
	}
	app.connectorTransitKey = transitKey
	if cfg.Auth.DeviceAuth.Enabled && !cfg.Auth.Enabled {
		return nil, errDeviceAuthRequiresAPIAuth
	}
	if cfg.Auth.MCPOAuth.Enabled && !cfg.Auth.Enabled {
		return nil, errMCPOAuthRequiresAPIAuth
	}
	if cfg.Auth.MCPOAuth.Enabled && len(cfg.Auth.CapabilityTokenSecrets) == 0 {
		return nil, errMCPOAuthRequiresCapabilitySecrets
	}
	if cfg.Auth.DeviceAuth.Enabled && deviceAuthReplicaCount(cfg.Auth.DeviceAuth) > 1 {
		dpop := deviceauth.NewDPoPVerifier(cfg.Auth.DeviceAuth.ClockSkew, cfg.Auth.DeviceAuth.DPoPProofTTL)
		if !dpop.ReplayStateShared() {
			return nil, errDeviceAuthRequiresSharedDPoPReplay
		}
	}
	deviceStore := deviceAuthStore(deps.StateStore)
	if cfg.Auth.DeviceAuth.Enabled && deviceStore == nil {
		return nil, errDeviceAuthRequiresStore
	}
	oauthStore := mcpOAuthStore(deps.StateStore)
	if cfg.Auth.MCPOAuth.Enabled && oauthStore == nil {
		return nil, errMCPOAuthRequiresStore
	}
	if deviceStore != nil {
		dpop := deviceauth.NewDPoPVerifier(cfg.Auth.DeviceAuth.ClockSkew, cfg.Auth.DeviceAuth.DPoPProofTTL)
		obsStore := deviceRiskObservationStore(deps.StateStore)
		if obsStore == nil {
			obsStore = risk.NewInMemoryObservationStore()
		}
		riskScorer := risk.NewScorer(
			risk.Thresholds{Elevated: cfg.Auth.DeviceAuth.RiskElevatedThreshold, High: cfg.Auth.DeviceAuth.RiskHighThreshold},
			risk.NoOpLookup{},
			risk.NoOpEmitter{},
			risk.NewVelocityDetector(),
			risk.NewCountryDriftDetector(),
			risk.NewASNDriftDetector(),
		)
		service, err := buildDeviceAuthService(cfg.Auth.DeviceAuth, deviceStore, dpop, riskScorer, obsStore)
		if err != nil {
			return nil, fmt.Errorf("device-auth bootstrap failed: %w", err)
		}
		if service != nil {
			app.deviceService = service
			app.deviceVerifier = service.Verifier()
			app.dpopVerifier = dpop
			app.riskScorer = riskScorer
			app.observationStore = obsStore
			app.deviceHandler = newDeviceAuthHTTPHandler(service, cfg.Auth.DeviceAuth, cfg.Auth.RequestOrigin)
		}
	}
	if cfg.Auth.Enabled && len(cfg.Auth.APICredentials) > 0 && len(cfg.Auth.CapabilityTokenSecrets) > 0 {
		app.oauthEndpointLimit = deviceauth.NewTokenBucket(oauthEndpointRatePerSecond, oauthEndpointBurst)
	}
	if cfg.Auth.MCPOAuth.Enabled {
		app.mcpOAuthRegisterLimit = deviceauth.NewTokenBucket(oauthRegisterRatePerSecond, oauthRegisterBurst)
		if app.oauthEndpointLimit == nil {
			app.oauthEndpointLimit = deviceauth.NewTokenBucket(oauthEndpointRatePerSecond, oauthEndpointBurst)
		}
		service, err := mcpoauth.NewService(cfg.Auth.MCPOAuth, oauthStore, func(ctx context.Context, grant mcpoauth.AccessGrant, ttl time.Duration, now time.Time) (string, error) {
			return issueCapabilityToken(cfg.Auth, capabilityClaims{
				Audience:       cfg.Auth.CapabilityTokenAudience,
				Subject:        grant.Subject,
				IssuedAt:       now.Unix(),
				CredentialID:   "mcp-oauth", // #nosec G101 -- credential identifier label, not a secret.
				ClientID:       grant.ClientID,
				Resource:       grant.Resource,
				TenantID:       grant.TenantID,
				AllowedTenants: grant.AllowedTenants,
				Scopes:         grant.Scopes,
				Roles:          grant.Roles,
				Groups:         grant.Groups,
			}, ttl, now)
		}, mcpoauth.WithOIDCProvider(newMCPOAuthOIDCClient(cfg.Auth.MCPOAuth.Upstream)))
		if err != nil {
			return nil, fmt.Errorf("MCP OAuth bootstrap failed: %w", err)
		}
		app.mcpOAuthService = service
	}
	app.services.sourceOps = newSourceService(app.sources)
	app.services.reports = app.newReportService()
	app.services.runtimeOps = newRuntimeService(app.cfg, app.deps, app.sources)
	app.services.claims = app.newClaimService()
	app.services.findings = app.newFindingService()
	app.services.knowledgeOps = app.newKnowledgeService()
	app.services.graphQueries = app.newGraphQueryService()
	app.services.graphFacts = graphfacts.New(claimStore(app.deps.StateStore))
	graphActionProviders := map[string]graphactions.ActionProvider{}
	if app.deviceService != nil {
		graphActionProviders[graphactions.ProviderCerebroDeviceAuth] = graphactions.CerebroDeviceProvider{Service: app.deviceService}
	}
	if app.services.graphActions, err = graphactionapi.NewServiceIfConfigured(app.cfg.GraphActions, app.findingService(), graphActionProviders); err != nil {
		return nil, fmt.Errorf("graph actions bootstrap failed: %w", err)
	}
	app.services.graphIngestOps = newGraphIngestService(app.cfg, app.deps, app.sources)
	app.services.workflowReplay = app.newWorkflowReplayService()
	app.services.jobs = app.newJobService()
	mux := http.NewServeMux()
	app.mux = mux
	app.registerRoutes(mux, cfg, deps, sources)
	app.handler = observability.Middleware(rateLimitMiddleware(cfg.RateLimit, cfg.Auth.RequestOrigin)(authMiddleware(cfg.Auth, AuthDependencies{
		DeviceVerifier: app.deviceVerifier,
		DPoPVerifier:   app.dpopVerifier,
		RiskScorer:     app.riskScorer,
		Observations:   app.observationStore,
	}, mux)))
	app.server = &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           app.handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    1 << 20, // 1 MB
	}
	return app, nil
}

func connectorTransitKeyFromConfig(credentialConfig config.ConnectorCredentialConfig) (*connectorcredentials.TransitKey, error) {
	if strings.TrimSpace(credentialConfig.TransitPrivateKey) == "" {
		return nil, nil
	}
	return connectorcredentials.NewTransitKeyFromPEM(credentialConfig.TransitPrivateKey)
}

// Handler returns the composed HTTP handler for embedding in tests or another server.
func (a *App) Handler() http.Handler {
	return a.handler
}

// ListenAndServe starts the bootstrap HTTP server.
func (a *App) ListenAndServe() error {
	if err := a.server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// Shutdown gracefully stops the bootstrap HTTP server.
func (a *App) Shutdown(ctx context.Context) error {
	if err := a.server.Shutdown(ctx); err != nil {
		return err
	}
	if a.services.jobs != nil {
		return a.services.jobs.Wait(ctx)
	}
	return nil
}

func (a *App) handleHealth(w http.ResponseWriter, r *http.Request) {
	response := publicHealthResponse(r.Context(), a.deps)
	statusCode := http.StatusOK
	if response.GetStatus() == "degraded" {
		statusCode = http.StatusServiceUnavailable
	}
	writeProtoJSON(w, statusCode, response)
}

func (a *App) handleLiveness(w http.ResponseWriter, _ *http.Request) {
	writeProtoJSON(w, http.StatusOK, publicLivenessResponse())
}

func (a *App) handleOpenAPI(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(apicontract.OpenAPIYAML)
}

func (a *App) handleMetrics(w http.ResponseWriter, r *http.Request) {
	observability.Default.Handler().ServeHTTP(w, r)
}

func authorizeSourceRuntimeIDTenant(ctx context.Context, store ports.SourceRuntimeStore, runtimeID string) error {
	if !hasAuthContext(ctx) {
		return nil
	}
	_, err := sourceRuntimeTenantID(ctx, store, runtimeID, false)
	return err
}

func sourceRuntimeTenantID(ctx context.Context, store ports.SourceRuntimeStore, runtimeID string, allowMissing bool) (string, error) {
	id := strings.TrimSpace(runtimeID)
	if id == "" {
		return "", nil
	}
	if store == nil {
		return "", sourceruntime.ErrRuntimeUnavailable
	}
	runtime, err := store.GetSourceRuntime(ctx, id)
	if err != nil {
		if allowMissing && errors.Is(err, ports.ErrSourceRuntimeNotFound) {
			return "", nil
		}
		return "", err
	}
	tenantID := strings.TrimSpace(runtime.GetTenantId())
	if err := authorizeTenantScopeRequired(ctx, tenantID); err != nil {
		return "", err
	}
	return tenantID, nil
}

func authorizePutSourceRuntimeTenant(ctx context.Context, store ports.SourceRuntimeStore, runtime *cerebrov1.SourceRuntime) error {
	if !hasAuthContext(ctx) || runtime == nil {
		return nil
	}
	id := strings.TrimSpace(runtime.GetId())
	if id == "" {
		return authorizeTenantScopeRequired(ctx, runtime.GetTenantId())
	}
	if store == nil {
		return sourceruntime.ErrRuntimeUnavailable
	}
	existing, err := store.GetSourceRuntime(ctx, id)
	switch {
	case err == nil:
		if err := authorizeTenantScopeRequired(ctx, existing.GetTenantId()); err != nil {
			return err
		}
		return authorizeTenantID(ctx, runtime.GetTenantId())
	case errors.Is(err, ports.ErrSourceRuntimeNotFound):
		return authorizeTenantScopeRequired(ctx, runtime.GetTenantId())
	default:
		return err
	}
}

func authorizeFindingIDTenant(ctx context.Context, store ports.FindingStore, findingID string) error {
	if !hasAuthContext(ctx) {
		return nil
	}
	id := strings.TrimSpace(findingID)
	if id == "" {
		return nil
	}
	if store == nil {
		return findings.ErrRuntimeUnavailable
	}
	finding, err := store.GetFinding(ctx, id)
	if err != nil {
		return err
	}
	return authorizeTenantID(ctx, finding.TenantID)
}

func authorizeReportRunTenant(ctx context.Context, run *cerebrov1.ReportRun) error {
	if run == nil {
		return nil
	}
	return authorizeTenantScopeRequired(ctx, run.GetParameters()["tenant_id"])
}

func authorizeGraphIngestRunListScope(ctx context.Context, runtimeID string) error {
	if !hasTenantScopedAuth(ctx) || strings.TrimSpace(runtimeID) != "" {
		return nil
	}
	return errTenantForbidden
}

func authorizeGlobalGraphHealthScope(ctx context.Context) error {
	if !hasTenantScopedAuth(ctx) {
		return nil
	}
	return errTenantForbidden
}

func (a *App) handleSources(w http.ResponseWriter, r *http.Request) {
	writeProtoJSON(w, http.StatusOK, a.sourceService().List())
}

func (a *App) handleListReportDefinitions(w http.ResponseWriter, r *http.Request) {
	writeProtoJSON(w, http.StatusOK, a.reportService().List())
}

func (a *App) handleCheckSource(w http.ResponseWriter, r *http.Request) {
	config, err := sourceConfigFromRequest(r)
	if err != nil {
		writeSourceError(w, err)
		return
	}
	if err := authorizeSourceConfigTenant(r.Context(), config); err != nil {
		writeSourceError(w, err)
		return
	}
	response, err := a.sourceService().Check(r.Context(), &cerebrov1.CheckSourceRequest{
		SourceId: r.PathValue("sourceID"),
		Config:   config,
	})
	if err != nil {
		writeSourceError(w, err)
		return
	}
	writeProtoJSON(w, http.StatusOK, response)
}

func (a *App) handleDiscoverSource(w http.ResponseWriter, r *http.Request) {
	config, err := sourceConfigFromRequest(r)
	if err != nil {
		writeSourceError(w, err)
		return
	}
	if err := authorizeSourceConfigTenant(r.Context(), config); err != nil {
		writeSourceError(w, err)
		return
	}
	response, err := a.sourceService().Discover(r.Context(), &cerebrov1.DiscoverSourceRequest{
		SourceId: r.PathValue("sourceID"),
		Config:   config,
	})
	if err != nil {
		writeSourceError(w, err)
		return
	}
	writeProtoJSON(w, http.StatusOK, response)
}

func (a *App) handleReadSource(w http.ResponseWriter, r *http.Request) {
	config, err := sourceConfigFromRequest(r)
	if err != nil {
		writeSourceError(w, err)
		return
	}
	if err := authorizeSourceConfigTenant(r.Context(), config); err != nil {
		writeSourceError(w, err)
		return
	}
	request := &cerebrov1.ReadSourceRequest{
		SourceId: r.PathValue("sourceID"),
		Config:   config,
	}
	rawCursors := r.URL.Query()["cursor"]
	if len(rawCursors) > 0 {
		cursor := rawCursors[len(rawCursors)-1]
		if cursor != "" {
			request.Cursor = &cerebrov1.SourceCursor{Opaque: cursor}
		}
	}
	response, err := a.sourceService().Read(r.Context(), request)
	if err != nil {
		writeSourceError(w, err)
		return
	}
	writeProtoJSON(w, http.StatusOK, response)
}

func (a *App) handleListClaims(w http.ResponseWriter, r *http.Request) {
	request := &cerebrov1.ListClaimsRequest{
		RuntimeId:     r.PathValue("runtimeID"),
		ClaimId:       r.URL.Query().Get("claim_id"),
		SubjectUrn:    r.URL.Query().Get("subject_urn"),
		Predicate:     r.URL.Query().Get("predicate"),
		ObjectUrn:     r.URL.Query().Get("object_urn"),
		ObjectValue:   r.URL.Query().Get("object_value"),
		ClaimType:     r.URL.Query().Get("claim_type"),
		Status:        r.URL.Query().Get("status"),
		SourceEventId: r.URL.Query().Get("source_event_id"),
	}
	if limit := r.URL.Query().Get("limit"); limit != "" {
		body := []byte(`{"limit":` + limit + `}`)
		if err := unmarshalHTTPProtoJSON(body, request); err != nil {
			writeClaimError(w, err)
			return
		}
		request.RuntimeId = r.PathValue("runtimeID")
		request.ClaimId = r.URL.Query().Get("claim_id")
		request.SubjectUrn = r.URL.Query().Get("subject_urn")
		request.Predicate = r.URL.Query().Get("predicate")
		request.ObjectUrn = r.URL.Query().Get("object_urn")
		request.ObjectValue = r.URL.Query().Get("object_value")
		request.ClaimType = r.URL.Query().Get("claim_type")
		request.Status = r.URL.Query().Get("status")
		request.SourceEventId = r.URL.Query().Get("source_event_id")
	}
	if err := authorizeSourceRuntimeIDTenant(r.Context(), sourceRuntimeStore(a.deps.StateStore), request.GetRuntimeId()); err != nil {
		writeClaimError(w, err)
		return
	}
	response, err := a.claimService().ListClaims(r.Context(), claims.ListRequest{
		RuntimeID:     request.GetRuntimeId(),
		ClaimID:       request.GetClaimId(),
		SubjectURN:    request.GetSubjectUrn(),
		Predicate:     request.GetPredicate(),
		ObjectURN:     request.GetObjectUrn(),
		ObjectValue:   request.GetObjectValue(),
		ClaimType:     request.GetClaimType(),
		Status:        request.GetStatus(),
		SourceEventID: request.GetSourceEventId(),
		Limit:         request.GetLimit(),
	})
	if err != nil {
		writeClaimError(w, err)
		return
	}
	writeProtoJSON(w, http.StatusOK, &cerebrov1.ListClaimsResponse{
		Claims: response.Claims,
	})
}

func (a *App) handleWriteClaims(w http.ResponseWriter, r *http.Request) {
	request := &cerebrov1.WriteClaimsRequest{}
	if err := readProtoJSON(r, request); err != nil {
		writeClaimError(w, err)
		return
	}
	request.RuntimeId = r.PathValue("runtimeID")
	if err := authorizeSourceRuntimeIDTenant(r.Context(), sourceRuntimeStore(a.deps.StateStore), request.GetRuntimeId()); err != nil {
		writeClaimError(w, err)
		return
	}
	response, err := a.claimService().WriteClaims(r.Context(), claims.WriteRequest{
		RuntimeID:       request.GetRuntimeId(),
		Claims:          request.GetClaims(),
		ReplaceExisting: request.GetReplaceExisting(),
	})
	if err != nil {
		writeClaimError(w, err)
		return
	}
	bumpGRCCacheForRuntime(r.Context(), a.deps, request.GetRuntimeId(), grcCacheScopeGraph, grcCacheScopeInventory)
	writeProtoJSON(w, http.StatusOK, &cerebrov1.WriteClaimsResponse{
		ClaimsWritten:          response.ClaimsWritten,
		EntitiesUpserted:       response.EntitiesUpserted,
		RelationLinksProjected: response.RelationLinksProjected,
		ClaimsRetracted:        response.ClaimsRetracted,
	})
}

func (s *bootstrapService) GetVersion(_ context.Context, _ *connect.Request[cerebrov1.GetVersionRequest]) (*connect.Response[cerebrov1.GetVersionResponse], error) {
	return connect.NewResponse(&cerebrov1.GetVersionResponse{
		ServiceName: buildinfo.ServiceName,
		Version:     buildinfo.Version,
		Commit:      buildinfo.Commit,
		BuildDate:   buildinfo.BuildDate,
		ApiVersion:  buildinfo.APIVersion,
	}), nil
}

func (s *bootstrapService) CheckHealth(ctx context.Context, _ *connect.Request[cerebrov1.CheckHealthRequest]) (*connect.Response[cerebrov1.CheckHealthResponse], error) {
	return connect.NewResponse(healthResponse(ctx, s.cfg, s.deps)), nil
}

func (s *bootstrapService) ListReportDefinitions(_ context.Context, _ *connect.Request[cerebrov1.ListReportDefinitionsRequest]) (*connect.Response[cerebrov1.ListReportDefinitionsResponse], error) {
	return connect.NewResponse(reports.New(
		findingStore(s.deps.StateStore),
		graphQueryStore(s.deps.GraphStore),
		reportStore(s.deps.StateStore),
	).List()), nil
}

func (s *bootstrapService) ListFindingRules(_ context.Context, _ *connect.Request[cerebrov1.ListFindingRulesRequest]) (*connect.Response[cerebrov1.ListFindingRulesResponse], error) {
	return connect.NewResponse(s.findingCoreService().ListRules()), nil
}

func (s *bootstrapService) RunReport(ctx context.Context, req *connect.Request[cerebrov1.RunReportRequest]) (*connect.Response[cerebrov1.RunReportResponse], error) {
	if err := authorizeTenantID(ctx, req.Msg.GetParameters()["tenant_id"]); err != nil {
		return nil, reportConnectError(err)
	}
	response, err := reports.New(
		findingStore(s.deps.StateStore),
		graphQueryStore(s.deps.GraphStore),
		reportStore(s.deps.StateStore),
	).Run(ctx, req.Msg)
	if err != nil {
		return nil, reportConnectError(err)
	}
	if err := authorizeTenantID(ctx, response.GetRun().GetParameters()["tenant_id"]); err != nil {
		return nil, reportConnectError(err)
	}
	return connect.NewResponse(response), nil
}

func (s *bootstrapService) GetReportRun(ctx context.Context, req *connect.Request[cerebrov1.GetReportRunRequest]) (*connect.Response[cerebrov1.GetReportRunResponse], error) {
	response, err := reports.New(
		findingStore(s.deps.StateStore),
		graphQueryStore(s.deps.GraphStore),
		reportStore(s.deps.StateStore),
	).Get(ctx, req.Msg)
	if err != nil {
		return nil, reportConnectError(err)
	}
	if err := authorizeReportRunTenant(ctx, response.GetRun()); err != nil {
		return nil, reportConnectError(normalizeIDLookupError(err, ports.ErrReportRunNotFound))
	}
	return connect.NewResponse(response), nil
}

func (s *bootstrapService) ListSources(_ context.Context, _ *connect.Request[cerebrov1.ListSourcesRequest]) (*connect.Response[cerebrov1.ListSourcesResponse], error) {
	return connect.NewResponse(newSourceService(s.sources).List()), nil
}

func (s *bootstrapService) CheckSource(ctx context.Context, req *connect.Request[cerebrov1.CheckSourceRequest]) (*connect.Response[cerebrov1.CheckSourceResponse], error) {
	response, err := newSourceService(s.sources).Check(ctx, req.Msg)
	if err != nil {
		return nil, sourceConnectError(err)
	}
	return connect.NewResponse(response), nil
}

func (s *bootstrapService) DiscoverSource(ctx context.Context, req *connect.Request[cerebrov1.DiscoverSourceRequest]) (*connect.Response[cerebrov1.DiscoverSourceResponse], error) {
	response, err := newSourceService(s.sources).Discover(ctx, req.Msg)
	if err != nil {
		return nil, sourceConnectError(err)
	}
	return connect.NewResponse(response), nil
}

func (s *bootstrapService) ReadSource(ctx context.Context, req *connect.Request[cerebrov1.ReadSourceRequest]) (*connect.Response[cerebrov1.ReadSourceResponse], error) {
	response, err := newSourceService(s.sources).Read(ctx, req.Msg)
	if err != nil {
		return nil, sourceConnectError(err)
	}
	return connect.NewResponse(response), nil
}

func (s *bootstrapService) PutSourceRuntime(ctx context.Context, req *connect.Request[cerebrov1.PutSourceRuntimeRequest]) (*connect.Response[cerebrov1.PutSourceRuntimeResponse], error) {
	if err := authorizePutSourceRuntimeTenant(ctx, sourceRuntimeStore(s.deps.StateStore), req.Msg.GetRuntime()); err != nil {
		return nil, sourceRuntimeConnectError(err)
	}
	response, err := newRuntimeService(s.cfg, s.deps, s.sources).Put(ctx, req.Msg)
	if err != nil {
		return nil, sourceRuntimeConnectError(err)
	}
	bumpGRCCacheForRuntime(ctx, s.deps, req.Msg.GetRuntime().GetId(), grcCacheScopeRuntime, grcCacheScopeGraph, grcCacheScopeInventory)
	return connect.NewResponse(response), nil
}

func (s *bootstrapService) GetSourceRuntime(ctx context.Context, req *connect.Request[cerebrov1.GetSourceRuntimeRequest]) (*connect.Response[cerebrov1.GetSourceRuntimeResponse], error) {
	if err := authorizeSourceRuntimeIDTenant(ctx, sourceRuntimeStore(s.deps.StateStore), req.Msg.GetId()); err != nil {
		return nil, sourceRuntimeConnectError(normalizeIDLookupError(err, ports.ErrSourceRuntimeNotFound))
	}
	response, err := newRuntimeService(s.cfg, s.deps, s.sources).Get(ctx, req.Msg)
	if err != nil {
		return nil, sourceRuntimeConnectError(err)
	}
	return connect.NewResponse(response), nil
}

func (s *bootstrapService) SyncSourceRuntime(ctx context.Context, req *connect.Request[cerebrov1.SyncSourceRuntimeRequest]) (*connect.Response[cerebrov1.SyncSourceRuntimeResponse], error) {
	if err := authorizeSourceRuntimeIDTenant(ctx, sourceRuntimeStore(s.deps.StateStore), req.Msg.GetId()); err != nil {
		return nil, sourceRuntimeConnectError(normalizeIDLookupError(err, ports.ErrSourceRuntimeNotFound))
	}
	response, err := newRuntimeService(s.cfg, s.deps, s.sources).SyncWithLease(ctx, req.Msg, sourceruntime.SyncWithLeaseOptions{
		LeaseStore: sourceRuntimeLeaseStore(s.deps.StateStore),
	})
	if err != nil {
		return nil, sourceRuntimeConnectError(err)
	}
	return connect.NewResponse(response), nil
}

func (s *bootstrapService) WriteClaims(ctx context.Context, req *connect.Request[cerebrov1.WriteClaimsRequest]) (*connect.Response[cerebrov1.WriteClaimsResponse], error) {
	if err := authorizeSourceRuntimeIDTenant(ctx, sourceRuntimeStore(s.deps.StateStore), req.Msg.GetRuntimeId()); err != nil {
		return nil, claimConnectError(err)
	}
	response, err := claims.New(
		sourceRuntimeStore(s.deps.StateStore),
		claimStore(s.deps.StateStore),
		sourceProjectionStateStore(s.deps.StateStore),
		sourceProjectionGraphStore(s.deps.GraphStore),
	).WriteClaims(ctx, claims.WriteRequest{
		RuntimeID:       req.Msg.GetRuntimeId(),
		Claims:          req.Msg.GetClaims(),
		ReplaceExisting: req.Msg.GetReplaceExisting(),
	})
	if err != nil {
		return nil, claimConnectError(err)
	}
	bumpGRCCacheForRuntime(ctx, s.deps, req.Msg.GetRuntimeId(), grcCacheScopeGraph, grcCacheScopeInventory)
	return connect.NewResponse(&cerebrov1.WriteClaimsResponse{
		ClaimsWritten:          response.ClaimsWritten,
		EntitiesUpserted:       response.EntitiesUpserted,
		RelationLinksProjected: response.RelationLinksProjected,
		ClaimsRetracted:        response.ClaimsRetracted,
	}), nil
}

func (s *bootstrapService) ListClaims(ctx context.Context, req *connect.Request[cerebrov1.ListClaimsRequest]) (*connect.Response[cerebrov1.ListClaimsResponse], error) {
	if err := authorizeSourceRuntimeIDTenant(ctx, sourceRuntimeStore(s.deps.StateStore), req.Msg.GetRuntimeId()); err != nil {
		return nil, claimConnectError(err)
	}
	response, err := claims.New(
		sourceRuntimeStore(s.deps.StateStore),
		claimStore(s.deps.StateStore),
		sourceProjectionStateStore(s.deps.StateStore),
		sourceProjectionGraphStore(s.deps.GraphStore),
	).ListClaims(ctx, claims.ListRequest{
		RuntimeID:     req.Msg.GetRuntimeId(),
		ClaimID:       req.Msg.GetClaimId(),
		SubjectURN:    req.Msg.GetSubjectUrn(),
		Predicate:     req.Msg.GetPredicate(),
		ObjectURN:     req.Msg.GetObjectUrn(),
		ObjectValue:   req.Msg.GetObjectValue(),
		ClaimType:     req.Msg.GetClaimType(),
		Status:        req.Msg.GetStatus(),
		SourceEventID: req.Msg.GetSourceEventId(),
		Limit:         req.Msg.GetLimit(),
	})
	if err != nil {
		return nil, claimConnectError(err)
	}
	return connect.NewResponse(&cerebrov1.ListClaimsResponse{
		Claims: response.Claims,
	}), nil
}

func (s *bootstrapService) ListFindings(ctx context.Context, req *connect.Request[cerebrov1.ListFindingsRequest]) (*connect.Response[cerebrov1.ListFindingsResponse], error) {
	if err := authorizeSourceRuntimeIDTenant(ctx, sourceRuntimeStore(s.deps.StateStore), req.Msg.GetRuntimeId()); err != nil {
		return nil, findingConnectError(err)
	}
	response, err := s.findingCoreService().ListFindings(ctx, findings.ListRequest{
		RuntimeID:   req.Msg.GetRuntimeId(),
		FindingID:   req.Msg.GetFindingId(),
		RuleID:      req.Msg.GetRuleId(),
		Severity:    req.Msg.GetSeverity(),
		Status:      findingStatusString(req.Msg.GetStatus()),
		ResourceURN: req.Msg.GetResourceUrn(),
		EventID:     req.Msg.GetEventId(),
		PolicyID:    req.Msg.GetPolicyId(),
		Limit:       req.Msg.GetLimit(),
		Order:       findingOrder(req.Msg.GetOrder()),
	})
	if err != nil {
		return nil, findingConnectError(err)
	}
	return connect.NewResponse(listFindingsResponse(response)), nil
}

func (s *bootstrapService) GetFinding(ctx context.Context, req *connect.Request[cerebrov1.GetFindingRequest]) (*connect.Response[cerebrov1.GetFindingResponse], error) {
	if err := authorizeFindingIDTenant(ctx, findingStore(s.deps.StateStore), req.Msg.GetId()); err != nil {
		return nil, findingConnectError(normalizeIDLookupError(err, ports.ErrFindingNotFound))
	}
	finding, err := s.findingCoreService().GetFinding(ctx, req.Msg.GetId())
	if err != nil {
		return nil, findingConnectError(err)
	}
	return connect.NewResponse(linktransport.FindingResponse(safeFindingMessage(finding), finding)), nil
}

func (s *bootstrapService) ListFindingCandidates(ctx context.Context, req *connect.Request[cerebrov1.ListFindingCandidatesRequest]) (*connect.Response[cerebrov1.ListFindingCandidatesResponse], error) {
	if err := authorizeSourceRuntimeIDTenant(ctx, sourceRuntimeStore(s.deps.StateStore), req.Msg.GetRuntimeId()); err != nil {
		return nil, findingConnectError(err)
	}
	response, err := s.findingCandidateService().ListFindingCandidates(ctx, findings.ListCandidatesRequest{
		RuntimeID:   req.Msg.GetRuntimeId(),
		CandidateID: req.Msg.GetCandidateId(),
		RuleID:      req.Msg.GetRuleId(),
		Status:      req.Msg.GetStatus(),
		Fingerprint: req.Msg.GetFingerprint(),
		Limit:       req.Msg.GetLimit(),
	})
	if err != nil {
		return nil, findingConnectError(err)
	}
	return connect.NewResponse(listFindingCandidatesResponse(response)), nil
}

func (s *bootstrapService) GetFindingCandidate(ctx context.Context, req *connect.Request[cerebrov1.GetFindingCandidateRequest]) (*connect.Response[cerebrov1.GetFindingCandidateResponse], error) {
	service := s.findingCandidateService()
	candidate, err := service.GetFindingCandidate(ctx, req.Msg.GetId())
	if err != nil {
		return nil, findingConnectError(err)
	}
	if err := authorizeSourceRuntimeIDTenant(ctx, sourceRuntimeStore(s.deps.StateStore), candidate.RuntimeID); err != nil {
		return nil, findingConnectError(normalizeIDLookupError(err, ports.ErrFindingCandidateNotFound))
	}
	return connect.NewResponse(&cerebrov1.GetFindingCandidateResponse{Candidate: safeFindingCandidateMessage(candidate)}), nil
}

func (s *bootstrapService) EvaluateSourceRuntimeFindingCandidates(ctx context.Context, req *connect.Request[cerebrov1.EvaluateSourceRuntimeFindingCandidatesRequest]) (*connect.Response[cerebrov1.EvaluateSourceRuntimeFindingCandidatesResponse], error) {
	if err := authorizeSourceRuntimeIDTenant(ctx, sourceRuntimeStore(s.deps.StateStore), req.Msg.GetId()); err != nil {
		return nil, findingConnectError(normalizeIDLookupError(err, ports.ErrSourceRuntimeNotFound))
	}
	response, err := s.findingCandidateService().EvaluateSourceRuntimeCandidateRules(ctx, findings.EvaluateCandidateRulesRequest{
		RuntimeID:  req.Msg.GetId(),
		RuleIDs:    req.Msg.GetRuleIds(),
		EventLimit: req.Msg.GetEventLimit(),
	})
	if err != nil {
		return nil, findingConnectError(err)
	}
	return connect.NewResponse(findingCandidateRulesResponse(response)), nil
}

func (s *bootstrapService) PromoteFindingCandidate(ctx context.Context, req *connect.Request[cerebrov1.PromoteFindingCandidateRequest]) (*connect.Response[cerebrov1.PromoteFindingCandidateResponse], error) {
	service := s.findingWorkflowService()
	candidate, err := service.GetFindingCandidate(ctx, req.Msg.GetId())
	if err != nil {
		return nil, findingConnectError(err)
	}
	if err := authorizeSourceRuntimeIDTenant(ctx, sourceRuntimeStore(s.deps.StateStore), candidate.RuntimeID); err != nil {
		return nil, findingConnectError(normalizeIDLookupError(err, ports.ErrFindingCandidateNotFound))
	}
	if err := authorizeFindingCandidatePromotion(ctx); err != nil {
		return nil, findingConnectError(err)
	}
	response, err := service.PromoteFindingCandidate(ctx, findings.PromoteCandidateRequest{
		CandidateID:           req.Msg.GetId(),
		PromotedBy:            req.Msg.GetPromotedBy(),
		Rationale:             req.Msg.GetRationale(),
		ChangeTicket:          req.Msg.GetChangeTicket(),
		FalsePositiveReviewed: req.Msg.GetFalsePositiveReviewed(),
		GraphCoverageReviewed: req.Msg.GetGraphCoverageReviewed(),
	})
	if err != nil {
		return nil, findingConnectError(err)
	}
	bumpGRCCacheForFinding(ctx, s.deps.QueryCache, response.Finding)
	return connect.NewResponse(promoteFindingCandidateResponse(response)), nil
}

func (s *bootstrapService) RejectFindingCandidate(ctx context.Context, req *connect.Request[cerebrov1.RejectFindingCandidateRequest]) (*connect.Response[cerebrov1.RejectFindingCandidateResponse], error) {
	service := s.findingWorkflowService()
	candidate, err := service.GetFindingCandidate(ctx, req.Msg.GetId())
	if err != nil {
		return nil, findingConnectError(err)
	}
	if err := authorizeSourceRuntimeIDTenant(ctx, sourceRuntimeStore(s.deps.StateStore), candidate.RuntimeID); err != nil {
		return nil, findingConnectError(normalizeIDLookupError(err, ports.ErrFindingCandidateNotFound))
	}
	if err := authorizeFindingCandidatePromotion(ctx); err != nil {
		return nil, findingConnectError(err)
	}
	response, err := service.RejectFindingCandidate(ctx, findings.RejectCandidateRequest{
		CandidateID: req.Msg.GetId(),
		RejectedBy:  req.Msg.GetRejectedBy(),
		Rationale:   req.Msg.GetRationale(),
	})
	if err != nil {
		return nil, findingConnectError(err)
	}
	return connect.NewResponse(rejectFindingCandidateResponse(response)), nil
}

func (s *bootstrapService) ResolveFinding(ctx context.Context, req *connect.Request[cerebrov1.ResolveFindingRequest]) (*connect.Response[cerebrov1.ResolveFindingResponse], error) {
	if err := authorizeFindingIDTenant(ctx, findingStore(s.deps.StateStore), req.Msg.GetId()); err != nil {
		return nil, findingConnectError(normalizeIDLookupError(err, ports.ErrFindingNotFound))
	}
	options, err := findingapi.StatusUpdateOptions(req.Msg.GetExpectedStatus(), timestampValue(req.Msg.GetLastObservedBefore()), req.Msg.GetStatusSource())
	if err != nil {
		return nil, findingConnectError(err)
	}
	finding, err := s.findingWorkflowService().ResolveFindingWithOptions(ctx, req.Msg.GetId(), req.Msg.GetReason(), options)
	if err != nil {
		return nil, findingConnectError(err)
	}
	bumpGRCCacheForFinding(ctx, s.deps.QueryCache, finding)
	return connect.NewResponse(&cerebrov1.ResolveFindingResponse{Finding: safeFindingMessage(finding)}), nil
}

func (s *bootstrapService) SuppressFinding(ctx context.Context, req *connect.Request[cerebrov1.SuppressFindingRequest]) (*connect.Response[cerebrov1.SuppressFindingResponse], error) {
	if err := authorizeFindingIDTenant(ctx, findingStore(s.deps.StateStore), req.Msg.GetId()); err != nil {
		return nil, findingConnectError(normalizeIDLookupError(err, ports.ErrFindingNotFound))
	}
	options, err := findingapi.StatusUpdateOptions(req.Msg.GetExpectedStatus(), timestampValue(req.Msg.GetLastObservedBefore()), req.Msg.GetStatusSource())
	if err != nil {
		return nil, findingConnectError(err)
	}
	finding, err := s.findingWorkflowService().SuppressFindingWithOptions(ctx, req.Msg.GetId(), req.Msg.GetReason(), options)
	if err != nil {
		return nil, findingConnectError(err)
	}
	bumpGRCCacheForFinding(ctx, s.deps.QueryCache, finding)
	return connect.NewResponse(&cerebrov1.SuppressFindingResponse{Finding: safeFindingMessage(finding)}), nil
}

func (s *bootstrapService) AssignFinding(ctx context.Context, req *connect.Request[cerebrov1.AssignFindingRequest]) (*connect.Response[cerebrov1.AssignFindingResponse], error) {
	if err := authorizeFindingIDTenant(ctx, findingStore(s.deps.StateStore), req.Msg.GetId()); err != nil {
		return nil, findingConnectError(normalizeIDLookupError(err, ports.ErrFindingNotFound))
	}
	finding, err := s.findingCoreService().AssignFinding(ctx, req.Msg.GetId(), req.Msg.GetAssignee())
	if err != nil {
		return nil, findingConnectError(err)
	}
	bumpGRCCacheForFinding(ctx, s.deps.QueryCache, finding)
	return connect.NewResponse(&cerebrov1.AssignFindingResponse{Finding: safeFindingMessage(finding)}), nil
}

func (s *bootstrapService) SetFindingDueDate(ctx context.Context, req *connect.Request[cerebrov1.SetFindingDueDateRequest]) (*connect.Response[cerebrov1.SetFindingDueDateResponse], error) {
	if err := authorizeFindingIDTenant(ctx, findingStore(s.deps.StateStore), req.Msg.GetId()); err != nil {
		return nil, findingConnectError(normalizeIDLookupError(err, ports.ErrFindingNotFound))
	}
	var dueAt time.Time
	if req.Msg.GetDueAt() != nil {
		dueAt = req.Msg.GetDueAt().AsTime()
	}
	finding, err := s.findingCoreService().SetFindingDueDate(ctx, req.Msg.GetId(), dueAt)
	if err != nil {
		return nil, findingConnectError(err)
	}
	bumpGRCCacheForFinding(ctx, s.deps.QueryCache, finding)
	return connect.NewResponse(&cerebrov1.SetFindingDueDateResponse{Finding: safeFindingMessage(finding)}), nil
}

func (s *bootstrapService) AddFindingNote(ctx context.Context, req *connect.Request[cerebrov1.AddFindingNoteRequest]) (*connect.Response[cerebrov1.AddFindingNoteResponse], error) {
	if err := authorizeFindingIDTenant(ctx, findingStore(s.deps.StateStore), req.Msg.GetId()); err != nil {
		return nil, findingConnectError(normalizeIDLookupError(err, ports.ErrFindingNotFound))
	}
	finding, err := s.findingWorkflowService().AddFindingNote(ctx, req.Msg.GetId(), req.Msg.GetNote())
	if err != nil {
		return nil, findingConnectError(err)
	}
	bumpGRCCacheForFinding(ctx, s.deps.QueryCache, finding)
	return connect.NewResponse(&cerebrov1.AddFindingNoteResponse{Finding: safeFindingMessage(finding)}), nil
}

func (s *bootstrapService) LinkFindingTicket(ctx context.Context, req *connect.Request[cerebrov1.LinkFindingTicketRequest]) (*connect.Response[cerebrov1.LinkFindingTicketResponse], error) {
	if err := authorizeFindingIDTenant(ctx, findingStore(s.deps.StateStore), req.Msg.GetId()); err != nil {
		return nil, findingConnectError(normalizeIDLookupError(err, ports.ErrFindingNotFound))
	}
	finding, err := s.findingWorkflowService().LinkFindingTicket(
		ctx,
		req.Msg.GetId(),
		req.Msg.GetUrl(),
		req.Msg.GetName(),
		req.Msg.GetExternalId(),
	)
	if err != nil {
		return nil, findingConnectError(err)
	}
	bumpGRCCacheForFinding(ctx, s.deps.QueryCache, finding)
	return connect.NewResponse(&cerebrov1.LinkFindingTicketResponse{Finding: safeFindingMessage(finding)}), nil
}

func (s *bootstrapService) LinkFindingExternalRef(ctx context.Context, req *connect.Request[cerebrov1.LinkFindingExternalRefRequest]) (*connect.Response[cerebrov1.LinkFindingExternalRefResponse], error) {
	if err := authorizeFindingIDTenant(ctx, findingStore(s.deps.StateStore), req.Msg.GetId()); err != nil {
		return nil, findingConnectError(normalizeIDLookupError(err, ports.ErrFindingNotFound))
	}
	finding, err := s.findingWorkflowService().LinkFindingExternalRef(ctx, req.Msg.GetId(), findingapi.ExternalRefFromLinkRequest(req.Msg))
	if err != nil {
		return nil, findingConnectError(err)
	}
	bumpGRCCacheForFinding(ctx, s.deps.QueryCache, finding)
	return connect.NewResponse(&cerebrov1.LinkFindingExternalRefResponse{Finding: safeFindingMessage(finding)}), nil
}

func (s *bootstrapService) ListFindingEvidence(ctx context.Context, req *connect.Request[cerebrov1.ListFindingEvidenceRequest]) (*connect.Response[cerebrov1.ListFindingEvidenceResponse], error) {
	if err := authorizeSourceRuntimeIDTenant(ctx, sourceRuntimeStore(s.deps.StateStore), req.Msg.GetRuntimeId()); err != nil {
		return nil, findingConnectError(err)
	}
	response, err := s.findingCoreService().ListEvidence(ctx, findings.ListEvidenceRequest{
		RuntimeID:    req.Msg.GetRuntimeId(),
		FindingID:    req.Msg.GetFindingId(),
		RunID:        req.Msg.GetRunId(),
		RuleID:       req.Msg.GetRuleId(),
		ClaimID:      req.Msg.GetClaimId(),
		EventID:      req.Msg.GetEventId(),
		GraphRootURN: req.Msg.GetGraphRootUrn(),
		GraphPathURN: req.Msg.GetGraphPathUrn(),
		Limit:        req.Msg.GetLimit(),
	})
	if err != nil {
		return nil, findingConnectError(err)
	}
	return connect.NewResponse(listFindingEvidenceResponse(response)), nil
}

func (s *bootstrapService) ListFindingEvaluationRuns(ctx context.Context, req *connect.Request[cerebrov1.ListFindingEvaluationRunsRequest]) (*connect.Response[cerebrov1.ListFindingEvaluationRunsResponse], error) {
	if err := authorizeSourceRuntimeIDTenant(ctx, sourceRuntimeStore(s.deps.StateStore), req.Msg.GetRuntimeId()); err != nil {
		return nil, findingConnectError(err)
	}
	response, err := s.findingCoreService().ListEvaluationRuns(ctx, findings.ListEvaluationRunsRequest{
		RuntimeID: req.Msg.GetRuntimeId(),
		RuleID:    req.Msg.GetRuleId(),
		Status:    req.Msg.GetStatus(),
		Limit:     req.Msg.GetLimit(),
	})
	if err != nil {
		return nil, findingConnectError(err)
	}
	return connect.NewResponse(&cerebrov1.ListFindingEvaluationRunsResponse{
		Runs: response.Runs,
	}), nil
}

func (s *bootstrapService) GetFindingEvaluationRun(ctx context.Context, req *connect.Request[cerebrov1.GetFindingEvaluationRunRequest]) (*connect.Response[cerebrov1.GetFindingEvaluationRunResponse], error) {
	run, err := s.findingCoreService().GetEvaluationRun(ctx, req.Msg.GetId())
	if err != nil {
		return nil, findingConnectError(err)
	}
	if err := authorizeSourceRuntimeIDTenant(ctx, sourceRuntimeStore(s.deps.StateStore), run.GetRuntimeId()); err != nil {
		return nil, findingConnectError(normalizeIDLookupError(err, ports.ErrFindingEvaluationRunNotFound))
	}
	return connect.NewResponse(&cerebrov1.GetFindingEvaluationRunResponse{Run: run}), nil
}

func (s *bootstrapService) GetFindingEvidence(ctx context.Context, req *connect.Request[cerebrov1.GetFindingEvidenceRequest]) (*connect.Response[cerebrov1.GetFindingEvidenceResponse], error) {
	evidence, err := s.findingCoreService().GetEvidence(ctx, req.Msg.GetId())
	if err != nil {
		return nil, findingConnectError(err)
	}
	if err := authorizeSourceRuntimeIDTenant(ctx, sourceRuntimeStore(s.deps.StateStore), evidence.GetRuntimeId()); err != nil {
		return nil, findingConnectError(normalizeIDLookupError(err, ports.ErrFindingEvidenceNotFound))
	}
	return connect.NewResponse(&cerebrov1.GetFindingEvidenceResponse{Evidence: safeFindingEvidence(evidence)}), nil
}

func (s *bootstrapService) EvaluateSourceRuntimeFindingRules(ctx context.Context, req *connect.Request[cerebrov1.EvaluateSourceRuntimeFindingRulesRequest]) (*connect.Response[cerebrov1.EvaluateSourceRuntimeFindingRulesResponse], error) {
	if err := authorizeSourceRuntimeIDTenant(ctx, sourceRuntimeStore(s.deps.StateStore), req.Msg.GetId()); err != nil {
		return nil, findingConnectError(normalizeIDLookupError(err, ports.ErrSourceRuntimeNotFound))
	}
	response, err := s.findingCoreService().EvaluateSourceRuntimeRules(ctx, findings.EvaluateRulesRequest{
		RuntimeID:  req.Msg.GetId(),
		RuleIDs:    req.Msg.GetRuleIds(),
		EventLimit: req.Msg.GetEventLimit(),
	})
	if response != nil {
		bumpGRCCacheForRuntime(ctx, s.deps, req.Msg.GetId(), grcCacheScopeFindings, grcCacheScopeEvidence, grcCacheScopeInventory)
	}
	if err != nil {
		return nil, findingConnectError(err)
	}
	return connect.NewResponse(findingRulesResponse(response)), nil
}

func (s *bootstrapService) EvaluateSourceRuntimeFindings(ctx context.Context, req *connect.Request[cerebrov1.EvaluateSourceRuntimeFindingsRequest]) (*connect.Response[cerebrov1.EvaluateSourceRuntimeFindingsResponse], error) {
	if err := authorizeSourceRuntimeIDTenant(ctx, sourceRuntimeStore(s.deps.StateStore), req.Msg.GetId()); err != nil {
		return nil, findingConnectError(normalizeIDLookupError(err, ports.ErrSourceRuntimeNotFound))
	}
	response, err := s.findingCoreService().EvaluateSourceRuntime(ctx, findings.EvaluateRequest{
		RuntimeID:  req.Msg.GetId(),
		RuleID:     req.Msg.GetRuleId(),
		EventLimit: req.Msg.GetEventLimit(),
	})
	if err != nil {
		return nil, findingConnectError(err)
	}
	bumpGRCCacheForRuntime(ctx, s.deps, req.Msg.GetId(), grcCacheScopeFindings, grcCacheScopeEvidence, grcCacheScopeInventory)
	return connect.NewResponse(findingResponse(response)), nil
}

func (s *bootstrapService) WriteDecision(ctx context.Context, req *connect.Request[cerebrov1.WriteDecisionRequest]) (*connect.Response[cerebrov1.WriteDecisionResponse], error) {
	metadata := map[string]any{}
	if req.Msg.GetMetadata() != nil {
		metadata = req.Msg.GetMetadata().AsMap()
	}
	if err := authorizeKnowledgeTenant(ctx, metadata, append(append([]string{}, req.Msg.GetTargetIds()...), append(req.Msg.GetEvidenceIds(), req.Msg.GetActionIds()...)...)...); err != nil {
		return nil, knowledgeConnectError(err)
	}
	result, err := knowledge.New(
		graphQueryStore(s.deps.GraphStore),
		sourceProjectionGraphStore(s.deps.GraphStore),
	).WithAppendLog(s.deps.AppendLog).WriteDecision(ctx, knowledge.DecisionWriteRequest{
		ID:            req.Msg.GetId(),
		DecisionType:  req.Msg.GetDecisionType(),
		Status:        req.Msg.GetStatus(),
		MadeBy:        req.Msg.GetMadeBy(),
		Rationale:     req.Msg.GetRationale(),
		TargetIDs:     req.Msg.GetTargetIds(),
		EvidenceIDs:   req.Msg.GetEvidenceIds(),
		ActionIDs:     req.Msg.GetActionIds(),
		SourceSystem:  req.Msg.GetSourceSystem(),
		SourceEventID: req.Msg.GetSourceEventId(),
		ObservedAt:    timestampValue(req.Msg.GetObservedAt()),
		ValidFrom:     timestampValue(req.Msg.GetValidFrom()),
		ValidTo:       timestampValue(req.Msg.GetValidTo()),
		Confidence:    req.Msg.GetConfidence(),
		Metadata:      metadata,
	})
	if err != nil {
		return nil, knowledgeConnectError(err)
	}
	return connect.NewResponse(&cerebrov1.WriteDecisionResponse{
		DecisionId:  result.DecisionID,
		TargetCount: result.TargetCount,
	}), nil
}

func (s *bootstrapService) WriteAction(ctx context.Context, req *connect.Request[cerebrov1.WriteActionRequest]) (*connect.Response[cerebrov1.WriteActionResponse], error) {
	metadata := map[string]any{}
	if req.Msg.GetMetadata() != nil {
		metadata = req.Msg.GetMetadata().AsMap()
	}
	if err := authorizeKnowledgeTenant(ctx, metadata, append(append([]string{req.Msg.GetDecisionId()}, req.Msg.GetTargetIds()...), req.Msg.GetRecommendationId())...); err != nil {
		return nil, knowledgeConnectError(err)
	}
	result, err := knowledge.New(
		graphQueryStore(s.deps.GraphStore),
		sourceProjectionGraphStore(s.deps.GraphStore),
	).WithAppendLog(s.deps.AppendLog).WriteAction(ctx, knowledge.ActionWriteRequest{
		ID:               req.Msg.GetId(),
		RecommendationID: req.Msg.GetRecommendationId(),
		InsightType:      req.Msg.GetInsightType(),
		Title:            req.Msg.GetTitle(),
		Summary:          req.Msg.GetSummary(),
		DecisionID:       req.Msg.GetDecisionId(),
		TargetIDs:        req.Msg.GetTargetIds(),
		SourceSystem:     req.Msg.GetSourceSystem(),
		SourceEventID:    req.Msg.GetSourceEventId(),
		ObservedAt:       timestampValue(req.Msg.GetObservedAt()),
		ValidFrom:        timestampValue(req.Msg.GetValidFrom()),
		ValidTo:          timestampValue(req.Msg.GetValidTo()),
		Confidence:       req.Msg.GetConfidence(),
		AutoGenerated:    req.Msg.GetAutoGenerated(),
		Metadata:         metadata,
	})
	if err != nil {
		return nil, knowledgeConnectError(err)
	}
	return connect.NewResponse(&cerebrov1.WriteActionResponse{
		ActionId:    result.ActionID,
		DecisionId:  result.DecisionID,
		TargetCount: result.TargetCount,
	}), nil
}

func (s *bootstrapService) WriteOutcome(ctx context.Context, req *connect.Request[cerebrov1.WriteOutcomeRequest]) (*connect.Response[cerebrov1.WriteOutcomeResponse], error) {
	metadata := map[string]any{}
	if req.Msg.GetMetadata() != nil {
		metadata = req.Msg.GetMetadata().AsMap()
	}
	if err := authorizeKnowledgeTenant(ctx, metadata, append([]string{req.Msg.GetDecisionId()}, req.Msg.GetTargetIds()...)...); err != nil {
		return nil, knowledgeConnectError(err)
	}
	result, err := knowledge.New(
		graphQueryStore(s.deps.GraphStore),
		sourceProjectionGraphStore(s.deps.GraphStore),
	).WithAppendLog(s.deps.AppendLog).WriteOutcome(ctx, knowledge.OutcomeWriteRequest{
		ID:            req.Msg.GetId(),
		DecisionID:    req.Msg.GetDecisionId(),
		OutcomeType:   req.Msg.GetOutcomeType(),
		Verdict:       req.Msg.GetVerdict(),
		ImpactScore:   req.Msg.GetImpactScore(),
		TargetIDs:     req.Msg.GetTargetIds(),
		SourceSystem:  req.Msg.GetSourceSystem(),
		SourceEventID: req.Msg.GetSourceEventId(),
		ObservedAt:    timestampValue(req.Msg.GetObservedAt()),
		ValidFrom:     timestampValue(req.Msg.GetValidFrom()),
		ValidTo:       timestampValue(req.Msg.GetValidTo()),
		Confidence:    req.Msg.GetConfidence(),
		Metadata:      metadata,
	})
	if err != nil {
		return nil, knowledgeConnectError(err)
	}
	return connect.NewResponse(&cerebrov1.WriteOutcomeResponse{
		OutcomeId:   result.OutcomeID,
		DecisionId:  result.DecisionID,
		TargetCount: result.TargetCount,
	}), nil
}

func (s *bootstrapService) ReplayWorkflowEvents(ctx context.Context, req *connect.Request[cerebrov1.ReplayWorkflowEventsRequest]) (*connect.Response[cerebrov1.ReplayWorkflowEventsResponse], error) {
	if err := authorizeTenantScopeRequired(ctx, req.Msg.GetTenantId()); err != nil {
		return nil, workflowReplayConnectError(err)
	}
	result, err := workflowprojection.NewReplayer(
		eventReplayer(s.deps.AppendLog),
		sourceProjectionGraphStore(s.deps.GraphStore),
	).Replay(ctx, workflowprojection.ReplayRequest{
		KindPrefix:      req.Msg.GetKindPrefix(),
		TenantID:        req.Msg.GetTenantId(),
		AttributeEquals: req.Msg.GetAttributeEquals(),
		Limit:           req.Msg.GetLimit(),
	})
	if err != nil {
		return nil, workflowReplayConnectError(err)
	}
	return connect.NewResponse(workflowReplayResponse(result)), nil
}

func (s *bootstrapService) GetEntityNeighborhood(ctx context.Context, req *connect.Request[cerebrov1.GetEntityNeighborhoodRequest]) (*connect.Response[cerebrov1.GetEntityNeighborhoodResponse], error) {
	if err := authorizeCerebroURNTenant(ctx, req.Msg.GetRootUrn()); err != nil {
		return nil, graphQueryConnectError(err)
	}
	response, err := graphquery.New(
		graphQueryStore(s.deps.GraphStore),
	).GetEntityNeighborhood(ctx, graphquery.NeighborhoodRequest{
		RootURN: req.Msg.GetRootUrn(),
		Limit:   req.Msg.GetLimit(),
	})
	if err != nil {
		return nil, graphQueryConnectError(err)
	}
	return connect.NewResponse(graphNeighborhoodResponse(response)), nil
}

func (s *bootstrapService) RunGraphIngestRuntime(ctx context.Context, req *connect.Request[cerebrov1.RunGraphIngestRuntimeRequest]) (*connect.Response[cerebrov1.RunGraphIngestRuntimeResponse], error) {
	if err := authorizeSourceRuntimeIDTenant(ctx, sourceRuntimeStore(s.deps.StateStore), req.Msg.GetRuntimeId()); err != nil {
		return nil, graphIngestConnectError(err)
	}
	result, err := newGraphIngestService(s.cfg, s.deps, s.sources).RunRuntime(ctx, graphingest.RuntimeRequest{
		RuntimeID:       req.Msg.GetRuntimeId(),
		PageLimit:       req.Msg.GetPageLimit(),
		CheckpointID:    req.Msg.GetCheckpointId(),
		ResetCheckpoint: req.Msg.GetResetCheckpoint(),
		Trigger:         "api",
	})
	if err != nil {
		return nil, graphIngestConnectError(err)
	}
	bumpGRCCacheForRuntime(ctx, s.deps, req.Msg.GetRuntimeId(), grcCacheScopeGraph, grcCacheScopeRuntime, grcCacheScopeInventory)
	return connect.NewResponse(&cerebrov1.RunGraphIngestRuntimeResponse{
		Result: graphIngestRunResultMessage(result),
	}), nil
}

func (s *bootstrapService) GetGraphIngestRun(ctx context.Context, req *connect.Request[cerebrov1.GetGraphIngestRunRequest]) (*connect.Response[cerebrov1.GetGraphIngestRunResponse], error) {
	run, err := newGraphIngestService(s.cfg, s.deps, s.sources).GetRun(ctx, req.Msg.GetId())
	if err != nil {
		return nil, graphIngestConnectError(err)
	}
	if err := authorizeTenantID(ctx, run.TenantID); err != nil {
		return nil, graphIngestConnectError(normalizeIDLookupError(err, graphingest.ErrRunNotFound))
	}
	return connect.NewResponse(&cerebrov1.GetGraphIngestRunResponse{
		Run: graphIngestRunMessage(run),
	}), nil
}

func (s *bootstrapService) ListGraphIngestRuns(ctx context.Context, req *connect.Request[cerebrov1.ListGraphIngestRunsRequest]) (*connect.Response[cerebrov1.ListGraphIngestRunsResponse], error) {
	if err := authorizeGraphIngestRunListScope(ctx, req.Msg.GetRuntimeId()); err != nil {
		return nil, graphIngestConnectError(err)
	}
	if req.Msg.GetRuntimeId() != "" {
		if err := authorizeSourceRuntimeIDTenant(ctx, sourceRuntimeStore(s.deps.StateStore), req.Msg.GetRuntimeId()); err != nil {
			return nil, graphIngestConnectError(err)
		}
	}
	result, err := newGraphIngestService(s.cfg, s.deps, s.sources).ListRuns(ctx, graphstore.IngestRunFilter{
		RuntimeID: req.Msg.GetRuntimeId(),
		Status:    req.Msg.GetStatus(),
		Limit:     int(req.Msg.GetLimit()),
	})
	if err != nil {
		return nil, graphIngestConnectError(err)
	}
	return connect.NewResponse(graphIngestListResponse(result)), nil
}

func (s *bootstrapService) CheckGraphIngestHealth(ctx context.Context, req *connect.Request[cerebrov1.CheckGraphIngestHealthRequest]) (*connect.Response[cerebrov1.CheckGraphIngestHealthResponse], error) {
	if err := authorizeGlobalGraphHealthScope(ctx); err != nil {
		return nil, graphIngestConnectError(err)
	}
	result, err := newGraphIngestService(s.cfg, s.deps, s.sources).Health(ctx, req.Msg.GetLimit())
	if err != nil {
		return nil, graphIngestConnectError(err)
	}
	return connect.NewResponse(graphIngestHealthResponse(result)), nil
}

func healthResponse(ctx context.Context, cfg config.Config, deps Dependencies) *cerebrov1.CheckHealthResponse {
	response := publicHealthResponse(ctx, deps)
	response.ServiceName = buildinfo.ServiceName
	response.Version = buildinfo.Version
	response.Commit = buildinfo.Commit
	response.BuildDate = buildinfo.BuildDate
	response.ApiVersion = buildinfo.APIVersion
	response.ImageTag = healthImageTag(cfg)
	return response
}

func publicHealthResponse(ctx context.Context, deps Dependencies) *cerebrov1.CheckHealthResponse {
	components := []*cerebrov1.ComponentStatus{
		componentStatus(ctx, "append_log", deps.AppendLog),
		componentStatus(ctx, "state_store", deps.StateStore),
		componentStatus(ctx, "graph_store", deps.GraphStore),
	}
	status := "ready"
	for _, component := range components {
		if component.Status == "error" {
			status = "degraded"
			break
		}
	}
	return &cerebrov1.CheckHealthResponse{
		Status:     status,
		CheckedAt:  timestamppb.Now(),
		Components: components,
	}
}

func publicLivenessResponse() *cerebrov1.CheckHealthResponse {
	return &cerebrov1.CheckHealthResponse{
		Status:    "live",
		CheckedAt: timestamppb.Now(),
	}
}

func healthImageTag(cfg config.Config) string {
	imageTag := strings.TrimSpace(cfg.ImageTag)
	if imageTag != "" {
		return imageTag
	}
	version := strings.TrimSpace(buildinfo.Version)
	if version == "" || version == "dev" {
		return ""
	}
	if strings.HasPrefix(version, "v") {
		return version
	}
	return "v" + version
}

func writeProtoJSON(w http.ResponseWriter, statusCode int, message proto.Message) {
	payload, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(message)
	if err != nil {
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_, _ = w.Write(payload)
}

func writeJSON(w http.ResponseWriter, statusCode int, value any) {
	payload, err := json.Marshal(value)
	if err != nil {
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_, _ = w.Write(payload)
}

func writeSourceRuntimeListJSON(w http.ResponseWriter, statusCode int, runtimes []*cerebrov1.SourceRuntime) {
	items := make([]json.RawMessage, 0, len(runtimes))
	for _, runtime := range runtimes {
		payload, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(runtime)
		if err != nil {
			http.Error(w, "failed to encode response", http.StatusInternalServerError)
			return
		}
		items = append(items, json.RawMessage(payload))
	}
	writeJSON(w, statusCode, map[string]any{"runtimes": items})
}

func uint32QueryParam(r *http.Request, key string) (uint32, error) {
	value := strings.TrimSpace(r.URL.Query().Get(key))
	if value == "" {
		return 0, nil
	}
	parsed, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("%w: invalid %s", graphquery.ErrInvalidRequest, key)
	}
	if parsed == 0 {
		return 0, fmt.Errorf("%w: %s must be at least 1", graphquery.ErrInvalidRequest, key)
	}
	return uint32(parsed), nil
}

func boolQueryParam(r *http.Request, key string) (bool, error) {
	value := strings.TrimSpace(r.URL.Query().Get(key))
	if value == "" {
		return false, nil
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("%w: invalid %s", errInvalidHTTPRequest, key)
	}
	return parsed, nil
}

func (a *App) sourceService() *sourceops.Service {
	if a != nil && a.services.sourceOps != nil {
		return a.services.sourceOps
	}
	return newSourceService(a.sources)
}

func (a *App) reportService() *reports.Service {
	if a != nil && a.services.reports != nil {
		return a.services.reports
	}
	return a.newReportService()
}

func (a *App) newReportService() *reports.Service {
	return newReportFeatureService(newReportFeatureDeps(a.deps))
}

func (a *App) runtimeService() *sourceruntime.Service {
	if a != nil && a.services.runtimeOps != nil {
		return a.services.runtimeOps
	}
	return newRuntimeService(a.cfg, a.deps, a.sources)
}

func newSourceService(sources *sourcecdk.Registry) *sourceops.Service {
	return newSourceFeatureService(newSourceFeatureDeps(sources))
}

func newRuntimeService(cfg config.Config, deps Dependencies, sources *sourcecdk.Registry) *sourceruntime.Service {
	return newRuntimeFeatureService(cfg, newRuntimeFeatureDeps(deps, sources))
}

func resolveRuntimeSourceConfig(ctx context.Context, sourceID string, values map[string]string) (map[string]string, error) {
	return resolveRuntimeSourceConfigWithStore(ctx, config.ConnectorCredentialConfig{}, config.ConnectorSecretStoreConfig{}, nil, sourceID, values)
}

func resolveRuntimeSourceConfigWithStore(ctx context.Context, credentialConfig config.ConnectorCredentialConfig, secretStoreConfig config.ConnectorSecretStoreConfig, store ports.StateStore, sourceID string, values map[string]string) (map[string]string, error) {
	if err := authorizeRuntimeConfigEnvReferences(ctx, sourceID, values); err != nil {
		return nil, err
	}
	resolved := values
	var err error
	if hasConnectorCredentialReferences(values) {
		broker, err := connectorCredentialBroker(credentialConfig, store, nil)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", sourceruntime.ErrRuntimeUnavailable, err)
		}
		resolved, err = broker.ResolveReferences(ctx, sourceID, values[sourceconfig.RuntimeTenantIDKey], values[sourceconfig.RuntimeIDKey], values)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", sourceruntime.ErrInvalidRequest, err)
		}
	}
	if err := connectorsecretstores.AuthorizeRuntimeReferences(sourceID, resolved[sourceconfig.RuntimeTenantIDKey], resolved[sourceconfig.RuntimeIDKey], resolved); err != nil {
		return nil, fmt.Errorf("%w: %w", sourceruntime.ErrInvalidRequest, err)
	}
	resolved, err = connectorsecretstores.NewResolver(secretStoreConfig).ResolveReferences(ctx, resolved)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", sourceruntime.ErrInvalidRequest, err)
	}
	resolved, err = config.ResolveSourceRuntimeConfigSecretReferences(ctx, sourceID, resolved)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", sourceruntime.ErrInvalidRequest, err)
	}
	if err := authorizeSourceConfigTenant(ctx, resolved); err != nil {
		return nil, err
	}
	return resolved, nil
}

func hasConnectorCredentialReferences(values map[string]string) bool {
	for _, value := range values {
		if sourceconfig.IsCredentialReference(value) {
			return true
		}
	}
	return false
}

func authorizeRuntimeConfigEnvReferences(ctx context.Context, sourceID string, values map[string]string) error {
	if !hasTenantScopedAuth(ctx) && !requiresTenantFilter(ctx) {
		return nil
	}
	for key, value := range values {
		envName, ok := sourceconfig.SecretReferenceName(value)
		if strings.TrimSpace(key) == "tenant_id" || !ok {
			continue
		}
		if sourceconfig.LiteralEnvPrefixKey(key) && !config.SourceConfigEnvReferenceAllowed(sourceID, key, envName) {
			continue
		}
		return errTenantForbidden
	}
	return nil
}

func (a *App) claimService() *claims.Service {
	if a != nil && a.services.claims != nil {
		return a.services.claims
	}
	return a.newClaimService()
}

func (a *App) graphFactsService() *graphfacts.Service {
	if a != nil && a.services.graphFacts != nil {
		return a.services.graphFacts
	}
	if a == nil {
		return graphfacts.New(nil)
	}
	return graphfacts.New(claimStore(a.deps.StateStore))
}

func (a *App) newClaimService() *claims.Service {
	return newClaimFeatureService(newClaimFeatureDeps(a.deps))
}

func (a *App) findingService() *findings.Service {
	if a != nil && a.services.findings != nil {
		return a.services.findings
	}
	return a.newFindingService()
}

func (a *App) newFindingService() *findings.Service {
	return newFindingWorkflowFeatureService(newFindingFeatureDeps(a.deps)).WithRuntimeIndexReplayPreparer(a.cfg.AppendLog.JetStreamRuntimeIndexEnabled, a.deps.AppendLog, a.deps.StateStore)
}

func (s *bootstrapService) findingCoreService() *findings.Service {
	return newFindingCoreFeatureService(newFindingFeatureDeps(s.deps)).WithRuntimeIndexReplayPreparer(s.cfg.AppendLog.JetStreamRuntimeIndexEnabled, s.deps.AppendLog, s.deps.StateStore)
}

func (s *bootstrapService) findingCandidateService() *findings.Service {
	return newFindingCandidateFeatureService(newFindingFeatureDeps(s.deps)).WithRuntimeIndexReplayPreparer(s.cfg.AppendLog.JetStreamRuntimeIndexEnabled, s.deps.AppendLog, s.deps.StateStore)
}

func (s *bootstrapService) findingWorkflowService() *findings.Service {
	return newFindingWorkflowFeatureService(newFindingFeatureDeps(s.deps)).WithRuntimeIndexReplayPreparer(s.cfg.AppendLog.JetStreamRuntimeIndexEnabled, s.deps.AppendLog, s.deps.StateStore)
}

const (
	startupFindingRiskBackfillJobID    = "finding-risk-backfill"
	startupFindingRiskBackfillLeaseTTL = 30 * time.Minute
)

// BackfillFindingRisk runs server-start finding risk migration work.
func (a *App) BackfillFindingRisk(ctx context.Context) error {
	if findingStore(a.deps.StateStore) == nil {
		return nil
	}
	if leaseStore := startupJobLeaseStore(a.deps.StateStore); leaseStore != nil {
		owner := startupJobLeaseOwner()
		acquired, err := leaseStore.AcquireStartupJobLease(ctx, startupFindingRiskBackfillJobID, owner, startupFindingRiskBackfillLeaseTTL)
		if err != nil {
			return err
		}
		if !acquired {
			return nil
		}
		defer func() {
			releaseCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer cancel()
			_ = leaseStore.ReleaseStartupJobLease(releaseCtx, startupFindingRiskBackfillJobID, owner)
		}()
	}
	return a.findingService().BackfillFindingRisk(ctx)
}

func (a *App) knowledgeService() *knowledge.Service {
	if a != nil && a.services.knowledgeOps != nil {
		return a.services.knowledgeOps
	}
	return a.newKnowledgeService()
}

func (a *App) newKnowledgeService() *knowledge.Service {
	return newKnowledgeFeatureService(newKnowledgeFeatureDeps(a.deps))
}

func (a *App) graphQueryService() *graphquery.Service {
	if a != nil && a.services.graphQueries != nil {
		return a.services.graphQueries
	}
	return a.newGraphQueryService()
}

func (a *App) newGraphQueryService() *graphquery.Service {
	return newGraphQueryFeatureService(newGraphQueryFeatureDeps(a.deps))
}

func (a *App) graphIngestService() *graphingest.Service {
	if a != nil && a.services.graphIngestOps != nil {
		return a.services.graphIngestOps
	}
	return newGraphIngestService(a.cfg, a.deps, a.sources)
}

func (a *App) workflowReplayService() *workflowprojection.Replayer {
	if a != nil && a.services.workflowReplay != nil {
		return a.services.workflowReplay
	}
	return a.newWorkflowReplayService()
}

func (a *App) newWorkflowReplayService() *workflowprojection.Replayer {
	return newWorkflowReplayFeatureService(newWorkflowReplayFeatureDeps(a.deps))
}

func newGraphIngestService(cfg config.Config, deps Dependencies, sources *sourcecdk.Registry) *graphingest.Service {
	return newGraphIngestFeatureService(cfg, newGraphIngestFeatureDeps(deps, sources))
}

func sourceConfigFromRequest(r *http.Request) (map[string]string, error) {
	values := make(map[string]string)
	for key, rawValues := range r.URL.Query() {
		if key == "cursor" || len(rawValues) == 0 {
			continue
		}
		if headerOnlySourceConfigKey(key) {
			return nil, fmt.Errorf("%w: source config key %q must not be supplied in query parameters", sourceops.ErrInvalidRequest, key)
		}
		values[key] = rawValues[len(rawValues)-1]
	}
	if rawConfig := strings.TrimSpace(r.Header.Get("X-Cerebro-Source-Config")); rawConfig != "" {
		headerValues := map[string]string{}
		if err := json.Unmarshal([]byte(rawConfig), &headerValues); err != nil {
			return nil, fmt.Errorf("%w: decode source config header: %w", sourceops.ErrInvalidRequest, err)
		}
		for key, value := range headerValues {
			trimmedKey := strings.TrimSpace(key)
			if trimmedKey != "" {
				values[trimmedKey] = value
			}
		}
	}
	return values, nil
}

func headerOnlySourceConfigKey(key string) bool {
	normalized := strings.ToLower(strings.TrimSpace(key))
	if normalized == "" {
		return false
	}
	compact := strings.NewReplacer("_", "", "-", "", ".", "").Replace(normalized)
	if compact == "accesskeyid" {
		return false
	}
	return sensitiveSourceConfigKey(normalized)
}

func sensitiveSourceConfigKey(key string) bool {
	value := strings.ToLower(strings.TrimSpace(key))
	if value == "" {
		return false
	}
	if strings.Contains(value, "token") || strings.Contains(value, "secret") || strings.Contains(value, "password") {
		return true
	}
	compact := strings.NewReplacer("_", "", "-", "", ".", "").Replace(value)
	if strings.Contains(compact, "apikey") ||
		strings.Contains(compact, "accesskey") ||
		strings.Contains(compact, "credential") ||
		strings.Contains(compact, "privatekey") ||
		strings.Contains(compact, "passphrase") ||
		strings.Contains(compact, "signingkey") {
		return true
	}
	return value == "key" || compact == "sshkey"
}

type bootstrapErrorMapping struct {
	match      func(error) bool
	httpStatus int
	code       connect.Code
}

func matchesAnyError(targets ...error) func(error) bool {
	return func(err error) bool {
		for _, target := range targets {
			if errors.Is(err, target) {
				return true
			}
		}
		return false
	}
}

func mappedHTTPStatusCode(err error, mappings []bootstrapErrorMapping) int {
	if errors.Is(err, errTenantForbidden) {
		return http.StatusForbidden
	}
	for _, mapping := range mappings {
		if mapping.match != nil && mapping.match(err) {
			return mapping.httpStatus
		}
	}
	return http.StatusInternalServerError
}

func normalizeIDLookupError(err error, normalized error) error {
	if errors.Is(err, errTenantForbidden) {
		return normalized
	}
	return err
}

func writeMappedBootstrapError(w http.ResponseWriter, err error, mappings []bootstrapErrorMapping) {
	statusCode := mappedHTTPStatusCode(err, mappings)
	http.Error(w, http.StatusText(statusCode), statusCode)
}

func mappedConnectError(err error, mappings []bootstrapErrorMapping) error {
	for _, mapping := range mappings {
		if mapping.match != nil && mapping.match(err) {
			return connect.NewError(mapping.code, err)
		}
	}
	return defaultConnectError(err)
}

var sourceErrorMappings = []bootstrapErrorMapping{
	{match: matchesAnyError(sourceops.ErrSourceNotFound), httpStatus: http.StatusNotFound, code: connect.CodeNotFound},
	{match: matchesAnyError(sourceops.ErrInvalidRequest, errInvalidHTTPRequest), httpStatus: http.StatusBadRequest, code: connect.CodeInvalidArgument},
}

var reportErrorMappings = []bootstrapErrorMapping{
	{match: matchesAnyError(reports.ErrReportNotFound, ports.ErrReportRunNotFound, ports.ErrReportScheduleNotFound), httpStatus: http.StatusNotFound, code: connect.CodeNotFound},
	{match: matchesAnyError(reports.ErrRuntimeUnavailable), httpStatus: http.StatusServiceUnavailable, code: connect.CodeUnavailable},
	{match: matchesAnyError(reports.ErrInvalidRequest, errInvalidHTTPRequest), httpStatus: http.StatusBadRequest, code: connect.CodeInvalidArgument},
}

func writeSourceError(w http.ResponseWriter, err error) {
	writeMappedBootstrapError(w, err, sourceErrorMappings)
}

func writeReportError(w http.ResponseWriter, err error) {
	writeMappedBootstrapError(w, err, reportErrorMappings)
}

func reportConnectError(err error) error {
	return mappedConnectError(err, reportErrorMappings)
}

func sourceConnectError(err error) error {
	return mappedConnectError(err, sourceErrorMappings)
}

var sourceRuntimeErrorMappings = []bootstrapErrorMapping{
	{match: matchesAnyError(ports.ErrSourceRuntimeNotFound, sourceops.ErrSourceNotFound), httpStatus: http.StatusNotFound, code: connect.CodeNotFound},
	{match: matchesAnyError(sourceruntime.ErrSyncInProgress), httpStatus: http.StatusConflict, code: connect.CodeAborted},
	{match: matchesAnyError(sourceruntime.ErrRuntimeUnavailable), httpStatus: http.StatusServiceUnavailable, code: connect.CodeUnavailable},
	{match: matchesAnyError(sourceruntime.ErrInvalidRequest, graphquery.ErrInvalidRequest, errInvalidHTTPRequest), httpStatus: http.StatusBadRequest, code: connect.CodeInvalidArgument},
}

var claimErrorMappings = []bootstrapErrorMapping{
	{match: matchesAnyError(ports.ErrSourceRuntimeNotFound), httpStatus: http.StatusNotFound, code: connect.CodeNotFound},
	{match: matchesAnyError(claims.ErrRuntimeUnavailable), httpStatus: http.StatusServiceUnavailable, code: connect.CodeUnavailable},
	{match: matchesAnyError(claims.ErrInvalidRequest, errInvalidHTTPRequest), httpStatus: http.StatusBadRequest, code: connect.CodeInvalidArgument},
}

var findingErrorMappings = []bootstrapErrorMapping{
	{match: matchesAnyError(ports.ErrSourceRuntimeNotFound, findings.ErrRuleNotFound, ports.ErrFindingNotFound, ports.ErrFindingCandidateNotFound, ports.ErrFindingEvaluationRunNotFound, ports.ErrFindingEvidenceNotFound), httpStatus: http.StatusNotFound, code: connect.CodeNotFound},
	{match: matchesAnyError(ports.ErrFindingStatusPreconditionFailed), httpStatus: http.StatusConflict, code: connect.CodeAborted},
	{match: matchesAnyError(findings.ErrRuntimeUnavailable), httpStatus: http.StatusServiceUnavailable, code: connect.CodeUnavailable},
	{match: matchesAnyError(findings.ErrRuleSelectionRequired, findings.ErrRuleUnsupported, findings.ErrInvalidRequest, errInvalidHTTPRequest), httpStatus: http.StatusBadRequest, code: connect.CodeInvalidArgument},
	{match: matchesAnyError(findings.ErrRuleUnavailable), httpStatus: http.StatusPreconditionFailed, code: connect.CodeFailedPrecondition},
}

var knowledgeErrorMappings = []bootstrapErrorMapping{
	{match: matchesAnyError(ports.ErrGraphEntityNotFound), httpStatus: http.StatusNotFound, code: connect.CodeNotFound},
	{match: matchesAnyError(knowledge.ErrRuntimeUnavailable), httpStatus: http.StatusServiceUnavailable, code: connect.CodeUnavailable},
	{match: matchesAnyError(knowledge.ErrInvalidRequest, errInvalidHTTPRequest), httpStatus: http.StatusBadRequest, code: connect.CodeInvalidArgument},
}

var graphQueryErrorMappings = []bootstrapErrorMapping{
	{match: matchesAnyError(ports.ErrGraphEntityNotFound), httpStatus: http.StatusNotFound, code: connect.CodeNotFound},
	{match: matchesAnyError(graphquery.ErrRuntimeUnavailable), httpStatus: http.StatusServiceUnavailable, code: connect.CodeUnavailable},
	{match: matchesAnyError(graphquery.ErrInvalidRequest, errInvalidHTTPRequest), httpStatus: http.StatusBadRequest, code: connect.CodeInvalidArgument},
}

var graphIngestErrorMappings = []bootstrapErrorMapping{
	{match: matchesAnyError(graphingest.ErrRunNotFound, ports.ErrSourceRuntimeNotFound, sourceops.ErrSourceNotFound), httpStatus: http.StatusNotFound, code: connect.CodeNotFound},
	{match: matchesAnyError(graphingest.ErrRuntimeUnavailable), httpStatus: http.StatusServiceUnavailable, code: connect.CodeUnavailable},
	{match: matchesAnyError(graphingest.ErrInvalidRequest, errInvalidHTTPRequest), httpStatus: http.StatusBadRequest, code: connect.CodeInvalidArgument},
}

var workflowReplayErrorMappings = []bootstrapErrorMapping{
	{match: matchesAnyError(workflowprojection.ErrRuntimeUnavailable), httpStatus: http.StatusServiceUnavailable, code: connect.CodeUnavailable},
	{match: matchesAnyError(errInvalidHTTPRequest), httpStatus: http.StatusBadRequest, code: connect.CodeInvalidArgument},
}

func writeSourceRuntimeError(w http.ResponseWriter, err error) {
	writeMappedBootstrapError(w, err, sourceRuntimeErrorMappings)
}

func sourceRuntimeConnectError(err error) error {
	return mappedConnectError(err, sourceRuntimeErrorMappings)
}

func writeClaimError(w http.ResponseWriter, err error) {
	writeMappedBootstrapError(w, err, claimErrorMappings)
}

func claimConnectError(err error) error {
	return mappedConnectError(err, claimErrorMappings)
}

func defaultConnectErrorCode(err error) connect.Code {
	switch {
	case errors.Is(err, errTenantForbidden):
		return connect.CodePermissionDenied
	case errors.Is(err, context.Canceled):
		return connect.CodeCanceled
	case errors.Is(err, context.DeadlineExceeded):
		return connect.CodeDeadlineExceeded
	default:
		return connect.CodeInternal
	}
}

func defaultConnectError(err error) error {
	code := defaultConnectErrorCode(err)
	if code == connect.CodeInternal {
		return connect.NewError(code, errors.New("internal error"))
	}
	return connect.NewError(code, err)
}

func findingConnectError(err error) error {
	return mappedConnectError(err, findingErrorMappings)
}

func knowledgeConnectError(err error) error {
	return mappedConnectError(err, knowledgeErrorMappings)
}

func graphQueryConnectError(err error) error {
	return mappedConnectError(err, graphQueryErrorMappings)
}

func graphIngestConnectError(err error) error {
	return mappedConnectError(err, graphIngestErrorMappings)
}

func workflowReplayConnectError(err error) error {
	return mappedConnectError(err, workflowReplayErrorMappings)
}

func writeFindingError(w http.ResponseWriter, err error) {
	writeMappedBootstrapError(w, err, findingErrorMappings)
}

func writeKnowledgeError(w http.ResponseWriter, err error) {
	writeMappedBootstrapError(w, err, knowledgeErrorMappings)
}

func writeGraphQueryError(w http.ResponseWriter, err error) {
	writeMappedBootstrapError(w, err, graphQueryErrorMappings)
}

func writeGraphIngestError(w http.ResponseWriter, err error) {
	writeMappedBootstrapError(w, err, graphIngestErrorMappings)
}

func writeWorkflowReplayError(w http.ResponseWriter, err error) {
	writeMappedBootstrapError(w, err, workflowReplayErrorMappings)
}

func timestampValue(value *timestamppb.Timestamp) time.Time {
	if value == nil || (value.GetSeconds() == 0 && value.GetNanos() == 0) {
		return time.Time{}
	}
	return value.AsTime().UTC()
}
func readProtoJSON(r *http.Request, message proto.Message) error {
	if r.Body == nil {
		return authorizeHTTPRequestTenant(r.Context(), message)
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxProtoJSONBodyBytes+1))
	if err != nil {
		return err
	}
	if len(body) > maxProtoJSONBodyBytes {
		return fmt.Errorf("%w: %w: %d bytes", errInvalidHTTPRequest, errProtoJSONBodyTooLarge, maxProtoJSONBodyBytes)
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return authorizeHTTPRequestTenant(r.Context(), message)
	}
	if err := unmarshalHTTPProtoJSON(body, message); err != nil {
		return err
	}
	return authorizeHTTPRequestTenant(r.Context(), message)
}

func unmarshalHTTPProtoJSON(body []byte, message proto.Message) error {
	if err := protojson.Unmarshal(body, message); err != nil {
		return invalidHTTPRequestError(err)
	}
	return nil
}

func invalidHTTPRequestError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w: %w", errInvalidHTTPRequest, err)
}

func sourceRuntimeStore(store ports.StateStore) ports.SourceRuntimeStore {
	runtimeStore, ok := store.(ports.SourceRuntimeStore)
	if !ok || isNilInterface(runtimeStore) {
		return nil
	}
	return runtimeStore
}

// sourceRuntimeLeaseStore returns the StateStore's lease coordinator when
// the underlying implementation supports it. The API's Sync handler uses
// this to serialize cursor advances across replicas; CLI and single-task
// callers receive nil and fall through to a plain Sync.
func sourceRuntimeLeaseStore(store ports.StateStore) ports.SourceRuntimeLeaseStore {
	leaseStore, ok := store.(ports.SourceRuntimeLeaseStore)
	if !ok || isNilInterface(leaseStore) {
		return nil
	}
	return leaseStore
}

func sourceProjectionStateStore(store ports.StateStore) ports.ProjectionStateStore {
	projectionStore, ok := store.(ports.ProjectionStateStore)
	if !ok || isNilInterface(projectionStore) {
		return nil
	}
	return projectionStore
}

func sourceProjectionGraphStore(store ports.GraphStore) ports.ProjectionGraphStore {
	projectionStore, ok := store.(ports.ProjectionGraphStore)
	if !ok || isNilInterface(projectionStore) {
		return nil
	}
	return projectionStore
}

func sourceProjector(stateStore ports.StateStore, graphStore ports.GraphStore) ports.SourceProjector {
	state := sourceProjectionStateStore(stateStore)
	graph := sourceProjectionGraphStore(graphStore)
	if state == nil && graph == nil {
		return nil
	}
	return sourceprojection.New(state, graph)
}

func graphQueryStore(store ports.GraphStore) ports.GraphQueryStore {
	queryStore, ok := store.(ports.GraphQueryStore)
	if !ok || isNilInterface(queryStore) {
		return nil
	}
	return queryStore
}

func askTrajectoryStore(store ports.StateStore) ports.AskTrajectoryStore {
	trajectoryStore, ok := store.(ports.AskTrajectoryStore)
	if !ok || isNilInterface(trajectoryStore) {
		return nil
	}
	return trajectoryStore
}

func findingStore(store ports.StateStore) ports.FindingStore {
	findingStore, ok := store.(ports.FindingStore)
	if !ok || isNilInterface(findingStore) {
		return nil
	}
	return findingStore
}

func findingEvaluationRunStore(store ports.StateStore) ports.FindingEvaluationRunStore {
	runStore, ok := store.(ports.FindingEvaluationRunStore)
	if !ok || isNilInterface(runStore) {
		return nil
	}
	return runStore
}

func findingEvidenceStore(store ports.StateStore) ports.FindingEvidenceStore {
	evidenceStore, ok := store.(ports.FindingEvidenceStore)
	if !ok || isNilInterface(evidenceStore) {
		return nil
	}
	return evidenceStore
}

func findingCandidateStore(store ports.StateStore) ports.FindingCandidateStore {
	candidateStore, ok := store.(ports.FindingCandidateStore)
	if !ok || isNilInterface(candidateStore) {
		return nil
	}
	return candidateStore
}

func endpointVulnerabilityFindingStore(store ports.StateStore) ports.EndpointVulnerabilityFindingStore {
	endpointStore, ok := store.(ports.EndpointVulnerabilityFindingStore)
	if !ok || isNilInterface(endpointStore) {
		return nil
	}
	return endpointStore
}

func claimStore(store ports.StateStore) ports.ClaimStore {
	claimStore, ok := store.(ports.ClaimStore)
	if !ok || isNilInterface(claimStore) {
		return nil
	}
	return claimStore
}

func deviceAuthStore(store ports.StateStore) deviceauth.Store {
	deviceStore, ok := store.(deviceauth.Store)
	if !ok || isNilInterface(deviceStore) {
		return nil
	}
	return deviceStore
}

func mcpOAuthStore(store ports.StateStore) mcpoauth.Store {
	oauthStore, ok := store.(mcpoauth.Store)
	if !ok || isNilInterface(oauthStore) {
		return nil
	}
	return oauthStore
}

func deviceRiskObservationStore(store ports.StateStore) risk.ObservationStore {
	observationStore, ok := store.(risk.ObservationStore)
	if !ok || isNilInterface(observationStore) {
		return nil
	}
	return observationStore
}

type startupJobLeaseProvider interface {
	AcquireStartupJobLease(context.Context, string, string, time.Duration) (bool, error)
	ReleaseStartupJobLease(context.Context, string, string) error
}

func startupJobLeaseStore(store ports.StateStore) startupJobLeaseProvider {
	leaseStore, ok := store.(startupJobLeaseProvider)
	if !ok || isNilInterface(leaseStore) {
		return nil
	}
	return leaseStore
}

func startupJobLeaseOwner() string {
	hostname, err := os.Hostname()
	if err != nil || strings.TrimSpace(hostname) == "" {
		hostname = "unknown-host"
	}
	return fmt.Sprintf("%s/%d/%d", hostname, os.Getpid(), time.Now().UnixNano())
}

func deviceAuthReplicaCount(cfg config.DeviceAuthConfig) int {
	if cfg.ReplicaCount <= 0 {
		return 1
	}
	return cfg.ReplicaCount
}

func isNilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func reportStore(store ports.StateStore) ports.ReportStore {
	reportStore, ok := store.(ports.ReportStore)
	if !ok || isNilInterface(reportStore) {
		return nil
	}
	return reportStore
}

func jobStore(store ports.StateStore) ports.JobStore {
	jobs, ok := store.(ports.JobStore)
	if !ok || isNilInterface(jobs) {
		return nil
	}
	return jobs
}

func runtimeBlocklistStore(store ports.StateStore) ports.RuntimeBlocklistStore {
	blocklist, ok := store.(ports.RuntimeBlocklistStore)
	if !ok || isNilInterface(blocklist) {
		return nil
	}
	return blocklist
}

func grcInventoryScopeStore(store ports.StateStore) ports.GRCInventoryScopeStore {
	scopeStore, ok := store.(ports.GRCInventoryScopeStore)
	if !ok || isNilInterface(scopeStore) {
		return nil
	}
	return scopeStore
}

func grcInventoryAssetReportStore(store ports.StateStore) ports.GRCInventoryAssetReportStore {
	reportStore, ok := store.(ports.GRCInventoryAssetReportStore)
	if !ok || isNilInterface(reportStore) {
		return nil
	}
	return reportStore
}

func grcVendorDiscoveryDecisionStore(store ports.StateStore) ports.GRCVendorDiscoveryDecisionStore {
	decisionStore, ok := store.(ports.GRCVendorDiscoveryDecisionStore)
	if !ok || isNilInterface(decisionStore) {
		return nil
	}
	return decisionStore
}

func grcFindingDispositionStore(store ports.StateStore) ports.GRCFindingDispositionStore {
	dispositionStore, ok := store.(ports.GRCFindingDispositionStore)
	if !ok || isNilInterface(dispositionStore) {
		return nil
	}
	return dispositionStore
}

func eventReplayer(appendLog ports.AppendLog) ports.EventReplayer {
	replayer, ok := appendLog.(ports.EventReplayer)
	if !ok || isNilInterface(replayer) {
		return nil
	}
	return replayer
}

func findingResponse(result *findings.EvaluateResult) *cerebrov1.EvaluateSourceRuntimeFindingsResponse {
	if result == nil {
		return &cerebrov1.EvaluateSourceRuntimeFindingsResponse{}
	}
	response := &cerebrov1.EvaluateSourceRuntimeFindingsResponse{
		Runtime:          redactSourceRuntime(result.Runtime),
		Rule:             result.Rule,
		EventsEvaluated:  result.EventsEvaluated,
		FindingsUpserted: boundedUint32(len(result.Findings)),
		Findings:         safeFindingMessages(result.Findings),
		Run:              result.Run,
		Evidence:         safeFindingEvidenceMessages(result.Evidence),
	}
	return response
}

func boundedUint32(value int) uint32 {
	if value <= 0 {
		return 0
	}
	if value > math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(value)
}

func boundedInt32(value int) int32 {
	if value > math.MaxInt32 {
		return math.MaxInt32
	}
	if value < math.MinInt32 {
		return math.MinInt32
	}
	return int32(value)
}

func findingRulesResponse(result *findings.EvaluateRulesResult) *cerebrov1.EvaluateSourceRuntimeFindingRulesResponse {
	if result == nil {
		return &cerebrov1.EvaluateSourceRuntimeFindingRulesResponse{}
	}
	evaluations := make([]*cerebrov1.FindingRuleEvaluation, 0, len(result.Evaluations))
	for _, evaluation := range result.Evaluations {
		evaluations = append(evaluations, findingRuleEvaluationMessage(evaluation))
	}
	return &cerebrov1.EvaluateSourceRuntimeFindingRulesResponse{
		Runtime:         redactSourceRuntime(result.Runtime),
		EventsEvaluated: result.EventsEvaluated,
		Evaluations:     evaluations,
	}
}

func findingCandidateRulesResponse(result *findings.EvaluateCandidateRulesResult) *cerebrov1.EvaluateSourceRuntimeFindingCandidatesResponse {
	if result == nil {
		return &cerebrov1.EvaluateSourceRuntimeFindingCandidatesResponse{}
	}
	evaluations := make([]*cerebrov1.FindingCandidateRuleEvaluation, 0, len(result.Evaluations))
	for _, evaluation := range result.Evaluations {
		evaluations = append(evaluations, findingCandidateRuleEvaluationMessage(evaluation))
	}
	return &cerebrov1.EvaluateSourceRuntimeFindingCandidatesResponse{
		Runtime:         redactSourceRuntime(result.Runtime),
		EventsEvaluated: result.EventsEvaluated,
		Evaluations:     evaluations,
	}
}

func redactSourceRuntime(runtime *cerebrov1.SourceRuntime) *cerebrov1.SourceRuntime {
	if runtime == nil {
		return nil
	}
	redacted := proto.Clone(runtime).(*cerebrov1.SourceRuntime)
	config := make(map[string]string, len(redacted.GetConfig()))
	for key, value := range redacted.GetConfig() {
		if sourceconfig.InternalKey(key) || key == resourcescope.ConfigKey {
			continue
		}
		if sensitiveSourceConfigKey(key) {
			config[key] = redactedAttributeValue
			continue
		}
		config[key] = value
	}
	redacted.Config = config
	return redacted
}

func findingRuleEvaluationMessage(result *findings.RuleEvaluationResult) *cerebrov1.FindingRuleEvaluation {
	if result == nil {
		return &cerebrov1.FindingRuleEvaluation{}
	}
	return &cerebrov1.FindingRuleEvaluation{
		Rule:     result.Rule,
		Findings: safeFindingMessages(result.Findings),
		Run:      result.Run,
		Evidence: safeFindingEvidenceMessages(result.Evidence),
	}
}

func findingCandidateRuleEvaluationMessage(result *findings.FindingCandidateEvaluationResult) *cerebrov1.FindingCandidateRuleEvaluation {
	if result == nil {
		return &cerebrov1.FindingCandidateRuleEvaluation{}
	}
	return &cerebrov1.FindingCandidateRuleEvaluation{
		Rule:       result.Rule,
		Run:        findingCandidateRunMessage(result.Run),
		Candidates: safeFindingCandidateMessages(result.Candidates),
	}
}

func listFindingsResponse(result *findings.ListResult) *cerebrov1.ListFindingsResponse {
	if result == nil {
		return &cerebrov1.ListFindingsResponse{}
	}
	return &cerebrov1.ListFindingsResponse{
		Findings: safeFindingMessages(result.Findings),
	}
}

func listFindingCandidatesResponse(result *findings.ListCandidatesResult) *cerebrov1.ListFindingCandidatesResponse {
	if result == nil {
		return &cerebrov1.ListFindingCandidatesResponse{}
	}
	return &cerebrov1.ListFindingCandidatesResponse{
		Candidates: safeFindingCandidateMessages(result.Candidates),
	}
}

func listFindingEvidenceResponse(result *findings.ListEvidenceResult) *cerebrov1.ListFindingEvidenceResponse {
	if result == nil {
		return &cerebrov1.ListFindingEvidenceResponse{}
	}
	return &cerebrov1.ListFindingEvidenceResponse{
		Evidence: safeFindingEvidenceMessages(result.Evidence),
	}
}

func promoteFindingCandidateResponse(result *findings.PromoteCandidateResult) *cerebrov1.PromoteFindingCandidateResponse {
	if result == nil {
		return &cerebrov1.PromoteFindingCandidateResponse{}
	}
	return &cerebrov1.PromoteFindingCandidateResponse{
		Finding:    safeFindingMessage(result.Finding),
		Candidate:  safeFindingCandidateMessage(result.Candidate),
		DecisionId: result.DecisionID,
	}
}

func rejectFindingCandidateResponse(result *findings.RejectCandidateResult) *cerebrov1.RejectFindingCandidateResponse {
	if result == nil {
		return &cerebrov1.RejectFindingCandidateResponse{}
	}
	return &cerebrov1.RejectFindingCandidateResponse{
		Candidate:  safeFindingCandidateMessage(result.Candidate),
		DecisionId: result.DecisionID,
	}
}

func safeFindingMessages(findings []*ports.FindingRecord) []*cerebrov1.Finding {
	messages := make([]*cerebrov1.Finding, 0, len(findings))
	for _, finding := range findings {
		messages = append(messages, safeFindingMessage(finding))
	}
	return messages
}

func safeFindingCandidateMessages(candidates []*ports.FindingCandidateRecord) []*cerebrov1.FindingCandidate {
	messages := make([]*cerebrov1.FindingCandidate, 0, len(candidates))
	for _, candidate := range candidates {
		messages = append(messages, safeFindingCandidateMessage(candidate))
	}
	return messages
}

func findingCandidateRunMessage(run *ports.FindingCandidateRun) *cerebrov1.FindingCandidateRun {
	if run == nil {
		return nil
	}
	message := &cerebrov1.FindingCandidateRun{
		Id:              run.ID,
		TenantId:        run.TenantID,
		RuntimeId:       run.RuntimeID,
		RuleId:          run.RuleID,
		Status:          run.Status,
		EventLimit:      run.EventLimit,
		EventsEvaluated: run.EventsEvaluated,
		EventsMatched:   run.EventsMatched,
		Candidates:      run.Candidates,
		Error:           run.Error,
	}
	if !run.StartedAt.IsZero() {
		message.StartedAt = timestamppb.New(run.StartedAt.UTC())
	}
	if !run.FinishedAt.IsZero() {
		message.FinishedAt = timestamppb.New(run.FinishedAt.UTC())
	}
	return message
}

func findingCandidateMessage(candidate *ports.FindingCandidateRecord) *cerebrov1.FindingCandidate {
	if candidate == nil {
		return nil
	}
	message := &cerebrov1.FindingCandidate{
		Id:                 candidate.ID,
		TenantId:           candidate.TenantID,
		RuntimeId:          candidate.RuntimeID,
		RuleId:             candidate.RuleID,
		Fingerprint:        candidate.Fingerprint,
		Status:             candidate.Status,
		Evidence:           candidate.Evidence,
		LastRunId:          candidate.LastRunID,
		ObservationCount:   candidate.ObservationCount,
		PromotedFindingId:  candidate.PromotedFindingID,
		DecisionId:         candidate.DecisionID,
		PromotedBy:         candidate.PromotedBy,
		PromotionRationale: candidate.PromotionRationale,
		ChangeTicket:       candidate.ChangeTicket,
		RejectedBy:         candidate.RejectedBy,
		RejectionRationale: candidate.RejectionRationale,
	}
	if !candidate.FirstObservedAt.IsZero() {
		message.FirstObservedAt = timestamppb.New(candidate.FirstObservedAt.UTC())
	}
	if !candidate.LastObservedAt.IsZero() {
		message.LastObservedAt = timestamppb.New(candidate.LastObservedAt.UTC())
	}
	if !candidate.PromotedAt.IsZero() {
		message.PromotedAt = timestamppb.New(candidate.PromotedAt.UTC())
	}
	if !candidate.RejectedAt.IsZero() {
		message.RejectedAt = timestamppb.New(candidate.RejectedAt.UTC())
	}
	if !candidate.CreatedAt.IsZero() {
		message.CreatedAt = timestamppb.New(candidate.CreatedAt.UTC())
	}
	if !candidate.UpdatedAt.IsZero() {
		message.UpdatedAt = timestamppb.New(candidate.UpdatedAt.UTC())
	}
	return message
}

func safeFindingCandidateMessage(candidate *ports.FindingCandidateRecord) *cerebrov1.FindingCandidate {
	message := findingCandidateMessage(candidate)
	if message == nil {
		return nil
	}
	message.Finding = safeFindingMessage(candidate.Finding)
	message.Evidence = safeFindingEvidenceMessages(candidate.Evidence)
	return message
}

func findingMessage(finding *ports.FindingRecord) *cerebrov1.Finding {
	if finding == nil {
		return nil
	}
	message := &cerebrov1.Finding{
		Id:                finding.ID,
		Fingerprint:       finding.Fingerprint,
		TenantId:          finding.TenantID,
		RuntimeId:         finding.RuntimeID,
		RuleId:            finding.RuleID,
		Title:             finding.Title,
		Severity:          finding.Severity,
		Status:            findingStatusMessage(finding.Status),
		Summary:           finding.Summary,
		ResourceUrns:      append([]string(nil), finding.ResourceURNs...),
		EventIds:          append([]string(nil), finding.EventIDs...),
		ObservedPolicyIds: append([]string(nil), finding.ObservedPolicyIDs...),
		PolicyId:          finding.PolicyID,
		PolicyName:        finding.PolicyName,
		CheckId:           finding.CheckID,
		CheckName:         finding.CheckName,
		ControlRefs:       findingControlRefMessages(finding.ControlRefs),
		Notes:             findingNoteMessages(finding.Notes),
		Tickets:           findingTicketMessages(finding.Tickets),
		ExternalRefs:      findingapi.ExternalRefMessages(finding.ExternalRefs),
		RiskScore:         boundedInt32(finding.RiskScore),
		LikelihoodScore:   boundedInt32(finding.LikelihoodScore),
		ImpactScore:       boundedInt32(finding.ImpactScore),
		ConfidenceScore:   boundedInt32(finding.ConfidenceScore),
		LikelihoodLevel:   finding.LikelihoodLevel,
		ImpactLevel:       finding.ImpactLevel,
		RiskReasons:       append([]string(nil), finding.RiskReasons...),
		RiskModelVersion:  finding.RiskModelVersion,
		RiskFactors:       findingRiskFactorMessages(finding.RiskFactors),
		Attributes:        make(map[string]string, len(finding.Attributes)),
		Assignee:          finding.Assignee,
		StatusReason:      finding.StatusReason,
	}
	for key, value := range finding.Attributes {
		message.Attributes[key] = value
	}
	if !finding.StatusUpdatedAt.IsZero() {
		message.StatusUpdatedAt = timestamppb.New(finding.StatusUpdatedAt)
	}
	if !finding.DueAt.IsZero() {
		message.DueAt = timestamppb.New(finding.DueAt)
	}
	if !finding.FirstObservedAt.IsZero() {
		message.FirstObservedAt = timestamppb.New(finding.FirstObservedAt)
	}
	if !finding.LastObservedAt.IsZero() {
		message.LastObservedAt = timestamppb.New(finding.LastObservedAt)
	}
	return message
}

func safeFindingMessage(finding *ports.FindingRecord) *cerebrov1.Finding {
	message := findingMessage(finding)
	if message == nil {
		return nil
	}
	message.Attributes = redactSensitiveAttributes(message.GetAttributes())
	return message
}

func safeFindingEvidenceMessages(evidence []*cerebrov1.FindingEvidence) []*cerebrov1.FindingEvidence {
	messages := make([]*cerebrov1.FindingEvidence, 0, len(evidence))
	for _, record := range evidence {
		messages = append(messages, safeFindingEvidence(record))
	}
	return messages
}

func safeFindingEvidence(evidence *cerebrov1.FindingEvidence) *cerebrov1.FindingEvidence {
	if evidence == nil {
		return nil
	}
	cloned := proto.Clone(evidence).(*cerebrov1.FindingEvidence)
	cloned.Attributes = redactSensitiveAttributes(cloned.GetAttributes())
	cloned.GraphRows = safeGraphEvidenceRows(cloned.GetGraphRows())
	for _, observation := range cloned.GetObservations() {
		if observation == nil {
			continue
		}
		observation.GraphRows = safeGraphEvidenceRows(observation.GetGraphRows())
	}
	return cloned
}

func safeGraphEvidenceRows(rows []*cerebrov1.GraphEvidenceRow) []*cerebrov1.GraphEvidenceRow {
	if len(rows) == 0 {
		return rows
	}
	safeRows := make([]*cerebrov1.GraphEvidenceRow, 0, len(rows))
	for _, row := range rows {
		if row == nil {
			continue
		}
		cloned := proto.Clone(row).(*cerebrov1.GraphEvidenceRow)
		cloned.Attributes = redactSensitiveAttributes(cloned.GetAttributes())
		for _, path := range cloned.GetPaths() {
			if path == nil {
				continue
			}
			path.Attributes = redactSensitiveAttributes(path.GetAttributes())
		}
		safeRows = append(safeRows, cloned)
	}
	return safeRows
}

func redactSensitiveAttributes(attributes map[string]string) map[string]string {
	if len(attributes) == 0 {
		return attributes
	}
	redacted := make(map[string]string, len(attributes))
	for key, value := range attributes {
		if sensitiveSourceConfigKey(key) {
			redacted[key] = redactedAttributeValue
			continue
		}
		redacted[key] = value
	}
	return redacted
}

func findingRiskFactorMessages(factors []ports.FindingRiskFactor) []*cerebrov1.FindingRiskFactor {
	messages := make([]*cerebrov1.FindingRiskFactor, 0, len(factors))
	for _, factor := range factors {
		message := &cerebrov1.FindingRiskFactor{
			FactorId:             factor.FactorID,
			Weight:               boundedInt32(factor.Weight),
			SeverityContribution: factor.SeverityContribution,
			EvidenceRefs:         append([]string(nil), factor.EvidenceRefs...),
			Category:             factor.Category,
			SuppressionScope:     factor.SuppressionScope,
		}
		if !factor.ObservedAt.IsZero() {
			message.ObservedAt = timestamppb.New(factor.ObservedAt)
		}
		messages = append(messages, message)
	}
	return messages
}

func findingControlRefMessages(values []ports.FindingControlRef) []*cerebrov1.FindingControlRef {
	if len(values) == 0 {
		return nil
	}
	messages := make([]*cerebrov1.FindingControlRef, 0, len(values))
	for _, value := range values {
		frameworkName := strings.TrimSpace(value.FrameworkName)
		controlID := strings.TrimSpace(value.ControlID)
		if frameworkName == "" || controlID == "" {
			continue
		}
		messages = append(messages, &cerebrov1.FindingControlRef{
			FrameworkName: frameworkName,
			ControlId:     controlID,
		})
	}
	return messages
}

func findingNoteMessages(values []ports.FindingNote) []*cerebrov1.FindingNote {
	if len(values) == 0 {
		return nil
	}
	messages := make([]*cerebrov1.FindingNote, 0, len(values))
	for _, value := range values {
		body := strings.TrimSpace(value.Body)
		if body == "" {
			continue
		}
		message := &cerebrov1.FindingNote{
			Id:   strings.TrimSpace(value.ID),
			Body: body,
		}
		if !value.CreatedAt.IsZero() {
			message.CreatedAt = timestamppb.New(value.CreatedAt)
		}
		messages = append(messages, message)
	}
	return messages
}

func findingTicketMessages(values []ports.FindingTicket) []*cerebrov1.FindingTicket {
	if len(values) == 0 {
		return nil
	}
	messages := make([]*cerebrov1.FindingTicket, 0, len(values))
	for _, value := range values {
		url := strings.TrimSpace(value.URL)
		if url == "" {
			continue
		}
		message := &cerebrov1.FindingTicket{
			Url:        url,
			Name:       strings.TrimSpace(value.Name),
			ExternalId: strings.TrimSpace(value.ExternalID),
		}
		if !value.LinkedAt.IsZero() {
			message.LinkedAt = timestamppb.New(value.LinkedAt)
		}
		messages = append(messages, message)
	}
	return messages
}

func findingStatusMessage(status string) cerebrov1.FindingStatus {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "open":
		return cerebrov1.FindingStatus_FINDING_STATUS_OPEN
	case "resolved":
		return cerebrov1.FindingStatus_FINDING_STATUS_RESOLVED
	case "suppressed":
		return cerebrov1.FindingStatus_FINDING_STATUS_SUPPRESSED
	default:
		return cerebrov1.FindingStatus_FINDING_STATUS_UNSPECIFIED
	}
}

func findingStatusString(status cerebrov1.FindingStatus) string {
	switch status {
	case cerebrov1.FindingStatus_FINDING_STATUS_OPEN:
		return "open"
	case cerebrov1.FindingStatus_FINDING_STATUS_RESOLVED:
		return "resolved"
	case cerebrov1.FindingStatus_FINDING_STATUS_SUPPRESSED:
		return "suppressed"
	default:
		return ""
	}
}

func findingOrder(order cerebrov1.FindingOrder) ports.FindingOrder {
	switch order {
	case cerebrov1.FindingOrder_FINDING_ORDER_PRIORITY:
		return ports.FindingOrderPriority
	case cerebrov1.FindingOrder_FINDING_ORDER_RISK_SCORE:
		return ports.FindingOrderRiskScore
	case cerebrov1.FindingOrder_FINDING_ORDER_LAST_OBSERVED:
		return ports.FindingOrderLastObserved
	default:
		return ""
	}
}

func parseFindingStatus(raw string) (cerebrov1.FindingStatus, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "open", "finding_status_open":
		return cerebrov1.FindingStatus_FINDING_STATUS_OPEN, nil
	case "resolved", "finding_status_resolved":
		return cerebrov1.FindingStatus_FINDING_STATUS_RESOLVED, nil
	case "suppressed", "finding_status_suppressed":
		return cerebrov1.FindingStatus_FINDING_STATUS_SUPPRESSED, nil
	default:
		return cerebrov1.FindingStatus_FINDING_STATUS_UNSPECIFIED, fmt.Errorf("%w: unsupported finding status %q", errInvalidHTTPRequest, raw)
	}
}

func parseFindingOrder(raw string) (cerebrov1.FindingOrder, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "last_observed", "finding_order_last_observed":
		return cerebrov1.FindingOrder_FINDING_ORDER_LAST_OBSERVED, nil
	case "priority", "finding_order_priority":
		return cerebrov1.FindingOrder_FINDING_ORDER_PRIORITY, nil
	case "risk_score", "risk", "finding_order_risk_score":
		return cerebrov1.FindingOrder_FINDING_ORDER_RISK_SCORE, nil
	default:
		return cerebrov1.FindingOrder_FINDING_ORDER_UNSPECIFIED, fmt.Errorf("%w: unsupported finding order %q", errInvalidHTTPRequest, raw)
	}
}

func workflowReplayResponse(result *workflowprojection.ReplayResult) *cerebrov1.ReplayWorkflowEventsResponse {
	if result == nil {
		return &cerebrov1.ReplayWorkflowEventsResponse{}
	}
	return &cerebrov1.ReplayWorkflowEventsResponse{
		EventsRead:        result.EventsRead,
		EventsProjected:   result.EventsProjected,
		EntitiesProjected: result.EntitiesProjected,
		LinksProjected:    result.LinksProjected,
		EventsFailed:      result.EventsFailed,
		Errors:            workflowReplayErrors(result.Errors),
	}
}

func workflowReplayErrors(errors []workflowprojection.ReplayError) []*cerebrov1.WorkflowReplayError {
	if len(errors) == 0 {
		return nil
	}
	items := make([]*cerebrov1.WorkflowReplayError, 0, len(errors))
	for _, replayErr := range errors {
		items = append(items, &cerebrov1.WorkflowReplayError{
			EventId: replayErr.EventID,
			Kind:    replayErr.Kind,
			Error:   replayErr.Error,
		})
	}
	return items
}

func graphNeighborhoodResponse(neighborhood *ports.EntityNeighborhood) *cerebrov1.GetEntityNeighborhoodResponse {
	if neighborhood == nil {
		return &cerebrov1.GetEntityNeighborhoodResponse{}
	}
	response := &cerebrov1.GetEntityNeighborhoodResponse{
		Root:      graphEntityMessage(neighborhood.Root),
		Neighbors: make([]*cerebrov1.GraphEntity, 0, len(neighborhood.Neighbors)),
		Relations: make([]*cerebrov1.GraphRelation, 0, len(neighborhood.Relations)),
	}
	for _, neighbor := range neighborhood.Neighbors {
		response.Neighbors = append(response.Neighbors, graphEntityMessage(neighbor))
	}
	for _, relation := range neighborhood.Relations {
		response.Relations = append(response.Relations, graphRelationMessage(relation))
	}
	return response
}

func graphIngestRunResultMessage(result *graphingest.RunResult) *cerebrov1.GraphIngestRunResult {
	if result == nil {
		return &cerebrov1.GraphIngestRunResult{}
	}
	return &cerebrov1.GraphIngestRunResult{
		Run:    graphIngestRunMessage(result.Run),
		Ingest: graphIngestResultMessage(result.Ingest),
	}
}

func graphIngestListResponse(result *graphingest.ListResult) *cerebrov1.ListGraphIngestRunsResponse {
	if result == nil {
		return &cerebrov1.ListGraphIngestRunsResponse{}
	}
	return &cerebrov1.ListGraphIngestRunsResponse{
		Runs:        graphIngestRunMessages(result.Runs),
		FailedCount: result.FailedCount,
	}
}

func graphIngestHealthResponse(result *graphingest.HealthResult) *cerebrov1.CheckGraphIngestHealthResponse {
	if result == nil {
		return &cerebrov1.CheckGraphIngestHealthResponse{}
	}
	return &cerebrov1.CheckGraphIngestHealthResponse{
		Status:       result.Status,
		CheckedAt:    timestamppb.New(result.CheckedAt),
		FailedCount:  result.FailedCount,
		RunningCount: result.RunningCount,
		FailedRuns:   graphIngestRunMessages(result.FailedRuns),
	}
}

func graphIngestRunMessages(runs []graphstore.IngestRun) []*cerebrov1.GraphIngestRun {
	messages := make([]*cerebrov1.GraphIngestRun, 0, len(runs))
	for _, run := range runs {
		messages = append(messages, graphIngestRunMessage(run))
	}
	return messages
}

func graphIngestRunMessage(run graphstore.IngestRun) *cerebrov1.GraphIngestRun {
	return &cerebrov1.GraphIngestRun{
		Id:                run.ID,
		RuntimeId:         run.RuntimeID,
		SourceId:          run.SourceID,
		TenantId:          run.TenantID,
		CheckpointId:      run.CheckpointID,
		Status:            run.Status,
		Trigger:           run.Trigger,
		PagesRead:         run.PagesRead,
		EventsRead:        run.EventsRead,
		EntitiesProjected: run.EntitiesProjected,
		LinksProjected:    run.LinksProjected,
		GraphNodesBefore:  run.GraphNodesBefore,
		GraphLinksBefore:  run.GraphLinksBefore,
		GraphNodesAfter:   run.GraphNodesAfter,
		GraphLinksAfter:   run.GraphLinksAfter,
		StartedAt:         run.StartedAt,
		FinishedAt:        run.FinishedAt,
		Error:             run.Error,
	}
}

func graphIngestResultMessage(result *graphingest.IngestResult) *cerebrov1.GraphIngestResult {
	if result == nil {
		return nil
	}
	return &cerebrov1.GraphIngestResult{
		SourceId:               result.SourceID,
		TenantId:               result.TenantID,
		PagesRead:              result.PagesRead,
		EventsRead:             result.EventsRead,
		EntitiesProjected:      result.EntitiesProjected,
		LinksProjected:         result.LinksProjected,
		GraphNodesBefore:       result.GraphNodesBefore,
		GraphLinksBefore:       result.GraphLinksBefore,
		GraphNodesAfter:        result.GraphNodesAfter,
		GraphLinksAfter:        result.GraphLinksAfter,
		NextCursor:             result.NextCursor,
		CheckpointId:           result.CheckpointID,
		CheckpointCursor:       result.CheckpointCursor,
		CheckpointResumed:      result.CheckpointResumed,
		CheckpointPersisted:    result.CheckpointPersisted,
		CheckpointComplete:     result.CheckpointComplete,
		CheckpointAlreadyFresh: result.CheckpointAlreadyFresh,
	}
}

func graphEntityMessage(node *ports.NeighborhoodNode) *cerebrov1.GraphEntity {
	if node == nil {
		return nil
	}
	return &cerebrov1.GraphEntity{
		Urn:        node.URN,
		EntityType: node.EntityType,
		Label:      node.Label,
	}
}

func graphRelationMessage(relation *ports.NeighborhoodRelation) *cerebrov1.GraphRelation {
	if relation == nil {
		return nil
	}
	return &cerebrov1.GraphRelation{
		FromUrn:  relation.FromURN,
		Relation: relation.Relation,
		ToUrn:    relation.ToURN,
	}
}

type pinger interface {
	Ping(context.Context) error
}

func componentStatus(ctx context.Context, name string, dependency pinger) *cerebrov1.ComponentStatus {
	status := &cerebrov1.ComponentStatus{Name: name, Status: "unconfigured"}
	if dependency == nil || isNilInterface(dependency) {
		return status
	}
	checkCtx, cancel := context.WithTimeout(ctx, healthCheckTimeout)
	defer cancel()
	if err := dependency.Ping(checkCtx); err != nil {
		status.Status = "error"
		status.Detail = "unhealthy"
		return status
	}
	status.Status = "ready"
	return status
}
