package api

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/writer/cerebro/internal/agents"
	"github.com/writer/cerebro/internal/apiauth"
	"github.com/writer/cerebro/internal/app"
	"github.com/writer/cerebro/internal/attackpath"
	"github.com/writer/cerebro/internal/auth"
	"github.com/writer/cerebro/internal/cache"
	"github.com/writer/cerebro/internal/executionstore"
	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/graph/builders"
	"github.com/writer/cerebro/internal/graphingest"
	"github.com/writer/cerebro/internal/health"
	"github.com/writer/cerebro/internal/identity"
	"github.com/writer/cerebro/internal/lineage"
	"github.com/writer/cerebro/internal/notifications"
	"github.com/writer/cerebro/internal/policy"
	"github.com/writer/cerebro/internal/postgres"
	"github.com/writer/cerebro/internal/providers"
	"github.com/writer/cerebro/internal/remediation"
	"github.com/writer/cerebro/internal/runtime"
	"github.com/writer/cerebro/internal/scanner"
	"github.com/writer/cerebro/internal/scheduler"
	"github.com/writer/cerebro/internal/snowflake"
	"github.com/writer/cerebro/internal/threatintel"
	"github.com/writer/cerebro/internal/ticketing"
	"github.com/writer/cerebro/internal/warehouse"
	"github.com/writer/cerebro/internal/webhooks"
)

var errManagedAPICredentialsUnavailable = errors.New("managed api credentials unavailable")

type graphRuntimeService interface {
	CurrentSecurityGraph() *graph.Graph
	CurrentSecurityGraphStore() graph.GraphStore
	CurrentSecurityGraphStoreForTenant(tenantID string) graph.GraphStore
	GraphBuildSnapshot() app.GraphBuildSnapshot
	CurrentRetentionStatus() app.RetentionStatus
	GraphFreshnessStatusSnapshot(now time.Time) app.GraphFreshnessStatus
	RebuildSecurityGraph(ctx context.Context) error
	TryApplySecurityGraphChanges(ctx context.Context, trigger string) (graph.GraphMutationSummary, bool, error)
}

type graphChangeApplyCapability interface {
	CanApplySecurityGraphChanges() bool
}

type apiCredentialService interface {
	APICredentialsSnapshot() map[string]apiauth.Credential
	APIKeysSnapshot() map[string]string
	LookupAPICredential(key string) (apiauth.Credential, bool)
	ManagedAPICredentials() []apiauth.ManagedCredentialRecord
	CreateManagedAPICredential(spec apiauth.ManagedCredentialSpec, now time.Time) (apiauth.ManagedCredentialRecord, string, error)
	RotateManagedAPICredential(id string, now time.Time) (apiauth.ManagedCredentialRecord, string, error)
	RevokeManagedAPICredential(id, reason string, now time.Time) (apiauth.ManagedCredentialRecord, error)
}

type agentSDKToolService interface {
	AgentSDKTools() []agents.Tool
}

type graphMutationService interface {
	MutateSecurityGraph(ctx context.Context, mutate func(*graph.Graph) error) (*graph.Graph, error)
}

// serverDependencies narrows API wiring down to the concrete services and small
// behavioral interfaces the HTTP layer actually consumes.
type serverDependencies struct {
	Config *app.Config
	Logger *slog.Logger

	Snowflake      *snowflake.Client
	Warehouse      warehouse.DataWarehouse
	PostgresClient *postgres.PostgresClient
	Policy         *policy.Engine
	Findings       findings.FindingStore
	Scanner        *scanner.Scanner
	Cache          *cache.PolicyCache
	ExecutionStore executionstore.Store
	GraphSnapshots *graph.GraphPersistenceStore

	Agents         *agents.AgentRegistry
	Ticketing      *ticketing.Service
	Identity       *identity.Service
	AttackPath     *attackpath.Graph
	Providers      *providers.Registry
	Webhooks       *webhooks.Service
	TapEventMapper *graphingest.Mapper
	Notifications  *notifications.Manager
	Scheduler      *scheduler.Scheduler

	AuditRepo interface {
		Log(ctx context.Context, entry *snowflake.AuditEntry) error
		List(ctx context.Context, resourceType, resourceID string, limit int) ([]*snowflake.AuditEntry, error)
	}
	PolicyHistoryRepo interface {
		Upsert(ctx context.Context, record *snowflake.PolicyHistoryRecord) error
		List(ctx context.Context, policyID string, limit int) ([]*snowflake.PolicyHistoryRecord, error)
	}
	RiskEngineStateRepo interface {
		SaveSnapshot(ctx context.Context, graphID string, snapshot []byte) error
		LoadSnapshot(ctx context.Context, graphID string) ([]byte, error)
	}
	ScanWatermarks *scanner.WatermarkStore

	RBAC           *auth.RBAC
	ThreatIntel    *threatintel.ThreatIntelService
	Health         *health.Registry
	Lineage        *lineage.LineageMapper
	Remediation    *remediation.Engine
	RuntimeDetect  *runtime.DetectionEngine
	RuntimeIngest  runtime.IngestStore
	RuntimeRespond *runtime.ResponseEngine

	RemediationExecutor *remediation.Executor

	SecurityGraph        *graph.Graph
	SecurityGraphBuilder *builders.Builder
	entitySearchBackend  graph.EntitySearchBackend

	graphRuntime          graphRuntimeService
	graphMutator          graphMutationService
	graphRuleDiscovery    graphRuleDiscoveryService
	graphSimulation       graphSimulationService
	apiCredentials        apiCredentialService
	agentSDKToolSource    agentSDKToolService
	agentSDKAdmin         agentSDKAdminService
	entitiesImpact        entitiesImpactService
	graphAdvisory         graphAdvisoryService
	graphWriteback        graphWritebackService
	lineage               lineageService
	orgAnalysis           orgAnalysisService
	orgPolicies           orgPolicyService
	forensics             forensicsService
	platformExecutions    platformExecutionService
	platformScanAudit     platformScanAuditService
	platformKnowledge     platformKnowledgeService
	platformWorkloadScan  platformWorkloadScanService
	rbacAdmin             rbacAdminService
	remediationOperations remediationOperationsService
	schedulerOperations   schedulerOperationsService
	syncHandlers          syncHandlerService
	ticketingOps          ticketingService
	threatRuntime         threatRuntimeService
}

type graphRuntimeAdapter struct {
	deps            *serverDependencies
	delegate        graphRuntimeService
	logger          *slog.Logger
	originalGraph   *graph.Graph
	originalBuilder *builders.Builder

	updateMu   sync.Mutex
	snapshotMu sync.RWMutex
	snapshot   app.GraphBuildSnapshot
}

func newServerDependenciesFromApp(application *app.App) serverDependencies {
	if application == nil {
		return serverDependencies{}
	}
	deps := serverDependencies{
		Config:               application.Config,
		Logger:               application.Logger,
		Snowflake:            application.Snowflake,
		Warehouse:            application.Warehouse,
		PostgresClient:       application.PostgresClient,
		Policy:               application.Policy,
		Findings:             application.Findings,
		Scanner:              application.Scanner,
		Cache:                application.Cache,
		ExecutionStore:       application.ExecutionStore,
		GraphSnapshots:       application.GraphSnapshots,
		Agents:               application.Agents,
		Ticketing:            application.Ticketing,
		Identity:             application.Identity,
		AttackPath:           application.AttackPath,
		Providers:            application.Providers,
		Webhooks:             application.Webhooks,
		TapEventMapper:       application.TapEventMapper,
		Notifications:        application.Notifications,
		Scheduler:            application.Scheduler,
		AuditRepo:            application.AuditRepo,
		PolicyHistoryRepo:    application.PolicyHistoryRepo,
		RiskEngineStateRepo:  application.RiskEngineStateRepo,
		ScanWatermarks:       application.ScanWatermarks,
		RBAC:                 application.RBAC,
		ThreatIntel:          application.ThreatIntel,
		Health:               application.Health,
		Lineage:              application.Lineage,
		Remediation:          application.Remediation,
		RemediationExecutor:  application.RemediationExecutor,
		RuntimeDetect:        application.RuntimeDetect,
		RuntimeIngest:        application.RuntimeIngest,
		RuntimeRespond:       application.RuntimeRespond,
		SecurityGraph:        application.SecurityGraph,
		SecurityGraphBuilder: application.SecurityGraphBuilder,
		graphMutator:         application,
		apiCredentials:       application,
		entitySearchBackend:  application.CurrentEntitySearchBackend(),
		agentSDKToolSource:   application,
	}
	deps.graphRuntime = &graphRuntimeAdapter{
		deps:            &deps,
		delegate:        application,
		logger:          application.Logger,
		originalGraph:   application.SecurityGraph,
		originalBuilder: application.SecurityGraphBuilder,
	}
	return deps
}

func (d serverDependencies) CurrentSecurityGraph() *graph.Graph {
	if d.graphRuntime != nil {
		if g := d.graphRuntime.CurrentSecurityGraph(); g != nil {
			return g
		}
	}
	return d.SecurityGraph
}

func (d serverDependencies) CurrentSecurityGraphStore() graph.GraphStore {
	if d.graphRuntime != nil {
		if store := d.graphRuntime.CurrentSecurityGraphStore(); store != nil {
			return store
		}
	}
	if d.SecurityGraph != nil {
		return d.SecurityGraph
	}
	return nil
}

func (d serverDependencies) CurrentSecurityGraphForTenant(tenantID string) *graph.Graph {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return d.CurrentSecurityGraph()
	}
	if scoped, ok := d.graphRuntime.(interface {
		CurrentSecurityGraphForTenant(string) *graph.Graph
	}); ok {
		if g := scoped.CurrentSecurityGraphForTenant(tenantID); g != nil {
			return g
		}
	}
	current := d.CurrentSecurityGraph()
	if current == nil {
		return nil
	}
	return current.SubgraphForTenant(tenantID)
}

func (d serverDependencies) CurrentSecurityGraphStoreForTenant(tenantID string) graph.GraphStore {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return d.CurrentSecurityGraphStore()
	}
	if d.graphRuntime != nil {
		if store := d.graphRuntime.CurrentSecurityGraphStoreForTenant(tenantID); store != nil {
			return store
		}
	}
	if scoped := d.CurrentSecurityGraphForTenant(tenantID); scoped != nil {
		return scoped
	}
	return nil
}

func (d serverDependencies) GraphBuildSnapshot() app.GraphBuildSnapshot {
	if d.graphRuntime == nil {
		return app.GraphBuildSnapshot{}
	}
	return d.graphRuntime.GraphBuildSnapshot()
}

func (d serverDependencies) CurrentRetentionStatus() app.RetentionStatus {
	if d.graphRuntime == nil {
		return app.RetentionStatus{}
	}
	return d.graphRuntime.CurrentRetentionStatus()
}

func (d serverDependencies) GraphFreshnessStatusSnapshot(now time.Time) app.GraphFreshnessStatus {
	if d.graphRuntime == nil {
		return app.GraphFreshnessStatus{}
	}
	return d.graphRuntime.GraphFreshnessStatusSnapshot(now)
}

func (d serverDependencies) GraphHealthSnapshot(now time.Time) app.GraphHealthSnapshot {
	if runtime, ok := d.graphRuntime.(interface {
		GraphHealthSnapshot(time.Time) app.GraphHealthSnapshot
	}); ok {
		return runtime.GraphHealthSnapshot(now)
	}

	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	snapshot := app.GraphHealthSnapshot{
		EvaluatedAt: now,
		WriterLease: app.GraphWriterLeaseStatus{Enabled: false, Role: app.GraphWriterRoleDisabled},
	}
	if current := d.CurrentSecurityGraph(); current != nil {
		snapshot.NodeCount = current.NodeCount()
		snapshot.EdgeCount = current.EdgeCount()
		if snapshot.NodeCount > 0 {
			snapshot.TierDistribution.Hot = 1
		}
	}
	if d.GraphSnapshots != nil {
		if records, err := d.GraphSnapshots.ListGraphSnapshotRecords(); err == nil {
			snapshot.SnapshotCount = len(records)
			snapshot.TierDistribution.Cold = len(records)
		}
	}
	if snapshot.NodeCount > 0 || snapshot.EdgeCount > 0 {
		snapshot.MemoryUsageEstimateBytes = app.EstimateGraphMemoryUsageBytes(snapshot.NodeCount, snapshot.EdgeCount)
	}
	return snapshot
}

func (d serverDependencies) RebuildSecurityGraph(ctx context.Context) error {
	if d.graphRuntime == nil {
		return errors.New("security graph runtime not configured")
	}
	return d.graphRuntime.RebuildSecurityGraph(ctx)
}

func (d serverDependencies) CanApplySecurityGraphChanges() bool {
	if capable, ok := d.graphRuntime.(graphChangeApplyCapability); ok {
		return capable.CanApplySecurityGraphChanges()
	}
	if d.graphRuntime != nil {
		return true
	}
	return d.SecurityGraphBuilder != nil
}

func (d serverDependencies) TryApplySecurityGraphChanges(ctx context.Context, trigger string) (graph.GraphMutationSummary, bool, error) {
	if d.graphRuntime == nil {
		return graph.GraphMutationSummary{}, false, errors.New("security graph runtime not configured")
	}
	return d.graphRuntime.TryApplySecurityGraphChanges(ctx, trigger)
}

func (d serverDependencies) MutateSecurityGraph(ctx context.Context, mutate func(*graph.Graph) error) (*graph.Graph, error) {
	if d.graphMutator == nil {
		return nil, errors.New("security graph runtime not configured")
	}
	return d.graphMutator.MutateSecurityGraph(ctx, mutate)
}

func (d serverDependencies) PlatformGraphSnapshotStore() *graph.GraphPersistenceStore {
	if d.GraphSnapshots != nil {
		return d.GraphSnapshots
	}
	snapshotPath := strings.TrimSpace(os.Getenv("GRAPH_SNAPSHOT_PATH"))
	maxSnapshots := 10
	if d.Config != nil {
		if configured := strings.TrimSpace(d.Config.GraphSnapshotPath); configured != "" {
			snapshotPath = configured
		}
		if d.Config.GraphSnapshotMaxRetained > 0 {
			maxSnapshots = d.Config.GraphSnapshotMaxRetained
		}
	}
	if snapshotPath == "" {
		snapshotPath = filepath.Join(".cerebro", "graph-snapshots")
	}
	store, err := graph.NewGraphPersistenceStore(graph.GraphPersistenceOptions{
		LocalPath:    snapshotPath,
		MaxSnapshots: maxSnapshots,
	})
	if err != nil {
		return nil
	}
	return store
}

func (d serverDependencies) APICredentialsSnapshot() map[string]apiauth.Credential {
	if d.apiCredentials == nil {
		return map[string]apiauth.Credential{}
	}
	return d.apiCredentials.APICredentialsSnapshot()
}

func (d serverDependencies) APIKeysSnapshot() map[string]string {
	if d.apiCredentials == nil {
		return map[string]string{}
	}
	return d.apiCredentials.APIKeysSnapshot()
}

func (d serverDependencies) LookupAPICredential(key string) (apiauth.Credential, bool) {
	if d.apiCredentials == nil {
		return apiauth.Credential{}, false
	}
	return d.apiCredentials.LookupAPICredential(key)
}

func (d serverDependencies) ManagedAPICredentials() []apiauth.ManagedCredentialRecord {
	if d.apiCredentials == nil {
		return nil
	}
	return d.apiCredentials.ManagedAPICredentials()
}

func (d serverDependencies) CreateManagedAPICredential(spec apiauth.ManagedCredentialSpec, now time.Time) (apiauth.ManagedCredentialRecord, string, error) {
	if d.apiCredentials == nil {
		return apiauth.ManagedCredentialRecord{}, "", errManagedAPICredentialsUnavailable
	}
	return d.apiCredentials.CreateManagedAPICredential(spec, now)
}

func (d serverDependencies) RotateManagedAPICredential(id string, now time.Time) (apiauth.ManagedCredentialRecord, string, error) {
	if d.apiCredentials == nil {
		return apiauth.ManagedCredentialRecord{}, "", errManagedAPICredentialsUnavailable
	}
	return d.apiCredentials.RotateManagedAPICredential(id, now)
}

func (d serverDependencies) RevokeManagedAPICredential(id, reason string, now time.Time) (apiauth.ManagedCredentialRecord, error) {
	if d.apiCredentials == nil {
		return apiauth.ManagedCredentialRecord{}, errManagedAPICredentialsUnavailable
	}
	return d.apiCredentials.RevokeManagedAPICredential(id, reason, now)
}

func (d serverDependencies) AgentSDKTools() []agents.Tool {
	if d.agentSDKToolSource == nil {
		return nil
	}
	return d.agentSDKToolSource.AgentSDKTools()
}

func (r *graphRuntimeAdapter) useLocalGraph() bool {
	if r == nil || r.deps == nil {
		return false
	}
	if r.delegate != nil {
		return r.originalBuilder == nil && r.deps.SecurityGraphBuilder != nil && (r.deps.SecurityGraph != nil || r.deps.SecurityGraphBuilder != nil)
	}
	return r.deps.SecurityGraph != nil || r.deps.SecurityGraphBuilder != nil
}

func (r *graphRuntimeAdapter) CurrentSecurityGraph() *graph.Graph {
	if r == nil {
		return nil
	}
	if local := r.detachedLocalGraph(); local != nil {
		return local
	}
	if r.useLocalGraph() && r.deps != nil {
		return r.deps.SecurityGraph
	}
	if r.delegate != nil {
		return r.delegate.CurrentSecurityGraph()
	}
	if r.deps != nil {
		return r.deps.SecurityGraph
	}
	return nil
}

func (r *graphRuntimeAdapter) CurrentSecurityGraphStore() graph.GraphStore {
	if r == nil {
		return nil
	}
	if local := r.detachedLocalGraph(); local != nil {
		return local
	}
	if r.useLocalGraph() && r.deps != nil && r.deps.SecurityGraph != nil {
		return r.deps.SecurityGraph
	}
	if scoped, ok := r.delegate.(interface {
		CurrentSecurityGraphStore() graph.GraphStore
	}); ok {
		return scoped.CurrentSecurityGraphStore()
	}
	return r.CurrentSecurityGraph()
}

func (r *graphRuntimeAdapter) CurrentSecurityGraphForTenant(tenantID string) *graph.Graph {
	if local := r.detachedLocalGraph(); local != nil {
		return local.SubgraphForTenant(tenantID)
	}
	if r.useLocalGraph() && r.deps != nil {
		if r.deps.SecurityGraph == nil {
			return nil
		}
		return r.deps.SecurityGraph.SubgraphForTenant(tenantID)
	}
	if scoped, ok := r.delegate.(interface {
		CurrentSecurityGraphForTenant(string) *graph.Graph
	}); ok {
		return scoped.CurrentSecurityGraphForTenant(tenantID)
	}
	current := r.CurrentSecurityGraph()
	if current == nil {
		return nil
	}
	return current.SubgraphForTenant(tenantID)
}

func (r *graphRuntimeAdapter) CurrentSecurityGraphStoreForTenant(tenantID string) graph.GraphStore {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return r.CurrentSecurityGraphStore()
	}
	if local := r.detachedLocalGraph(); local != nil {
		return local.SubgraphForTenant(tenantID)
	}
	if r.useLocalGraph() && r.deps != nil {
		if r.deps.SecurityGraph == nil {
			return nil
		}
		return r.deps.SecurityGraph.SubgraphForTenant(tenantID)
	}
	if scoped, ok := r.delegate.(interface {
		CurrentSecurityGraphStoreForTenant(string) graph.GraphStore
	}); ok {
		return scoped.CurrentSecurityGraphStoreForTenant(tenantID)
	}
	if current := r.CurrentSecurityGraphForTenant(tenantID); current != nil {
		return current
	}
	return nil
}

func (r *graphRuntimeAdapter) GraphBuildSnapshot() app.GraphBuildSnapshot {
	if r == nil {
		return app.GraphBuildSnapshot{}
	}
	if !r.useLocalGraph() && r.delegate != nil {
		return r.delegate.GraphBuildSnapshot()
	}
	r.snapshotMu.RLock()
	snapshot := r.snapshot
	r.snapshotMu.RUnlock()
	if current := r.CurrentSecurityGraph(); current != nil {
		snapshot.NodeCount = current.NodeCount()
	}
	return snapshot
}

func (r *graphRuntimeAdapter) CurrentRetentionStatus() app.RetentionStatus {
	if r == nil || r.delegate == nil {
		return app.RetentionStatus{}
	}
	return r.delegate.CurrentRetentionStatus()
}

func (r *graphRuntimeAdapter) GraphFreshnessStatusSnapshot(now time.Time) app.GraphFreshnessStatus {
	if r == nil || r.delegate == nil {
		return app.GraphFreshnessStatus{}
	}
	return r.delegate.GraphFreshnessStatusSnapshot(now)
}

func (r *graphRuntimeAdapter) GraphHealthSnapshot(now time.Time) app.GraphHealthSnapshot {
	if r == nil {
		return app.GraphHealthSnapshot{}
	}
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	if provider, ok := r.delegate.(interface {
		GraphHealthSnapshot(time.Time) app.GraphHealthSnapshot
	}); ok {
		snapshot := provider.GraphHealthSnapshot(now)
		if current := r.CurrentSecurityGraph(); current != nil {
			snapshot.NodeCount = current.NodeCount()
			snapshot.EdgeCount = current.EdgeCount()
			if snapshot.TierDistribution.Hot == 0 && snapshot.NodeCount > 0 {
				snapshot.TierDistribution.Hot = 1
			}
		}
		snapshot.MemoryUsageEstimateBytes = app.EstimateGraphMemoryUsageBytes(snapshot.NodeCount, snapshot.EdgeCount)
		if builder := r.localBuilder(); builder != nil {
			if last := builder.LastMutation().Until; !last.IsZero() {
				snapshot.LastMutationAt = last.UTC()
			}
		}
		return snapshot
	}

	snapshot := app.GraphHealthSnapshot{
		EvaluatedAt: now,
		WriterLease: app.GraphWriterLeaseStatus{Enabled: false, Role: app.GraphWriterRoleDisabled},
	}
	if current := r.CurrentSecurityGraph(); current != nil {
		snapshot.NodeCount = current.NodeCount()
		snapshot.EdgeCount = current.EdgeCount()
		if snapshot.NodeCount > 0 {
			snapshot.TierDistribution.Hot = 1
		}
		snapshot.MemoryUsageEstimateBytes = app.EstimateGraphMemoryUsageBytes(snapshot.NodeCount, snapshot.EdgeCount)
	}
	if builder := r.localBuilder(); builder != nil {
		if last := builder.LastMutation().Until; !last.IsZero() {
			snapshot.LastMutationAt = last.UTC()
		}
	}
	return snapshot
}

func (r *graphRuntimeAdapter) RebuildSecurityGraph(ctx context.Context) error {
	if r == nil {
		return errors.New("security graph runtime not configured")
	}
	if !r.useLocalGraph() && r.delegate != nil {
		err := r.delegate.RebuildSecurityGraph(ctx)
		if r.deps != nil {
			r.deps.SecurityGraph = r.delegate.CurrentSecurityGraph()
		}
		return err
	}
	builder := r.localBuilder()
	if builder == nil {
		return errors.New("security graph not initialized")
	}

	r.updateMu.Lock()
	defer r.updateMu.Unlock()

	r.setSnapshot(app.GraphBuildBuilding, time.Time{}, nil)
	if err := builder.Build(ctx); err != nil {
		r.setSnapshot(app.GraphBuildFailed, time.Now().UTC(), err)
		return err
	}
	graphValue := builder.Graph()
	if r.deps != nil {
		r.deps.SecurityGraph = graphValue
	}
	builtAt := time.Now().UTC()
	if graphValue != nil {
		builtAt = graphValue.Metadata().BuiltAt
	}
	r.setSnapshot(app.GraphBuildSuccess, builtAt, nil)
	return nil
}

func (r *graphRuntimeAdapter) CanApplySecurityGraphChanges() bool {
	if r == nil {
		return false
	}
	if r.useLocalGraph() {
		return r.localBuilder() != nil
	}
	if capable, ok := r.delegate.(graphChangeApplyCapability); ok {
		return capable.CanApplySecurityGraphChanges()
	}
	return r.originalBuilder != nil
}

func (r *graphRuntimeAdapter) TryApplySecurityGraphChanges(ctx context.Context, trigger string) (graph.GraphMutationSummary, bool, error) {
	if r == nil {
		return graph.GraphMutationSummary{}, false, errors.New("security graph runtime not configured")
	}
	if !r.useLocalGraph() && r.delegate != nil {
		summary, applied, err := r.delegate.TryApplySecurityGraphChanges(ctx, trigger)
		if r.deps != nil {
			r.deps.SecurityGraph = r.delegate.CurrentSecurityGraph()
		}
		return summary, applied, err
	}
	builder := r.localBuilder()
	if builder == nil {
		return graph.GraphMutationSummary{}, false, errors.New("security graph not initialized")
	}
	if !r.updateMu.TryLock() {
		return graph.GraphMutationSummary{}, false, nil
	}
	defer r.updateMu.Unlock()

	summary, err := builder.ApplyChanges(ctx, time.Time{})
	if err != nil {
		if r.logger != nil {
			r.logger.Warn("incremental graph apply failed",
				"trigger", trigger,
				"error", err,
			)
		}
		r.setSnapshot(app.GraphBuildFailed, time.Now().UTC(), err)
		return graph.GraphMutationSummary{}, true, err
	}

	if r.deps != nil {
		r.deps.SecurityGraph = builder.Graph()
	}
	current := r.CurrentSecurityGraph()
	builtAt := time.Time{}
	if current != nil {
		builtAt = current.Metadata().BuiltAt
	}
	r.setSnapshot(app.GraphBuildSuccess, builtAt, nil)
	return summary, true, nil
}

func (r *graphRuntimeAdapter) localBuilder() *builders.Builder {
	if r == nil || r.deps == nil {
		return nil
	}
	return r.deps.SecurityGraphBuilder
}

func (r *graphRuntimeAdapter) setSnapshot(state app.GraphBuildState, builtAt time.Time, err error) {
	if r == nil {
		return
	}
	r.snapshotMu.Lock()
	defer r.snapshotMu.Unlock()
	r.snapshot.State = state
	if !builtAt.IsZero() {
		r.snapshot.LastBuildAt = builtAt.UTC()
	}
	if err != nil {
		r.snapshot.LastError = err.Error()
	} else {
		r.snapshot.LastError = ""
	}
}

func (r *graphRuntimeAdapter) detachedLocalGraph() *graph.Graph {
	if r == nil || r.deps == nil || r.deps.SecurityGraph == nil || r.deps.SecurityGraphBuilder == nil {
		return nil
	}
	if r.delegate != nil && r.originalBuilder != nil {
		return nil
	}
	return r.deps.SecurityGraph
}
