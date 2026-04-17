package scan

import (
	"context"
	"log/slog"
	"time"

	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/graph/builders"
	"github.com/writer/cerebro/internal/notifications"
	"github.com/writer/cerebro/internal/policy"
	"github.com/writer/cerebro/internal/scanner"
	"github.com/writer/cerebro/internal/scheduler"
	"github.com/writer/cerebro/internal/warehouse"
	"github.com/writer/cerebro/internal/webhooks"
)

type RetentionCleaner interface {
	CleanupAuditLogs(ctx context.Context, olderThan time.Time) (int64, error)
	CleanupAgentData(ctx context.Context, olderThan time.Time) (sessionsDeleted, messagesDeleted int64, err error)
	CleanupGraphData(ctx context.Context, olderThan time.Time) (pathsDeleted, edgesDeleted, nodesDeleted int64, err error)
	CleanupAccessReviewData(ctx context.Context, olderThan time.Time) (reviewsDeleted, itemsDeleted int64, err error)
}

type Config struct {
	ScanInterval              string
	ScanTables                string
	SecurityDigestInterval    string
	RetentionJobInterval      time.Duration
	AuditRetentionDays        int
	SessionRetentionDays      int
	GraphRetentionDays        int
	AccessReviewRetentionDays int
	ScanTableTimeout          time.Duration
	ScanMaxConcurrent         int
	ScanMinConcurrent         int
	ScanAdaptiveConcurrency   bool
	ScanRetryAttempts         int
	ScanRetryBackoff          time.Duration
	ScanRetryMaxBackoff       time.Duration
}

type QueryPolicyScanResult struct {
	Policies int
	Findings []policy.Finding
	Errors   []string
}

type OrgTopologyPolicyScanResult struct {
	Assets   int
	Findings []policy.Finding
	Errors   []string
}

type APISurfaceFindingScanResult struct {
	Endpoints int
	Findings  []policy.Finding
	Errors    []string
}

type GraphAnalysisSummary struct {
	GraphToxicCount         int
	GraphPaths              int
	OrgTopologyFindingCount int
	OrgTopologyErrorCount   int
	APISurfaceFindingCount  int
	APISurfaceErrorCount    int
}

type Dependencies struct {
	Logger                           func() *slog.Logger
	Config                           func() *Config
	SchedulerGetter                  func() *scheduler.Scheduler
	SchedulerSetter                  func(*scheduler.Scheduler)
	Warehouse                        func() warehouse.DataWarehouse
	Policy                           func() *policy.Engine
	Findings                         func() findings.FindingStore
	Scanner                          func() *scanner.Scanner
	Notifications                    func() *notifications.Manager
	Webhooks                         func() *webhooks.Service
	SecurityGraphBuilder             func() *builders.Builder
	RetentionRepo                    func() RetentionCleaner
	ScanWatermarks                   func() *scanner.WatermarkStore
	AvailableTables                  func() []string
	SetAvailableTables               func([]string)
	GraphRebuildInterval             func() time.Duration
	CurrentLiveSecurityGraph         func() *graph.Graph
	WaitForGraph                     func(context.Context) bool
	CurrentOrStoredSecurityGraphView func() (*graph.Graph, error)
	ApplySecurityGraphChanges        func(context.Context, string) (graph.GraphMutationSummary, error)
	UpsertFindingAndRemediate        func(context.Context, policy.Finding) *findings.Finding
	ScanAndPersistDSPMFindings       func(context.Context, string, []map[string]interface{}) int64
	ScanQueryPolicies                func(context.Context) QueryPolicyScanResult
	ScanOrgTopologyPolicies          func(context.Context) OrgTopologyPolicyScanResult
	ScanAPISurfaceFindings           func(context.Context) APISurfaceFindingScanResult
}

type Runtime struct {
	deps Dependencies
}

func NewRuntime(deps Dependencies) *Runtime {
	return &Runtime{deps: deps}
}

func (r *Runtime) logger() *slog.Logger {
	if r == nil || r.deps.Logger == nil {
		return slog.Default()
	}
	if logger := r.deps.Logger(); logger != nil {
		return logger
	}
	return slog.Default()
}

func (r *Runtime) config() *Config {
	if r == nil || r.deps.Config == nil {
		return nil
	}
	return r.deps.Config()
}

func (r *Runtime) Scheduler() *scheduler.Scheduler {
	if r == nil || r.deps.SchedulerGetter == nil {
		return nil
	}
	return r.deps.SchedulerGetter()
}

func (r *Runtime) SetScheduler(s *scheduler.Scheduler) {
	if r == nil || r.deps.SchedulerSetter == nil {
		return
	}
	r.deps.SchedulerSetter(s)
}

func (r *Runtime) warehouse() warehouse.DataWarehouse {
	if r == nil || r.deps.Warehouse == nil {
		return nil
	}
	return r.deps.Warehouse()
}

func (r *Runtime) policy() *policy.Engine {
	if r == nil || r.deps.Policy == nil {
		return nil
	}
	return r.deps.Policy()
}

func (r *Runtime) findingsStore() findings.FindingStore {
	if r == nil || r.deps.Findings == nil {
		return nil
	}
	return r.deps.Findings()
}

func (r *Runtime) scanner() *scanner.Scanner {
	if r == nil || r.deps.Scanner == nil {
		return nil
	}
	return r.deps.Scanner()
}

func (r *Runtime) notifications() *notifications.Manager {
	if r == nil || r.deps.Notifications == nil {
		return nil
	}
	return r.deps.Notifications()
}

func (r *Runtime) webhooks() *webhooks.Service {
	if r == nil || r.deps.Webhooks == nil {
		return nil
	}
	return r.deps.Webhooks()
}

func (r *Runtime) securityGraphBuilder() *builders.Builder {
	if r == nil || r.deps.SecurityGraphBuilder == nil {
		return nil
	}
	return r.deps.SecurityGraphBuilder()
}

func (r *Runtime) retentionRepo() RetentionCleaner {
	if r == nil || r.deps.RetentionRepo == nil {
		return nil
	}
	return r.deps.RetentionRepo()
}

func (r *Runtime) scanWatermarks() *scanner.WatermarkStore {
	if r == nil || r.deps.ScanWatermarks == nil {
		return nil
	}
	return r.deps.ScanWatermarks()
}

func (r *Runtime) availableTables() []string {
	if r == nil || r.deps.AvailableTables == nil {
		return nil
	}
	tables := r.deps.AvailableTables()
	if len(tables) == 0 {
		return nil
	}
	return append([]string(nil), tables...)
}

func (r *Runtime) setAvailableTables(tables []string) {
	if r == nil || r.deps.SetAvailableTables == nil {
		return
	}
	if len(tables) == 0 {
		r.deps.SetAvailableTables(nil)
		return
	}
	r.deps.SetAvailableTables(append([]string(nil), tables...))
}

func (r *Runtime) graphRebuildInterval() time.Duration {
	if r == nil || r.deps.GraphRebuildInterval == nil {
		return time.Hour
	}
	if interval := r.deps.GraphRebuildInterval(); interval > 0 {
		return interval
	}
	return time.Hour
}

func (r *Runtime) currentLiveSecurityGraph() *graph.Graph {
	if r == nil || r.deps.CurrentLiveSecurityGraph == nil {
		return nil
	}
	return r.deps.CurrentLiveSecurityGraph()
}

func (r *Runtime) waitForGraph(ctx context.Context) bool {
	if r == nil || r.deps.WaitForGraph == nil {
		return false
	}
	return r.deps.WaitForGraph(ctx)
}

func (r *Runtime) currentOrStoredSecurityGraphView() (*graph.Graph, error) {
	if r == nil || r.deps.CurrentOrStoredSecurityGraphView == nil {
		return nil, nil
	}
	return r.deps.CurrentOrStoredSecurityGraphView()
}

func (r *Runtime) applySecurityGraphChanges(ctx context.Context, trigger string) (graph.GraphMutationSummary, error) {
	if r == nil || r.deps.ApplySecurityGraphChanges == nil {
		return graph.GraphMutationSummary{}, nil
	}
	return r.deps.ApplySecurityGraphChanges(ctx, trigger)
}

func (r *Runtime) upsertFindingAndRemediate(ctx context.Context, finding policy.Finding) *findings.Finding {
	if r == nil || r.deps.UpsertFindingAndRemediate == nil {
		return nil
	}
	return r.deps.UpsertFindingAndRemediate(ctx, finding)
}

func (r *Runtime) scanAndPersistDSPMFindings(ctx context.Context, table string, assets []map[string]interface{}) int64 {
	if r == nil || r.deps.ScanAndPersistDSPMFindings == nil {
		return 0
	}
	return r.deps.ScanAndPersistDSPMFindings(ctx, table, assets)
}

func (r *Runtime) scanQueryPolicies(ctx context.Context) QueryPolicyScanResult {
	if r == nil || r.deps.ScanQueryPolicies == nil {
		return QueryPolicyScanResult{}
	}
	return r.deps.ScanQueryPolicies(ctx)
}

func (r *Runtime) scanOrgTopologyPolicies(ctx context.Context) OrgTopologyPolicyScanResult {
	if r == nil || r.deps.ScanOrgTopologyPolicies == nil {
		return OrgTopologyPolicyScanResult{}
	}
	return r.deps.ScanOrgTopologyPolicies(ctx)
}

func (r *Runtime) scanAPISurfaceFindings(ctx context.Context) APISurfaceFindingScanResult {
	if r == nil || r.deps.ScanAPISurfaceFindings == nil {
		return APISurfaceFindingScanResult{}
	}
	return r.deps.ScanAPISurfaceFindings(ctx)
}
