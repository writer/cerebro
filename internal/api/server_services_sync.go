package api

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/app"
	"github.com/writer/cerebro/internal/graph"
	nativesync "github.com/writer/cerebro/internal/sync"
	"github.com/writer/cerebro/internal/warehouse"
)

var errSyncWarehouseUnavailable = errors.New("warehouse not configured")

type syncRunner interface {
	RunAzure(ctx context.Context, req azureSyncRequest) ([]nativesync.SyncResult, error)
	RunK8s(ctx context.Context, req k8sSyncRequest) ([]nativesync.SyncResult, error)
	RunAWS(ctx context.Context, req awsSyncRequest) (*awsSyncOutcome, error)
	RunAWSOrg(ctx context.Context, req awsOrgSyncRequest) (*awsOrgSyncOutcome, error)
	RunGCP(ctx context.Context, req gcpSyncRequest) (*gcpSyncOutcome, error)
	RunGCPAsset(ctx context.Context, req gcpAssetSyncRequest) ([]nativesync.SyncResult, error)
}

type syncHandlerService interface {
	BackfillRelationshipIDs(ctx context.Context, batchSize int) (syncBackfillResult, error)
	SyncAzure(ctx context.Context, req azureSyncRequest) (syncRunResult, error)
	SyncK8s(ctx context.Context, req k8sSyncRequest) (syncRunResult, error)
	SyncAWS(ctx context.Context, req awsSyncRequest) (awsSyncRunResult, error)
	SyncAWSOrg(ctx context.Context, req awsOrgSyncRequest) (awsOrgSyncRunResult, error)
	SyncGCP(ctx context.Context, req gcpSyncRequest) (gcpSyncRunResult, error)
	SyncGCPAsset(ctx context.Context, req gcpAssetSyncRequest) (syncRunResult, error)
}

type syncBackfillResult struct {
	Scanned int64 `json:"scanned"`
	Updated int64 `json:"updated"`
	Deleted int64 `json:"deleted"`
	Skipped int64 `json:"skipped"`
}

type syncRunResult struct {
	Results     []nativesync.SyncResult `json:"results"`
	GraphUpdate map[string]any          `json:"graph_update,omitempty"`
}

type awsSyncRunResult struct {
	Results                    []nativesync.SyncResult `json:"results"`
	RelationshipsExtracted     int64                   `json:"relationships_extracted"`
	RelationshipsSkippedReason string                  `json:"relationships_skipped_reason,omitempty"`
	GraphUpdate                map[string]any          `json:"graph_update,omitempty"`
}

type awsOrgSyncRunResult struct {
	Results       []nativesync.SyncResult `json:"results"`
	AccountErrors []string                `json:"account_errors,omitempty"`
	GraphUpdate   map[string]any          `json:"graph_update,omitempty"`
}

type gcpSyncRunResult struct {
	Results                    []nativesync.SyncResult `json:"results"`
	RelationshipsExtracted     int64                   `json:"relationships_extracted"`
	RelationshipsSkippedReason string                  `json:"relationships_skipped_reason,omitempty"`
	GraphUpdate                map[string]any          `json:"graph_update,omitempty"`
}

type serverSyncHandlerService struct {
	deps   *serverDependencies
	runner syncRunner
}

func newSyncHandlerService(deps *serverDependencies) syncHandlerService {
	return serverSyncHandlerService{
		deps:   deps,
		runner: newSyncRunner(deps),
	}
}

func (s serverSyncHandlerService) BackfillRelationshipIDs(ctx context.Context, batchSize int) (syncBackfillResult, error) {
	store, err := s.warehouse()
	if err != nil {
		return syncBackfillResult{}, err
	}
	extractor := nativesync.NewRelationshipExtractor(store, s.logger())
	stats, err := extractor.BackfillNormalizedRelationshipIDs(ctx, batchSize)
	if err != nil {
		return syncBackfillResult{}, err
	}
	return syncBackfillResult{
		Scanned: int64(stats.Scanned),
		Updated: int64(stats.Updated),
		Deleted: int64(stats.Deleted),
		Skipped: int64(stats.Skipped),
	}, nil
}

func (s serverSyncHandlerService) SyncAzure(ctx context.Context, req azureSyncRequest) (syncRunResult, error) {
	if s.runner == nil {
		return syncRunResult{}, errSyncWarehouseUnavailable
	}
	results, err := s.runner.RunAzure(ctx, req)
	if err != nil {
		return syncRunResult{}, err
	}
	return syncRunResult{
		Results:     results,
		GraphUpdate: s.applySecurityGraphUpdateAfterSync(ctx, "azure", req.Validate),
	}, nil
}

func (s serverSyncHandlerService) SyncK8s(ctx context.Context, req k8sSyncRequest) (syncRunResult, error) {
	if s.runner == nil {
		return syncRunResult{}, errSyncWarehouseUnavailable
	}
	results, err := s.runner.RunK8s(ctx, req)
	if err != nil {
		return syncRunResult{}, err
	}
	return syncRunResult{
		Results:     results,
		GraphUpdate: s.applySecurityGraphUpdateAfterSync(ctx, "k8s", req.Validate),
	}, nil
}

func (s serverSyncHandlerService) SyncAWS(ctx context.Context, req awsSyncRequest) (awsSyncRunResult, error) {
	if s.runner == nil {
		return awsSyncRunResult{}, errSyncWarehouseUnavailable
	}
	outcome, err := s.runner.RunAWS(ctx, req)
	if err != nil {
		return awsSyncRunResult{}, err
	}
	if outcome == nil {
		outcome = &awsSyncOutcome{}
	}
	return awsSyncRunResult{
		Results:                    outcome.Results,
		RelationshipsExtracted:     outcome.RelationshipsExtracted,
		RelationshipsSkippedReason: outcome.RelationshipsSkippedReason,
		GraphUpdate:                s.applySecurityGraphUpdateAfterSync(ctx, "aws", req.Validate),
	}, nil
}

func (s serverSyncHandlerService) SyncAWSOrg(ctx context.Context, req awsOrgSyncRequest) (awsOrgSyncRunResult, error) {
	if s.runner == nil {
		return awsOrgSyncRunResult{}, errSyncWarehouseUnavailable
	}
	outcome, err := s.runner.RunAWSOrg(ctx, req)
	if err != nil {
		return awsOrgSyncRunResult{}, err
	}
	if outcome == nil {
		outcome = &awsOrgSyncOutcome{}
	}
	return awsOrgSyncRunResult{
		Results:       outcome.Results,
		AccountErrors: outcome.AccountErrors,
		GraphUpdate:   s.applySecurityGraphUpdateAfterSync(ctx, "aws_org", req.Validate),
	}, nil
}

func (s serverSyncHandlerService) SyncGCP(ctx context.Context, req gcpSyncRequest) (gcpSyncRunResult, error) {
	if s.runner == nil {
		return gcpSyncRunResult{}, errSyncWarehouseUnavailable
	}
	outcome, err := s.runner.RunGCP(ctx, req)
	if err != nil {
		return gcpSyncRunResult{}, err
	}
	if outcome == nil {
		outcome = &gcpSyncOutcome{}
	}
	return gcpSyncRunResult{
		Results:                    outcome.Results,
		RelationshipsExtracted:     outcome.RelationshipsExtracted,
		RelationshipsSkippedReason: outcome.RelationshipsSkippedReason,
		GraphUpdate:                s.applySecurityGraphUpdateAfterSync(ctx, "gcp", req.Validate),
	}, nil
}

func (s serverSyncHandlerService) SyncGCPAsset(ctx context.Context, req gcpAssetSyncRequest) (syncRunResult, error) {
	if s.runner == nil {
		return syncRunResult{}, errSyncWarehouseUnavailable
	}
	results, err := s.runner.RunGCPAsset(ctx, req)
	if err != nil {
		return syncRunResult{}, err
	}
	return syncRunResult{
		Results:     results,
		GraphUpdate: s.applySecurityGraphUpdateAfterSync(ctx, "gcp_asset", req.Validate),
	}, nil
}

func (s serverSyncHandlerService) warehouse() (warehouse.DataWarehouse, error) {
	if s.deps == nil || s.deps.Warehouse == nil {
		return nil, errSyncWarehouseUnavailable
	}
	return s.deps.Warehouse, nil
}

func (s serverSyncHandlerService) logger() *slog.Logger {
	if s.deps != nil && s.deps.Logger != nil {
		return s.deps.Logger
	}
	return slog.Default()
}

func (s serverSyncHandlerService) applySecurityGraphUpdateAfterSync(ctx context.Context, provider string, validate bool) map[string]any {
	if validate || s.deps == nil || !s.deps.CanApplySecurityGraphChanges() {
		return nil
	}

	trigger := "sync_" + strings.ToLower(strings.TrimSpace(provider))
	graphCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.graphPostSyncUpdateTimeout())
	defer cancel()

	summary, applied, err := s.deps.TryApplySecurityGraphChanges(graphCtx, trigger)
	if !applied {
		return map[string]any{
			"status":     "busy",
			"trigger":    trigger,
			"error":      "graph update already in progress",
			"error_code": "GRAPH_UPDATE_BUSY",
		}
	}
	if err != nil {
		s.logger().Warn("post-sync graph update failed", "provider", provider, "error", err)
		return map[string]any{
			"status":     "failed",
			"trigger":    trigger,
			"error":      "graph update failed",
			"error_code": "GRAPH_UPDATE_FAILED",
		}
	}

	status := "noop"
	if summary.Mode == graph.GraphMutationModeFullRebuild || summary.HasChanges() {
		status = "applied"
	}
	return map[string]any{
		"status":  status,
		"trigger": trigger,
		"summary": summary.Payload(trigger),
	}
}

func (s serverSyncHandlerService) graphPostSyncUpdateTimeout() time.Duration {
	if s.deps != nil {
		return s.deps.Config.GraphPostSyncUpdateTimeoutOrDefault()
	}
	return (*app.Config)(nil).GraphPostSyncUpdateTimeoutOrDefault()
}

type defaultSyncRunner struct {
	warehouse warehouse.SyncWarehouse
	logger    *slog.Logger
}

func newSyncRunner(deps *serverDependencies) syncRunner {
	if deps == nil {
		return nil
	}
	if deps.syncRunner != nil {
		return deps.syncRunner
	}
	if deps.Warehouse == nil {
		return nil
	}
	return defaultSyncRunner{
		warehouse: deps.Warehouse,
		logger:    deps.Logger,
	}
}

func syncRunnerLogger(logger *slog.Logger) *slog.Logger {
	if logger != nil {
		return logger
	}
	return slog.Default()
}

func (r defaultSyncRunner) RunAzure(ctx context.Context, req azureSyncRequest) ([]nativesync.SyncResult, error) {
	return runAzureSyncWithOptions(ctx, r.warehouse, r.logger, req)
}

func (r defaultSyncRunner) RunK8s(ctx context.Context, req k8sSyncRequest) ([]nativesync.SyncResult, error) {
	return runK8sSyncWithOptions(ctx, r.warehouse, r.logger, req)
}

func (r defaultSyncRunner) RunAWS(ctx context.Context, req awsSyncRequest) (*awsSyncOutcome, error) {
	return runAWSSyncWithOptions(ctx, r.warehouse, r.logger, req)
}

func (r defaultSyncRunner) RunAWSOrg(ctx context.Context, req awsOrgSyncRequest) (*awsOrgSyncOutcome, error) {
	return runAWSOrgSyncWithOptions(ctx, r.warehouse, r.logger, req)
}

func (r defaultSyncRunner) RunGCP(ctx context.Context, req gcpSyncRequest) (*gcpSyncOutcome, error) {
	return runGCPSyncWithOptions(ctx, r.warehouse, r.logger, req)
}

func (r defaultSyncRunner) RunGCPAsset(ctx context.Context, req gcpAssetSyncRequest) ([]nativesync.SyncResult, error) {
	return runGCPAssetSyncWithOptions(ctx, r.warehouse, r.logger, req)
}
