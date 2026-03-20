package api

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/app"
	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/snowflake"
	nativesync "github.com/writer/cerebro/internal/sync"
)

var errSyncSnowflakeUnavailable = errors.New("snowflake not configured")

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
	deps *serverDependencies
}

func newSyncHandlerService(deps *serverDependencies) syncHandlerService {
	return serverSyncHandlerService{deps: deps}
}

func (s serverSyncHandlerService) BackfillRelationshipIDs(ctx context.Context, batchSize int) (syncBackfillResult, error) {
	client, err := s.snowflake()
	if err != nil {
		return syncBackfillResult{}, err
	}
	extractor := nativesync.NewRelationshipExtractor(client, s.logger())
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
	client, err := s.snowflake()
	if err != nil {
		return syncRunResult{}, err
	}
	results, err := runAzureSyncWithOptions(ctx, client, req)
	if err != nil {
		return syncRunResult{}, err
	}
	return syncRunResult{
		Results:     results,
		GraphUpdate: s.applySecurityGraphUpdateAfterSync(ctx, "azure", req.Validate),
	}, nil
}

func (s serverSyncHandlerService) SyncK8s(ctx context.Context, req k8sSyncRequest) (syncRunResult, error) {
	client, err := s.snowflake()
	if err != nil {
		return syncRunResult{}, err
	}
	results, err := runK8sSyncWithOptions(ctx, client, req)
	if err != nil {
		return syncRunResult{}, err
	}
	return syncRunResult{
		Results:     results,
		GraphUpdate: s.applySecurityGraphUpdateAfterSync(ctx, "k8s", req.Validate),
	}, nil
}

func (s serverSyncHandlerService) SyncAWS(ctx context.Context, req awsSyncRequest) (awsSyncRunResult, error) {
	client, err := s.snowflake()
	if err != nil {
		return awsSyncRunResult{}, err
	}
	outcome, err := runAWSSyncWithOptions(ctx, client, req)
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
	client, err := s.snowflake()
	if err != nil {
		return awsOrgSyncRunResult{}, err
	}
	outcome, err := runAWSOrgSyncWithOptions(ctx, client, req)
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
	client, err := s.snowflake()
	if err != nil {
		return gcpSyncRunResult{}, err
	}
	outcome, err := runGCPSyncWithOptions(ctx, client, req)
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
	client, err := s.snowflake()
	if err != nil {
		return syncRunResult{}, err
	}
	results, err := runGCPAssetSyncWithOptions(ctx, client, req)
	if err != nil {
		return syncRunResult{}, err
	}
	return syncRunResult{
		Results:     results,
		GraphUpdate: s.applySecurityGraphUpdateAfterSync(ctx, "gcp_asset", req.Validate),
	}, nil
}

func (s serverSyncHandlerService) snowflake() (*snowflake.Client, error) {
	if s.deps == nil || s.deps.Snowflake == nil {
		return nil, errSyncSnowflakeUnavailable
	}
	return s.deps.Snowflake, nil
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
