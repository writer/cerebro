package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/evalops/cerebro/internal/snowflake"
	nativesync "github.com/evalops/cerebro/internal/sync"
)

func (s *Server) backfillRelationshipIDs(w http.ResponseWriter, r *http.Request) {
	var req struct {
		BatchSize int `json:"batch_size"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}
	if req.BatchSize <= 0 {
		req.BatchSize = 200
	}

	if s.app.Snowflake == nil {
		s.error(w, http.StatusServiceUnavailable, "snowflake not configured")
		return
	}

	extractor := nativesync.NewRelationshipExtractor(s.app.Snowflake, s.app.Logger)
	stats, err := extractor.BackfillNormalizedRelationshipIDs(r.Context(), req.BatchSize)
	if err != nil {
		s.errorFromErr(w, err)
		return
	}

	s.json(w, http.StatusOK, map[string]interface{}{
		"scanned": stats.Scanned,
		"updated": stats.Updated,
		"deleted": stats.Deleted,
		"skipped": stats.Skipped,
	})
}

type azureSyncRequest struct {
	Subscription string   `json:"subscription"`
	Concurrency  int      `json:"concurrency"`
	Tables       []string `json:"tables"`
	Validate     bool     `json:"validate"`
}

var runAzureSyncWithOptions = func(ctx context.Context, client *snowflake.Client, req azureSyncRequest) ([]nativesync.SyncResult, error) {
	opts := []nativesync.AzureEngineOption{}
	if req.Subscription != "" {
		opts = append(opts, nativesync.WithAzureSubscription(req.Subscription))
	}
	if req.Concurrency > 0 {
		opts = append(opts, nativesync.WithAzureConcurrency(req.Concurrency))
	}
	if len(req.Tables) > 0 {
		opts = append(opts, nativesync.WithAzureTableFilter(req.Tables))
	}

	syncer, err := nativesync.NewAzureSyncEngine(client, slog.Default(), opts...)
	if err != nil {
		return nil, fmt.Errorf("create azure sync engine: %w", err)
	}

	if req.Validate {
		results, err := syncer.ValidateTables(ctx)
		if err != nil {
			return nil, fmt.Errorf("validation failed: %w", err)
		}
		return results, nil
	}

	results, err := syncer.SyncAll(ctx)
	if err != nil {
		return nil, fmt.Errorf("sync failed: %w", err)
	}
	return results, nil
}

func (s *Server) syncAzure(w http.ResponseWriter, r *http.Request) {
	var req azureSyncRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}

	req.Subscription = strings.TrimSpace(req.Subscription)
	req.Tables = normalizeSyncTables(req.Tables)

	if s.app.Snowflake == nil {
		s.error(w, http.StatusServiceUnavailable, "snowflake not configured")
		return
	}

	results, err := runAzureSyncWithOptions(r.Context(), s.app.Snowflake, req)
	if err != nil {
		s.errorFromErr(w, err)
		return
	}

	s.json(w, http.StatusOK, map[string]interface{}{
		"provider": "azure",
		"validate": req.Validate,
		"results":  results,
	})
}

type k8sSyncRequest struct {
	Kubeconfig  string   `json:"kubeconfig"`
	Context     string   `json:"context"`
	Namespace   string   `json:"namespace"`
	Concurrency int      `json:"concurrency"`
	Tables      []string `json:"tables"`
	Validate    bool     `json:"validate"`
}

var runK8sSyncWithOptions = func(ctx context.Context, client *snowflake.Client, req k8sSyncRequest) ([]nativesync.SyncResult, error) {
	opts := []nativesync.K8sEngineOption{}
	if req.Kubeconfig != "" {
		opts = append(opts, nativesync.WithK8sKubeconfig(req.Kubeconfig))
	}
	if req.Context != "" {
		opts = append(opts, nativesync.WithK8sContext(req.Context))
	}
	if req.Namespace != "" {
		opts = append(opts, nativesync.WithK8sNamespace(req.Namespace))
	}
	if req.Concurrency > 0 {
		opts = append(opts, nativesync.WithK8sConcurrency(req.Concurrency))
	}
	if len(req.Tables) > 0 {
		opts = append(opts, nativesync.WithK8sTableFilter(req.Tables))
	}

	syncer := nativesync.NewK8sSyncEngine(client, slog.Default(), opts...)
	if req.Validate {
		results, err := syncer.ValidateTables(ctx)
		if err != nil {
			return nil, fmt.Errorf("validation failed: %w", err)
		}
		return results, nil
	}

	results, err := syncer.SyncAll(ctx)
	if err != nil {
		return nil, fmt.Errorf("sync failed: %w", err)
	}
	return results, nil
}

func (s *Server) syncK8s(w http.ResponseWriter, r *http.Request) {
	var req k8sSyncRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}

	req.Kubeconfig = strings.TrimSpace(req.Kubeconfig)
	req.Context = strings.TrimSpace(req.Context)
	req.Namespace = strings.TrimSpace(req.Namespace)
	req.Tables = normalizeSyncTables(req.Tables)

	if s.app.Snowflake == nil {
		s.error(w, http.StatusServiceUnavailable, "snowflake not configured")
		return
	}

	results, err := runK8sSyncWithOptions(r.Context(), s.app.Snowflake, req)
	if err != nil {
		s.errorFromErr(w, err)
		return
	}

	s.json(w, http.StatusOK, map[string]interface{}{
		"provider": "k8s",
		"validate": req.Validate,
		"results":  results,
	})
}

type awsSyncRequest struct {
	Profile     string   `json:"profile"`
	Region      string   `json:"region"`
	MultiRegion bool     `json:"multi_region"`
	Concurrency int      `json:"concurrency"`
	Tables      []string `json:"tables"`
	Validate    bool     `json:"validate"`
}

type awsSyncOutcome struct {
	Results                    []nativesync.SyncResult
	RelationshipsExtracted     int64
	RelationshipsSkippedReason string
}

var runAWSSyncWithOptions = func(ctx context.Context, client *snowflake.Client, req awsSyncRequest) (*awsSyncOutcome, error) {
	loadOptions := make([]func(*config.LoadOptions) error, 0, 2)
	if req.Profile != "" {
		loadOptions = append(loadOptions, config.WithSharedConfigProfile(req.Profile))
	}
	if req.Region != "" {
		loadOptions = append(loadOptions, config.WithRegion(req.Region))
	}
	awsCfg, err := config.LoadDefaultConfig(ctx, loadOptions...)
	if err != nil {
		return nil, fmt.Errorf("load AWS config: %w", err)
	}

	opts := []nativesync.EngineOption{}
	if req.Concurrency > 0 {
		opts = append(opts, nativesync.WithConcurrency(req.Concurrency))
	}
	if len(req.Tables) > 0 {
		opts = append(opts, nativesync.WithTableFilter(req.Tables))
	}
	if req.MultiRegion {
		opts = append(opts, nativesync.WithRegions(nativesync.DefaultAWSRegions))
	} else {
		region := req.Region
		if region == "" {
			region = awsCfg.Region
		}
		if region == "" {
			region = "us-east-1"
		}
		opts = append(opts, nativesync.WithRegions([]string{region}))
	}

	syncer := nativesync.NewSyncEngine(client, slog.Default(), opts...)
	if req.Validate {
		results, err := syncer.ValidateTablesWithConfig(ctx, awsCfg)
		if err != nil {
			return nil, fmt.Errorf("validation failed: %w", err)
		}
		return &awsSyncOutcome{Results: results}, nil
	}

	results, err := syncer.SyncAllWithConfig(ctx, awsCfg)
	if err != nil {
		return nil, fmt.Errorf("sync failed: %w", err)
	}

	outcome := &awsSyncOutcome{Results: results}
	if len(req.Tables) > 0 {
		outcome.RelationshipsSkippedReason = "table filter is set"
		return outcome, nil
	}

	allowed, reason := nativesync.CanExtractRelationships(results, nil)
	if !allowed {
		outcome.RelationshipsSkippedReason = reason
		return outcome, nil
	}

	extractor := nativesync.NewRelationshipExtractor(client, slog.Default())
	relCount, err := extractor.ExtractAndPersist(ctx)
	if err != nil {
		outcome.RelationshipsSkippedReason = fmt.Sprintf("relationship extraction failed: %v", err)
		return outcome, nil
	}
	outcome.RelationshipsExtracted = int64(relCount)

	return outcome, nil
}

func (s *Server) syncAWS(w http.ResponseWriter, r *http.Request) {
	var req awsSyncRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}

	req.Profile = strings.TrimSpace(req.Profile)
	req.Region = strings.TrimSpace(req.Region)
	req.Tables = normalizeSyncTables(req.Tables)

	if s.app.Snowflake == nil {
		s.error(w, http.StatusServiceUnavailable, "snowflake not configured")
		return
	}

	outcome, err := runAWSSyncWithOptions(r.Context(), s.app.Snowflake, req)
	if err != nil {
		s.errorFromErr(w, err)
		return
	}
	if outcome == nil {
		outcome = &awsSyncOutcome{}
	}

	resp := map[string]interface{}{
		"provider":                "aws",
		"validate":                req.Validate,
		"results":                 outcome.Results,
		"relationships_extracted": outcome.RelationshipsExtracted,
	}
	if outcome.RelationshipsSkippedReason != "" {
		resp["relationships_skipped_reason"] = outcome.RelationshipsSkippedReason
	}

	s.json(w, http.StatusOK, resp)
}

type gcpSyncRequest struct {
	Project     string   `json:"project"`
	Concurrency int      `json:"concurrency"`
	Tables      []string `json:"tables"`
	Validate    bool     `json:"validate"`
}

type gcpSyncOutcome struct {
	Results                    []nativesync.SyncResult
	RelationshipsExtracted     int64
	RelationshipsSkippedReason string
}

var runGCPSyncWithOptions = func(ctx context.Context, client *snowflake.Client, req gcpSyncRequest) (*gcpSyncOutcome, error) {
	if req.Project == "" {
		return nil, fmt.Errorf("project is required")
	}

	opts := []nativesync.GCPEngineOption{nativesync.WithGCPProject(req.Project)}
	if req.Concurrency > 0 {
		opts = append(opts, nativesync.WithGCPConcurrency(req.Concurrency))
	}
	if len(req.Tables) > 0 {
		opts = append(opts, nativesync.WithGCPTableFilter(req.Tables))
	}

	syncer := nativesync.NewGCPSyncEngine(client, slog.Default(), opts...)
	if req.Validate {
		results, err := syncer.ValidateTables(ctx)
		if err != nil {
			return nil, fmt.Errorf("validation failed: %w", err)
		}
		return &gcpSyncOutcome{Results: results}, nil
	}

	results, err := syncer.SyncAll(ctx)
	if err != nil {
		return nil, fmt.Errorf("sync failed: %w", err)
	}

	outcome := &gcpSyncOutcome{Results: results}
	if len(req.Tables) > 0 {
		outcome.RelationshipsSkippedReason = "table filter is set"
		return outcome, nil
	}

	extractor := nativesync.NewRelationshipExtractor(client, slog.Default())
	relCount, err := extractor.ExtractAndPersist(ctx)
	if err != nil {
		outcome.RelationshipsSkippedReason = fmt.Sprintf("relationship extraction failed: %v", err)
		return outcome, nil
	}
	outcome.RelationshipsExtracted = int64(relCount)

	return outcome, nil
}

func (s *Server) syncGCP(w http.ResponseWriter, r *http.Request) {
	var req gcpSyncRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}

	req.Project = strings.TrimSpace(req.Project)
	req.Tables = normalizeSyncTables(req.Tables)
	if req.Project == "" {
		s.error(w, http.StatusBadRequest, "project is required")
		return
	}

	if s.app.Snowflake == nil {
		s.error(w, http.StatusServiceUnavailable, "snowflake not configured")
		return
	}

	outcome, err := runGCPSyncWithOptions(r.Context(), s.app.Snowflake, req)
	if err != nil {
		s.errorFromErr(w, err)
		return
	}
	if outcome == nil {
		outcome = &gcpSyncOutcome{}
	}

	resp := map[string]interface{}{
		"provider":                "gcp",
		"validate":                req.Validate,
		"results":                 outcome.Results,
		"relationships_extracted": outcome.RelationshipsExtracted,
	}
	if outcome.RelationshipsSkippedReason != "" {
		resp["relationships_skipped_reason"] = outcome.RelationshipsSkippedReason
	}

	s.json(w, http.StatusOK, resp)
}

type gcpAssetSyncRequest struct {
	Projects    []string `json:"projects"`
	Concurrency int      `json:"concurrency"`
	Tables      []string `json:"tables"`
	Validate    bool     `json:"validate"`
}

var runGCPAssetSyncWithOptions = func(ctx context.Context, client *snowflake.Client, req gcpAssetSyncRequest) ([]nativesync.SyncResult, error) {
	if len(req.Projects) == 0 {
		return nil, fmt.Errorf("projects are required")
	}

	opts := []nativesync.GCPAssetOption{nativesync.WithProjects(req.Projects)}
	if req.Concurrency > 0 {
		opts = append(opts, nativesync.WithAssetConcurrency(req.Concurrency))
	}
	if len(req.Tables) > 0 {
		opts = append(opts, nativesync.WithAssetTypeFilter(req.Tables))
	}

	syncer := nativesync.NewGCPAssetInventoryEngine(client, slog.Default(), opts...)
	if req.Validate {
		results, err := syncer.ValidateTables(ctx)
		if err != nil {
			return nil, fmt.Errorf("validation failed: %w", err)
		}
		return results, nil
	}

	results, err := syncer.SyncAll(ctx)
	if err != nil {
		return nil, fmt.Errorf("sync failed: %w", err)
	}
	return results, nil
}

func (s *Server) syncGCPAsset(w http.ResponseWriter, r *http.Request) {
	var req gcpAssetSyncRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}

	req.Projects = normalizeSyncProjects(req.Projects)
	req.Tables = normalizeSyncTables(req.Tables)
	if len(req.Projects) == 0 {
		s.error(w, http.StatusBadRequest, "projects are required")
		return
	}

	if s.app.Snowflake == nil {
		s.error(w, http.StatusServiceUnavailable, "snowflake not configured")
		return
	}

	results, err := runGCPAssetSyncWithOptions(r.Context(), s.app.Snowflake, req)
	if err != nil {
		s.errorFromErr(w, err)
		return
	}

	s.json(w, http.StatusOK, map[string]interface{}{
		"provider": "gcp_asset",
		"validate": req.Validate,
		"results":  results,
	})
}

func normalizeSyncProjects(raw []string) []string {
	if len(raw) == 0 {
		return nil
	}

	normalized := make([]string, 0, len(raw))
	seen := make(map[string]struct{}, len(raw))
	for _, project := range raw {
		name := strings.TrimSpace(project)
		if name == "" {
			continue
		}
		key := strings.ToLower(name)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		normalized = append(normalized, name)
	}
	if len(normalized) == 0 {
		return nil
	}
	return normalized
}

func normalizeSyncTables(raw []string) []string {
	if len(raw) == 0 {
		return nil
	}

	normalized := make([]string, 0, len(raw))
	seen := make(map[string]struct{}, len(raw))
	for _, table := range raw {
		name := strings.ToLower(strings.TrimSpace(table))
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		normalized = append(normalized, name)
	}
	if len(normalized) == 0 {
		return nil
	}
	return normalized
}
