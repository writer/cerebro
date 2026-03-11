package sync

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	asset "cloud.google.com/go/asset/apiv1"
	"cloud.google.com/go/asset/apiv1/assetpb"
	"google.golang.org/api/iterator"

	"github.com/writer/cerebro/internal/metrics"
	"github.com/writer/cerebro/internal/snowflake"
	"github.com/writer/cerebro/internal/warehouse"
	"golang.org/x/sync/errgroup"
)

// GCPAssetInventoryEngine uses Cloud Asset Inventory API for efficient bulk resource fetching
type GCPAssetInventoryEngine struct {
	sf          warehouse.SyncWarehouse
	logger      *slog.Logger
	concurrency int
	scope       string // organization/ORG_ID, folder/FOLDER_ID, or project/PROJECT_ID
	projects    []string
	assetFilter map[string]struct{}
}

// GCPAssetOption configures the GCP Asset Inventory engine
type GCPAssetOption func(*GCPAssetInventoryEngine)

func WithAssetScope(scope string) GCPAssetOption {
	return func(e *GCPAssetInventoryEngine) { e.scope = scope }
}

func WithProjects(projects []string) GCPAssetOption {
	return func(e *GCPAssetInventoryEngine) { e.projects = projects }
}

func WithAssetConcurrency(n int) GCPAssetOption {
	return func(e *GCPAssetInventoryEngine) { e.concurrency = n }
}

func WithAssetTypeFilter(types []string) GCPAssetOption {
	return func(e *GCPAssetInventoryEngine) { e.assetFilter = normalizeTableFilter(types) }
}

// NewGCPAssetInventoryEngine creates a new engine using Cloud Asset Inventory API
func NewGCPAssetInventoryEngine(sf warehouse.SyncWarehouse, logger *slog.Logger, opts ...GCPAssetOption) *GCPAssetInventoryEngine {
	e := &GCPAssetInventoryEngine{
		sf:          sf,
		logger:      logger,
		concurrency: 10,
	}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

// GCPAssetType maps asset types to table names
var GCPAssetTypes = map[string]string{
	"compute.googleapis.com/Instance":        "gcp_compute_instances",
	"compute.googleapis.com/Firewall":        "gcp_compute_firewalls",
	"compute.googleapis.com/Network":         "gcp_compute_networks",
	"compute.googleapis.com/Subnetwork":      "gcp_compute_subnetworks",
	"storage.googleapis.com/Bucket":          "gcp_storage_buckets",
	"iam.googleapis.com/ServiceAccount":      "gcp_iam_service_accounts",
	"iam.googleapis.com/Role":                "gcp_iam_roles",
	"sqladmin.googleapis.com/Instance":       "gcp_sql_instances",
	"cloudfunctions.googleapis.com/Function": "gcp_cloudfunctions_functions",
	"pubsub.googleapis.com/Topic":            "gcp_pubsub_topics",
	"container.googleapis.com/Cluster":       "gcp_container_clusters",
	"cloudkms.googleapis.com/CryptoKey":      "gcp_kms_keys",
	"orgpolicy.googleapis.com/Policy":        "gcp_org_policies",
	"secretmanager.googleapis.com/Secret":    "gcp_secretmanager_secrets",
	"bigquery.googleapis.com/Dataset":        "gcp_bigquery_datasets",
	"bigquery.googleapis.com/Table":          "gcp_bigquery_tables",
	"run.googleapis.com/Service":             "gcp_run_services",
	"logging.googleapis.com/LogSink":         "gcp_logging_sinks",
	"dns.googleapis.com/ManagedZone":         "gcp_dns_zones",
}

// SyncAll syncs all GCP resources using Cloud Asset Inventory API
func (e *GCPAssetInventoryEngine) SyncAll(ctx context.Context) ([]SyncResult, error) {
	if e.scope == "" && len(e.projects) == 0 {
		return nil, fmt.Errorf("either scope or projects must be set")
	}

	client, err := asset.NewClient(ctx, gcpClientOptionsFromContext(ctx)...)
	if err != nil {
		return nil, fmt.Errorf("create asset client: %w", err)
	}
	defer func() { _ = client.Close() }()

	// If we have multiple projects, sync each one
	if len(e.projects) > 0 {
		return e.syncMultipleProjects(ctx, client)
	}

	// Single scope sync
	return e.syncScope(ctx, client, e.scope)
}

// ValidateTables ensures required Snowflake tables exist without fetching assets.
func (e *GCPAssetInventoryEngine) ValidateTables(ctx context.Context) ([]SyncResult, error) {
	assetTypes := make([]string, 0, len(GCPAssetTypes))
	for assetType, tableName := range GCPAssetTypes {
		if len(e.assetFilter) > 0 && !matchesFilter(e.assetFilter, assetType, tableName) {
			continue
		}
		assetTypes = append(assetTypes, assetType)
	}
	if len(assetTypes) == 0 {
		return nil, fmt.Errorf("no GCP asset types matched filter: %s", strings.Join(filterNames(e.assetFilter), ", "))
	}

	results := make([]SyncResult, len(assetTypes))
	var mu sync.Mutex
	var errs []error
	var group errgroup.Group
	limit := e.concurrency
	if limit <= 0 {
		limit = 1
	}
	group.SetLimit(limit)

	for i, assetType := range assetTypes {
		idx := i
		at := assetType
		group.Go(func() error {
			result, err := e.validateAssetType(ctx, at)
			mu.Lock()
			results[idx] = result
			if err != nil {
				errs = append(errs, err)
			}
			mu.Unlock()
			return nil
		})
	}

	_ = group.Wait()
	return results, errors.Join(errs...)
}

func (e *GCPAssetInventoryEngine) syncMultipleProjects(ctx context.Context, client *asset.Client) ([]SyncResult, error) {
	var allResults []SyncResult
	var mu sync.Mutex
	var errs []error
	var group errgroup.Group
	limit := e.concurrency
	if limit <= 0 {
		limit = 1
	}
	group.SetLimit(limit)

	for _, project := range e.projects {
		proj := project
		group.Go(func() error {
			scope := fmt.Sprintf("projects/%s", proj)
			results, err := e.syncScope(ctx, client, scope)
			mu.Lock()
			allResults = append(allResults, results...)
			if err != nil {
				errs = append(errs, fmt.Errorf("sync project %s: %w", proj, err))
			}
			mu.Unlock()
			return nil
		})
	}

	_ = group.Wait()
	return allResults, errors.Join(errs...)
}

func (e *GCPAssetInventoryEngine) syncScope(ctx context.Context, client *asset.Client, scope string) ([]SyncResult, error) {
	var results []SyncResult
	start := time.Now()

	// Get all asset types we support
	assetTypes := make([]string, 0, len(GCPAssetTypes))
	for assetType, tableName := range GCPAssetTypes {
		if len(e.assetFilter) > 0 && !matchesFilter(e.assetFilter, assetType, tableName) {
			continue
		}
		assetTypes = append(assetTypes, assetType)
	}
	if len(assetTypes) == 0 {
		return nil, fmt.Errorf("no GCP asset types matched filter: %s", strings.Join(filterNames(e.assetFilter), ", "))
	}

	e.logger.Info("fetching assets via Cloud Asset Inventory", "scope", scope, "types", len(assetTypes))

	// Use SearchAllResources for efficient bulk fetching
	req := &assetpb.SearchAllResourcesRequest{
		Scope:      scope,
		AssetTypes: assetTypes,
		PageSize:   500, // Maximum page size
	}

	// Group assets by type
	assetsByType := make(map[string][]*assetpb.ResourceSearchResult)
	totalAssets := 0

	it := client.SearchAllResources(ctx, req)
	for {
		result, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			e.logger.Error("search assets failed", "error", err)
			break
		}

		assetType := result.AssetType
		assetsByType[assetType] = append(assetsByType[assetType], result)
		totalAssets++
	}

	e.logger.Info("fetched assets", "total", totalAssets, "types", len(assetsByType), "duration", time.Since(start))

	// Process each asset type in parallel
	var mu sync.Mutex
	var errs []error
	var group errgroup.Group
	limit := e.concurrency
	if limit <= 0 {
		limit = 1
	}
	group.SetLimit(limit)

	for assetType, assets := range assetsByType {
		at := assetType
		assetBatch := assets
		group.Go(func() error {
			result, err := e.syncAssetType(ctx, scope, at, assetBatch)
			mu.Lock()
			results = append(results, result)
			if err != nil {
				errs = append(errs, err)
			}
			mu.Unlock()
			return nil
		})
	}

	_ = group.Wait()
	return results, errors.Join(errs...)
}

func (e *GCPAssetInventoryEngine) syncAssetType(ctx context.Context, scope, assetType string, assets []*assetpb.ResourceSearchResult) (SyncResult, error) {
	start := time.Now()
	tableName, ok := GCPAssetTypes[assetType]
	if !ok {
		replacer := strings.NewReplacer(".", "_", "/", "_", "-", "_")
		tableName = strings.ToLower(replacer.Replace(assetType))
	}

	result := SyncResult{
		Table: tableName,
	}
	defer func() {
		if result.Duration == 0 {
			result.Duration = time.Since(start)
		}
		metrics.RecordSyncMetrics("gcp-asset", result.Table, result.Region, result.Duration, result.Synced, result.Errors)
	}()

	if err := snowflake.ValidateTableName(tableName); err != nil {
		result.Errors = 1
		result.Error = err.Error()
		result.Duration = time.Since(start)
		return result, fmt.Errorf("gcp asset %s: invalid table name: %w", tableName, err)
	}

	// Convert assets to rows
	rows := make([]map[string]interface{}, 0, len(assets))
	for _, asset := range assets {
		row := e.assetToRow(asset)
		rows = append(rows, row)
	}

	// Ensure table exists
	columns := e.getColumnsForAssetType()
	if err := e.ensureTable(ctx, tableName, columns); err != nil {
		e.logger.Error("ensure table failed", "table", tableName, "error", err)
		result.Errors = 1
		result.Error = err.Error()
		result.Duration = time.Since(start)
		return result, fmt.Errorf("gcp asset %s: ensure table: %w", tableName, err)
	}

	// Upsert with change detection
	gcpEngine := &GCPSyncEngine{sf: e.sf, logger: e.logger, projectID: gcpProjectIDFromScope(scope)}
	changes, err := gcpEngine.upsertWithChanges(ctx, tableName, columns, rows)
	if err != nil {
		e.logger.Error("upsert failed", "table", tableName, "error", err)
		result.Errors = 1
		result.Error = err.Error()
		result.Duration = time.Since(start)
		return result, fmt.Errorf("gcp asset %s: upsert: %w", tableName, err)
	}

	syncTime := time.Now().UTC()
	if err := gcpEngine.emitCDCEvents(ctx, tableName, changes, rows, syncTime); err != nil {
		e.logger.Warn("failed to emit CDC events", "table", tableName, "error", err)
	}

	result.Synced = len(rows)
	result.Changes = changes
	result.SyncTime = syncTime
	result.Duration = time.Since(start)

	if changes.HasChanges() {
		e.logger.Info("synced with changes", "table", tableName, "count", len(rows), "changes", changes.Summary())
	} else {
		e.logger.Info("synced", "table", tableName, "count", len(rows))
	}

	return result, nil
}

func (e *GCPAssetInventoryEngine) validateAssetType(ctx context.Context, assetType string) (SyncResult, error) {
	start := time.Now()
	tableName, ok := GCPAssetTypes[assetType]
	if !ok {
		replacer := strings.NewReplacer(".", "_", "/", "_", "-", "_")
		tableName = strings.ToLower(replacer.Replace(assetType))
	}

	result := SyncResult{
		Table: tableName,
	}
	defer func() {
		if result.Duration == 0 {
			result.Duration = time.Since(start)
		}
		metrics.RecordSyncMetrics("gcp-asset", result.Table, result.Region, result.Duration, result.Synced, result.Errors)
	}()

	if err := snowflake.ValidateTableName(tableName); err != nil {
		result.Errors = 1
		result.Error = err.Error()
		result.Duration = time.Since(start)
		return result, fmt.Errorf("gcp asset %s: invalid table name: %w", tableName, err)
	}

	columns := e.getColumnsForAssetType()
	if err := e.ensureTable(ctx, tableName, columns); err != nil {
		e.logger.Error("ensure table failed", "table", tableName, "error", err)
		result.Errors = 1
		result.Error = err.Error()
		result.Duration = time.Since(start)
		return result, fmt.Errorf("gcp asset %s: ensure table: %w", tableName, err)
	}

	result.Duration = time.Since(start)
	return result, nil
}

func (e *GCPAssetInventoryEngine) assetToRow(asset *assetpb.ResourceSearchResult) map[string]interface{} {
	// Parse project from name: //service.googleapis.com/projects/PROJECT/...
	project := ""
	if parts := strings.Split(asset.Project, "/"); len(parts) >= 2 {
		project = parts[len(parts)-1]
	}

	// Parse location from name
	location := asset.Location

	row := map[string]interface{}{
		"_cq_id":            asset.Name,
		"name":              asset.DisplayName,
		"asset_type":        asset.AssetType,
		"project":           project,
		"location":          location,
		"description":       asset.Description,
		"state":             asset.State,
		"create_time":       asset.CreateTime.AsTime().Format(time.RFC3339),
		"update_time":       asset.UpdateTime.AsTime().Format(time.RFC3339),
		"labels":            asset.Labels,
		"network_tags":      asset.NetworkTags,
		"kms_keys":          asset.KmsKeys,
		"parent_full_name":  asset.ParentFullResourceName,
		"parent_asset_type": asset.ParentAssetType,
		"folders":           asset.Folders,
		"organization":      asset.Organization,
	}

	// Add additional data if available
	if asset.AdditionalAttributes != nil {
		additionalData := make(map[string]interface{})
		for k, v := range asset.AdditionalAttributes.AsMap() {
			additionalData[k] = v
		}
		row["additional_attributes"] = additionalData
	}

	// Parse relationships (map of relationship type -> RelatedResources)
	if len(asset.Relationships) > 0 {
		relationships := make([]map[string]interface{}, 0)
		for relType, relResources := range asset.Relationships {
			if relResources != nil && len(relResources.RelatedResources) > 0 {
				for _, relResource := range relResources.RelatedResources {
					relationships = append(relationships, map[string]interface{}{
						"type":               relType,
						"full_resource_name": relResource.FullResourceName,
						"asset_type":         relResource.AssetType,
					})
				}
			}
		}
		row["relationships"] = relationships
	}

	// Add versioned resources if available
	if len(asset.VersionedResources) > 0 {
		versions := make([]map[string]interface{}, 0, len(asset.VersionedResources))
		for _, vr := range asset.VersionedResources {
			versions = append(versions, map[string]interface{}{
				"version":  vr.Version,
				"resource": vr.Resource.AsMap(),
			})
		}
		row["versioned_resources"] = versions
	}

	// Add attached resources
	if len(asset.AttachedResources) > 0 {
		attached := make([]string, 0, len(asset.AttachedResources))
		for _, ar := range asset.AttachedResources {
			attached = append(attached, ar.AssetType)
		}
		row["attached_resources"] = attached
	}

	return row
}

func (e *GCPAssetInventoryEngine) getColumnsForAssetType() []string {
	return []string{
		"name",
		"asset_type",
		"project",
		"location",
		"description",
		"state",
		"create_time",
		"update_time",
		"labels",
		"network_tags",
		"kms_keys",
		"parent_full_name",
		"parent_asset_type",
		"folders",
		"organization",
		"additional_attributes",
		"relationships",
		"versioned_resources",
		"attached_resources",
	}
}

func (e *GCPAssetInventoryEngine) ensureTable(ctx context.Context, table string, columns []string) error {
	if err := snowflake.ValidateTableName(table); err != nil {
		return fmt.Errorf("invalid table name: %w", err)
	}

	for _, col := range columns {
		if err := snowflake.ValidateColumnName(col); err != nil {
			return fmt.Errorf("invalid column name %q: %w", col, err)
		}
	}
	colDefs := make([]string, len(columns))
	for i, col := range columns {
		colDefs[i] = fmt.Sprintf("%s VARIANT", strings.ToUpper(col))
	}

	createQuery := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
		_CQ_ID VARCHAR PRIMARY KEY,
		_CQ_SYNC_TIME TIMESTAMP_TZ DEFAULT CURRENT_TIMESTAMP(),
		_CQ_HASH VARCHAR,
		%s
	)`, table, strings.Join(colDefs, ", "))

	_, err := e.sf.Exec(ctx, createQuery)
	return err
}

func gcpProjectIDFromScope(scope string) string {
	trimmed := strings.TrimSpace(scope)
	if !strings.HasPrefix(trimmed, "projects/") {
		return ""
	}
	parts := strings.Split(trimmed, "/")
	if len(parts) < 2 {
		return ""
	}
	return strings.TrimSpace(parts[1])
}

// ListOrganizationProjects lists all projects in an organization
func ListOrganizationProjects(ctx context.Context, orgID string) ([]string, error) {
	client, err := asset.NewClient(ctx, gcpClientOptionsFromContext(ctx)...)
	if err != nil {
		return nil, fmt.Errorf("create asset client: %w", err)
	}
	defer func() { _ = client.Close() }()

	scope := fmt.Sprintf("organizations/%s", orgID)
	req := &assetpb.SearchAllResourcesRequest{
		Scope:      scope,
		AssetTypes: []string{"cloudresourcemanager.googleapis.com/Project"},
		PageSize:   500,
	}

	var projects []string
	it := client.SearchAllResources(ctx, req)
	for {
		result, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("search projects: %w", err)
		}

		// Extract project ID from name
		// Format: //cloudresourcemanager.googleapis.com/projects/PROJECT_ID
		parts := strings.Split(result.Name, "/")
		if len(parts) > 0 {
			projectID := parts[len(parts)-1]
			projects = append(projects, projectID)
		}
	}

	return projects, nil
}
