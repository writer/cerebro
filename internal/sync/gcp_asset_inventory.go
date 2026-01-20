package sync

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	asset "cloud.google.com/go/asset/apiv1"
	"cloud.google.com/go/asset/apiv1/assetpb"
	"google.golang.org/api/iterator"

	"github.com/writerinternal/cerebro/internal/snowflake"
)

// GCPAssetInventoryEngine uses Cloud Asset Inventory API for efficient bulk resource fetching
type GCPAssetInventoryEngine struct {
	sf          *snowflake.Client
	logger      *slog.Logger
	concurrency int
	scope       string // organization/ORG_ID, folder/FOLDER_ID, or project/PROJECT_ID
	projects    []string
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

// NewGCPAssetInventoryEngine creates a new engine using Cloud Asset Inventory API
func NewGCPAssetInventoryEngine(sf *snowflake.Client, logger *slog.Logger, opts ...GCPAssetOption) *GCPAssetInventoryEngine {
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
	"compute.googleapis.com/Instance":       "gcp_compute_instances",
	"compute.googleapis.com/Firewall":       "gcp_compute_firewalls",
	"compute.googleapis.com/Network":        "gcp_compute_networks",
	"compute.googleapis.com/Subnetwork":     "gcp_compute_subnetworks",
	"storage.googleapis.com/Bucket":         "gcp_storage_buckets",
	"iam.googleapis.com/ServiceAccount":     "gcp_iam_service_accounts",
	"sqladmin.googleapis.com/Instance":      "gcp_sql_instances",
	"cloudfunctions.googleapis.com/Function": "gcp_cloudfunctions_functions",
	"pubsub.googleapis.com/Topic":           "gcp_pubsub_topics",
	"container.googleapis.com/Cluster":      "gcp_container_clusters",
	"cloudkms.googleapis.com/CryptoKey":     "gcp_kms_keys",
	"secretmanager.googleapis.com/Secret":   "gcp_secretmanager_secrets",
	"bigquery.googleapis.com/Dataset":       "gcp_bigquery_datasets",
	"bigquery.googleapis.com/Table":         "gcp_bigquery_tables",
	"run.googleapis.com/Service":            "gcp_run_services",
	"logging.googleapis.com/LogSink":        "gcp_logging_sinks",
	"dns.googleapis.com/ManagedZone":        "gcp_dns_zones",
}

// SyncAll syncs all GCP resources using Cloud Asset Inventory API
func (e *GCPAssetInventoryEngine) SyncAll(ctx context.Context) ([]SyncResult, error) {
	if e.scope == "" && len(e.projects) == 0 {
		return nil, fmt.Errorf("either scope or projects must be set")
	}

	client, err := asset.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("create asset client: %w", err)
	}
	defer client.Close()

	// If we have multiple projects, sync each one
	if len(e.projects) > 0 {
		return e.syncMultipleProjects(ctx, client)
	}

	// Single scope sync
	return e.syncScope(ctx, client, e.scope)
}

func (e *GCPAssetInventoryEngine) syncMultipleProjects(ctx context.Context, client *asset.Client) ([]SyncResult, error) {
	var allResults []SyncResult
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, e.concurrency)

	for _, project := range e.projects {
		wg.Add(1)
		go func(proj string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			scope := fmt.Sprintf("projects/%s", proj)
			results, err := e.syncScope(ctx, client, scope)
			if err != nil {
				e.logger.Error("sync project failed", "project", proj, "error", err)
				return
			}

			mu.Lock()
			allResults = append(allResults, results...)
			mu.Unlock()
		}(project)
	}

	wg.Wait()
	return allResults, nil
}

func (e *GCPAssetInventoryEngine) syncScope(ctx context.Context, client *asset.Client, scope string) ([]SyncResult, error) {
	var results []SyncResult
	start := time.Now()

	// Get all asset types we support
	assetTypes := make([]string, 0, len(GCPAssetTypes))
	for at := range GCPAssetTypes {
		assetTypes = append(assetTypes, at)
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
		if err == iterator.Done {
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
	var wg sync.WaitGroup
	var mu sync.Mutex
	sem := make(chan struct{}, e.concurrency)

	for assetType, assets := range assetsByType {
		wg.Add(1)
		go func(at string, a []*assetpb.ResourceSearchResult) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			result := e.syncAssetType(ctx, at, a)
			mu.Lock()
			results = append(results, result)
			mu.Unlock()
		}(assetType, assets)
	}

	wg.Wait()
	return results, nil
}

func (e *GCPAssetInventoryEngine) syncAssetType(ctx context.Context, assetType string, assets []*assetpb.ResourceSearchResult) SyncResult {
	start := time.Now()
	tableName, ok := GCPAssetTypes[assetType]
	if !ok {
		tableName = strings.ToLower(strings.ReplaceAll(assetType, ".", "_"))
		tableName = strings.ReplaceAll(tableName, "/", "_")
	}

	result := SyncResult{
		Table: tableName,
	}

	// Convert assets to rows
	rows := make([]map[string]interface{}, 0, len(assets))
	for _, asset := range assets {
		row := e.assetToRow(asset)
		rows = append(rows, row)
	}

	// Ensure table exists
	columns := e.getColumnsForAssetType(assetType)
	if err := e.ensureTable(ctx, tableName, columns); err != nil {
		e.logger.Error("ensure table failed", "table", tableName, "error", err)
		result.Errors = 1
		result.Duration = time.Since(start)
		return result
	}

	// Upsert with change detection
	gcpEngine := &GCPSyncEngine{sf: e.sf, logger: e.logger}
	changes, err := gcpEngine.upsertWithChanges(ctx, tableName, rows)
	if err != nil {
		e.logger.Error("upsert failed", "table", tableName, "error", err)
		result.Errors = 1
		result.Duration = time.Since(start)
		return result
	}

	result.Synced = len(rows)
	result.Changes = changes
	result.Duration = time.Since(start)

	if changes.HasChanges() {
		e.logger.Info("synced with changes", "table", tableName, "count", len(rows), "changes", changes.Summary())
	} else {
		e.logger.Info("synced", "table", tableName, "count", len(rows))
	}

	return result
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
						"type":              relType,
						"full_resource_name": relResource.FullResourceName,
						"asset_type":        relResource.AssetType,
					})
				}
			}
		}
		row["relationships"] = relationships
	}

	// Add versioned resources if available
	if len(asset.VersionedResources) > 0 {
		versions := make([]map[string]interface{}, 0)
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

func (e *GCPAssetInventoryEngine) getColumnsForAssetType(_ string) []string {
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

// ListOrganizationProjects lists all projects in an organization
func ListOrganizationProjects(ctx context.Context, orgID string) ([]string, error) {
	client, err := asset.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("create asset client: %w", err)
	}
	defer client.Close()

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
		if err == iterator.Done {
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
