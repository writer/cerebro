package sync

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	azpolicy "github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/keyvault/armkeyvault"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/sql/armsql"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	"github.com/writer/cerebro/internal/metrics"
	"github.com/writer/cerebro/internal/snowflake"
	"github.com/writer/cerebro/internal/snowflake/tableops"
	"github.com/writer/cerebro/internal/warehouse"
	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"
)

// AzureSyncEngine orchestrates Azure resource syncing with change detection
type AzureSyncEngine struct {
	sf                      warehouse.SyncWarehouse
	logger                  *slog.Logger
	concurrency             int
	subscriptionConcurrency int
	subscriptionID          string
	subscriptionIDs         []string
	managementGroupID       string
	credential              *azidentity.DefaultAzureCredential
	tableFilter             map[string]struct{}
	rateLimiter             *rate.Limiter
	retryOptions            retryOptions
	httpClient              *http.Client
	tokenCredential         azcore.TokenCredential
	listEnabledFunc         func(context.Context) ([]string, error)
}

// AzureEngineOption configures the Azure sync engine
type AzureEngineOption func(*AzureSyncEngine)

func newAzureHTTPClient() *http.Client {
	return &http.Client{Timeout: 30 * time.Second}
}

func WithAzureSubscription(subscriptionID string) AzureEngineOption {
	return func(e *AzureSyncEngine) { e.subscriptionID = subscriptionID }
}

func WithAzureSubscriptions(subscriptionIDs []string) AzureEngineOption {
	return func(e *AzureSyncEngine) { e.subscriptionIDs = NormalizeAzureSubscriptionIDs(subscriptionIDs) }
}

func WithAzureManagementGroup(managementGroupID string) AzureEngineOption {
	return func(e *AzureSyncEngine) { e.managementGroupID = strings.TrimSpace(managementGroupID) }
}

func WithAzureSubscriptionConcurrency(n int) AzureEngineOption {
	return func(e *AzureSyncEngine) { e.subscriptionConcurrency = n }
}

func WithAzureConcurrency(n int) AzureEngineOption {
	return func(e *AzureSyncEngine) { e.concurrency = n }
}

func WithAzureTableFilter(tables []string) AzureEngineOption {
	return func(e *AzureSyncEngine) { e.tableFilter = normalizeTableFilter(tables) }
}

func NewAzureSyncEngine(sf warehouse.SyncWarehouse, logger *slog.Logger, opts ...AzureEngineOption) (*AzureSyncEngine, error) {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("create Azure credential: %w", err)
	}

	e := &AzureSyncEngine{
		sf:                      sf,
		logger:                  logger,
		concurrency:             10,
		subscriptionConcurrency: 4,
		credential:              cred,
		httpClient:              newAzureHTTPClient(),
		tokenCredential:         cred,
	}
	for _, opt := range opts {
		opt(e)
	}
	if e.rateLimiter == nil {
		e.rateLimiter = rate.NewLimiter(defaultAzureRateLimit, defaultAzureRateBurst)
	}
	if e.retryOptions.Attempts == 0 {
		e.retryOptions = defaultAzureRetryOptions()
	}
	return e, nil
}

// AzureTableSpec defines an Azure table to sync
type AzureTableSpec struct {
	Name    string
	Columns []string
	Fetch   func(ctx context.Context, cred *azidentity.DefaultAzureCredential, subscriptionID string) ([]map[string]interface{}, error)
}

// SyncAll syncs all Azure resources with change detection
func (e *AzureSyncEngine) SyncAll(ctx context.Context) ([]SyncResult, error) {
	subscriptionIDs, err := e.resolveSubscriptionIDs(ctx)
	if err != nil {
		return nil, fmt.Errorf("resolve azure subscriptions: %w", err)
	}
	tables := filterAzureTables(e.getAzureTables(), e.tableFilter)
	if len(e.tableFilter) > 0 && len(tables) == 0 {
		return nil, fmt.Errorf("no Azure tables matched filter: %s", strings.Join(filterNames(e.tableFilter), ", "))
	}
	results := make([]SyncResult, 0, len(tables)*len(subscriptionIDs))
	var mu sync.Mutex
	var errs []error
	var group errgroup.Group
	limit := e.subscriptionConcurrency
	if limit <= 0 {
		limit = 1
	}
	group.SetLimit(limit)

	for _, subscriptionID := range subscriptionIDs {
		subscriptionID := subscriptionID
		group.Go(func() error {
			subResults, err := e.syncSubscription(ctx, subscriptionID, tables)
			if err != nil {
				mu.Lock()
				errs = append(errs, err)
				mu.Unlock()
			}
			mu.Lock()
			results = append(results, subResults...)
			mu.Unlock()
			return nil
		})
	}

	_ = group.Wait()
	sortAzureSyncResults(results)

	// Persist change history
	if err := e.persistChangeHistory(ctx, results); err != nil {
		e.logger.Warn("failed to persist change history", "error", err)
	}

	return results, errors.Join(errs...)
}

// ValidateTables ensures required Snowflake tables exist without fetching Azure resources.
func (e *AzureSyncEngine) ValidateTables(ctx context.Context) ([]SyncResult, error) {
	subscriptionIDs, err := e.resolveSubscriptionIDs(ctx)
	if err != nil {
		return nil, fmt.Errorf("resolve azure subscriptions: %w", err)
	}
	tables := filterAzureTables(e.getAzureTables(), e.tableFilter)
	if len(e.tableFilter) > 0 && len(tables) == 0 {
		return nil, fmt.Errorf("no Azure tables matched filter: %s", strings.Join(filterNames(e.tableFilter), ", "))
	}
	results := make([]SyncResult, 0, len(tables)*len(subscriptionIDs))
	var mu sync.Mutex
	var errs []error
	var group errgroup.Group
	limit := e.subscriptionConcurrency
	if limit <= 0 {
		limit = 1
	}
	group.SetLimit(limit)

	for _, subscriptionID := range subscriptionIDs {
		subscriptionID := subscriptionID
		group.Go(func() error {
			subResults, err := e.validateSubscription(ctx, subscriptionID, tables)
			if err != nil {
				mu.Lock()
				errs = append(errs, err)
				mu.Unlock()
			}
			mu.Lock()
			results = append(results, subResults...)
			mu.Unlock()
			return nil
		})
	}

	_ = group.Wait()
	sortAzureSyncResults(results)
	return results, errors.Join(errs...)
}

func (e *AzureSyncEngine) resolveSubscriptionIDs(ctx context.Context) ([]string, error) {
	explicit := NormalizeAzureSubscriptionIDs(append(append([]string{}, e.subscriptionIDs...), e.subscriptionID))
	if len(explicit) > 0 {
		return explicit, nil
	}
	if strings.TrimSpace(e.managementGroupID) != "" {
		return e.listManagementGroupSubscriptions(ctx, e.managementGroupID)
	}
	return e.listEnabledSubscriptions(ctx)
}

func (e *AzureSyncEngine) listEnabledSubscriptions(ctx context.Context) ([]string, error) {
	if e.listEnabledFunc != nil {
		return e.listEnabledFunc(ctx)
	}

	client, err := armsubscriptions.NewClient(e.credential, nil)
	if err != nil {
		return nil, err
	}

	pager := client.NewListPager(nil)
	subscriptionIDs := make([]string, 0)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, sub := range page.Value {
			if sub.SubscriptionID != nil && sub.State != nil && *sub.State == armsubscriptions.SubscriptionStateEnabled {
				subscriptionIDs = append(subscriptionIDs, strings.TrimSpace(*sub.SubscriptionID))
			}
		}
	}
	subscriptionIDs = NormalizeAzureSubscriptionIDs(subscriptionIDs)
	if len(subscriptionIDs) == 0 {
		return nil, fmt.Errorf("no enabled subscriptions found")
	}
	return subscriptionIDs, nil
}

func (e *AzureSyncEngine) listManagementGroupSubscriptions(ctx context.Context, managementGroupID string) ([]string, error) {
	enabledSubscriptions, err := e.listEnabledSubscriptions(ctx)
	if err != nil {
		return nil, err
	}

	credential := e.tokenCredential
	if credential == nil {
		credential = e.credential
	}
	if credential == nil {
		return nil, fmt.Errorf("azure token credential not configured")
	}

	token, err := credential.GetToken(ctx, azpolicy.TokenRequestOptions{Scopes: []string{"https://management.azure.com/.default"}})
	if err != nil {
		return nil, fmt.Errorf("acquire Azure management token: %w", err)
	}

	endpoint, err := buildAzureManagementGroupURL(managementGroupID)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("azure management group query failed for %s: status %d", strings.TrimSpace(managementGroupID), resp.StatusCode)
	}

	var payload map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("decode Azure management group response: %w", err)
	}

	subscriptionIDs := extractAzureManagementGroupSubscriptionIDs(payload)
	if len(subscriptionIDs) == 0 {
		return nil, fmt.Errorf("no subscriptions found under management group %s", strings.TrimSpace(managementGroupID))
	}

	enabledSet := make(map[string]struct{}, len(enabledSubscriptions))
	for _, subscriptionID := range enabledSubscriptions {
		enabledSet[strings.ToLower(subscriptionID)] = struct{}{}
	}

	filtered := make([]string, 0, len(subscriptionIDs))
	for _, subscriptionID := range subscriptionIDs {
		if _, ok := enabledSet[strings.ToLower(subscriptionID)]; ok {
			filtered = append(filtered, subscriptionID)
		}
	}
	filtered = NormalizeAzureSubscriptionIDs(filtered)
	if len(filtered) == 0 {
		return nil, fmt.Errorf("no enabled subscriptions found under management group %s", strings.TrimSpace(managementGroupID))
	}
	return filtered, nil
}

func buildAzureManagementGroupURL(managementGroupID string) (string, error) {
	groupID := strings.TrimSpace(managementGroupID)
	if groupID == "" {
		return "", fmt.Errorf("azure management group ID is required")
	}
	params := url.Values{}
	params.Set("api-version", "2020-05-01")
	params.Set("$expand", "children")
	params.Set("$recurse", "true")
	return fmt.Sprintf(
		"https://management.azure.com/providers/Microsoft.Management/managementGroups/%s?%s",
		url.PathEscape(groupID),
		params.Encode(),
	), nil
}

func extractAzureManagementGroupSubscriptionIDs(payload map[string]any) []string {
	if payload == nil {
		return nil
	}
	seen := make(map[string]struct{})
	var subscriptionIDs []string
	var walk func(map[string]any)
	walk = func(node map[string]any) {
		if node == nil {
			return
		}
		if subscriptionID := azureManagementGroupSubscriptionID(node); subscriptionID != "" {
			if _, ok := seen[subscriptionID]; !ok {
				seen[subscriptionID] = struct{}{}
				subscriptionIDs = append(subscriptionIDs, subscriptionID)
			}
		}
		for _, child := range azureManagementGroupChildren(node) {
			walk(child)
		}
	}
	walk(payload)
	sort.Strings(subscriptionIDs)
	return subscriptionIDs
}

func azureManagementGroupChildren(node map[string]any) []map[string]any {
	children := make([]map[string]any, 0)
	appendChildren := func(raw any) {
		items, ok := raw.([]any)
		if !ok {
			return
		}
		for _, item := range items {
			child, ok := item.(map[string]any)
			if !ok {
				continue
			}
			children = append(children, child)
		}
	}
	appendChildren(node["children"])
	if properties, ok := node["properties"].(map[string]any); ok {
		appendChildren(properties["children"])
	}
	return children
}

func azureManagementGroupSubscriptionID(node map[string]any) string {
	childType := strings.ToLower(strings.TrimSpace(stringValue(node["childType"])))
	resourceType := strings.ToLower(strings.TrimSpace(stringValue(node["type"])))
	id := strings.TrimSpace(stringValue(node["id"]))
	name := strings.TrimSpace(stringValue(node["name"]))

	isSubscription := childType == "subscription" ||
		strings.Contains(resourceType, "/subscriptions") ||
		strings.HasPrefix(strings.ToLower(id), "/subscriptions/")
	if !isSubscription {
		return ""
	}
	if name != "" && !strings.Contains(strings.ToLower(name), "managementgroup") {
		return name
	}
	if strings.HasPrefix(strings.ToLower(id), "/subscriptions/") {
		parts := strings.Split(strings.Trim(id, "/"), "/")
		if len(parts) >= 2 {
			return strings.TrimSpace(parts[1])
		}
	}
	return ""
}

// NormalizeAzureSubscriptionIDs trims, de-duplicates case-insensitively, and
// sorts Azure subscription IDs for stable downstream execution.
func NormalizeAzureSubscriptionIDs(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	normalized := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		key := strings.ToLower(trimmed)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		normalized = append(normalized, trimmed)
	}
	if len(normalized) == 0 {
		return nil
	}
	sort.Strings(normalized)
	return normalized
}

func sortAzureSyncResults(results []SyncResult) {
	sort.Slice(results, func(i, j int) bool {
		if results[i].Region == results[j].Region {
			return results[i].Table < results[j].Table
		}
		return results[i].Region < results[j].Region
	})
}

func (e *AzureSyncEngine) syncSubscription(ctx context.Context, subscriptionID string, tables []AzureTableSpec) ([]SyncResult, error) {
	results := make([]SyncResult, len(tables))
	var mu sync.Mutex
	var errs []error
	var group errgroup.Group
	limit := e.concurrency
	if limit <= 0 {
		limit = 1
	}
	group.SetLimit(limit)

	for i, table := range tables {
		idx := i
		tableSpec := table
		group.Go(func() error {
			result, err := e.syncTable(ctx, tableSpec, subscriptionID)
			results[idx] = result
			if err != nil {
				mu.Lock()
				errs = append(errs, err)
				mu.Unlock()
			}
			return nil
		})
	}

	_ = group.Wait()
	return results, errors.Join(errs...)
}

func (e *AzureSyncEngine) validateSubscription(ctx context.Context, subscriptionID string, tables []AzureTableSpec) ([]SyncResult, error) {
	results := make([]SyncResult, len(tables))
	var mu sync.Mutex
	var errs []error
	var group errgroup.Group
	limit := e.concurrency
	if limit <= 0 {
		limit = 1
	}
	group.SetLimit(limit)

	for i, table := range tables {
		idx := i
		tableSpec := table
		group.Go(func() error {
			result, err := e.validateTable(ctx, tableSpec, subscriptionID)
			results[idx] = result
			if err != nil {
				mu.Lock()
				errs = append(errs, err)
				mu.Unlock()
			}
			return nil
		})
	}

	_ = group.Wait()
	return results, errors.Join(errs...)
}

func (e *AzureSyncEngine) syncTable(ctx context.Context, table AzureTableSpec, subscriptionID string) (SyncResult, error) {
	start := time.Now()
	result := SyncResult{
		Table:  table.Name,
		Region: subscriptionID,
	}
	defer func() {
		if result.Duration == 0 {
			result.Duration = time.Since(start)
		}
		metrics.RecordSyncMetrics("azure", result.Table, result.Region, result.Duration, result.Synced, result.Errors)
	}()

	if err := snowflake.ValidateTableName(table.Name); err != nil {
		result.Errors = 1
		result.Error = err.Error()
		result.Duration = time.Since(start)
		return result, fmt.Errorf("azure %s (subscription %s): invalid table name: %w", table.Name, subscriptionID, err)
	}

	e.logger.Info("syncing", "table", table.Name, "subscription_id", subscriptionID)

	if err := e.ensureTable(ctx, table.Name, table.Columns); err != nil {
		e.logger.Error("ensure table failed", "table", table.Name, "error", err)
		result.Errors = 1
		result.Error = err.Error()
		result.Duration = time.Since(start)
		return result, fmt.Errorf("azure %s (subscription %s): ensure table: %w", table.Name, subscriptionID, err)
	}

	rows, err := e.fetchWithRetry(ctx, table, subscriptionID)
	if err != nil {
		e.logger.Error("fetch failed", "table", table.Name, "error", err)
		result.Errors = 1
		result.Error = err.Error()
		result.Duration = time.Since(start)
		return result, fmt.Errorf("azure %s (subscription %s): fetch: %w", table.Name, subscriptionID, err)
	}

	rows = normalizeRows(table.Name, table.Columns, rows, e.logger)

	changes, err := e.upsertWithChanges(ctx, table.Name, table.Columns, rows, subscriptionID)
	if err != nil {
		e.logger.Error("upsert failed", "table", table.Name, "error", err)
		result.Errors = 1
		result.Error = err.Error()
		result.Duration = time.Since(start)
		return result, fmt.Errorf("azure %s (subscription %s): upsert: %w", table.Name, subscriptionID, err)
	}

	result.Synced = len(rows)
	result.Changes = changes
	result.Duration = time.Since(start)

	if changes.HasChanges() {
		e.logger.Info("detected changes", "table", table.Name, "added", len(changes.Added), "modified", len(changes.Modified), "removed", len(changes.Removed))
	}

	e.logger.Info("synced", "table", table.Name, "count", result.Synced, "subscription_id", subscriptionID)
	return result, nil
}

func (e *AzureSyncEngine) validateTable(ctx context.Context, table AzureTableSpec, subscriptionID string) (SyncResult, error) {
	start := time.Now()
	result := SyncResult{
		Table:  table.Name,
		Region: subscriptionID,
	}
	defer func() {
		if result.Duration == 0 {
			result.Duration = time.Since(start)
		}
		metrics.RecordSyncMetrics("azure", result.Table, result.Region, result.Duration, result.Synced, result.Errors)
	}()

	if err := snowflake.ValidateTableName(table.Name); err != nil {
		result.Errors = 1
		result.Error = err.Error()
		result.Duration = time.Since(start)
		return result, fmt.Errorf("azure %s (subscription %s): invalid table name: %w", table.Name, subscriptionID, err)
	}

	if err := e.ensureTable(ctx, table.Name, table.Columns); err != nil {
		e.logger.Error("ensure table failed", "table", table.Name, "error", err)
		result.Errors = 1
		result.Error = err.Error()
		result.Duration = time.Since(start)
		return result, fmt.Errorf("azure %s (subscription %s): ensure table: %w", table.Name, subscriptionID, err)
	}

	result.Duration = time.Since(start)
	return result, nil
}

func (e *AzureSyncEngine) ensureTable(ctx context.Context, table string, columns []string) error {
	return tableops.EnsureVariantTable(ctx, e.sf, table, columns, tableops.EnsureVariantTableOptions{
		AddMissingColumns: false,
	})
}

func (e *AzureSyncEngine) upsertWithChanges(ctx context.Context, table string, columns []string, rows []map[string]interface{}, subscriptionID string) (*ChangeSet, error) {
	scopeColumn, scopeValues := azureScopeFilter(columns, rows, subscriptionID)
	return upsertScopedRowsWithChanges(ctx, e.sf, e.logger, table, rows, scopeColumn, scopeValues, e.hashRowContent, false)
}

func azureScopeFilter(columns []string, rows []map[string]interface{}, subscriptionID string) (string, []string) {
	if !hasColumn(columns, "subscription_id") {
		return "", nil
	}

	values := make(map[string]struct{})
	for _, row := range rows {
		if row == nil {
			continue
		}
		raw, ok := row["subscription_id"]
		if !ok || raw == nil {
			continue
		}
		if val := strings.TrimSpace(stringValue(raw)); val != "" {
			values[val] = struct{}{}
		}
	}
	if len(values) == 0 && strings.TrimSpace(subscriptionID) != "" {
		values[strings.TrimSpace(subscriptionID)] = struct{}{}
	}

	out := make([]string, 0, len(values))
	for val := range values {
		out = append(out, val)
	}
	sort.Strings(out)
	return "SUBSCRIPTION_ID", out
}

func (e *AzureSyncEngine) hashRowContent(row map[string]interface{}) string {
	return hashRowContentWithMode(row, false)
}

func (e *AzureSyncEngine) persistChangeHistory(ctx context.Context, results []SyncResult) error {
	return persistProviderChangeHistory(ctx, e.sf, e.logger, "azure", results)
}

// getAzureTables returns all Azure table definitions
func (e *AzureSyncEngine) getAzureTables() []AzureTableSpec {
	return []AzureTableSpec{
		e.azureVirtualMachineTable(),
		e.azureAKSClusterTable(),
		e.azureAKSNodePoolTable(),
		e.azureRBACRoleAssignmentTable(),
		e.azurePolicyAssignmentTable(),
		e.azureGraphServicePrincipalTable(),
		e.azureDefenderAssessmentTable(),
		e.azureStorageAccountTable(),
		e.azureStorageContainerTable(),
		e.azureStorageBlobTable(),
		e.azureNetworkSecurityGroupTable(),
		e.azureVirtualNetworkTable(),
		e.azureSQLServerTable(),
		e.azureSQLDatabaseTable(),
		e.azureKeyVaultTable(),
		e.azureKeyVaultKeyTable(),
		e.azureLoadBalancerTable(),
		e.azurePublicIPTable(),
		e.azureNetworkInterfaceTable(),
		e.azureDiskTable(),
		e.azureFunctionAppTable(),
	}
}

// Azure Virtual Machines
func (e *AzureSyncEngine) azureVirtualMachineTable() AzureTableSpec {
	return AzureTableSpec{
		Name: "azure_compute_virtual_machines",
		Columns: []string{
			"id", "name", "location", "resource_group", "vm_size", "os_type",
			"os_disk", "data_disks", "network_interfaces", "availability_set",
			"zones", "identity", "tags", "provisioning_state", "subscription_id",
		},
		Fetch: func(ctx context.Context, cred *azidentity.DefaultAzureCredential, subscriptionID string) ([]map[string]interface{}, error) {
			client, err := armcompute.NewVirtualMachinesClient(subscriptionID, cred, nil)
			if err != nil {
				return nil, err
			}

			var results []map[string]interface{}
			pager := client.NewListAllPager(nil)
			for pager.More() {
				page, err := pager.NextPage(ctx)
				if err != nil {
					return nil, err
				}
				for _, vm := range page.Value {
					row := map[string]interface{}{
						"_cq_id":          *vm.ID,
						"id":              ptrStr(vm.ID),
						"name":            ptrStr(vm.Name),
						"location":        ptrStr(vm.Location),
						"subscription_id": subscriptionID,
						"tags":            vm.Tags,
					}

					if vm.Properties != nil {
						row["provisioning_state"] = ptrStr(vm.Properties.ProvisioningState)
						if vm.Properties.HardwareProfile != nil {
							row["vm_size"] = string(*vm.Properties.HardwareProfile.VMSize)
						}
						if vm.Properties.StorageProfile != nil {
							if vm.Properties.StorageProfile.OSDisk != nil {
								row["os_type"] = string(*vm.Properties.StorageProfile.OSDisk.OSType)
								row["os_disk"] = vm.Properties.StorageProfile.OSDisk
							}
							row["data_disks"] = vm.Properties.StorageProfile.DataDisks
						}
						if vm.Properties.NetworkProfile != nil {
							row["network_interfaces"] = vm.Properties.NetworkProfile.NetworkInterfaces
						}
						if vm.Properties.AvailabilitySet != nil {
							row["availability_set"] = ptrStr(vm.Properties.AvailabilitySet.ID)
						}
					}

					row["zones"] = vm.Zones
					row["identity"] = vm.Identity

					// Extract resource group from ID
					if vm.ID != nil {
						parts := strings.Split(*vm.ID, "/")
						for i, p := range parts {
							if strings.EqualFold(p, "resourceGroups") && i+1 < len(parts) {
								row["resource_group"] = parts[i+1]
								break
							}
						}
					}

					results = append(results, row)
				}
			}
			return results, nil
		},
	}
}

// Azure Storage Accounts
func (e *AzureSyncEngine) azureStorageAccountTable() AzureTableSpec {
	return AzureTableSpec{
		Name: "azure_storage_accounts",
		Columns: []string{
			"id", "name", "location", "resource_group", "sku", "kind",
			"access_tier", "https_only", "minimum_tls_version", "allow_blob_public_access",
			"network_acls", "encryption", "primary_endpoints", "tags", "subscription_id",
		},
		Fetch: func(ctx context.Context, cred *azidentity.DefaultAzureCredential, subscriptionID string) ([]map[string]interface{}, error) {
			client, err := armstorage.NewAccountsClient(subscriptionID, cred, nil)
			if err != nil {
				return nil, err
			}

			var results []map[string]interface{}
			pager := client.NewListPager(nil)
			for pager.More() {
				page, err := pager.NextPage(ctx)
				if err != nil {
					return nil, err
				}
				for _, sa := range page.Value {
					row := map[string]interface{}{
						"_cq_id":          *sa.ID,
						"id":              ptrStr(sa.ID),
						"name":            ptrStr(sa.Name),
						"location":        ptrStr(sa.Location),
						"subscription_id": subscriptionID,
						"tags":            sa.Tags,
					}

					if sa.SKU != nil {
						row["sku"] = string(*sa.SKU.Name)
					}
					if sa.Kind != nil {
						row["kind"] = string(*sa.Kind)
					}

					if sa.Properties != nil {
						if sa.Properties.AccessTier != nil {
							row["access_tier"] = string(*sa.Properties.AccessTier)
						}
						row["https_only"] = sa.Properties.EnableHTTPSTrafficOnly
						if sa.Properties.MinimumTLSVersion != nil {
							row["minimum_tls_version"] = string(*sa.Properties.MinimumTLSVersion)
						}
						row["allow_blob_public_access"] = sa.Properties.AllowBlobPublicAccess
						row["network_acls"] = sa.Properties.NetworkRuleSet
						row["encryption"] = sa.Properties.Encryption
						row["primary_endpoints"] = sa.Properties.PrimaryEndpoints
					}

					if sa.ID != nil {
						parts := strings.Split(*sa.ID, "/")
						for i, p := range parts {
							if strings.EqualFold(p, "resourceGroups") && i+1 < len(parts) {
								row["resource_group"] = parts[i+1]
								break
							}
						}
					}

					results = append(results, row)
				}
			}
			return results, nil
		},
	}
}

// Azure Network Security Groups
func (e *AzureSyncEngine) azureNetworkSecurityGroupTable() AzureTableSpec {
	return AzureTableSpec{
		Name: "azure_network_security_groups",
		Columns: []string{
			"id", "name", "location", "resource_group", "security_rules",
			"default_security_rules", "network_interfaces", "subnets", "tags", "subscription_id",
		},
		Fetch: func(ctx context.Context, cred *azidentity.DefaultAzureCredential, subscriptionID string) ([]map[string]interface{}, error) {
			client, err := armnetwork.NewSecurityGroupsClient(subscriptionID, cred, nil)
			if err != nil {
				return nil, err
			}

			var results []map[string]interface{}
			pager := client.NewListAllPager(nil)
			for pager.More() {
				page, err := pager.NextPage(ctx)
				if err != nil {
					return nil, err
				}
				for _, nsg := range page.Value {
					row := map[string]interface{}{
						"_cq_id":          *nsg.ID,
						"id":              ptrStr(nsg.ID),
						"name":            ptrStr(nsg.Name),
						"location":        ptrStr(nsg.Location),
						"subscription_id": subscriptionID,
						"tags":            nsg.Tags,
					}

					if nsg.Properties != nil {
						row["security_rules"] = nsg.Properties.SecurityRules
						row["default_security_rules"] = nsg.Properties.DefaultSecurityRules
						row["network_interfaces"] = nsg.Properties.NetworkInterfaces
						row["subnets"] = nsg.Properties.Subnets
					}

					if nsg.ID != nil {
						parts := strings.Split(*nsg.ID, "/")
						for i, p := range parts {
							if strings.EqualFold(p, "resourceGroups") && i+1 < len(parts) {
								row["resource_group"] = parts[i+1]
								break
							}
						}
					}

					results = append(results, row)
				}
			}
			return results, nil
		},
	}
}

// Azure Virtual Networks
func (e *AzureSyncEngine) azureVirtualNetworkTable() AzureTableSpec {
	return AzureTableSpec{
		Name: "azure_network_virtual_networks",
		Columns: []string{
			"id", "name", "location", "resource_group", "address_space",
			"subnets", "peerings", "enable_ddos_protection", "tags", "subscription_id",
		},
		Fetch: func(ctx context.Context, cred *azidentity.DefaultAzureCredential, subscriptionID string) ([]map[string]interface{}, error) {
			client, err := armnetwork.NewVirtualNetworksClient(subscriptionID, cred, nil)
			if err != nil {
				return nil, err
			}

			var results []map[string]interface{}
			pager := client.NewListAllPager(nil)
			for pager.More() {
				page, err := pager.NextPage(ctx)
				if err != nil {
					return nil, err
				}
				for _, vnet := range page.Value {
					row := map[string]interface{}{
						"_cq_id":          *vnet.ID,
						"id":              ptrStr(vnet.ID),
						"name":            ptrStr(vnet.Name),
						"location":        ptrStr(vnet.Location),
						"subscription_id": subscriptionID,
						"tags":            vnet.Tags,
					}

					if vnet.Properties != nil {
						row["address_space"] = vnet.Properties.AddressSpace
						row["subnets"] = vnet.Properties.Subnets
						row["peerings"] = vnet.Properties.VirtualNetworkPeerings
						row["enable_ddos_protection"] = vnet.Properties.EnableDdosProtection
					}

					if vnet.ID != nil {
						parts := strings.Split(*vnet.ID, "/")
						for i, p := range parts {
							if strings.EqualFold(p, "resourceGroups") && i+1 < len(parts) {
								row["resource_group"] = parts[i+1]
								break
							}
						}
					}

					results = append(results, row)
				}
			}
			return results, nil
		},
	}
}

// Azure SQL Servers
func (e *AzureSyncEngine) azureSQLServerTable() AzureTableSpec {
	return AzureTableSpec{
		Name: "azure_sql_servers",
		Columns: []string{
			"id", "name", "location", "resource_group", "version", "state",
			"administrator_login", "public_network_access", "minimal_tls_version",
			"tags", "subscription_id",
		},
		Fetch: func(ctx context.Context, cred *azidentity.DefaultAzureCredential, subscriptionID string) ([]map[string]interface{}, error) {
			client, err := armsql.NewServersClient(subscriptionID, cred, nil)
			if err != nil {
				return nil, err
			}

			var results []map[string]interface{}
			pager := client.NewListPager(nil)
			for pager.More() {
				page, err := pager.NextPage(ctx)
				if err != nil {
					return nil, err
				}
				for _, server := range page.Value {
					row := map[string]interface{}{
						"_cq_id":          *server.ID,
						"id":              ptrStr(server.ID),
						"name":            ptrStr(server.Name),
						"location":        ptrStr(server.Location),
						"subscription_id": subscriptionID,
						"tags":            server.Tags,
					}

					if server.Properties != nil {
						row["version"] = ptrStr(server.Properties.Version)
						row["state"] = ptrStr(server.Properties.State)
						row["administrator_login"] = ptrStr(server.Properties.AdministratorLogin)
						if server.Properties.PublicNetworkAccess != nil {
							row["public_network_access"] = string(*server.Properties.PublicNetworkAccess)
						}
						if server.Properties.MinimalTLSVersion != nil {
							row["minimal_tls_version"] = string(*server.Properties.MinimalTLSVersion)
						}
					}

					if server.ID != nil {
						parts := strings.Split(*server.ID, "/")
						for i, p := range parts {
							if strings.EqualFold(p, "resourceGroups") && i+1 < len(parts) {
								row["resource_group"] = parts[i+1]
								break
							}
						}
					}

					results = append(results, row)
				}
			}
			return results, nil
		},
	}
}

// Azure SQL Databases
func (e *AzureSyncEngine) azureSQLDatabaseTable() AzureTableSpec {
	return AzureTableSpec{
		Name: "azure_sql_databases",
		Columns: []string{
			"id", "name", "location", "resource_group", "server_name", "status",
			"collation", "max_size_bytes", "sku", "zone_redundant",
			"transparent_data_encryption", "tags", "subscription_id",
		},
		Fetch: func(ctx context.Context, cred *azidentity.DefaultAzureCredential, subscriptionID string) ([]map[string]interface{}, error) {
			serverClient, err := armsql.NewServersClient(subscriptionID, cred, nil)
			if err != nil {
				return nil, err
			}

			dbClient, err := armsql.NewDatabasesClient(subscriptionID, cred, nil)
			if err != nil {
				return nil, err
			}

			var results []map[string]interface{}

			// List all servers first
			serverPager := serverClient.NewListPager(nil)
			for serverPager.More() {
				serverPage, err := serverPager.NextPage(ctx)
				if err != nil {
					return nil, err
				}

				for _, server := range serverPage.Value {
					if server.Name == nil || server.ID == nil {
						continue
					}

					// Extract resource group
					var resourceGroup string
					parts := strings.Split(*server.ID, "/")
					for i, p := range parts {
						if strings.EqualFold(p, "resourceGroups") && i+1 < len(parts) {
							resourceGroup = parts[i+1]
							break
						}
					}

					// List databases for this server
					dbPager := dbClient.NewListByServerPager(resourceGroup, *server.Name, nil)
					for dbPager.More() {
						dbPage, err := dbPager.NextPage(ctx)
						if err != nil {
							continue // Skip on error, don't fail entire sync
						}

						for _, db := range dbPage.Value {
							row := map[string]interface{}{
								"_cq_id":          *db.ID,
								"id":              ptrStr(db.ID),
								"name":            ptrStr(db.Name),
								"location":        ptrStr(db.Location),
								"resource_group":  resourceGroup,
								"server_name":     *server.Name,
								"subscription_id": subscriptionID,
								"tags":            db.Tags,
							}

							if db.Properties != nil {
								row["status"] = string(*db.Properties.Status)
								row["collation"] = ptrStr(db.Properties.Collation)
								row["max_size_bytes"] = db.Properties.MaxSizeBytes
								row["zone_redundant"] = db.Properties.ZoneRedundant
							}

							if db.SKU != nil {
								row["sku"] = map[string]interface{}{
									"name":     ptrStr(db.SKU.Name),
									"tier":     ptrStr(db.SKU.Tier),
									"capacity": db.SKU.Capacity,
								}
							}

							results = append(results, row)
						}
					}
				}
			}

			return results, nil
		},
	}
}

// Azure Key Vaults
func (e *AzureSyncEngine) azureKeyVaultTable() AzureTableSpec {
	return AzureTableSpec{
		Name: "azure_keyvault_vaults",
		Columns: []string{
			"id", "name", "location", "resource_group", "vault_uri",
			"sku", "tenant_id", "access_policies", "enable_soft_delete",
			"soft_delete_retention_days", "enable_purge_protection",
			"network_acls", "tags", "subscription_id",
		},
		Fetch: func(ctx context.Context, cred *azidentity.DefaultAzureCredential, subscriptionID string) ([]map[string]interface{}, error) {
			client, err := armkeyvault.NewVaultsClient(subscriptionID, cred, nil)
			if err != nil {
				return nil, err
			}

			var results []map[string]interface{}
			pager := client.NewListBySubscriptionPager(nil)
			for pager.More() {
				page, err := pager.NextPage(ctx)
				if err != nil {
					return nil, err
				}
				for _, vault := range page.Value {
					row := map[string]interface{}{
						"_cq_id":          *vault.ID,
						"id":              ptrStr(vault.ID),
						"name":            ptrStr(vault.Name),
						"location":        ptrStr(vault.Location),
						"subscription_id": subscriptionID,
						"tags":            vault.Tags,
					}

					if vault.Properties != nil {
						row["vault_uri"] = ptrStr(vault.Properties.VaultURI)
						row["tenant_id"] = ptrStr(vault.Properties.TenantID)
						row["access_policies"] = vault.Properties.AccessPolicies
						row["enable_soft_delete"] = vault.Properties.EnableSoftDelete
						row["soft_delete_retention_days"] = vault.Properties.SoftDeleteRetentionInDays
						row["enable_purge_protection"] = vault.Properties.EnablePurgeProtection
						row["network_acls"] = vault.Properties.NetworkACLs

						if vault.Properties.SKU != nil {
							row["sku"] = string(*vault.Properties.SKU.Name)
						}
					}

					if vault.ID != nil {
						parts := strings.Split(*vault.ID, "/")
						for i, p := range parts {
							if strings.EqualFold(p, "resourceGroups") && i+1 < len(parts) {
								row["resource_group"] = parts[i+1]
								break
							}
						}
					}

					results = append(results, row)
				}
			}
			return results, nil
		},
	}
}

// Azure Load Balancers
func (e *AzureSyncEngine) azureLoadBalancerTable() AzureTableSpec {
	return AzureTableSpec{
		Name: "azure_network_load_balancers",
		Columns: []string{
			"id", "name", "location", "resource_group", "sku",
			"frontend_ip_configurations", "backend_address_pools",
			"load_balancing_rules", "probes", "inbound_nat_rules",
			"tags", "subscription_id",
		},
		Fetch: func(ctx context.Context, cred *azidentity.DefaultAzureCredential, subscriptionID string) ([]map[string]interface{}, error) {
			client, err := armnetwork.NewLoadBalancersClient(subscriptionID, cred, nil)
			if err != nil {
				return nil, err
			}

			var results []map[string]interface{}
			pager := client.NewListAllPager(nil)
			for pager.More() {
				page, err := pager.NextPage(ctx)
				if err != nil {
					return nil, err
				}
				for _, lb := range page.Value {
					row := map[string]interface{}{
						"_cq_id":          *lb.ID,
						"id":              ptrStr(lb.ID),
						"name":            ptrStr(lb.Name),
						"location":        ptrStr(lb.Location),
						"subscription_id": subscriptionID,
						"tags":            lb.Tags,
					}

					if lb.SKU != nil {
						row["sku"] = string(*lb.SKU.Name)
					}

					if lb.Properties != nil {
						row["frontend_ip_configurations"] = lb.Properties.FrontendIPConfigurations
						row["backend_address_pools"] = lb.Properties.BackendAddressPools
						row["load_balancing_rules"] = lb.Properties.LoadBalancingRules
						row["probes"] = lb.Properties.Probes
						row["inbound_nat_rules"] = lb.Properties.InboundNatRules
					}

					if lb.ID != nil {
						parts := strings.Split(*lb.ID, "/")
						for i, p := range parts {
							if strings.EqualFold(p, "resourceGroups") && i+1 < len(parts) {
								row["resource_group"] = parts[i+1]
								break
							}
						}
					}

					results = append(results, row)
				}
			}
			return results, nil
		},
	}
}

// Azure Public IPs
func (e *AzureSyncEngine) azurePublicIPTable() AzureTableSpec {
	return AzureTableSpec{
		Name: "azure_network_public_ip_addresses",
		Columns: []string{
			"id", "name", "location", "resource_group", "sku",
			"ip_address", "public_ip_allocation_method", "public_ip_address_version",
			"dns_settings", "ip_configuration", "tags", "subscription_id",
		},
		Fetch: func(ctx context.Context, cred *azidentity.DefaultAzureCredential, subscriptionID string) ([]map[string]interface{}, error) {
			client, err := armnetwork.NewPublicIPAddressesClient(subscriptionID, cred, nil)
			if err != nil {
				return nil, err
			}

			var results []map[string]interface{}
			pager := client.NewListAllPager(nil)
			for pager.More() {
				page, err := pager.NextPage(ctx)
				if err != nil {
					return nil, err
				}
				for _, pip := range page.Value {
					row := map[string]interface{}{
						"_cq_id":          *pip.ID,
						"id":              ptrStr(pip.ID),
						"name":            ptrStr(pip.Name),
						"location":        ptrStr(pip.Location),
						"subscription_id": subscriptionID,
						"tags":            pip.Tags,
					}

					if pip.SKU != nil {
						row["sku"] = string(*pip.SKU.Name)
					}

					if pip.Properties != nil {
						row["ip_address"] = ptrStr(pip.Properties.IPAddress)
						if pip.Properties.PublicIPAllocationMethod != nil {
							row["public_ip_allocation_method"] = string(*pip.Properties.PublicIPAllocationMethod)
						}
						if pip.Properties.PublicIPAddressVersion != nil {
							row["public_ip_address_version"] = string(*pip.Properties.PublicIPAddressVersion)
						}
						row["dns_settings"] = pip.Properties.DNSSettings
						row["ip_configuration"] = pip.Properties.IPConfiguration
					}

					if pip.ID != nil {
						parts := strings.Split(*pip.ID, "/")
						for i, p := range parts {
							if strings.EqualFold(p, "resourceGroups") && i+1 < len(parts) {
								row["resource_group"] = parts[i+1]
								break
							}
						}
					}

					results = append(results, row)
				}
			}
			return results, nil
		},
	}
}

// Azure Network Interfaces
func (e *AzureSyncEngine) azureNetworkInterfaceTable() AzureTableSpec {
	return AzureTableSpec{
		Name: "azure_network_interfaces",
		Columns: []string{
			"id", "name", "location", "resource_group", "mac_address",
			"ip_configurations", "dns_settings", "network_security_group",
			"virtual_machine", "tags", "subscription_id",
		},
		Fetch: func(ctx context.Context, cred *azidentity.DefaultAzureCredential, subscriptionID string) ([]map[string]interface{}, error) {
			client, err := armnetwork.NewInterfacesClient(subscriptionID, cred, nil)
			if err != nil {
				return nil, err
			}

			var results []map[string]interface{}
			pager := client.NewListAllPager(nil)
			for pager.More() {
				page, err := pager.NextPage(ctx)
				if err != nil {
					return nil, err
				}
				for _, nic := range page.Value {
					row := map[string]interface{}{
						"_cq_id":          *nic.ID,
						"id":              ptrStr(nic.ID),
						"name":            ptrStr(nic.Name),
						"location":        ptrStr(nic.Location),
						"subscription_id": subscriptionID,
						"tags":            nic.Tags,
					}

					if nic.Properties != nil {
						row["mac_address"] = ptrStr(nic.Properties.MacAddress)
						row["ip_configurations"] = nic.Properties.IPConfigurations
						row["dns_settings"] = nic.Properties.DNSSettings
						if nic.Properties.NetworkSecurityGroup != nil {
							row["network_security_group"] = ptrStr(nic.Properties.NetworkSecurityGroup.ID)
						}
						if nic.Properties.VirtualMachine != nil {
							row["virtual_machine"] = ptrStr(nic.Properties.VirtualMachine.ID)
						}
					}

					if nic.ID != nil {
						parts := strings.Split(*nic.ID, "/")
						for i, p := range parts {
							if strings.EqualFold(p, "resourceGroups") && i+1 < len(parts) {
								row["resource_group"] = parts[i+1]
								break
							}
						}
					}

					results = append(results, row)
				}
			}
			return results, nil
		},
	}
}

// Azure Disks
func (e *AzureSyncEngine) azureDiskTable() AzureTableSpec {
	return AzureTableSpec{
		Name: "azure_compute_disks",
		Columns: []string{
			"id", "name", "location", "resource_group", "sku",
			"disk_size_gb", "disk_state", "os_type", "encryption_settings",
			"managed_by", "zones", "tags", "subscription_id",
		},
		Fetch: func(ctx context.Context, cred *azidentity.DefaultAzureCredential, subscriptionID string) ([]map[string]interface{}, error) {
			client, err := armcompute.NewDisksClient(subscriptionID, cred, nil)
			if err != nil {
				return nil, err
			}

			var results []map[string]interface{}
			pager := client.NewListPager(nil)
			for pager.More() {
				page, err := pager.NextPage(ctx)
				if err != nil {
					return nil, err
				}
				for _, disk := range page.Value {
					row := map[string]interface{}{
						"_cq_id":          *disk.ID,
						"id":              ptrStr(disk.ID),
						"name":            ptrStr(disk.Name),
						"location":        ptrStr(disk.Location),
						"subscription_id": subscriptionID,
						"tags":            disk.Tags,
						"managed_by":      ptrStr(disk.ManagedBy),
						"zones":           disk.Zones,
					}

					if disk.SKU != nil {
						row["sku"] = string(*disk.SKU.Name)
					}

					if disk.Properties != nil {
						row["disk_size_gb"] = disk.Properties.DiskSizeGB
						if disk.Properties.DiskState != nil {
							row["disk_state"] = string(*disk.Properties.DiskState)
						}
						if disk.Properties.OSType != nil {
							row["os_type"] = string(*disk.Properties.OSType)
						}
						row["encryption_settings"] = disk.Properties.EncryptionSettingsCollection
					}

					if disk.ID != nil {
						parts := strings.Split(*disk.ID, "/")
						for i, p := range parts {
							if strings.EqualFold(p, "resourceGroups") && i+1 < len(parts) {
								row["resource_group"] = parts[i+1]
								break
							}
						}
					}

					results = append(results, row)
				}
			}
			return results, nil
		},
	}
}

// Helper function for pointer strings
func ptrStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
