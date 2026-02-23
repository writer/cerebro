package sync

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/writerinternal/cerebro/internal/metrics"
	"github.com/writerinternal/cerebro/internal/snowflake"
)

// K8sEngineOption configures the Kubernetes sync engine.
type K8sEngineOption func(*K8sSyncEngine)

// K8sSyncEngine syncs Kubernetes resources to Snowflake.
type K8sSyncEngine struct {
	sf          *snowflake.Client
	logger      *slog.Logger
	concurrency int
	kubeconfig  string
	kubeContext string
	namespace   string
	tableFilter map[string]struct{}
}

// K8sTableSpec defines a Kubernetes table to sync.
type K8sTableSpec struct {
	Name    string
	Columns []string
	Fetch   func(ctx context.Context, client kubernetes.Interface, namespace, clusterName string) ([]map[string]interface{}, error)
}

// WithK8sKubeconfig sets the kubeconfig path.
func WithK8sKubeconfig(path string) K8sEngineOption {
	return func(e *K8sSyncEngine) { e.kubeconfig = strings.TrimSpace(path) }
}

// WithK8sContext sets the kubeconfig context to use.
func WithK8sContext(name string) K8sEngineOption {
	return func(e *K8sSyncEngine) { e.kubeContext = strings.TrimSpace(name) }
}

// WithK8sNamespace sets the Kubernetes namespace to sync.
func WithK8sNamespace(namespace string) K8sEngineOption {
	return func(e *K8sSyncEngine) { e.namespace = strings.TrimSpace(namespace) }
}

// WithK8sConcurrency sets the concurrency for Kubernetes sync.
func WithK8sConcurrency(concurrency int) K8sEngineOption {
	return func(e *K8sSyncEngine) { e.concurrency = concurrency }
}

// WithK8sTableFilter sets a table filter for Kubernetes sync.
func WithK8sTableFilter(tables []string) K8sEngineOption {
	return func(e *K8sSyncEngine) { e.tableFilter = normalizeTableFilter(tables) }
}

// NewK8sSyncEngine creates a Kubernetes sync engine.
func NewK8sSyncEngine(sf *snowflake.Client, logger *slog.Logger, opts ...K8sEngineOption) *K8sSyncEngine {
	e := &K8sSyncEngine{
		sf:          sf,
		logger:      logger,
		concurrency: 10,
	}
	for _, opt := range opts {
		opt(e)
	}
	if e.logger == nil {
		e.logger = slog.Default()
	}
	return e
}

// SyncAll syncs all Kubernetes tables with change detection.
func (e *K8sSyncEngine) SyncAll(ctx context.Context) ([]SyncResult, error) {
	client, clusterName, namespace, err := e.newClient()
	if err != nil {
		return nil, err
	}

	tables := filterK8sTables(e.getK8sTables(), e.tableFilter)
	if len(e.tableFilter) > 0 && len(tables) == 0 {
		return nil, fmt.Errorf("no Kubernetes tables matched filter: %s", strings.Join(filterNames(e.tableFilter), ", "))
	}

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
			result, err := e.syncTable(ctx, tableSpec, client, clusterName, namespace)
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

	if err := e.persistChangeHistory(ctx, results); err != nil {
		e.logger.Warn("failed to persist change history", "error", err)
	}

	return results, errors.Join(errs...)
}

// ValidateTables ensures the Kubernetes tables exist without fetching resources.
func (e *K8sSyncEngine) ValidateTables(ctx context.Context) ([]SyncResult, error) {
	_, clusterName, _, err := e.newClient()
	if err != nil {
		return nil, err
	}

	tables := filterK8sTables(e.getK8sTables(), e.tableFilter)
	if len(e.tableFilter) > 0 && len(tables) == 0 {
		return nil, fmt.Errorf("no Kubernetes tables matched filter: %s", strings.Join(filterNames(e.tableFilter), ", "))
	}

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
			result, err := e.validateTable(ctx, tableSpec, clusterName)
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

func (e *K8sSyncEngine) syncTable(ctx context.Context, table K8sTableSpec, client kubernetes.Interface, clusterName, namespace string) (SyncResult, error) {
	start := time.Now()
	result := SyncResult{
		Table:  table.Name,
		Region: clusterName,
	}
	defer func() {
		if result.Duration == 0 {
			result.Duration = time.Since(start)
		}
		metrics.RecordSyncMetrics("k8s", result.Table, result.Region, result.Duration, result.Synced, result.Errors)
	}()

	if err := snowflake.ValidateTableName(table.Name); err != nil {
		result.Errors = 1
		result.Error = err.Error()
		result.Duration = time.Since(start)
		return result, fmt.Errorf("k8s %s: invalid table name: %w", table.Name, err)
	}

	e.logger.Info("syncing", "table", table.Name, "cluster", clusterName)

	if err := e.ensureTable(ctx, table.Name, table.Columns); err != nil {
		e.logger.Error("ensure table failed", "table", table.Name, "error", err)
		result.Errors = 1
		result.Error = err.Error()
		result.Duration = time.Since(start)
		return result, fmt.Errorf("k8s %s: ensure table: %w", table.Name, err)
	}

	rows, err := table.Fetch(ctx, client, namespace, clusterName)
	if err != nil {
		e.logger.Error("fetch failed", "table", table.Name, "error", err)
		result.Errors = 1
		result.Error = err.Error()
		result.Duration = time.Since(start)
		return result, fmt.Errorf("k8s %s: fetch: %w", table.Name, err)
	}

	rows = normalizeRows(table.Name, table.Columns, rows, e.logger)

	changes, err := e.upsertWithChanges(ctx, table.Name, rows)
	if err != nil {
		e.logger.Error("upsert failed", "table", table.Name, "error", err)
		result.Errors = 1
		result.Error = err.Error()
		result.Duration = time.Since(start)
		return result, fmt.Errorf("k8s %s: upsert: %w", table.Name, err)
	}

	syncTime := time.Now().UTC()
	if err := e.emitCDCEvents(ctx, table.Name, changes, rows, syncTime, clusterName); err != nil {
		e.logger.Warn("failed to emit CDC events", "table", table.Name, "error", err)
	}

	result.Synced = len(rows)
	result.Changes = changes
	result.SyncTime = syncTime
	result.Duration = time.Since(start)

	if changes.HasChanges() {
		e.logger.Info("detected changes", "table", table.Name, "added", len(changes.Added), "modified", len(changes.Modified), "removed", len(changes.Removed))
	}

	e.logger.Info("synced", "table", table.Name, "count", result.Synced)
	return result, nil
}

func (e *K8sSyncEngine) validateTable(ctx context.Context, table K8sTableSpec, clusterName string) (SyncResult, error) {
	start := time.Now()
	result := SyncResult{
		Table:  table.Name,
		Region: clusterName,
	}
	defer func() {
		if result.Duration == 0 {
			result.Duration = time.Since(start)
		}
		metrics.RecordSyncMetrics("k8s", result.Table, result.Region, result.Duration, result.Synced, result.Errors)
	}()

	if err := snowflake.ValidateTableName(table.Name); err != nil {
		result.Errors = 1
		result.Error = err.Error()
		result.Duration = time.Since(start)
		return result, fmt.Errorf("k8s %s: invalid table name: %w", table.Name, err)
	}

	if err := e.ensureTable(ctx, table.Name, table.Columns); err != nil {
		e.logger.Error("ensure table failed", "table", table.Name, "error", err)
		result.Errors = 1
		result.Error = err.Error()
		result.Duration = time.Since(start)
		return result, fmt.Errorf("k8s %s: ensure table: %w", table.Name, err)
	}

	result.Duration = time.Since(start)
	return result, nil
}

func (e *K8sSyncEngine) emitCDCEvents(ctx context.Context, table string, changes *ChangeSet, rows []map[string]interface{}, syncTime time.Time, clusterName string) error {
	if changes == nil || !changes.HasChanges() {
		return nil
	}

	lookup := buildRowLookup(rows)
	events := buildCDCEventsFromChanges(table, "k8s", clusterName, "", changes, lookup, syncTime, e.hashRowContent)
	if len(events) == 0 {
		return nil
	}

	return e.sf.InsertCDCEvents(ctx, events)
}

func (e *K8sSyncEngine) ensureTable(ctx context.Context, table string, columns []string) error {
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

	if _, err := e.sf.Exec(ctx, createQuery); err != nil {
		return err
	}

	existingCols, err := e.getTableColumns(ctx, table)
	if err != nil {
		return nil
	}

	existingSet := make(map[string]bool)
	for _, col := range existingCols {
		existingSet[strings.ToUpper(col)] = true
	}

	for _, col := range columns {
		upperCol := strings.ToUpper(col)
		if !existingSet[upperCol] {
			alterQuery := fmt.Sprintf("ALTER TABLE %s ADD COLUMN IF NOT EXISTS %s VARIANT", table, upperCol)
			if _, err := e.sf.Exec(ctx, alterQuery); err != nil {
				e.logger.Debug("failed to add column", "table", table, "column", upperCol, "error", err)
			}
		}
	}

	return nil
}

func (e *K8sSyncEngine) getTableColumns(ctx context.Context, table string) ([]string, error) {
	if err := snowflake.ValidateTableName(table); err != nil {
		return nil, err
	}

	query := `
        SELECT COLUMN_NAME
        FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_NAME = ?
        AND TABLE_SCHEMA = CURRENT_SCHEMA()
    `

	result, err := e.sf.Query(ctx, query, strings.ToUpper(table))
	if err != nil {
		return nil, err
	}

	var columns []string
	for _, row := range result.Rows {
		if col := queryRowString(row, "column_name"); col != "" {
			columns = append(columns, col)
		}
	}
	return columns, nil
}

func (e *K8sSyncEngine) upsertWithChanges(ctx context.Context, table string, rows []map[string]interface{}) (*ChangeSet, error) {
	changes := &ChangeSet{}
	if err := snowflake.ValidateTableName(table); err != nil {
		return changes, fmt.Errorf("invalid table name %s: %w", table, err)
	}

	if len(rows) == 0 {
		existing := e.getExistingHashes(ctx, table)
		for id := range existing {
			changes.Removed = append(changes.Removed, id)
		}
		if len(changes.Removed) > 0 {
			if _, err := e.sf.Exec(ctx, fmt.Sprintf("TRUNCATE TABLE %s", table)); err != nil {
				if _, err := e.sf.Exec(ctx, fmt.Sprintf("DELETE FROM %s", table)); err != nil {
					e.logger.Debug("delete failed", "error", err)
				}
			}
		}
		return changes, nil
	}

	existing := e.getExistingHashes(ctx, table)
	newRows := make(map[string]string)
	for _, row := range rows {
		id, ok := row["_cq_id"].(string)
		if !ok {
			continue
		}
		hash := e.hashRowContent(row)
		newRows[id] = hash
	}

	for id, oldHash := range existing {
		if newHash, exists := newRows[id]; !exists {
			changes.Removed = append(changes.Removed, id)
		} else if newHash != oldHash {
			changes.Modified = append(changes.Modified, id)
		}
	}

	for id := range newRows {
		if _, exists := existing[id]; !exists {
			changes.Added = append(changes.Added, id)
		}
	}

	if _, err := e.sf.Exec(ctx, fmt.Sprintf("TRUNCATE TABLE %s", table)); err != nil {
		if _, err := e.sf.Exec(ctx, fmt.Sprintf("DELETE FROM %s", table)); err != nil {
			e.logger.Debug("delete failed", "error", err)
		}
	}

	insertRows := make([]map[string]interface{}, 0, len(rows))
	for _, row := range rows {
		id, ok := row["_cq_id"].(string)
		if !ok {
			continue
		}
		hash := e.hashRowContent(row)
		newRow := make(map[string]interface{}, len(row)+1)
		newRow["_cq_id"] = id
		newRow["_cq_hash"] = hash
		for k, v := range row {
			if k == "_cq_id" || k == "_cq_hash" {
				continue
			}
			newRow[k] = v
		}
		insertRows = append(insertRows, newRow)
	}

	if err := insertRowsBatch(ctx, e.sf, table, insertRows); err != nil {
		return changes, fmt.Errorf("insert rows: %w", err)
	}

	return changes, nil
}

func (e *K8sSyncEngine) getExistingHashes(ctx context.Context, table string) map[string]string {
	result := make(map[string]string)
	if err := snowflake.ValidateTableName(table); err != nil {
		return result
	}

	query := fmt.Sprintf("SELECT _CQ_ID, _CQ_HASH FROM %s", table)
	rows, err := e.sf.Query(ctx, query)
	if err != nil {
		return result
	}

	return decodeExistingHashes(rows.Rows)
}

func (e *K8sSyncEngine) hashRowContent(row map[string]interface{}) string {
	return hashRowContentWithMode(row, false)
}

func (e *K8sSyncEngine) persistChangeHistory(ctx context.Context, results []SyncResult) error {
	createQuery := `CREATE TABLE IF NOT EXISTS _sync_change_history (
        id VARCHAR PRIMARY KEY,
        table_name VARCHAR,
        change_type VARCHAR,
        resource_id VARCHAR,
        sync_time TIMESTAMP_TZ DEFAULT CURRENT_TIMESTAMP(),
        provider VARCHAR
    )`

	if _, err := e.sf.Exec(ctx, createQuery); err != nil {
		return err
	}

	for _, r := range results {
		if r.Changes == nil {
			continue
		}

		for _, id := range r.Changes.Added {
			e.insertChangeRecord(ctx, r.Table, "added", id)
		}
		for _, id := range r.Changes.Modified {
			e.insertChangeRecord(ctx, r.Table, "modified", id)
		}
		for _, id := range r.Changes.Removed {
			e.insertChangeRecord(ctx, r.Table, "removed", id)
		}
	}

	return nil
}

func (e *K8sSyncEngine) insertChangeRecord(ctx context.Context, table, changeType, resourceID string) {
	id := fmt.Sprintf("%s-%s-%s-%d", table, changeType, resourceID, time.Now().UnixNano())
	query := `INSERT INTO _sync_change_history (id, table_name, change_type, resource_id, provider)
        SELECT ?, ?, ?, ?, 'k8s'`

	if _, err := e.sf.Exec(ctx, query, id, table, changeType, resourceID); err != nil {
		e.logger.Debug("failed to insert change record", "error", err)
	}
}

func (e *K8sSyncEngine) newClient() (kubernetes.Interface, string, string, error) {
	config, clusterName, _, err := e.loadKubeConfig()
	if err != nil {
		return nil, "", "", err
	}

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, "", "", fmt.Errorf("create kubernetes client: %w", err)
	}

	namespace := e.namespace
	if namespace == "" {
		namespace = metav1.NamespaceAll
	}

	clusterName = normalizeClusterName(clusterName)
	return client, clusterName, namespace, nil
}

func (e *K8sSyncEngine) loadKubeConfig() (*rest.Config, string, string, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if e.kubeconfig != "" {
		rules.ExplicitPath = e.kubeconfig
	}
	overrides := &clientcmd.ConfigOverrides{}
	if e.kubeContext != "" {
		overrides.CurrentContext = e.kubeContext
	}
	clientConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides)

	cfg, err := clientConfig.ClientConfig()
	if err == nil {
		rawConfig, _ := clientConfig.RawConfig()
		contextName := rawConfig.CurrentContext
		if overrides.CurrentContext != "" {
			contextName = overrides.CurrentContext
		}
		clusterName := contextName
		if ctxConfig, ok := rawConfig.Contexts[contextName]; ok && ctxConfig.Cluster != "" {
			clusterName = ctxConfig.Cluster
		}
		namespace, _, _ := clientConfig.Namespace()
		return cfg, clusterName, namespace, nil
	}

	if e.kubeconfig != "" {
		return nil, "", "", fmt.Errorf("load kubeconfig: %w", err)
	}

	inClusterCfg, inClusterErr := rest.InClusterConfig()
	if inClusterErr != nil {
		return nil, "", "", fmt.Errorf("load kubeconfig: %w", errors.Join(err, inClusterErr))
	}

	return inClusterCfg, "in-cluster", "", nil
}

func normalizeClusterName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return "kubernetes"
	}
	return name
}
