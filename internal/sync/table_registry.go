package sync

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/evalops/cerebro/internal/providers"
)

// TableProvider identifies the provider that owns a table.
type TableProvider string

const (
	TableProviderAWS        TableProvider = "aws"
	TableProviderGCP        TableProvider = "gcp"
	TableProviderAzure      TableProvider = "azure"
	TableProviderKubernetes TableProvider = "k8s"
	TableProviderExternal   TableProvider = "external"
)

// TableSource identifies where the table data comes from.
type TableSource string

const (
	TableSourceNative         TableSource = "native"
	TableSourceAssetInventory TableSource = "asset_inventory"
	TableSourceSecurity       TableSource = "security"
)

// TableRegistration represents a table being added to the registry.
type TableRegistration struct {
	Name     string
	Provider TableProvider
	Columns  []string
	Source   TableSource
}

// RegisteredTable captures normalized metadata for a table.
type RegisteredTable struct {
	Name     string
	Provider TableProvider
	Columns  []string
	Sources  []TableSource
}

func (t RegisteredTable) hasSource(source TableSource) bool {
	for _, existing := range t.Sources {
		if existing == source {
			return true
		}
	}
	return false
}

// TableRegistry stores all known tables and their metadata.
type TableRegistry struct {
	mu         sync.RWMutex
	tables     map[string]*RegisteredTable
	byProvider map[TableProvider][]*RegisteredTable
}

var (
	globalTableRegistry     *TableRegistry
	globalTableRegistryOnce sync.Once
	registerAllTablesOnce   sync.Once
)

// ExpectedTables are high-signal tables that must remain registered.
var ExpectedTables = []string{
	"aws_iam_roles",
	"aws_ec2_instances",
	"aws_s3_buckets",
	"aws_kms_keys",
	"gcp_compute_instances",
	"gcp_storage_buckets",
	"gcp_iam_service_accounts",
	"gcp_container_vulnerabilities",
	"gcp_artifact_registry_images",
	"gcp_scc_findings",
	"azure_compute_virtual_machines",
	"azure_aks_clusters",
	"azure_rbac_role_assignments",
	"azure_policy_assignments",
	"azure_graph_service_principals",
	"azure_defender_assessments",
	"azure_storage_accounts",
	"k8s_cluster_inventory",
	"k8s_core_pods",
	"k8s_core_namespaces",
	"k8s_core_configmaps",
	"k8s_core_nodes",
	"k8s_core_persistent_volumes",
	"k8s_core_services",
	"k8s_core_service_accounts",
	"k8s_apps_deployments",
	"k8s_networking_ingresses",
	"k8s_rbac_cluster_roles",
	"k8s_rbac_roles",
	"k8s_rbac_cluster_role_bindings",
	"k8s_rbac_role_bindings",
	"k8s_rbac_service_account_bindings",
	"k8s_rbac_risky_bindings",
	"k8s_audit_events",
	"okta_users",
	"okta_groups",
	"okta_applications",
	"sentinelone_agents",
	"github_repositories",
	"github_organizations",
	"crowdstrike_hosts",
	"entra_users",
	"entra_groups",
}

// GlobalTableRegistry returns the singleton table registry.
func GlobalTableRegistry() *TableRegistry {
	globalTableRegistryOnce.Do(func() {
		globalTableRegistry = NewTableRegistry()
	})
	return globalTableRegistry
}

// NewTableRegistry creates an empty table registry.
func NewTableRegistry() *TableRegistry {
	return &TableRegistry{
		tables:     make(map[string]*RegisteredTable),
		byProvider: make(map[TableProvider][]*RegisteredTable),
	}
}

// RegisterAllTables auto-registers all native sync tables.
func RegisterAllTables() {
	registerAllTablesOnce.Do(func() {
		registry := GlobalTableRegistry()

		registerAWSTables(registry, (&SyncEngine{}).getAWSTables())
		registerGCPTables(registry, (&GCPSyncEngine{}).getGCPTables())
		registerAzureTables(registry, (&AzureSyncEngine{}).getAzureTables())
		registerK8sTables(registry, (&K8sSyncEngine{}).getK8sTables())
		registerGCPSecurityTables(registry)
		registerGCPAssetInventoryTables(registry)
		registerExternalProviderTables(registry)

		if missing := registry.VerifyExpectedTables(); len(missing) > 0 {
			panic(fmt.Sprintf("missing expected table registrations: %s", strings.Join(missing, ", ")))
		}
	})
}

func registerAWSTables(registry *TableRegistry, tables []TableSpec) {
	for _, table := range tables {
		registry.MustRegister(TableRegistration{
			Name:     table.Name,
			Provider: TableProviderAWS,
			Columns:  table.Columns,
			Source:   TableSourceNative,
		})
	}
}

func registerGCPTables(registry *TableRegistry, tables []GCPTableSpec) {
	for _, table := range tables {
		registry.MustRegister(TableRegistration{
			Name:     table.Name,
			Provider: TableProviderGCP,
			Columns:  table.Columns,
			Source:   TableSourceNative,
		})
	}
}

func registerAzureTables(registry *TableRegistry, tables []AzureTableSpec) {
	for _, table := range tables {
		registry.MustRegister(TableRegistration{
			Name:     table.Name,
			Provider: TableProviderAzure,
			Columns:  table.Columns,
			Source:   TableSourceNative,
		})
	}
}

func registerK8sTables(registry *TableRegistry, tables []K8sTableSpec) {
	for _, table := range tables {
		registry.MustRegister(TableRegistration{
			Name:     table.Name,
			Provider: TableProviderKubernetes,
			Columns:  table.Columns,
			Source:   TableSourceNative,
		})
	}
}

func registerGCPSecurityTables(registry *TableRegistry) {
	for _, tableName := range []string{
		"gcp_container_vulnerabilities",
		"gcp_artifact_registry_images",
		"gcp_scc_findings",
	} {
		registry.MustRegister(TableRegistration{
			Name:     tableName,
			Provider: TableProviderGCP,
			Columns:  []string{"_cq_id"},
			Source:   TableSourceSecurity,
		})
	}
}

func registerGCPAssetInventoryTables(registry *TableRegistry) {
	for _, tableName := range GCPAssetTypes {
		registry.MustRegister(TableRegistration{
			Name:     tableName,
			Provider: TableProviderGCP,
			Columns:  []string{"_cq_id"},
			Source:   TableSourceAssetInventory,
		})
	}
}

func registerExternalProviderTables(registry *TableRegistry) {
	for _, tableName := range providers.AllProviderTableNames() {
		err := registry.Register(TableRegistration{
			Name:     tableName,
			Provider: TableProviderExternal,
			Columns:  []string{"_cq_id"},
			Source:   TableSourceNative,
		})
		if err == nil {
			continue
		}
		if strings.Contains(err.Error(), "already registered for provider") {
			continue
		}
		panic(fmt.Sprintf("failed to register external provider table %q: %v", tableName, err))
	}
}

// Register validates and adds a table registration.
func (r *TableRegistry) Register(registration TableRegistration) error {
	normalized, err := normalizeTableRegistration(registration)
	if err != nil {
		return err
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	existing, exists := r.tables[normalized.Name]
	if exists {
		if existing.Provider != normalized.Provider {
			return fmt.Errorf("table %q already registered for provider %q", normalized.Name, existing.Provider)
		}

		existing.Columns = mergeUnique(existing.Columns, normalized.Columns)
		if !existing.hasSource(normalized.Source) {
			existing.Sources = append(existing.Sources, normalized.Source)
			sort.Slice(existing.Sources, func(i, j int) bool { return existing.Sources[i] < existing.Sources[j] })
		}
		return nil
	}

	registered := &RegisteredTable{
		Name:     normalized.Name,
		Provider: normalized.Provider,
		Columns:  append([]string(nil), normalized.Columns...),
		Sources:  []TableSource{normalized.Source},
	}

	r.tables[normalized.Name] = registered
	r.byProvider[normalized.Provider] = append(r.byProvider[normalized.Provider], registered)
	return nil
}

// MustRegister registers a table and panics on validation errors.
func (r *TableRegistry) MustRegister(registration TableRegistration) {
	if err := r.Register(registration); err != nil {
		panic(fmt.Sprintf("failed to register table %q: %v", registration.Name, err))
	}
}

func normalizeTableRegistration(registration TableRegistration) (TableRegistration, error) {
	name := strings.ToLower(strings.TrimSpace(registration.Name))
	if name == "" {
		return TableRegistration{}, fmt.Errorf("table name is required")
	}
	if !isValidTableName(name) {
		return TableRegistration{}, fmt.Errorf("invalid table name %q", registration.Name)
	}

	provider := normalizeTableProvider(registration.Provider)
	if provider == "" {
		return TableRegistration{}, fmt.Errorf("provider is required for table %q", name)
	}

	source := normalizeTableSource(registration.Source)
	if strings.TrimSpace(string(registration.Source)) != "" && source == "" {
		return TableRegistration{}, fmt.Errorf("invalid source %q for table %q", registration.Source, name)
	}
	if source == "" {
		source = TableSourceNative
	}

	columns := normalizeColumns(registration.Columns)
	if len(columns) == 0 {
		columns = []string{"_cq_id"}
	}

	return TableRegistration{
		Name:     name,
		Provider: provider,
		Columns:  columns,
		Source:   source,
	}, nil
}

func normalizeTableProvider(provider TableProvider) TableProvider {
	switch TableProvider(strings.ToLower(strings.TrimSpace(string(provider)))) {
	case TableProviderAWS, TableProviderGCP, TableProviderAzure, TableProviderKubernetes, TableProviderExternal:
		return TableProvider(strings.ToLower(strings.TrimSpace(string(provider))))
	default:
		return ""
	}
}

func normalizeTableSource(source TableSource) TableSource {
	switch TableSource(strings.ToLower(strings.TrimSpace(string(source)))) {
	case TableSourceNative, TableSourceAssetInventory, TableSourceSecurity:
		return TableSource(strings.ToLower(strings.TrimSpace(string(source))))
	case "":
		return ""
	default:
		return ""
	}
}

func normalizeColumns(columns []string) []string {
	normalized := make([]string, 0, len(columns))
	seen := make(map[string]struct{}, len(columns))
	for _, column := range columns {
		name := strings.ToLower(strings.TrimSpace(column))
		if name == "" {
			continue
		}
		if !isValidTableName(name) {
			continue
		}
		if _, exists := seen[name]; exists {
			continue
		}
		seen[name] = struct{}{}
		normalized = append(normalized, name)
	}
	return normalized
}

func mergeUnique(current []string, additions []string) []string {
	if len(additions) == 0 {
		return current
	}
	merged := append([]string(nil), current...)
	seen := make(map[string]struct{}, len(merged)+len(additions))
	for _, value := range merged {
		seen[value] = struct{}{}
	}
	for _, value := range additions {
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		merged = append(merged, value)
	}
	return merged
}

func isValidTableName(name string) bool {
	if name == "" {
		return false
	}
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' {
			continue
		}
		return false
	}
	return true
}

// Get returns the registered table by name.
func (r *TableRegistry) Get(name string) (RegisteredTable, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	registered, ok := r.tables[strings.ToLower(strings.TrimSpace(name))]
	if !ok {
		return RegisteredTable{}, false
	}

	copyValue := *registered
	copyValue.Columns = append([]string(nil), registered.Columns...)
	copyValue.Sources = append([]TableSource(nil), registered.Sources...)
	return copyValue, true
}

// Names returns all registered table names sorted alphabetically.
func (r *TableRegistry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.tables))
	for name := range r.tables {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// NamesByProvider returns table names for a provider sorted alphabetically.
func (r *TableRegistry) NamesByProvider(provider TableProvider) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	normalized := normalizeTableProvider(provider)
	if normalized == "" {
		return nil
	}

	tables := r.byProvider[normalized]
	names := make([]string, 0, len(tables))
	for _, table := range tables {
		names = append(names, table.Name)
	}
	sort.Strings(names)
	return names
}

// TableRegistryStats summarizes table registration coverage.
type TableRegistryStats struct {
	TotalTables        int
	ByProvider         map[TableProvider]int
	BySource           map[TableSource]int
	MultiSourceTables  int
	TablesWithNoColumn int
}

// Stats returns registration statistics.
func (r *TableRegistry) Stats() TableRegistryStats {
	r.mu.RLock()
	defer r.mu.RUnlock()

	stats := TableRegistryStats{
		TotalTables: len(r.tables),
		ByProvider:  make(map[TableProvider]int),
		BySource:    make(map[TableSource]int),
	}

	for _, table := range r.tables {
		stats.ByProvider[table.Provider]++
		if len(table.Columns) == 0 {
			stats.TablesWithNoColumn++
		}
		if len(table.Sources) > 1 {
			stats.MultiSourceTables++
		}
		for _, source := range table.Sources {
			stats.BySource[source]++
		}
	}

	return stats
}

// Validate checks registry consistency and baseline provider coverage.
func (r *TableRegistry) Validate() []error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var errs []error

	minimumByProvider := map[TableProvider]int{
		TableProviderAWS:        120,
		TableProviderGCP:        20,
		TableProviderAzure:      10,
		TableProviderKubernetes: 10,
	}

	for provider, minimum := range minimumByProvider {
		count := len(r.byProvider[provider])
		if count < minimum {
			errs = append(errs, fmt.Errorf("provider %s has %d tables, minimum required is %d", provider, count, minimum))
		}
	}

	for name, table := range r.tables {
		if !isValidTableName(name) {
			errs = append(errs, fmt.Errorf("invalid table name %q", name))
		}
		if table.Provider == "" {
			errs = append(errs, fmt.Errorf("table %q missing provider", name))
		}
		if len(table.Columns) == 0 {
			errs = append(errs, fmt.Errorf("table %q missing columns", name))
		}
		if len(table.Sources) == 0 {
			errs = append(errs, fmt.Errorf("table %q missing sources", name))
		}
	}

	return errs
}

// VerifyExpectedTables ensures expected baseline tables remain registered.
func (r *TableRegistry) VerifyExpectedTables() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	missing := make([]string, 0)
	for _, name := range ExpectedTables {
		if _, ok := r.tables[name]; !ok {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	return missing
}
