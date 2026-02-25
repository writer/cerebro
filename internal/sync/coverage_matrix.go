package sync

import (
	"sort"
	"strings"
)

// AWSCoverageEntry captures table-level AWS sync coverage metadata.
type AWSCoverageEntry struct {
	Service     string   `json:"service"`
	Table       string   `json:"table"`
	PrimaryKeys []string `json:"primary_keys"`
	Regions     []string `json:"regions"`
	Scope       string   `json:"scope"`
}

// AWSCoverageGap describes required high-value tables that are not currently covered.
type AWSCoverageGap struct {
	Service       string   `json:"service"`
	MissingTables []string `json:"missing_tables"`
}

// GCPCoverageEntry captures GCP table coverage across native API and Asset Inventory paths.
type GCPCoverageEntry struct {
	Service        string   `json:"service"`
	Table          string   `json:"table"`
	PrimaryKeys    []string `json:"primary_keys"`
	NativeAPI      bool     `json:"native_api"`
	AssetInventory bool     `json:"asset_inventory"`
}

// GCPCoverageSummary compares source overlap between native and Asset Inventory ingestion.
type GCPCoverageSummary struct {
	BothSources        []string `json:"both_sources"`
	NativeOnly         []string `json:"native_only"`
	AssetInventoryOnly []string `json:"asset_inventory_only"`
}

// AzureCoverageEntry captures Azure sync coverage metadata.
type AzureCoverageEntry struct {
	Service     string   `json:"service"`
	Table       string   `json:"table"`
	PrimaryKeys []string `json:"primary_keys"`
	Source      string   `json:"source"`
}

var awsHighValueCoverageRequirements = map[string][]string{
	"iam": {
		"aws_iam_roles",
		"aws_iam_users",
		"aws_iam_policies",
	},
	"ec2": {
		"aws_ec2_instances",
		"aws_ec2_security_groups",
		"aws_ec2_vpcs",
	},
	"s3": {
		"aws_s3_buckets",
		"aws_s3_bucket_policies",
	},
	"kms": {
		"aws_kms_keys",
		"aws_kms_aliases",
		"aws_kms_key_policies",
	},
	"rds": {
		"aws_rds_instances",
		"aws_rds_db_clusters",
	},
	"cloudtrail": {
		"aws_cloudtrail_trails",
		"aws_cloudtrail_event_selectors",
	},
}

var awsHighValueCoverageOrder = []string{"iam", "ec2", "s3", "kms", "rds", "cloudtrail"}

// BuildAWSCoverageMatrix returns a service-to-table coverage matrix for AWS sync.
// If configuredRegions is empty, DefaultAWSRegions are used.
func BuildAWSCoverageMatrix(configuredRegions []string) []AWSCoverageEntry {
	regions := normalizeCoverageRegions(configuredRegions)
	tables := (&SyncEngine{}).getAWSTables()

	entries := make([]AWSCoverageEntry, 0, len(tables))
	for _, table := range tables {
		entries = append(entries, AWSCoverageEntry{
			Service:     awsServiceFromTableName(table.Name),
			Table:       table.Name,
			PrimaryKeys: awsPrimaryKeysForTable(table),
			Regions:     append([]string(nil), regionsForTable(table.Name, regions)...),
			Scope:       awsScopeLabel(table.Scope),
		})
	}

	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Service == entries[j].Service {
			return entries[i].Table < entries[j].Table
		}
		return entries[i].Service < entries[j].Service
	})

	return entries
}

// AWSCoverageGaps reports missing high-value AWS tables by service.
func AWSCoverageGaps(entries []AWSCoverageEntry) []AWSCoverageGap {
	present := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		if entry.Table == "" {
			continue
		}
		present[strings.ToLower(entry.Table)] = struct{}{}
	}

	gaps := make([]AWSCoverageGap, 0)
	for _, service := range awsHighValueCoverageOrder {
		required := awsHighValueCoverageRequirements[service]
		missing := make([]string, 0)
		for _, table := range required {
			if _, ok := present[strings.ToLower(table)]; !ok {
				missing = append(missing, table)
			}
		}
		if len(missing) == 0 {
			continue
		}
		gaps = append(gaps, AWSCoverageGap{Service: service, MissingTables: missing})
	}

	return gaps
}

// BuildGCPCoverageMatrix returns GCP table coverage and indicates whether each table
// is sourced from native APIs, Asset Inventory, or both.
func BuildGCPCoverageMatrix() []GCPCoverageEntry {
	nativeTables := (&GCPSyncEngine{}).getGCPTables()
	entriesByTable := make(map[string]*GCPCoverageEntry, len(nativeTables)+len(GCPAssetTypes))

	for _, table := range nativeTables {
		key := strings.ToLower(table.Name)
		entriesByTable[key] = &GCPCoverageEntry{
			Service:     providerServiceFromTableName("gcp", table.Name),
			Table:       table.Name,
			PrimaryKeys: providerPrimaryKeyColumns(table.Columns),
			NativeAPI:   true,
		}
	}

	for _, tableName := range GCPAssetTypes {
		key := strings.ToLower(tableName)
		entry, ok := entriesByTable[key]
		if !ok {
			entry = &GCPCoverageEntry{
				Service:     providerServiceFromTableName("gcp", tableName),
				Table:       tableName,
				PrimaryKeys: []string{"_cq_id"},
			}
			entriesByTable[key] = entry
		}
		entry.AssetInventory = true
	}

	entries := make([]GCPCoverageEntry, 0, len(entriesByTable))
	for _, entry := range entriesByTable {
		entries = append(entries, *entry)
	}

	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Service == entries[j].Service {
			return entries[i].Table < entries[j].Table
		}
		return entries[i].Service < entries[j].Service
	})

	return entries
}

// SummarizeGCPCoverageSources reports table overlap between native and Asset Inventory paths.
func SummarizeGCPCoverageSources(entries []GCPCoverageEntry) GCPCoverageSummary {
	summary := GCPCoverageSummary{}
	for _, entry := range entries {
		switch {
		case entry.NativeAPI && entry.AssetInventory:
			summary.BothSources = append(summary.BothSources, entry.Table)
		case entry.NativeAPI:
			summary.NativeOnly = append(summary.NativeOnly, entry.Table)
		case entry.AssetInventory:
			summary.AssetInventoryOnly = append(summary.AssetInventoryOnly, entry.Table)
		}
	}

	sort.Strings(summary.BothSources)
	sort.Strings(summary.NativeOnly)
	sort.Strings(summary.AssetInventoryOnly)
	return summary
}

// BuildAzureCoverageMatrix returns Azure table coverage metadata for ARM and Graph sync.
func BuildAzureCoverageMatrix() []AzureCoverageEntry {
	tables := (&AzureSyncEngine{}).getAzureTables()
	entries := make([]AzureCoverageEntry, 0, len(tables))

	for _, table := range tables {
		entries = append(entries, AzureCoverageEntry{
			Service:     providerServiceFromTableName("azure", table.Name),
			Table:       table.Name,
			PrimaryKeys: providerPrimaryKeyColumns(table.Columns),
			Source:      azureSourceFromTableName(table.Name),
		})
	}

	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Service == entries[j].Service {
			return entries[i].Table < entries[j].Table
		}
		return entries[i].Service < entries[j].Service
	})

	return entries
}

func normalizeCoverageRegions(regions []string) []string {
	if len(regions) == 0 {
		return append([]string(nil), DefaultAWSRegions...)
	}

	normalized := make([]string, 0, len(regions))
	seen := make(map[string]struct{}, len(regions))
	for _, region := range regions {
		trimmed := strings.ToLower(strings.TrimSpace(region))
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		normalized = append(normalized, trimmed)
	}

	if len(normalized) == 0 {
		return append([]string(nil), DefaultAWSRegions...)
	}

	sort.Strings(normalized)
	return normalized
}

func awsServiceFromTableName(tableName string) string {
	return providerServiceFromTableName("aws", tableName)
}

func awsPrimaryKeysForTable(table TableSpec) []string {
	if composite, ok := awsCompositeKeyColumns[table.Name]; ok && len(composite) > 0 {
		return append([]string(nil), composite...)
	}

	return providerPrimaryKeyColumns(table.Columns)
}

func providerServiceFromTableName(provider, tableName string) string {
	normalized := strings.ToLower(strings.TrimSpace(tableName))
	normalized = strings.TrimPrefix(normalized, strings.ToLower(strings.TrimSpace(provider))+"_")
	if normalized == "" {
		return "unknown"
	}
	parts := strings.Split(normalized, "_")
	if len(parts) == 0 || parts[0] == "" {
		return "unknown"
	}
	return parts[0]
}

func providerPrimaryKeyColumns(columns []string) []string {
	for _, column := range []string{"arn", "id", "resource_arn", "resource_id", "instance_id", "name"} {
		if hasColumn(columns, column) {
			return []string{column}
		}
	}

	return []string{"_cq_id"}
}

func awsScopeLabel(scope TableRegionScope) string {
	if scope == TableRegionScopeGlobal {
		return "global"
	}
	return "regional"
}

func azureSourceFromTableName(tableName string) string {
	normalized := strings.ToLower(strings.TrimSpace(tableName))
	if strings.HasPrefix(normalized, "azure_graph_") {
		return "graph"
	}
	return "arm"
}
