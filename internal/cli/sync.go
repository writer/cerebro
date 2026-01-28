package cli

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/spf13/cobra"

	"github.com/writerinternal/cerebro/internal/app"
	"github.com/writerinternal/cerebro/internal/snowflake"
	nativesync "github.com/writerinternal/cerebro/internal/sync"
)

var syncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Sync cloud assets to Snowflake",
	Long: `Sync cloud assets from AWS, GCP, or Azure to Snowflake using Cerebro's native scanners.

Examples:
  cerebro sync                                    # Sync AWS (default)
  cerebro sync --gcp --gcp-project my-project    # Sync GCP
  cerebro sync --azure                           # Sync Azure`,
	RunE: runSync,
}

var (
	syncScanAfter         bool
	syncGCP               bool
	syncGCPProject        string
	syncGCPProjects       string // comma-separated list of projects
	syncGCPOrg            string // organization ID for multi-project sync
	syncMultiRegion       bool
	syncRegion            string
	syncUseAssetAPI       bool   // use Cloud Asset Inventory API
	syncSecurity          bool   // sync security data (vulnerabilities, SCC findings)
	syncAzure             bool   // sync Azure resources
	syncAzureSubscription string // Azure subscription ID
	syncConcurrency       int
	syncTable             string
)

func init() {
	syncCmd.Flags().BoolVar(&syncScanAfter, "scan-after", false, "Run policy scan after successful sync")
	syncCmd.Flags().BoolVar(&syncGCP, "gcp", false, "Sync GCP resources instead of AWS")
	syncCmd.Flags().StringVar(&syncGCPProject, "gcp-project", "", "GCP project ID to sync (required with --gcp unless using --gcp-org)")
	syncCmd.Flags().StringVar(&syncGCPProjects, "gcp-projects", "", "Comma-separated list of GCP project IDs to sync")
	syncCmd.Flags().StringVar(&syncGCPOrg, "gcp-org", "", "GCP organization ID for multi-project sync (syncs all projects)")
	syncCmd.Flags().BoolVar(&syncMultiRegion, "multi-region", false, "Scan all major AWS regions (us-east-1, us-west-2, eu-west-1, etc.)")
	syncCmd.Flags().StringVarP(&syncRegion, "region", "r", "", "AWS region to sync when --multi-region is false")
	syncCmd.Flags().BoolVar(&syncUseAssetAPI, "asset-api", false, "Use GCP Cloud Asset Inventory API for efficient bulk fetching")
	syncCmd.Flags().BoolVar(&syncSecurity, "security", false, "Sync security data (Container Analysis vulnerabilities, SCC findings, Artifact Registry)")
	syncCmd.Flags().BoolVar(&syncAzure, "azure", false, "Sync Azure resources")
	syncCmd.Flags().StringVar(&syncAzureSubscription, "azure-subscription", "", "Azure subscription ID (optional, will auto-discover if not set)")
	syncCmd.Flags().IntVar(&syncConcurrency, "concurrency", 20, "Max concurrent table syncs for native engines")
	syncCmd.Flags().StringVar(&syncTable, "table", "", "Sync only specific table(s), comma-separated (e.g., aws_iam_accounts)")
}

func runSync(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	start := time.Now()

	// Azure sync
	if syncAzure {
		return runAzureSync(ctx, start)
	}

	// GCP sync
	if syncGCP {
		// Handle multi-project sync via organization
		if syncGCPOrg != "" {
			return runGCPOrgSync(ctx, start, syncGCPOrg)
		}
		// Handle multi-project sync via explicit list
		if syncGCPProjects != "" {
			projects := strings.Split(syncGCPProjects, ",")
			for i, p := range projects {
				projects[i] = strings.TrimSpace(p)
			}
			return runGCPMultiProjectSync(ctx, start, projects)
		}
		// Handle single project sync
		if syncGCPProject == "" {
			return fmt.Errorf("--gcp-project, --gcp-projects, or --gcp-org is required with --gcp")
		}
		if syncUseAssetAPI {
			return runGCPAssetAPISync(ctx, start, []string{syncGCPProject})
		}
		return runGCPSync(ctx, start, syncGCPProject)
	}

	return runNativeSync(ctx, start)
}

func runGCPSync(ctx context.Context, start time.Time, projectID string) error {
	Info("Starting GCP sync for project: %s", projectID)
	tableFilter := parseTableFilter(syncTable)
	tableFilterSet := buildTableFilterSet(tableFilter)
	if len(tableFilter) > 0 {
		Info("Filtering GCP tables: %s", strings.Join(tableFilter, ", "))
	}

	client, err := createSnowflakeClient()
	if err != nil {
		return fmt.Errorf("create snowflake client: %w", err)
	}
	defer func() { _ = client.Close() }()

	options := []nativesync.GCPEngineOption{nativesync.WithGCPProject(projectID)}
	if syncConcurrency > 0 {
		options = append(options, nativesync.WithGCPConcurrency(syncConcurrency))
	}
	if len(tableFilter) > 0 {
		options = append(options, nativesync.WithGCPTableFilter(tableFilter))
	}
	syncer := nativesync.NewGCPSyncEngine(client, slog.Default(), options...)
	results, err := syncer.SyncAll(ctx)
	if err != nil {
		return fmt.Errorf("sync failed: %w", err)
	}

	printSyncResults(results, start, "GCP")

	// Sync security data if requested
	if syncSecurity {
		if len(tableFilterSet) == 0 || tableFilterMatches(tableFilterSet,
			"gcp_container_vulnerabilities",
			"gcp_artifact_registry_images",
			"gcp_scc_findings",
		) {
			Info("Syncing GCP security data (Container Analysis, Artifact Registry, SCC)...")
			secOptions := []nativesync.GCPSecurityOption{}
			if len(tableFilterSet) > 0 {
				secOptions = append(secOptions, nativesync.WithGCPSecurityTableFilter(tableFilter))
			}
			securitySyncer := nativesync.NewGCPSecuritySync(client, slog.Default(), projectID, syncGCPOrg, secOptions...)
			if secErr := securitySyncer.SyncAll(ctx); secErr != nil {
				Warning("Security sync failed: %v", secErr)
			} else {
				Success("Security data synced successfully")
			}
		} else {
			Info("Skipping GCP security sync because --table filter is set")
		}
	}

	if len(tableFilterSet) == 0 {
		// Extract resource relationships for graph building
		Info("Extracting resource relationships...")
		relExtractor := nativesync.NewRelationshipExtractor(client, slog.Default())
		relCount, err := relExtractor.ExtractAndPersist(ctx)
		if err != nil {
			Warning("Relationship extraction failed: %v", err)
		} else {
			Info("Extracted %d relationships", relCount)
		}
	} else {
		Info("Skipping relationship extraction because --table filter is set")
	}

	return nil
}

func runGCPOrgSync(ctx context.Context, start time.Time, orgID string) error {
	Info("Discovering projects in organization: %s", orgID)

	// List all projects in the organization using Cloud Asset Inventory
	projects, err := nativesync.ListOrganizationProjects(ctx, orgID)
	if err != nil {
		return fmt.Errorf("list organization projects: %w", err)
	}

	Info("Found %d projects in organization", len(projects))

	if syncUseAssetAPI {
		return runGCPAssetAPISync(ctx, start, projects)
	}
	return runGCPMultiProjectSync(ctx, start, projects)
}

func runGCPMultiProjectSync(ctx context.Context, start time.Time, projects []string) error {
	Info("Starting GCP multi-project sync for %d projects...", len(projects))
	tableFilter := parseTableFilter(syncTable)
	if len(tableFilter) > 0 {
		Info("Filtering GCP tables: %s", strings.Join(tableFilter, ", "))
	}

	client, err := createSnowflakeClient()
	if err != nil {
		return fmt.Errorf("create snowflake client: %w", err)
	}
	defer func() { _ = client.Close() }()

	var allResults []nativesync.SyncResult
	for i, projectID := range projects {
		Info("[%d/%d] Syncing project: %s", i+1, len(projects), projectID)
		options := []nativesync.GCPEngineOption{nativesync.WithGCPProject(projectID)}
		if syncConcurrency > 0 {
			options = append(options, nativesync.WithGCPConcurrency(syncConcurrency))
		}
		if len(tableFilter) > 0 {
			options = append(options, nativesync.WithGCPTableFilter(tableFilter))
		}
		syncer := nativesync.NewGCPSyncEngine(client, slog.Default(), options...)
		results, err := syncer.SyncAll(ctx)
		if err != nil {
			Warning("Failed to sync project %s: %v", projectID, err)
			continue
		}
		allResults = append(allResults, results...)
	}

	printSyncResults(allResults, start, "GCP")
	return nil
}

func runGCPAssetAPISync(ctx context.Context, start time.Time, projects []string) error {
	Info("Starting GCP sync via Cloud Asset Inventory API for %d projects...", len(projects))
	tableFilter := parseTableFilter(syncTable)
	if len(tableFilter) > 0 {
		Info("Filtering GCP asset types: %s", strings.Join(tableFilter, ", "))
	}

	client, err := createSnowflakeClient()
	if err != nil {
		return fmt.Errorf("create snowflake client: %w", err)
	}
	defer func() { _ = client.Close() }()

	options := []nativesync.GCPAssetOption{nativesync.WithProjects(projects)}
	if syncConcurrency > 0 {
		options = append(options, nativesync.WithAssetConcurrency(syncConcurrency))
	}
	if len(tableFilter) > 0 {
		options = append(options, nativesync.WithAssetTypeFilter(tableFilter))
	}
	syncer := nativesync.NewGCPAssetInventoryEngine(client, slog.Default(), options...)
	results, err := syncer.SyncAll(ctx)
	if err != nil {
		return fmt.Errorf("sync failed: %w", err)
	}

	printSyncResults(results, start, "GCP (Asset API)")
	return nil
}

func runAzureSync(ctx context.Context, start time.Time) error {
	if syncAzureSubscription != "" {
		Info("Starting Azure sync for subscription: %s", syncAzureSubscription)
	} else {
		Info("Starting Azure sync (auto-discovering subscriptions)...")
	}
	tableFilter := parseTableFilter(syncTable)
	if len(tableFilter) > 0 {
		Info("Filtering Azure tables: %s", strings.Join(tableFilter, ", "))
	}

	client, err := createSnowflakeClient()
	if err != nil {
		return fmt.Errorf("create snowflake client: %w", err)
	}
	defer func() { _ = client.Close() }()

	opts := []nativesync.AzureEngineOption{}
	if syncAzureSubscription != "" {
		opts = append(opts, nativesync.WithAzureSubscription(syncAzureSubscription))
	}
	if syncConcurrency > 0 {
		opts = append(opts, nativesync.WithAzureConcurrency(syncConcurrency))
	}
	if len(tableFilter) > 0 {
		opts = append(opts, nativesync.WithAzureTableFilter(tableFilter))
	}

	syncer, err := nativesync.NewAzureSyncEngine(client, slog.Default(), opts...)
	if err != nil {
		return fmt.Errorf("create azure sync engine: %w", err)
	}

	results, err := syncer.SyncAll(ctx)
	if err != nil {
		return fmt.Errorf("sync failed: %w", err)
	}

	printSyncResults(results, start, "Azure")

	if syncScanAfter {
		Info("Triggering policy scan...")
		if err := runPostSyncScan(ctx, tableFilter); err != nil {
			Warning("Post-sync scan failed: %v", err)
		}
	}

	return nil
}

func runNativeSync(ctx context.Context, start time.Time) error {
	awsCfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return fmt.Errorf("load AWS config: %w", err)
	}

	tableFilter := parseTableFilter(syncTable)

	region := syncRegion
	if region == "" {
		region = awsCfg.Region
	}
	if region == "" {
		region = "us-east-1"
	}

	if syncMultiRegion {
		if syncRegion != "" {
			Warning("Ignoring --region because --multi-region is set")
		}
		Info("Starting multi-region AWS sync (%d regions, concurrency=%d)...", len(nativesync.DefaultAWSRegions), syncConcurrency)
	} else {
		Info("Starting native AWS sync (region=%s, concurrency=%d)...", region, syncConcurrency)
	}
	if len(tableFilter) > 0 {
		Info("Filtering AWS tables: %s", strings.Join(tableFilter, ", "))
	}

	client, err := createSnowflakeClient()
	if err != nil {
		return fmt.Errorf("create snowflake client: %w", err)
	}
	defer func() { _ = client.Close() }()

	opts := []nativesync.EngineOption{}
	if syncConcurrency > 0 {
		opts = append(opts, nativesync.WithConcurrency(syncConcurrency))
	}
	if len(tableFilter) > 0 {
		opts = append(opts, nativesync.WithTableFilter(tableFilter))
	}
	if syncMultiRegion {
		opts = append(opts, nativesync.WithRegions(nativesync.DefaultAWSRegions))
	} else {
		opts = append(opts, nativesync.WithRegions([]string{region}))
	}

	syncer := nativesync.NewSyncEngine(client, slog.Default(), opts...)
	results, err := syncer.SyncAllWithConfig(ctx, awsCfg)
	if err != nil {
		return fmt.Errorf("sync failed: %w", err)
	}

	printSyncResults(results, start, "AWS")

	if len(tableFilter) == 0 {
		// Extract resource relationships for graph building
		Info("Extracting resource relationships...")
		relExtractor := nativesync.NewRelationshipExtractor(client, slog.Default())
		relCount, err := relExtractor.ExtractAndPersist(ctx)
		if err != nil {
			Warning("Relationship extraction failed: %v", err)
		} else {
			Info("Extracted %d relationships", relCount)
		}
	} else {
		Info("Skipping relationship extraction because --table filter is set")
	}

	if syncScanAfter {
		Info("Triggering policy scan...")
		if err := runPostSyncScan(ctx, tableFilter); err != nil {
			Warning("Post-sync scan failed: %v", err)
		}
	}

	return nil
}

func parseTableFilter(value string) []string {
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	filtered := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		filtered = append(filtered, trimmed)
	}
	return filtered
}

func buildTableFilterSet(tables []string) map[string]struct{} {
	if len(tables) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(tables))
	for _, table := range tables {
		trimmed := strings.TrimSpace(strings.ToLower(table))
		if trimmed == "" {
			continue
		}
		set[trimmed] = struct{}{}
	}
	if len(set) == 0 {
		return nil
	}
	return set
}

func tableFilterMatches(filter map[string]struct{}, names ...string) bool {
	if len(filter) == 0 {
		return true
	}
	for _, name := range names {
		if name == "" {
			continue
		}
		if _, ok := filter[strings.ToLower(name)]; ok {
			return true
		}
	}
	return false
}

func printSyncResults(results []nativesync.SyncResult, start time.Time, provider string) {
	fmt.Println()
	fmt.Printf("%s Sync Results:\n", provider)
	fmt.Println("─────────────────────────────────────────")

	totalSynced := 0
	totalErrors := 0
	totalAdded := 0
	totalModified := 0
	totalRemoved := 0

	for _, r := range results {
		status := "✓"
		if r.Errors > 0 {
			status = "✗"
		}

		changeInfo := ""
		if r.Changes != nil && r.Changes.HasChanges() {
			changeInfo = fmt.Sprintf(" [%s]", r.Changes.Summary())
			totalAdded += len(r.Changes.Added)
			totalModified += len(r.Changes.Modified)
			totalRemoved += len(r.Changes.Removed)
		}

		fmt.Printf("  %s %-30s %4d resources (%s)%s\n", status, r.Table, r.Synced, r.Duration.Round(time.Millisecond), changeInfo)
		totalSynced += r.Synced
		totalErrors += r.Errors
	}

	fmt.Println("─────────────────────────────────────────")
	fmt.Printf("  Total: %d resources synced in %s\n", totalSynced, time.Since(start).Round(time.Second))

	if totalAdded > 0 || totalModified > 0 || totalRemoved > 0 {
		fmt.Printf("  Changes: +%d added, ~%d modified, -%d removed\n", totalAdded, totalModified, totalRemoved)
	}

	if totalErrors > 0 {
		Warning("%d tables had errors", totalErrors)
	} else {
		Success("Sync completed successfully")
	}
}

func createSnowflakeClient() (*snowflake.Client, error) {
	cfg := snowflake.DSNConfigFromEnv()
	if missing := cfg.MissingFields(); len(missing) > 0 {
		return nil, fmt.Errorf("snowflake not configured: set %s", strings.Join(missing, ", "))
	}

	return snowflake.NewClient(snowflake.ClientConfig{
		Account:    cfg.Account,
		User:       cfg.User,
		PrivateKey: cfg.PrivateKey,
		Database:   cfg.Database,
		Schema:     cfg.Schema,
		Warehouse:  cfg.Warehouse,
		Role:       cfg.Role,
	})
}

func runPostSyncScan(ctx context.Context, tableFilter []string) error {
	application, err := app.New(ctx)
	if err != nil {
		return fmt.Errorf("failed to initialize app: %w", err)
	}
	defer func() { _ = application.Close() }()

	if application.Snowflake == nil {
		return fmt.Errorf("snowflake not configured: set SNOWFLAKE_PRIVATE_KEY/ACCOUNT/USER or SNOWFLAKE_CONNECTION_STRING")
	}

	fmt.Println("Scanning synced assets...")

	filterSet := buildTableFilterSet(tableFilter)
	if len(filterSet) > 0 {
		fmt.Printf("Filtering scan tables: %s\n", strings.Join(tableFilter, ", "))
	}

	// Get tables that have policies defined
	policies := application.Policy.ListPolicies()
	tableSet := make(map[string]struct{})
	for _, p := range policies {
		for _, table := range p.GetRequiredTables() {
			tableSet[table] = struct{}{}
		}
	}

	tables := make([]string, 0, len(tableSet))
	for table := range tableSet {
		tables = append(tables, table)
	}

	if len(filterSet) > 0 {
		filtered := make([]string, 0, len(tables))
		for _, table := range tables {
			if tableFilterMatches(filterSet, table) {
				filtered = append(filtered, table)
			}
		}
		tables = filtered
		if len(tables) == 0 {
			fmt.Println("No tables to scan for selected filter")
			return nil
		}
	}

	if len(tables) == 0 {
		fmt.Println("No tables to scan")
		return nil
	}

	fmt.Printf("Scanning %d tables with %d policies\n", len(tables), len(policies))

	totalScanned := 0
	totalViolations := 0
	const batchSize = 1000

	for _, table := range tables {
		filter := snowflake.AssetFilter{Limit: batchSize}

		// Use watermarks for incremental scanning if available
		if application.ScanWatermarks != nil {
			if wm := application.ScanWatermarks.GetWatermark(table); wm != nil {
				filter.Since = wm.LastScanTime
				fmt.Printf("  %s: incremental scan (since %s)\n", table, wm.LastScanTime.Format(time.RFC3339))
			}
		}

		tableScanned := int64(0)
		offset := 0
		for {
			filter.Offset = offset
			assets, err := application.Snowflake.GetAssets(ctx, table, filter)
			if err != nil {
				Warning("Failed to fetch %s: %v", table, err)
				break
			}

			if len(assets) == 0 {
				break
			}

			result := application.Scanner.ScanAssets(ctx, assets)
			totalScanned += int(result.Scanned)
			totalViolations += int(result.Violations)
			tableScanned += result.Scanned

			// Persist findings
			for _, f := range result.Findings {
				application.Findings.Upsert(ctx, f)
			}

			if len(assets) < batchSize {
				break
			}
			offset += batchSize
		}

		// Update watermark
		if application.ScanWatermarks != nil && tableScanned > 0 {
			application.ScanWatermarks.SetWatermark(table, time.Now().UTC(), tableScanned)
		}

		if tableScanned > 0 {
			fmt.Printf("  %s: scanned %d assets\n", table, tableScanned)
		}
	}

	// Persist watermarks
	if application.ScanWatermarks != nil {
		_ = application.ScanWatermarks.PersistWatermarks(ctx)
	}

	// Sync findings to persistent storage
	if err := application.Findings.Sync(ctx); err != nil {
		Warning("Failed to sync findings: %v", err)
	}

	fmt.Printf("\nPost-sync scan complete: %d assets scanned, %d violations found\n", totalScanned, totalViolations)
	return nil
}
