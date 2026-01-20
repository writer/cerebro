package cli

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/writerinternal/cerebro/internal/app"
	"github.com/writerinternal/cerebro/internal/snowflake"
	nativesync "github.com/writerinternal/cerebro/internal/sync"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan assets against security policies",
	Long: `Scan cloud assets from Snowflake against Cedar security policies.

Examples:
  cerebro scan                           # Scan all tables
  cerebro scan --table aws_s3_buckets    # Scan specific table
  cerebro scan --limit 1000              # Limit assets per table
  cerebro scan --dry-run                 # Show what would be scanned`,
	RunE: runScan,
}

var (
	scanTables              []string
	scanLimit               int
	scanDryRun              bool
	scanOutput              string
	scanFull                bool
	scanToxicCombos         bool
	scanUseGraph            bool
	scanExtractRelationships bool
)

func init() {
	scanCmd.Flags().StringSliceVarP(&scanTables, "table", "t", nil, "Tables to scan (can specify multiple: -t table1 -t table2)")
	scanCmd.Flags().IntVarP(&scanLimit, "limit", "l", 500, "Maximum assets to scan per table")
	scanCmd.Flags().BoolVar(&scanDryRun, "dry-run", false, "Show what would be scanned without scanning")
	scanCmd.Flags().StringVarP(&scanOutput, "output", "o", "table", "Output format (table, json, csv)")
	scanCmd.Flags().BoolVar(&scanFull, "full", false, "Force full scan, ignoring watermarks")
	scanCmd.Flags().BoolVar(&scanToxicCombos, "toxic-combos", true, "Detect toxic combinations of risk factors")
	scanCmd.Flags().BoolVar(&scanUseGraph, "graph", true, "Use security graph for enhanced analysis (attack paths, blast radius)")
	scanCmd.Flags().BoolVar(&scanExtractRelationships, "extract-relationships", false, "Extract resource relationships before scanning")
}

func runScan(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	application, err := app.New(ctx)
	if err != nil {
		return fmt.Errorf("failed to initialize: %w", err)
	}
	defer func() { _ = application.Close() }()

	if application.Snowflake == nil {
		return fmt.Errorf("snowflake not configured - set SNOWFLAKE_CONNECTION_STRING")
	}

	// Extract relationships if requested
	if scanExtractRelationships {
		Info("Extracting resource relationships from synced data...")
		relExtractor := nativesync.NewRelationshipExtractor(application.Snowflake, application.Logger)
		relCount, err := relExtractor.ExtractAndPersist(ctx)
		if err != nil {
			Warning("Relationship extraction had errors: %v", err)
		}
		Info("Extracted %d relationships", relCount)
	}

	policies := application.Policy.ListPolicies()
	if len(policies) == 0 {
		return fmt.Errorf("no policies loaded")
	}

	Info("Loaded %d policies", len(policies))

	graphAvailable := false
	if scanUseGraph {
		Info("Building security graph for enhanced analysis...")
		if err := application.RebuildSecurityGraph(ctx); err != nil {
			Warning("Security graph build failed, falling back to profile-based analysis: %v", err)
		} else if application.SecurityGraph != nil && application.SecurityGraph.NodeCount() > 0 {
			graphAvailable = true
		} else {
			Warning("Security graph is empty, falling back to profile-based analysis")
		}
	}

	// Determine tables to scan
	var tables []string
	if len(scanTables) > 0 {
		tables = scanTables
	} else {
		// Get tables based on resource types in policies
		tableSet := make(map[string]bool)
		for _, p := range policies {
			// Extract table name from resource pattern (e.g., "aws::s3::bucket" -> "aws_s3_buckets")
			if t := resourceToTable(p.Resource); t != "" {
				tableSet[t] = true
			}
		}
		for t := range tableSet {
			tables = append(tables, t)
		}
	}

	if len(tables) == 0 {
		Warning("No tables to scan - policies may not have table mappings")
		return nil
	}

	if scanDryRun {
		fmt.Println(bold("\nDry run - would scan:"))
		for _, t := range tables {
			fmt.Printf("  - %s (up to %d assets)\n", t, scanLimit)
		}
		fmt.Printf("\nUsing %d policies\n", len(policies))
		return nil
	}

	// Scan each table
	start := time.Now()
	var totalScanned int64
	var totalViolations int64
	var allFindings []map[string]interface{}

	for _, table := range tables {
		fmt.Printf("\n%s Scanning %s...\n", color(colorCyan, "→"), table)

		filter := snowflake.AssetFilter{Limit: scanLimit}

		// Use incremental scanning if available and not forced full scan
		// Note: scanWatermarks is available in application but not currently exposed in CLI
		// We'll check the watermark store directly
		if !scanFull && application.ScanWatermarks != nil {
			if wm := application.ScanWatermarks.GetWatermark(table); wm != nil {
				// Check if full scan is forced or needed (e.g. schema change, very old watermark)
				// For now, simple logic: if watermark exists and we aren't forcing full scan
				filter.Since = wm.LastScanTime
				fmt.Printf("  Incremental scan (since %s)\n", wm.LastScanTime.Format(time.RFC3339))
			}
		}
		if scanFull {
			fmt.Printf("  Full scan (--full flag set)\n")
		}

		assets, err := application.Snowflake.GetAssets(ctx, table, filter)
		if err != nil {
			Warning("Failed to fetch %s: %v", table, err)
			continue
		}

		if len(assets) == 0 {
			fmt.Printf("  No new assets found\n")
			continue
		}

		var scannedCount, violationCount int64
		var toxicCount int

		// Standard policy scan
		result := application.Scanner.ScanAssets(ctx, assets)
		scannedCount = result.Scanned
		violationCount = result.Violations

		for _, f := range result.Findings {
			application.Findings.Upsert(ctx, f)
			allFindings = append(allFindings, map[string]interface{}{
				"id":          f.ID,
				"policy_id":   f.PolicyID,
				"resource_id": f.ResourceID,
				"severity":    f.Severity,
			})
		}

		// Profile-based toxic combinations (only when graph analysis is not used)
		if scanToxicCombos && !graphAvailable {
			toxicFindings := application.Scanner.DetectToxicCombinations(ctx, assets)
			toxicCount = len(toxicFindings)
			violationCount += int64(toxicCount)

			for _, f := range toxicFindings {
				application.Findings.Upsert(ctx, f)
				allFindings = append(allFindings, map[string]interface{}{
					"id":          f.ID,
					"policy_id":   f.PolicyID,
					"resource_id": f.ResourceID,
					"severity":    f.Severity,
					"toxic_combo": true,
					"graph_based": false,
				})
			}
		}

		if scanToxicCombos && toxicCount > 0 {
			fmt.Printf("  Scanned: %d, Violations: %d (policy: %d, toxic: %s) (%s)\n",
				scannedCount,
				violationCount,
				len(result.Findings),
				color(colorRed, fmt.Sprintf("%d", toxicCount)),
				result.Duration.Round(time.Millisecond))
		} else {
			fmt.Printf("  Scanned: %d, Violations: %d (%s)\n",
				scannedCount,
				violationCount,
				result.Duration.Round(time.Millisecond))
		}

		totalScanned += scannedCount
		totalViolations += violationCount

		// Update watermark
		if application.ScanWatermarks != nil {
			application.ScanWatermarks.SetWatermark(table, time.Now().UTC(), scannedCount)
			// Persist watermarks (best effort)
			go func() {
				_ = application.ScanWatermarks.PersistWatermarks(ctx)
			}()
		}
	}

	var graphAttackPaths []map[string]interface{}
	var graphToxicCount int
	if scanToxicCombos && graphAvailable {
		graphResult := application.Scanner.AnalyzeGraph(ctx, application.SecurityGraph)
		if graphResult != nil {
			graphToxicCount = len(graphResult.ToxicCombinations)
			for _, f := range graphResult.ToxicCombinations {
				application.Findings.Upsert(ctx, f)
				allFindings = append(allFindings, map[string]interface{}{
					"id":          f.ID,
					"policy_id":   f.PolicyID,
					"resource_id": f.ResourceID,
					"severity":    f.Severity,
					"toxic_combo": true,
					"graph_based": true,
				})
			}

			for _, ap := range graphResult.AttackPaths {
				graphAttackPaths = append(graphAttackPaths, map[string]interface{}{
					"id":             ap.ID,
					"entry_point":    ap.EntryPoint,
					"target":         ap.Target,
					"steps":          ap.Steps,
					"risk_score":     ap.RiskScore,
					"exploitability": ap.Exploitability,
					"impact":         ap.Impact,
				})
			}

			totalViolations += int64(graphToxicCount)
		}
	}

	if graphAvailable {
		fmt.Printf("\nGraph analysis: toxic combinations: %d, attack paths: %d\n", graphToxicCount, len(graphAttackPaths))
	}

	duration := time.Since(start)

	if scanOutput == FormatJSON {
		return JSONOutput(map[string]interface{}{
			"scanned":            totalScanned,
			"violations":         totalViolations,
			"duration":           duration.String(),
			"findings":           allFindings,
			"graph_used":         graphAvailable,
			"graph_toxic_count":  graphToxicCount,
			"graph_attack_paths": graphAttackPaths,
		})
	}

	if scanOutput == FormatCSV {
		// CSV header
		headers := []string{"severity", "policy_id", "resource_id", "resource_name", "toxic_combo"}
		rows := make([][]string, 0, len(allFindings))
		for _, f := range allFindings {
			rows = append(rows, []string{
				toString(f["severity"]),
				toString(f["policy_id"]),
				toString(f["resource_id"]),
				toString(f["resource_name"]),
				toString(f["toxic_combo"]),
			})
		}
		return CSVOutput(headers, rows)
	}

	// Summary
	fmt.Println()
	fmt.Println(strings.Repeat("=", 50))
	fmt.Printf("%s Scan Complete\n", bold("✓"))
	fmt.Println(strings.Repeat("=", 50))
	fmt.Printf("Assets scanned:  %d\n", totalScanned)
	if totalViolations > 0 {
		fmt.Printf("Violations:      %s\n", color(colorRed, fmt.Sprintf("%d", totalViolations)))
	} else {
		fmt.Printf("Violations:      %s\n", color(colorGreen, "0"))
	}
	fmt.Printf("Duration:        %s\n", duration.Round(time.Millisecond))
	fmt.Printf("Policies:        %d\n", len(policies))

	return nil
}

func resourceToTable(resource string) string {
	// Map resource patterns to Snowflake table names
	mapping := map[string]string{
		// AWS - synced by native engine
		"aws::s3::bucket":             "aws_s3_buckets",
		"aws::ec2::instance":          "aws_ec2_instances",
		"aws::ec2::security_group":    "aws_ec2_security_groups",
		"aws::ec2::vpc":               "aws_ec2_vpcs",
		"aws::iam::user":              "aws_iam_users",
		"aws::iam::role":              "aws_iam_roles",
		"aws::iam::credential_report": "aws_iam_credential_reports",
		"aws::lambda::function":       "aws_lambda_functions",
		"aws::ecs::cluster":           "aws_ecs_clusters",
		"aws::ecs::service":           "aws_ecs_services",
		"aws::ecs::task_definition":   "aws_ecs_task_definitions",
		"aws::ecr::repository":        "aws_ecr_repositories",
		"aws::kms::key":               "aws_kms_keys",
		"aws::secretsmanager::secret": "aws_secretsmanager_secrets",
		"aws::rds::instance":          "aws_rds_instances",
		"aws::rds::db_instance":       "aws_rds_instances",
		"aws::dynamodb::table":        "aws_dynamodb_tables",
		"aws::redshift::cluster":      "aws_redshift_clusters",
		"aws::elbv2::load_balancer":   "aws_elbv2_load_balancers",
		"aws::elbv2::target_group":    "aws_elbv2_target_groups",
		"aws::sns::topic":             "aws_sns_topics",
		"aws::efs::file_system":       "aws_efs_file_systems",
		"aws::efs::mount_target":      "aws_efs_mount_targets",
		"aws::cloudtrail::trail":      "aws_cloudtrail_trails",
		"aws::sqs::queue":             "aws_sqs_queues",
		"aws::logs::log_group":        "aws_cloudwatch_log_groups",
		"aws::cloudwatch::log_group":  "aws_cloudwatch_log_groups",
		// GCP - synced by native engine
		"gcp::storage::bucket":          "gcp_storage_buckets",
		"gcp::compute::instance":        "gcp_compute_instances",
		"gcp::compute::firewall":        "gcp_compute_firewalls",
		"gcp::compute::network":         "gcp_compute_networks",
		"gcp::compute::subnetwork":      "gcp_compute_subnetworks",
		"gcp::iam::service_account":     "gcp_iam_service_accounts",
		"gcp::sql::database_instance":   "gcp_sql_instances",
		"gcp::cloudfunctions::function": "gcp_cloudfunctions_functions",
		"gcp::cloudrun::service":        "gcp_cloudrun_services",
		"gcp::cloudrun::revision":       "gcp_cloudrun_revisions",
		"gcp::pubsub::topic":            "gcp_pubsub_topics",
		"gcp::container::cluster":       "gcp_container_clusters",
		// Azure
		"azure::storage::account":         "azure_storage_accounts",
		"azure::compute::vm":              "azure_compute_virtual_machines",
		"azure::compute::virtual_machine": "azure_compute_virtual_machines",
	}

	if table, ok := mapping[resource]; ok {
		return table
	}

	// Try to construct table name from resource pattern
	// e.g., "aws::s3::bucket" -> "aws_s3_buckets"
	parts := strings.Split(resource, "::")
	if len(parts) >= 3 {
		tableName := parts[0] + "_" + parts[1] + "_" + parts[2] + "s"
		return strings.ToLower(tableName)
	}

	return ""
}

// toString safely converts interface{} to string
func toString(v interface{}) string {
	if v == nil {
		return ""
	}
	switch val := v.(type) {
	case string:
		return val
	case bool:
		if val {
			return "true"
		}
		return "false"
	default:
		return fmt.Sprintf("%v", v)
	}
}
