package cli

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/writerinternal/cerebro/internal/app"
	"github.com/writerinternal/cerebro/internal/snowflake"
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
	scanTable  string
	scanLimit  int
	scanDryRun bool
	scanOutput string
)

func init() {
	scanCmd.Flags().StringVarP(&scanTable, "table", "t", "", "Scan specific table only")
	scanCmd.Flags().IntVarP(&scanLimit, "limit", "l", 500, "Maximum assets to scan per table")
	scanCmd.Flags().BoolVar(&scanDryRun, "dry-run", false, "Show what would be scanned without scanning")
	scanCmd.Flags().StringVarP(&scanOutput, "output", "o", "table", "Output format (table,json)")
}

func runScan(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	application, err := app.New(ctx)
	if err != nil {
		return fmt.Errorf("failed to initialize: %w", err)
	}
	defer application.Close()

	if application.Snowflake == nil {
		return fmt.Errorf("snowflake not configured - set SNOWFLAKE_CONNECTION_STRING")
	}

	policies := application.Policy.ListPolicies()
	if len(policies) == 0 {
		return fmt.Errorf("no policies loaded")
	}

	Info("Loaded %d policies", len(policies))

	// Determine tables to scan
	var tables []string
	if scanTable != "" {
		tables = []string{scanTable}
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
		
		// Use incremental scanning if available and not dry run
		// Note: scanWatermarks is available in application but not currently exposed in CLI
		// We'll check the watermark store directly
		if application.ScanWatermarks != nil {
			if wm := application.ScanWatermarks.GetWatermark(table); wm != nil {
				// Check if full scan is forced or needed (e.g. schema change, very old watermark)
				// For now, simple logic: if watermark exists and we aren't forcing full scan
				filter.Since = wm.LastScanTime
				fmt.Printf("  Incremental scan (since %s)\n", wm.LastScanTime.Format(time.RFC3339))
			}
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

		result := application.Scanner.ScanAssets(ctx, assets)
		totalScanned += result.Scanned
		totalViolations += result.Violations

		// Update watermark
		if application.ScanWatermarks != nil {
			application.ScanWatermarks.SetWatermark(table, time.Now().UTC(), result.Scanned)
			// Persist watermarks (best effort)
			go application.ScanWatermarks.PersistWatermarks(ctx)
		}

		// Persist findings
		for _, f := range result.Findings {
			application.Findings.Upsert(ctx, f)
			resourceID := ""
			if arn, ok := f.Resource["arn"].(string); ok {
				resourceID = arn
			} else if name, ok := f.Resource["name"].(string); ok {
				resourceID = name
			}
			allFindings = append(allFindings, map[string]interface{}{
				"id":          f.ID,
				"policy_id":   f.PolicyID,
				"resource_id": resourceID,
				"severity":    f.Severity,
			})
		}

		// Show table results
		fmt.Printf("  Scanned: %d, Violations: %d (%s)\n",
			result.Scanned,
			result.Violations,
			result.Duration.Round(time.Millisecond))
	}

	duration := time.Since(start)

	if scanOutput == FormatJSON {
		return JSONOutput(map[string]interface{}{
			"scanned":    totalScanned,
			"violations": totalViolations,
			"duration":   duration.String(),
			"findings":   allFindings,
		})
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
	// Map resource patterns to CloudQuery table names
	mapping := map[string]string{
		"aws::s3::bucket":          "aws_s3_buckets",
		"aws::ec2::instance":       "aws_ec2_instances",
		"aws::iam::user":           "aws_iam_users",
		"aws::iam::role":           "aws_iam_roles",
		"aws::rds::instance":       "aws_rds_instances",
		"aws::lambda::function":    "aws_lambda_functions",
		"aws::ec2::security_group": "aws_ec2_security_groups",
		"gcp::storage::bucket":     "gcp_storage_buckets",
		"gcp::compute::instance":   "gcp_compute_instances",
		"azure::storage::account":  "azure_storage_accounts",
		"azure::compute::vm":       "azure_compute_virtual_machines",
	}

	if table, ok := mapping[resource]; ok {
		return table
	}

	// Try to construct table name from resource pattern
	// e.g., "aws::s3::bucket" -> "aws_s3_buckets"
	parts := strings.Split(resource, "::")
	if len(parts) >= 3 {
		return parts[0] + "_" + parts[1] + "_" + parts[2] + "s"
	}

	return ""
}
