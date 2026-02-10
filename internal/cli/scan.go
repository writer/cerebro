package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/writerinternal/cerebro/internal/app"
	"github.com/writerinternal/cerebro/internal/policy"
	"github.com/writerinternal/cerebro/internal/scanner"
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
	scanTables               []string
	scanLimit                int
	scanDryRun               bool
	scanOutput               string
	scanFull                 bool
	scanToxicCombos          bool
	scanUseGraph             bool
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
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	application, err := app.New(ctx)
	if err != nil {
		return fmt.Errorf("failed to initialize: %w", err)
	}
	defer func() { _ = application.Close() }()

	if application.Snowflake == nil {
		return fmt.Errorf("snowflake not configured: set SNOWFLAKE_PRIVATE_KEY, SNOWFLAKE_ACCOUNT, and SNOWFLAKE_USER")
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
		spinner := NewSpinner("Waiting for security graph")
		spinner.Start()
		if application.WaitForGraph(ctx) {
			spinner.Stop(true, fmt.Sprintf("Security graph ready (%d nodes, %d edges)", application.SecurityGraph.NodeCount(), application.SecurityGraph.EdgeCount()))
			graphAvailable = true
		} else {
			spinner.Stop(false, "Security graph not available, falling back to profile-based analysis")
		}
	}

	// Build set of available tables for filtering
	availableSet := make(map[string]bool)
	if application.AvailableTables != nil {
		for _, t := range application.AvailableTables {
			availableSet[strings.ToLower(t)] = true
		}
	}

	// Determine tables to scan
	var tables []string
	if len(scanTables) > 0 {
		tables = scanTables
	} else {
		tableSet := make(map[string]bool)
		for _, p := range policies {
			for _, t := range resourceToTables(p.Resource) {
				tableSet[t] = true
			}
		}
		for t := range tableSet {
			tables = append(tables, t)
		}
	}

	// Filter to only tables that actually exist in Snowflake
	if len(availableSet) > 0 {
		var valid []string
		skipped := 0
		for _, t := range tables {
			if availableSet[strings.ToLower(t)] {
				valid = append(valid, t)
			} else {
				skipped++
			}
		}
		if skipped > 0 {
			Info("Skipped %d tables not present in Snowflake", skipped)
		}
		tables = valid
	}

	if len(tables) == 0 {
		Warning("No tables to scan - policies may not have table mappings or tables not synced")
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

	// Scan tables concurrently
	start := time.Now()
	var totalScanned int64
	var totalViolations int64
	var allFindings []map[string]interface{}
	var scanMu sync.Mutex

	// Limit concurrent Snowflake queries to avoid overwhelming the warehouse
	const maxConcurrentScans = 6
	sem := make(chan struct{}, maxConcurrentScans)

	var scanWg sync.WaitGroup
	for _, table := range tables {
		table := table
		scanWg.Add(1)
		sem <- struct{}{} // acquire semaphore
		go func() {
			defer scanWg.Done()
			defer func() { <-sem }() // release semaphore

			scanned, violations, fnds := scanOneTable(ctx, application, table, scanFull, scanLimit, scanToxicCombos, graphAvailable)

			scanMu.Lock()
			totalScanned += scanned
			totalViolations += violations
			allFindings = append(allFindings, fnds...)
			scanMu.Unlock()
		}()
	}
	scanWg.Wait()

	// Start watermark persistence in the background while graph analysis runs.
	// We wait for it before returning so the Snowflake pool isn't closed underneath it.
	wmDone := make(chan struct{})
	if application.ScanWatermarks != nil {
		go func() {
			defer close(wmDone)
			wmCtx, wmCancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer wmCancel()
			if err := application.ScanWatermarks.PersistWatermarks(wmCtx); err != nil {
				Warning("Failed to persist watermarks: %v", err)
			}
		}()
	} else {
		close(wmDone)
	}

	// Track SQL toxic-combo risk categories per resource to avoid double-counting in graph analysis.
	sqlToxicRiskSets := make(map[string][]map[string]bool)

	// Relationship-based toxic combination detection (SQL query approach)
	if scanToxicCombos && application.Snowflake != nil {
		toxicFindings, err := detectToxicCombinationsFromRelationships(ctx, application.Snowflake)
		if err != nil {
			Warning("Failed to detect toxic combinations from relationships: %v", err)
		} else if len(toxicFindings) > 0 {
			// Count by severity
			critCount, highCount := 0, 0
			for _, f := range toxicFindings {
				if rid := normalizeResourceID(toString(f["resource_id"])); rid != "" {
					if risks := canonicalizeSQLRiskCategories(toString(f["risks"])); len(risks) > 0 {
						sqlToxicRiskSets[rid] = append(sqlToxicRiskSets[rid], risks)
					}
				}
				policyID := toString(f["policy_id"])
				resourceID := toString(f["resource_id"])
				resourceName := toString(f["resource_name"])
				if application.Findings != nil && policyID != "" && resourceID != "" {
					title := toString(f["title"])
					if title == "" {
						title = policyID
					}
					resource := map[string]interface{}{"id": resourceID}
					if resourceName != "" {
						resource["name"] = resourceName
					}
					if url := toString(f["url"]); url != "" {
						resource["url"] = url
					}
					if sa := toString(f["service_account"]); sa != "" {
						resource["service_account"] = sa
					}
					application.Findings.Upsert(ctx, policy.Finding{
						ID:             fmt.Sprintf("%s:%s", policyID, resourceID),
						PolicyID:       policyID,
						PolicyName:     title,
						Title:          title,
						Severity:       strings.ToLower(toString(f["severity"])),
						Description:    toString(f["description"]),
						Resource:       resource,
						ResourceID:     resourceID,
						ResourceName:   resourceName,
						RiskCategories: parseRiskCategories(toString(f["risks"])),
					})
				}
				switch toString(f["severity"]) {
				case "CRITICAL":
					critCount++
				case "HIGH":
					highCount++
				}
				allFindings = append(allFindings, f)
			}
			fmt.Printf("\n%s Toxic combinations detected:\n", color(colorRed, "⚠"))
			if critCount > 0 {
				fmt.Printf("  %s CRITICAL findings\n", color(colorRed, fmt.Sprintf("%d", critCount)))
			}
			if highCount > 0 {
				fmt.Printf("  %s HIGH findings\n", color(colorYellow, fmt.Sprintf("%d", highCount)))
			}
			totalViolations += int64(len(toxicFindings))
		}
	}

	var graphAttackPaths []map[string]interface{}
	var graphToxicCount int
	if scanToxicCombos && graphAvailable {
		graphResult := application.Scanner.AnalyzeGraph(ctx, application.SecurityGraph)
		if graphResult != nil {
			for _, f := range graphResult.ToxicCombinations {
				resourceID := normalizeResourceID(f.ResourceID)
				graphRiskSet := canonicalizeGraphRiskCategories(f.RiskCategories)
				if shouldSkipGraphToxicCombination(resourceID, graphRiskSet, sqlToxicRiskSets) {
					continue
				}
				application.Findings.Upsert(ctx, f)
				graphToxicCount++
				allFindings = append(allFindings, map[string]interface{}{
					"id":              f.ID,
					"policy_id":       f.PolicyID,
					"title":           f.Title,
					"description":     f.Description,
					"resource_id":     f.ResourceID,
					"resource_name":   f.ResourceName,
					"severity":        f.Severity,
					"risk_categories": f.RiskCategories,
					"remediation":     f.Remediation,
					"toxic_combo":     true,
					"graph_based":     true,
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
		if graphToxicCount > 0 {
			for _, f := range allFindings {
				gb, _ := f["graph_based"].(bool)
				tc, _ := f["toxic_combo"].(bool)
				if gb && tc {
					sev := toString(f["severity"])
					sevColor := colorYellow
					if sev == "critical" || sev == "CRITICAL" {
						sevColor = colorRed
					}
					fmt.Printf("  %s %s: %s\n", color(sevColor, "["+strings.ToUpper(sev)+"]"), toString(f["title"]), toString(f["resource_id"]))
				}
			}
		}
		if len(graphAttackPaths) > 0 {
			fmt.Println("\nAttack paths:")
			for _, ap := range graphAttackPaths {
				fmt.Printf("  %s -> %s (risk=%v)\n", toString(ap["entry_point"]), toString(ap["target"]), ap["risk_score"])
			}
		}
	}

	// Downgrade severity for findings from known dev/test environments.
	// This reduces alert fatigue without hiding the findings entirely.
	for i, f := range allFindings {
		if isDevResource(toString(f["resource_id"])) {
			orig := strings.ToUpper(toString(f["severity"]))
			if orig == "CRITICAL" || orig == "HIGH" {
				allFindings[i]["severity"] = "LOW"
				allFindings[i]["severity_original"] = orig
				allFindings[i]["dev_environment"] = true
			}
		}
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
		// CSV header - include title and risks for toxic combo parity
		headers := []string{"severity", "policy_id", "title", "resource_id", "resource_name", "risks", "toxic_combo"}
		rows := make([][]string, 0, len(allFindings))
		for _, f := range allFindings {
			rows = append(rows, []string{
				toString(f["severity"]),
				toString(f["policy_id"]),
				toString(f["title"]),
				toString(f["resource_id"]),
				toString(f["resource_name"]),
				toString(f["risks"]),
				toString(f["toxic_combo"]),
			})
		}
		return CSVOutput(headers, rows)
	}

	// Count by severity
	sevCounts := map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
	for _, f := range allFindings {
		sev := strings.ToUpper(toString(f["severity"]))
		sevCounts[sev]++
	}

	// Summary
	fmt.Println()
	fmt.Println(strings.Repeat("=", 50))
	fmt.Printf("%s Scan Complete\n", bold("✓"))
	fmt.Println(strings.Repeat("=", 50))
	fmt.Printf("Assets scanned:  %d\n", totalScanned)
	if totalViolations > 0 {
		fmt.Printf("Violations:      %s\n", color(colorRed, fmt.Sprintf("%d", totalViolations)))
		if sevCounts["CRITICAL"] > 0 {
			fmt.Printf("  Critical:      %s\n", color(colorRed, fmt.Sprintf("%d", sevCounts["CRITICAL"])))
		}
		if sevCounts["HIGH"] > 0 {
			fmt.Printf("  High:          %s\n", color(colorYellow, fmt.Sprintf("%d", sevCounts["HIGH"])))
		}
		if sevCounts["MEDIUM"] > 0 {
			fmt.Printf("  Medium:        %d\n", sevCounts["MEDIUM"])
		}
		if sevCounts["LOW"] > 0 {
			fmt.Printf("  Low:           %d\n", sevCounts["LOW"])
		}
	} else {
		fmt.Printf("Violations:      %s\n", color(colorGreen, "0"))
	}
	fmt.Printf("Duration:        %s\n", duration.Round(time.Millisecond))
	fmt.Printf("Policies:        %d\n", len(policies))

	// Show top resources with the most findings (helps prioritize remediation)
	if totalViolations > 0 {
		resourceCounts := make(map[string]int)
		resourceSev := make(map[string]string) // track highest severity per resource
		resourceLabels := make(map[string]string)
		for _, f := range allFindings {
			rid := normalizeResourceID(toString(f["resource_id"]))
			if rid == "" {
				continue
			}
			resourceCounts[rid]++
			sev := strings.ToUpper(toString(f["severity"]))
			if prev, ok := resourceSev[rid]; !ok || sevRank(sev) > sevRank(prev) {
				resourceSev[rid] = sev
			}
			if _, ok := resourceLabels[rid]; !ok {
				if name := strings.TrimSpace(toString(f["resource_name"])); name != "" {
					resourceLabels[rid] = name
				} else {
					resourceLabels[rid] = rid
				}
			}
		}
		// Show resources with 3+ findings
		type resourceEntry struct {
			id    string
			count int
			sev   string
		}
		var top []resourceEntry
		for rid, cnt := range resourceCounts {
			if cnt >= 3 {
				top = append(top, resourceEntry{rid, cnt, resourceSev[rid]})
			}
		}
		if len(top) > 0 {
			// Sort by count descending
			for i := 0; i < len(top); i++ {
				for j := i + 1; j < len(top); j++ {
					if top[j].count > top[i].count {
						top[i], top[j] = top[j], top[i]
					}
				}
			}
			if len(top) > 10 {
				top = top[:10]
			}
			fmt.Println("\nTop resources by finding count:")
			for _, r := range top {
				label := resourceLabels[r.id]
				if label == "" {
					label = r.id
				}
				if len(label) > 60 {
					label = "..." + label[len(label)-57:]
				}
				dev := ""
				if isDevResource(r.id) {
					dev = " (dev)"
				}
				fmt.Printf("  %3d  [%s] %s%s\n", r.count, r.sev, label, dev)
			}
		}
	}

	// Wait for watermark persistence to finish before the pool closes
	<-wmDone

	return nil
}

func sevRank(sev string) int {
	switch sev {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	default:
		return 0
	}
}

func parseRiskCategories(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	items := make([]string, 0, len(parts))
	for _, part := range parts {
		item := strings.TrimSpace(part)
		if item != "" {
			items = append(items, item)
		}
	}
	return items
}

func canonicalizeSQLRiskCategories(raw string) map[string]bool {
	return canonicalizeRiskCategories(parseRiskCategories(raw))
}

func canonicalizeGraphRiskCategories(categories []string) map[string]bool {
	return canonicalizeRiskCategories(categories)
}

func canonicalizeRiskCategories(categories []string) map[string]bool {
	if len(categories) == 0 {
		return nil
	}
	canon := make(map[string]bool)
	for _, category := range categories {
		label := canonicalizeRiskLabel(category)
		if label != "" {
			canon[label] = true
		}
	}
	if len(canon) == 0 {
		return nil
	}
	return canon
}

func canonicalizeRiskLabel(label string) string {
	label = strings.TrimSpace(label)
	if label == "" {
		return ""
	}
	label = strings.Trim(label, "\"")
	label = strings.ToLower(label)
	label = strings.ReplaceAll(label, "-", "_")
	label = strings.ReplaceAll(label, " ", "_")
	label = strings.ReplaceAll(label, "__", "_")
	switch label {
	case "external_exposure", "public_exposure", "public_access", "internet_exposure":
		return "network_exposure"
	case "unprotected_data", "data_exposure", "data_access":
		return "sensitive_data"
	case "unprotected_principal":
		return "over_privilege"
	case "no_authentication", "no_auth":
		return "weak_authentication"
	case "confused_deputy":
		return "privilege_escalation"
	}
	return label
}

func shouldSkipGraphToxicCombination(resourceID string, graphRisks map[string]bool, sqlRiskSets map[string][]map[string]bool) bool {
	if resourceID == "" || len(graphRisks) == 0 {
		return false
	}
	sets := sqlRiskSets[resourceID]
	if len(sets) == 0 {
		return false
	}
	for _, sqlSet := range sets {
		if riskSetSuperset(sqlSet, graphRisks) {
			return true
		}
	}
	return false
}

func riskSetSuperset(superset map[string]bool, subset map[string]bool) bool {
	if len(subset) == 0 {
		return false
	}
	for key := range subset {
		if !superset[key] {
			return false
		}
	}
	return true
}

func normalizeResourceID(id string) string {
	id = strings.TrimSpace(id)
	id = strings.Trim(id, "\"")
	return id
}

var resourceTableMapping = map[string]string{
	// AWS
	"aws::s3::bucket":                     "aws_s3_buckets",
	"aws::ec2::instance":                  "aws_ec2_instances",
	"aws::ec2::security_group":            "aws_ec2_security_groups",
	"aws::ec2::vpc":                       "aws_ec2_vpcs",
	"aws::iam::user":                      "aws_iam_users",
	"aws::iam::role":                      "aws_iam_roles",
	"aws::iam::credential_report":         "aws_iam_credential_reports",
	"aws::iam::account_password_policy":   "aws_iam_account_password_policies",
	"aws::lambda::function":               "aws_lambda_functions",
	"aws::ecs::cluster":                   "aws_ecs_clusters",
	"aws::ecs::service":                   "aws_ecs_services",
	"aws::ecs::task_definition":           "aws_ecs_task_definitions",
	"aws::ecr::repository":                "aws_ecr_repositories",
	"aws::kms::key":                       "aws_kms_keys",
	"aws::secretsmanager::secret":         "aws_secretsmanager_secrets",
	"aws::rds::instance":                  "aws_rds_instances",
	"aws::rds::db_instance":               "aws_rds_db_instances",
	"aws::dynamodb::table":                "aws_dynamodb_tables",
	"aws::redshift::cluster":              "aws_redshift_clusters",
	"aws::elbv2::load_balancer":           "aws_elbv2_load_balancers",
	"aws::elbv2::target_group":            "aws_elbv2_target_groups",
	"aws::sns::topic":                     "aws_sns_topics",
	"aws::efs::file_system":               "aws_efs_file_systems",
	"aws::efs::mount_target":              "aws_efs_mount_targets",
	"aws::cloudtrail::trail":              "aws_cloudtrail_trails",
	"aws::sqs::queue":                     "aws_sqs_queues",
	"aws::logs::log_group":                "aws_cloudwatch_log_groups",
	"aws::cloudwatch::log_group":          "aws_cloudwatch_log_groups",
	"aws::eks::cluster":                   "aws_eks_clusters",
	"aws::elasticache::cluster":           "aws_elasticache_clusters",
	"aws::apigateway::method":             "aws_apigateway_rest_api_methods",
	"aws::codebuild::project":             "aws_codebuild_projects",
	"aws::sagemaker::training_job":        "aws_sagemaker_training_jobs",
	"aws::bedrock::custom_model":          "aws_bedrock_custom_models",
	"aws::appsync::graphql_api":           "aws_appsync_graphql_apis",
	"aws::ec2::ebs_encryption_by_default": "aws_ec2_ebs_encryption_by_defaults",
	"aws::sagemaker::model_package_group": "aws_sagemaker_model_package_groups",
	"aws::ecr::public_repository":         "aws_ecr_public_repositories",
	"aws::iam::account_summary":           "aws_iam_account_summaries",
	// GCP
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
	"gcp::logging::project_sink":    "gcp_logging_project_sinks",
	"gcp::dns::managed_zone":        "gcp_dns_managed_zones",
	// Azure
	"azure::storage::account":         "azure_storage_accounts",
	"azure::compute::vm":              "azure_compute_virtual_machines",
	"azure::compute::virtual_machine": "azure_compute_virtual_machines",
	"azure::network::security_group":  "azure_network_security_groups",
	"azure::sql::server":              "azure_sql_servers",
	"azure::ad::user":                 "azure_ad_users",
}

// resourceToTables resolves a policy resource string (possibly pipe-separated)
// into one or more Snowflake table names.
func resourceToTables(resource string) []string {
	parts := strings.Split(resource, "|")
	seen := make(map[string]bool)
	var tables []string
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if t := resourceToTable(part); t != "" && !seen[t] {
			seen[t] = true
			tables = append(tables, t)
		}
	}
	return tables
}

func resourceToTable(resource string) string {
	if table, ok := resourceTableMapping[resource]; ok {
		return table
	}

	// Try to construct table name from resource pattern
	parts := strings.Split(resource, "::")
	if len(parts) >= 3 {
		tableName := parts[0] + "_" + parts[1] + "_" + pluralize(parts[2])
		return strings.ToLower(tableName)
	}

	// Already looks like a table name (e.g. "aws_iam_roles")
	if strings.Contains(resource, "_") && !strings.Contains(resource, "::") && !strings.Contains(resource, "|") {
		return strings.ToLower(resource)
	}

	return ""
}

func pluralize(s string) string {
	if s == "" {
		return s
	}
	if strings.HasSuffix(s, "s") {
		return s
	}
	if strings.HasSuffix(s, "y") && len(s) > 1 {
		// policy -> policies, summary -> summaries
		c := s[len(s)-2]
		if c != 'a' && c != 'e' && c != 'i' && c != 'o' && c != 'u' {
			return s[:len(s)-1] + "ies"
		}
	}
	return s + "s"
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

func filterCDCEvents(events []snowflake.CDCEvent) ([]string, time.Time) {
	ids := make([]string, 0, len(events))
	var maxTime time.Time
	for _, event := range events {
		if event.EventTime.After(maxTime) {
			maxTime = event.EventTime
		}
		if isRemovalEvent(event.ChangeType) {
			continue
		}
		if event.ResourceID != "" {
			ids = append(ids, event.ResourceID)
		}
	}

	return dedupeStrings(ids), maxTime
}

func dedupeStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

// scanOneTable fetches assets from one Snowflake table, evaluates policies, and returns results.
func scanOneTable(ctx context.Context, application *app.App, table string, full bool, limit int, toxicCombos, graphAvailable bool) (scanned, violations int64, findings []map[string]interface{}) {
	fmt.Printf("\n%s Scanning %s...\n", color(colorCyan, "→"), table)

	filter := snowflake.AssetFilter{Limit: limit}
	useCDC := false
	var cdcCursor time.Time
	var cdcIDs []string

	if !full && application.ScanWatermarks != nil {
		if wm := application.ScanWatermarks.GetWatermark(table); wm != nil {
			filter.Since = wm.LastScanTime
			filter.SinceID = wm.LastScanID

			cdcEvents, err := application.Snowflake.GetCDCEvents(ctx, table, wm.LastScanTime, limit)
			if err != nil {
				Warning("Failed to query CDC events for %s, falling back to sync_time: %v", table, err)
			} else {
				useCDC = true
				cdcIDs, cdcCursor = filterCDCEvents(cdcEvents)
			}
		}
	}

	var assets []map[string]interface{}
	var err error
	if useCDC && !full {
		if len(cdcIDs) == 0 {
			if !cdcCursor.IsZero() && application.ScanWatermarks != nil {
				application.ScanWatermarks.SetWatermark(table, cdcCursor, "", 0)
			}
			fmt.Printf("  No assets to scan for CDC changes\n")
			return 0, 0, nil
		}
		assets, err = application.Snowflake.GetAssetsByIDs(ctx, table, cdcIDs)
	} else {
		assets, err = application.Snowflake.GetAssets(ctx, table, filter)
	}
	if err != nil {
		Warning("Failed to fetch %s: %v", table, err)
		return 0, 0, nil
	}

	if len(assets) == 0 {
		fmt.Printf("  No new assets found\n")
		return 0, 0, nil
	}

	result := application.Scanner.ScanAssets(ctx, assets)
	scanned = result.Scanned
	violations = result.Violations

	for _, f := range result.Findings {
		application.Findings.Upsert(ctx, f)
		findings = append(findings, map[string]interface{}{
			"id":          f.ID,
			"policy_id":   f.PolicyID,
			"resource_id": f.ResourceID,
			"severity":    f.Severity,
		})
	}

	if toxicCombos && !graphAvailable {
		toxicFindings := application.Scanner.DetectToxicCombinations(ctx, assets)
		violations += int64(len(toxicFindings))
		for _, f := range toxicFindings {
			application.Findings.Upsert(ctx, f)
			findings = append(findings, map[string]interface{}{
				"id":          f.ID,
				"policy_id":   f.PolicyID,
				"resource_id": f.ResourceID,
				"severity":    f.Severity,
				"toxic_combo": true,
				"graph_based": false,
			})
		}
	}

	fmt.Printf("  Scanned: %d, Violations: %d (%s)\n",
		scanned, violations, result.Duration.Round(time.Millisecond))

	// Update watermark
	if application.ScanWatermarks != nil {
		cursorTime, cursorID := scanner.ExtractScanCursor(assets)
		if useCDC && !full && !cdcCursor.IsZero() {
			if scanner.IsCursorAfter(cdcCursor, "", cursorTime, cursorID) {
				cursorTime = cdcCursor
				cursorID = ""
			}
		}
		if cursorTime.IsZero() {
			cursorTime = time.Now().UTC()
		}
		application.ScanWatermarks.SetWatermark(table, cursorTime, cursorID, scanned)
	}

	return scanned, violations, findings
}

// devResourcePatterns identifies resources in development/test environments.
var devResourcePatterns = []string{
	"-dev-", "-dev/", "/dev/", "-staging-", "-staging/", "/staging/",
	"-test-", "-test/", "/test/", "-sandbox-", "-sandbox/", "/sandbox/",
	"writer-sa-dev", // GCP dev project
}

func isDevResource(resourceID string) bool {
	lower := strings.ToLower(resourceID)
	for _, p := range devResourcePatterns {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

func isRemovalEvent(changeType string) bool {
	switch strings.ToLower(changeType) {
	case "remove", "removed", "delete", "deleted":
		return true
	default:
		return false
	}
}

// detectToxicCombinationsFromRelationships queries the relationship table to detect toxic combinations
func detectToxicCombinationsFromRelationships(ctx context.Context, sf *snowflake.Client) ([]map[string]interface{}, error) {
	// Query for toxic combinations using relationship data
	query := `
WITH toxic_cloudrun_with_vuln AS (
    -- CRITICAL: Cloud Run with default SA + public exposure + unpinned image (vulnerability risk)
    SELECT 
        s.NAME as resource_id,
        REPLACE(s.NAME, '"', '') as clean_name,
        REPLACE(s.URI, '"', '') as url,
        r_sa.TARGET_ID as service_account,
        TEMPLATE:containers[0]:image::VARCHAR as container_image,
        CASE 
            WHEN TEMPLATE:containers[0]:image::VARCHAR LIKE '%:latest%' 
                 OR (TEMPLATE:containers[0]:image::VARCHAR NOT LIKE '%@sha256:%' 
                     AND TEMPLATE:containers[0]:image::VARCHAR NOT LIKE '%:%') 
            THEN TRUE ELSE FALSE 
        END as unpinned_image
    FROM GCP_CLOUDRUN_SERVICES s
    JOIN RAW.RESOURCE_RELATIONSHIPS r_sa 
        ON REPLACE(s.NAME, '"', '') = r_sa.SOURCE_ID 
        AND r_sa.REL_TYPE = 'USES_DEFAULT_SA'
    WHERE s.INGRESS = 'INGRESS_TRAFFIC_ALL'
),
toxic_buckets AS (
    -- CRITICAL: Public buckets
    SELECT 
        b.NAME as resource_id,
        REPLACE(b.NAME, '"', '') as clean_name,
        REPLACE(b.SELF_LINK, '"', '') as url,
        NULL as service_account,
        NULL as container_image,
        FALSE as unpinned_image
    FROM GCP_STORAGE_BUCKETS b
    WHERE b.IAM_POLICY LIKE '%allUsers%' OR b.IAM_POLICY LIKE '%allAuthenticatedUsers%'
),
high_iam_confused_deputy AS (
    -- HIGH: IAM roles without confused deputy protection that trust AWS services
    SELECT 
        r.ARN as resource_id,
        REPLACE(r.ARN, '"', '') as clean_name,
        NULL as url,
        NULL as service_account,
        NULL as container_image,
        FALSE as unpinned_image
    FROM AWS_IAM_ROLES r
    WHERE r.ASSUME_ROLE_POLICY_DOCUMENT NOT LIKE '%aws:SourceArn%'
      AND r.ASSUME_ROLE_POLICY_DOCUMENT NOT LIKE '%aws:SourceAccount%'
      AND r.ASSUME_ROLE_POLICY_DOCUMENT LIKE '%sts:AssumeRole%'
      AND r.ASSUME_ROLE_POLICY_DOCUMENT LIKE '%Service%'
),
high_cloudrun_no_auth AS (
    -- HIGH: Cloud Run services with no authentication (not using default SA)
    SELECT 
        s.NAME as resource_id,
        REPLACE(s.NAME, '"', '') as clean_name,
        REPLACE(s.URI, '"', '') as url,
        NULL as service_account,
        TEMPLATE:containers[0]:image::VARCHAR as container_image,
        FALSE as unpinned_image
    FROM GCP_CLOUDRUN_SERVICES s
    WHERE s.INGRESS = 'INGRESS_TRAFFIC_ALL'
      AND NOT EXISTS (
          SELECT 1 FROM RAW.RESOURCE_RELATIONSHIPS r 
          WHERE REPLACE(s.NAME, '"', '') = r.SOURCE_ID AND r.REL_TYPE = 'USES_DEFAULT_SA'
      )
)
-- CRITICAL: Cloud Run with default SA + public + unpinned image = vulnerability risk
SELECT 
    'CRITICAL' as severity,
    'toxic-cloudrun-vuln-default-sa' as policy_id,
    'Internet-facing Cloud Run with vulnerabilities and data access' as title,
    clean_name as resource_name,
    resource_id,
    url,
    service_account,
    container_image,
    'Cloud Run is public, uses default SA with data access, and runs unpinned image susceptible to supply chain attacks' as description,
    'EXTERNAL_EXPOSURE, VULNERABILITY, UNPROTECTED_PRINCIPAL, UNPROTECTED_DATA' as risks
FROM toxic_cloudrun_with_vuln
WHERE unpinned_image = TRUE

UNION ALL

-- CRITICAL: Cloud Run with default SA + public (no unpinned image)
SELECT 
    'CRITICAL' as severity,
    'toxic-cloudrun-external-default-sa' as policy_id,
    'Internet-facing Cloud Run with default SA and data access' as title,
    clean_name as resource_name,
    resource_id,
    url,
    service_account,
    container_image,
    'Cloud Run service is publicly accessible, uses default compute service account with broad permissions' as description,
    'EXTERNAL_EXPOSURE, UNPROTECTED_PRINCIPAL, UNPROTECTED_DATA' as risks
FROM toxic_cloudrun_with_vuln
WHERE unpinned_image = FALSE

UNION ALL

SELECT 
    'CRITICAL' as severity,
    'toxic-bucket-public-data' as policy_id,
    'Publicly readable bucket contains sensitive data' as title,
    clean_name as resource_name,
    resource_id,
    url,
    service_account,
    container_image,
    'Storage bucket is publicly accessible and may contain sensitive data' as description,
    'EXTERNAL_EXPOSURE, UNPROTECTED_DATA' as risks
FROM toxic_buckets

UNION ALL

SELECT 
    'HIGH' as severity,
    'iam-confused-deputy-risk' as policy_id,
    'IAM role vulnerable to confused deputy attack' as title,
    clean_name as resource_name,
    resource_id,
    url,
    service_account,
    container_image,
    'IAM role trust policy allows AWS services to assume it without SourceArn/SourceAccount conditions' as description,
    'CONFUSED_DEPUTY, PRIVILEGE_ESCALATION' as risks
FROM high_iam_confused_deputy

UNION ALL

SELECT 
    'HIGH' as severity,
    'cloudrun-public-no-auth' as policy_id,
    'Cloud Run service publicly accessible' as title,
    clean_name as resource_name,
    resource_id,
    url,
    service_account,
    container_image,
    'Cloud Run service is exposed to internet without IAM authentication' as description,
    'EXTERNAL_EXPOSURE, NO_AUTHENTICATION' as risks
FROM high_cloudrun_no_auth
`
	result, err := sf.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("toxic combination query failed: %w", err)
	}

	return mapToxicCombinationRows(result.Rows), nil
}

func mapToxicCombinationRows(rows []map[string]interface{}) []map[string]interface{} {
	findings := make([]map[string]interface{}, 0, len(rows))
	for _, row := range rows {
		f := map[string]interface{}{
			"severity":        toString(row["severity"]),
			"policy_id":       toString(row["policy_id"]),
			"title":           toString(row["title"]),
			"resource_id":     toString(row["resource_id"]),
			"resource_name":   toString(row["resource_name"]),
			"url":             toString(row["url"]),
			"service_account": toString(row["service_account"]),
			"description":     toString(row["description"]),
			"risks":           toString(row["risks"]),
			"toxic_combo":     true,
		}
		// Skip rows where the query returned empty/NULL columns
		if f["policy_id"] == "" && f["severity"] == "" {
			continue
		}
		findings = append(findings, f)
	}
	return findings
}
