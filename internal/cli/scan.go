package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/writer/cerebro/internal/app"
	"github.com/writer/cerebro/internal/policy"
	"github.com/writer/cerebro/internal/scanner"
	"github.com/writer/cerebro/internal/snowflake"
	nativesync "github.com/writer/cerebro/internal/sync"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan assets against security policies",
	Long: `Scan cloud assets from Snowflake against Cedar security policies.

Examples:
  cerebro scan                           # Scan all tables
  cerebro scan --table aws_s3_buckets    # Scan specific table
  cerebro scan --limit 1000              # Limit assets per table
  cerebro scan --dry-run                 # Show what would be scanned
  cerebro scan --preflight               # Validate scan prerequisites
  cerebro scan --local-fixture fixture.json  # Run local scan from fixture data`,
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
	scanPreflight            bool
	scanLocalFixture         string
	scanSnapshotDir          string
)

const (
	findingSourcePolicy             = "policy"
	findingSourceQueryPolicy        = "query_policy"
	findingSourceToxicCombo         = "toxic_combo"
	findingSourceToxicComboGraph    = "toxic_combo_graph"
	findingSourceToxicRelationship  = "toxic_combo_relationship"
	defaultSummaryTopLimit          = 5
	defaultRemediationPolicyIDLimit = 3
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
	scanCmd.Flags().BoolVar(&scanPreflight, "preflight", false, "Validate scan prerequisites and exit")
	scanCmd.Flags().StringVar(&scanLocalFixture, "local-fixture", "", "Path to local scan fixture JSON (table->assets) for scanning without Snowflake")
	scanCmd.Flags().StringVar(&scanSnapshotDir, "snapshot-dir", "", "Directory containing provider snapshot JSON files (<table>.json) for local scan mode")
}

func runScan(cmd *cobra.Command, args []string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	application, err := app.New(ctx)
	if err != nil {
		return fmt.Errorf("failed to initialize: %w", err)
	}
	defer func() { _ = application.Close() }()

	localDataset, err := resolveLocalScanDataset()
	if err != nil {
		return err
	}

	if scanPreflight {
		return runScanPreflight(application, localDataset)
	}

	localMode := localDataset != nil && len(localDataset.Tables) > 0
	if application.Snowflake == nil && !localMode {
		preflight := evaluateScanPreflight(application, nil)
		return fmt.Errorf("scan preflight failed: %s (run 'cerebro scan --preflight' for details)", preflight.Message)
	}

	if localMode {
		Info("Local scan mode enabled (%d tables from %s)", len(localDataset.Tables), localDataset.Source)
	}

	// Extract relationships if requested
	if scanExtractRelationships {
		if application.Snowflake == nil {
			Warning("Skipping relationship extraction in local scan mode (Snowflake not configured)")
		} else {
			Info("Extracting resource relationships from synced data...")
			relExtractor := nativesync.NewRelationshipExtractor(application.Snowflake, application.Logger)
			relCount, err := relExtractor.ExtractAndPersist(ctx)
			if err != nil {
				Warning("Relationship extraction had errors: %v", err)
			}
			Info("Extracted %d relationships", relCount)
		}
	}

	policies := application.Policy.ListPolicies()
	if len(policies) == 0 {
		return fmt.Errorf("no policies loaded")
	}

	Info("Loaded %d policies", len(policies))

	tuning := application.ScanTuning()

	graphAvailable := false
	if scanUseGraph && !localMode {
		spinner := NewSpinner("Waiting for security graph")
		spinner.Start()
		graphCtx := ctx
		cancel := func() {}
		if tuning.GraphWaitTimeout > 0 {
			graphCtx, cancel = context.WithTimeout(ctx, tuning.GraphWaitTimeout)
		}
		graphReady := application.WaitForGraph(graphCtx)
		cancel()
		if graphReady {
			spinner.Stop(true, fmt.Sprintf("Security graph ready (%d nodes, %d edges)", application.SecurityGraph.NodeCount(), application.SecurityGraph.EdgeCount()))
			graphAvailable = true
		} else {
			spinner.Stop(false, "Security graph not available, falling back to profile-based analysis")
		}
	}

	// Build set of available tables for filtering
	availableSet := make(map[string]bool)
	availableTables := application.AvailableTables
	if localMode {
		availableTables = sortedDatasetTables(localDataset)
		application.AvailableTables = append([]string(nil), availableTables...)
	} else if application.Snowflake != nil {
		if tables, err := application.Snowflake.ListAvailableTables(ctx); err == nil {
			application.AvailableTables = tables
			availableTables = tables
		} else {
			Warning("Failed to list available tables: %v", err)
		}
	}
	for _, t := range availableTables {
		availableSet[strings.ToLower(t)] = true
	}

	// Determine tables to scan
	var tables []string
	if len(scanTables) > 0 {
		tables = scanTables
	} else if len(availableTables) > 0 {
		tables = scannableTablesFromAvailable(availableTables)
		if localMode && len(tables) == 0 {
			tables = append([]string(nil), availableTables...)
		}
	} else {
		tables = nativesync.SupportedTableNames()
	}
	if len(tables) == 0 && !localMode {
		tables = nativesync.SupportedTableNames()
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
			if localMode {
				Info("Skipped %d tables not present in local dataset", skipped)
			} else {
				Info("Skipped %d tables not present in Snowflake", skipped)
			}
		}
		tables = valid
	}

	if len(tables) == 0 {
		if localMode {
			Warning("No tables to scan in local dataset")
		} else {
			Warning("No tables to scan - policies may not have table mappings or tables not synced")
		}
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
	var tableProfiles []scanner.TableScanProfile
	var scanMu sync.Mutex

	// Limit concurrent table scans to avoid overwhelming resources
	limiter := scanner.NewAdaptiveLimiter(tuning.MinConcurrent, tuning.MaxConcurrent, tuning.MaxConcurrent)

	var scanWg sync.WaitGroup
	for _, table := range tables {
		table := table
		scanWg.Add(1)
		go func() {
			defer scanWg.Done()
			if err := limiter.Acquire(ctx); err != nil {
				return
			}
			defer limiter.Release()

			var scanned, violations int64
			var fnds []map[string]interface{}
			var profile scanner.TableScanProfile
			if localMode {
				assets := localDataset.Tables[strings.ToLower(table)]
				scanned, violations, fnds, profile = scanOneLocalTable(ctx, application, table, assets, scanLimit, scanToxicCombos, graphAvailable, tuning)
			} else {
				scanned, violations, fnds, profile = scanOneTable(ctx, application, table, scanFull, scanLimit, scanToxicCombos, graphAvailable, tuning)
			}

			scanMu.Lock()
			totalScanned += scanned
			totalViolations += violations
			allFindings = append(allFindings, fnds...)
			tableProfiles = append(tableProfiles, profile)
			scanMu.Unlock()

			if tuning.AdaptiveConcurrency {
				adjustAdaptiveConcurrency(limiter, tuning, profile)
			}
		}()
	}
	scanWg.Wait()

	queryPolicyFindingCount := 0
	queryPolicyErrorCount := 0
	if !localMode {
		queryPolicyResult := application.ScanQueryPolicies(ctx)
		queryPolicyFindingCount = len(queryPolicyResult.Findings)
		queryPolicyErrorCount = len(queryPolicyResult.Errors)
		for _, errMsg := range queryPolicyResult.Errors {
			Warning("Query policy execution failed: %s", errMsg)
		}
		if queryPolicyFindingCount > 0 {
			for _, f := range queryPolicyResult.Findings {
				application.Findings.Upsert(ctx, f)
				allFindings = append(allFindings, policyFindingToMap(f, findingSourceQueryPolicy, map[string]interface{}{"query_policy": true}))
			}
			totalViolations += int64(queryPolicyFindingCount)
			fmt.Printf("\nQuery-policy findings: %d\n", queryPolicyFindingCount)
		}
	}
	// Track SQL toxic-combo risk categories per resource to avoid double-counting in graph analysis.
	sqlToxicRiskSets := make(map[string][]map[string]bool)

	// Relationship-based toxic combination detection (SQL query approach)
	if !localMode && scanToxicCombos && application.Snowflake != nil {
		var toxicCursor *scanner.ToxicScanCursor
		if application.ScanWatermarks != nil {
			if wm := application.ScanWatermarks.GetWatermark("_toxic_relationships"); wm != nil {
				toxicCursor = &scanner.ToxicScanCursor{SinceTime: wm.LastScanTime, SinceID: wm.LastScanID}
			}
		}
		toxicResult, err := scanner.DetectRelationshipToxicCombinations(ctx, application.Snowflake, toxicCursor)
		if err != nil {
			Warning("Failed to detect toxic combinations from relationships: %v", err)
		} else if len(toxicResult.Findings) > 0 {
			// Count by severity
			critCount, highCount := 0, 0
			for _, f := range toxicResult.Findings {
				if rid := normalizeResourceID(f.ResourceID); rid != "" {
					if risks := canonicalizeSQLRiskCategories(f.Risks); len(risks) > 0 {
						sqlToxicRiskSets[rid] = append(sqlToxicRiskSets[rid], risks)
					}
				}
				if application.Findings != nil && f.PolicyID != "" && f.ResourceID != "" {
					application.Findings.Upsert(ctx, f.ToPolicyFinding())
				}
				switch f.Severity {
				case "CRITICAL":
					critCount++
				case "HIGH":
					highCount++
				}
				allFindings = append(allFindings, relationshipFindingToMap(f))
			}
			fmt.Printf("\n%s Toxic combinations detected:\n", color(colorRed, "⚠"))
			if critCount > 0 {
				fmt.Printf("  %s CRITICAL findings\n", color(colorRed, fmt.Sprintf("%d", critCount)))
			}
			if highCount > 0 {
				fmt.Printf("  %s HIGH findings\n", color(colorYellow, fmt.Sprintf("%d", highCount)))
			}
			totalViolations += int64(len(toxicResult.Findings))
		}
		if err == nil && application.ScanWatermarks != nil && !toxicResult.MaxSyncTime.IsZero() {
			application.ScanWatermarks.SetWatermark("_toxic_relationships", toxicResult.MaxSyncTime, toxicResult.MaxCursorID, int64(len(toxicResult.Findings)))
		}
	}

	// Persist all watermarks (including toxic) in background while graph analysis runs.
	// Launched after toxic watermark is set so it is included in persistence.
	type watermarkResult struct {
		attempted bool
		err       error
		duration  time.Duration
	}
	wmResultCh := make(chan watermarkResult, 1)
	if !localMode && application.ScanWatermarks != nil {
		go func() {
			started := time.Now()
			err := application.ScanWatermarks.PersistWatermarksWithRetry(ctx, scanner.DefaultWatermarkPersistOptions())
			wmResultCh <- watermarkResult{attempted: true, err: err, duration: time.Since(started)}
		}()
	} else {
		wmResultCh <- watermarkResult{}
	}

	var graphAttackPaths []map[string]interface{}
	var graphStats scanner.AttackPathStats
	var graphChokepoints []scanner.AttackPathChokepointSummary
	var graphToxicCount int
	if scanToxicCombos && graphAvailable {
		graphResult := application.Scanner.AnalyzeGraph(ctx, application.SecurityGraph)
		if graphResult != nil {
			graphStats = graphResult.AttackPathStats
			graphChokepoints = graphResult.Chokepoints
			for _, f := range graphResult.ToxicCombinations {
				resourceID := normalizeResourceID(f.ResourceID)
				graphRiskSet := canonicalizeGraphRiskCategories(f.RiskCategories)
				if shouldSkipGraphToxicCombination(resourceID, graphRiskSet, sqlToxicRiskSets) {
					continue
				}
				application.Findings.Upsert(ctx, f)
				graphToxicCount++
				allFindings = append(allFindings, policyFindingToMap(f, findingSourceToxicComboGraph, map[string]interface{}{
					"toxic_combo": true,
					"graph_based": true,
				}))
			}

			for _, ap := range graphResult.AttackPaths {
				graphAttackPaths = append(graphAttackPaths, map[string]interface{}{
					"id":             ap.ID,
					"entry_point":    ap.EntryPoint,
					"target":         ap.Target,
					"steps":          ap.Steps,
					"length":         ap.Length,
					"risk_score":     ap.RiskScore,
					"exploitability": ap.Exploitability,
					"impact":         ap.Impact,
				})
			}

			totalViolations += int64(graphToxicCount)
		}
	}

	if graphAvailable {
		pathTotal := graphStats.TotalPaths
		if pathTotal == 0 {
			pathTotal = len(graphAttackPaths)
		}
		fmt.Printf("\nGraph analysis: toxic combinations: %d, attack paths: %d\n", graphToxicCount, pathTotal)
		if graphStats.CriticalPaths > 0 {
			fmt.Printf("  Critical paths: %d\n", graphStats.CriticalPaths)
		}
		if dist := formatPathLengthDistribution(graphStats.LengthCounts); dist != "" {
			fmt.Printf("  Path lengths: %s\n", dist)
		}
		if len(graphChokepoints) > 0 && pathTotal > 0 {
			fmt.Println("  Chokepoints:")
			for _, cp := range graphChokepoints {
				label := cp.NodeName
				if label == "" {
					label = cp.NodeID
				}
				if len(label) > 60 {
					label = "..." + label[len(label)-57:]
				}
				dev := ""
				if isDevResource(cp.NodeID) {
					dev = " (dev)"
				}
				fmt.Printf("    %s blocks %d/%d paths (impact %.0f%%)%s\n", label, cp.BlockedPaths, pathTotal, cp.RemediationImpact*100, dev)
			}
		}
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
				fmt.Printf("  %s -> %s (%d hops, risk=%v)\n", toString(ap["entry_point"]), toString(ap["target"]), toInt(ap["length"]), ap["risk_score"])
			}
		}
	}

	// Annotate findings from known dev/test environments with triage metadata.
	// The canonical severity is preserved; only triage fields are added.
	for i, f := range allFindings {
		if isDevResource(toString(f["resource_id"])) {
			allFindings[i]["environment_context"] = "development"
			orig := strings.ToUpper(toString(f["severity"]))
			if orig == "CRITICAL" || orig == "HIGH" {
				allFindings[i]["triage_priority"] = "LOW"
				allFindings[i]["triage_score"] = triageScoreForDevSeverity(orig)
				allFindings[i]["dev_environment"] = true
			}
		}
	}

	duration := time.Since(start)
	profileSummary := scanner.SummarizeTableProfiles(tableProfiles, duration)
	slowTables := scanner.FilterSlowTables(tableProfiles, tuning.ProfileSlowThreshold)

	var coverageReport *policy.CoverageReport
	if application.AvailableTables != nil && application.Policy != nil {
		report := application.Policy.CoverageReport(application.AvailableTables)
		coverageReport = &report
	}

	toxicSummary := summarizeToxicCombos(allFindings)
	policyHotspots := summarizePolicyHotspots(allFindings, defaultSummaryTopLimit)
	remediationActions := summarizeRemediationActions(allFindings, defaultSummaryTopLimit)
	wmResult := <-wmResultCh
	var watermarkInfo map[string]interface{}
	if wmResult.attempted {
		watermarkInfo = map[string]interface{}{
			"persisted": wmResult.err == nil,
			"duration":  wmResult.duration.String(),
		}
		if wmResult.err != nil {
			watermarkInfo["error"] = wmResult.err.Error()
		}
	}

	if scanOutput == FormatJSON {
		payload := map[string]interface{}{
			"scanned":                 totalScanned,
			"violations":              totalViolations,
			"duration":                duration.String(),
			"findings":                allFindings,
			"query_policy_findings":   queryPolicyFindingCount,
			"query_policy_errors":     queryPolicyErrorCount,
			"graph_used":              graphAvailable,
			"graph_toxic_count":       graphToxicCount,
			"graph_attack_paths":      graphAttackPaths,
			"attack_path_stats":       graphStats,
			"attack_path_chokepoints": graphChokepoints,
			"toxic_combo_summary":     toxicSummary,
			"policy_hotspots":         policyHotspots,
			"remediation_actions":     remediationActions,
		}
		payload["scan_profile"] = scanProfilePayload(profileSummary, slowTables, tuning.ProfileSlowThreshold)
		if coverageReport != nil {
			payload["policy_coverage"] = coverageReport
		}
		if watermarkInfo != nil {
			payload["watermarks"] = watermarkInfo
		}
		return JSONOutput(payload)
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
				findingRiskString(f),
				toString(f["toxic_combo"]),
			})
		}
		return CSVOutput(headers, rows)
	}

	if scanOutput == FormatTable {
		printScanProfiling(tableProfiles, tuning.ProfileSlowThreshold)
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
	if coverageReport != nil && coverageReport.TotalPolicies > 0 {
		fmt.Printf("Policy coverage: %.1f%% (%d/%d", coverageReport.CoveragePercent, coverageReport.CoveredPolicies, coverageReport.TotalPolicies)
		if coverageReport.UnknownResourcePolicies > 0 {
			fmt.Printf(", %d unknown", coverageReport.UnknownResourcePolicies)
		}
		if coverageReport.KnownCoveragePercent > 0 {
			fmt.Printf(", %.1f%% known", coverageReport.KnownCoveragePercent)
		}
		fmt.Println(")")
		if missing := topMissingTables(coverageReport.MissingTables, 5); len(missing) > 0 {
			fmt.Printf("  Missing tables: %s\n", strings.Join(missing, ", "))
		}
	}
	if wmResult.attempted {
		if wmResult.err != nil {
			fmt.Printf("Watermarks:      %s\n", color(colorYellow, "failed: "+truncateStr(wmResult.err.Error(), 120)))
		} else {
			fmt.Printf("Watermarks:      persisted (%s)\n", wmResult.duration.Round(time.Millisecond))
		}
	}
	if queryPolicyFindingCount > 0 || queryPolicyErrorCount > 0 {
		fmt.Printf("Query policies:  %d findings, %d errors\n", queryPolicyFindingCount, queryPolicyErrorCount)
	}
	if toxicSummary.Total > 0 {
		fmt.Printf("Toxic combos:    %d across %d resources\n", toxicSummary.Total, toxicSummary.ResourceCount)
		if toxicSummary.SeverityCounts["CRITICAL"] > 0 {
			fmt.Printf("  Critical:      %s\n", color(colorRed, fmt.Sprintf("%d", toxicSummary.SeverityCounts["CRITICAL"])))
		}
		if toxicSummary.SeverityCounts["HIGH"] > 0 {
			fmt.Printf("  High:          %s\n", color(colorYellow, fmt.Sprintf("%d", toxicSummary.SeverityCounts["HIGH"])))
		}
		if toxicSummary.SeverityCounts["MEDIUM"] > 0 {
			fmt.Printf("  Medium:        %d\n", toxicSummary.SeverityCounts["MEDIUM"])
		}
		if toxicSummary.SeverityCounts["LOW"] > 0 {
			fmt.Printf("  Low:           %d\n", toxicSummary.SeverityCounts["LOW"])
		}
		if len(toxicSummary.TopResources) > 0 {
			fmt.Println("  Top toxic resources:")
			for _, r := range toxicSummary.TopResources {
				label := r.ResourceName
				if label == "" {
					label = r.ResourceID
				}
				if len(label) > 60 {
					label = "..." + label[len(label)-57:]
				}
				dev := ""
				if r.DevEnvironment {
					dev = " (dev)"
				}
				fmt.Printf("    %s: %d combos (max %s)%s\n", label, r.Count, r.HighestSeverity, dev)
			}
		}
	}

	if len(policyHotspots) > 0 {
		fmt.Println("\nPolicy hotspots:")
		for _, hotspot := range policyHotspots {
			policyLabel := hotspot.PolicyID
			if hotspot.PolicyName != "" && !strings.EqualFold(hotspot.PolicyName, hotspot.PolicyID) {
				policyLabel = fmt.Sprintf("%s (%s)", hotspot.PolicyID, truncateStr(hotspot.PolicyName, 42))
			}
			example := ""
			if hotspot.SampleResource != "" {
				example = fmt.Sprintf(", e.g. %s", truncateStr(hotspot.SampleResource, 48))
			}
			fmt.Printf("  %s %s: %d findings across %d resources%s\n",
				severityLabel(hotspot.HighestSeverity),
				policyLabel,
				hotspot.Count,
				hotspot.ResourceCount,
				example,
			)
		}
	}

	if len(remediationActions) > 0 {
		fmt.Println("\nPriority remediation actions:")
		for _, remediation := range remediationActions {
			policyHint := ""
			if len(remediation.PolicyIDs) > 0 {
				policyHint = fmt.Sprintf(" [policies: %s]", strings.Join(remediation.PolicyIDs, ", "))
			}
			example := ""
			if remediation.ExampleResource != "" {
				example = fmt.Sprintf(" (e.g. %s)", truncateStr(remediation.ExampleResource, 40))
			}
			fmt.Printf("  %s x%d %s%s%s\n",
				severityLabel(remediation.HighestSeverity),
				remediation.Count,
				truncateStr(remediation.Remediation, 96),
				policyHint,
				example,
			)
		}
		fmt.Println("Next step:       cerebro findings list --severity critical,high --output table")
	}

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
	return scanner.ParseRiskCategories(raw)
}

func canonicalizeSQLRiskCategories(raw string) map[string]bool {
	return scanner.CanonicalizeRiskCategories(scanner.ParseRiskCategories(raw))
}

func canonicalizeGraphRiskCategories(categories []string) map[string]bool {
	return scanner.CanonicalizeRiskCategories(categories)
}

func canonicalizeRiskCategories(categories []string) map[string]bool {
	return scanner.CanonicalizeRiskCategories(categories)
}

func shouldSkipGraphToxicCombination(resourceID string, graphRisks map[string]bool, sqlRiskSets map[string][]map[string]bool) bool {
	return scanner.ShouldSkipGraphToxicCombination(resourceID, graphRisks, sqlRiskSets)
}

func normalizeResourceID(id string) string {
	return scanner.NormalizeResourceID(id)
}

type toxicComboSummary struct {
	Total          int                         `json:"total"`
	ResourceCount  int                         `json:"resource_count"`
	SeverityCounts map[string]int              `json:"severity_counts"`
	TopResources   []toxicComboResourceSummary `json:"top_resources"`
}

type toxicComboResourceSummary struct {
	ResourceID      string `json:"resource_id"`
	ResourceName    string `json:"resource_name"`
	Count           int    `json:"count"`
	HighestSeverity string `json:"highest_severity"`
	DevEnvironment  bool   `json:"dev_environment"`
}

type policyHotspotSummary struct {
	PolicyID        string `json:"policy_id"`
	PolicyName      string `json:"policy_name,omitempty"`
	Title           string `json:"title,omitempty"`
	Count           int    `json:"count"`
	HighestSeverity string `json:"highest_severity"`
	ResourceCount   int    `json:"resource_count"`
	SampleResource  string `json:"sample_resource,omitempty"`
}

type remediationActionSummary struct {
	Remediation     string   `json:"remediation"`
	Count           int      `json:"count"`
	HighestSeverity string   `json:"highest_severity"`
	PolicyIDs       []string `json:"policy_ids,omitempty"`
	ExampleResource string   `json:"example_resource,omitempty"`
}

func summarizePolicyHotspots(findings []map[string]interface{}, limit int) []policyHotspotSummary {
	if limit <= 0 || len(findings) == 0 {
		return nil
	}

	type aggregate struct {
		summary     policyHotspotSummary
		resourceSet map[string]struct{}
	}

	aggregates := make(map[string]*aggregate)
	for _, finding := range findings {
		policyID := strings.TrimSpace(toString(finding["policy_id"]))
		if policyID == "" {
			continue
		}

		agg := aggregates[policyID]
		if agg == nil {
			title := strings.TrimSpace(toString(finding["title"]))
			if title == "" {
				title = policyID
			}
			agg = &aggregate{
				summary: policyHotspotSummary{
					PolicyID:        policyID,
					PolicyName:      strings.TrimSpace(toString(finding["policy_name"])),
					Title:           title,
					HighestSeverity: strings.ToUpper(strings.TrimSpace(toString(finding["severity"]))),
				},
				resourceSet: make(map[string]struct{}),
			}
			aggregates[policyID] = agg
		}

		agg.summary.Count++
		severity := strings.ToUpper(strings.TrimSpace(toString(finding["severity"])))
		if sevRank(severity) > sevRank(agg.summary.HighestSeverity) {
			agg.summary.HighestSeverity = severity
		}
		if agg.summary.PolicyName == "" {
			agg.summary.PolicyName = strings.TrimSpace(toString(finding["policy_name"]))
		}

		resourceID := normalizeResourceID(toString(finding["resource_id"]))
		if resourceID != "" {
			agg.resourceSet[resourceID] = struct{}{}
			if agg.summary.SampleResource == "" {
				resourceName := strings.TrimSpace(toString(finding["resource_name"]))
				if resourceName == "" {
					resourceName = resourceID
				}
				agg.summary.SampleResource = resourceName
			}
		}
	}

	if len(aggregates) == 0 {
		return nil
	}

	summary := make([]policyHotspotSummary, 0, len(aggregates))
	for _, agg := range aggregates {
		agg.summary.ResourceCount = len(agg.resourceSet)
		summary = append(summary, agg.summary)
	}

	sort.Slice(summary, func(i, j int) bool {
		if summary[i].Count == summary[j].Count {
			if sevRank(summary[i].HighestSeverity) == sevRank(summary[j].HighestSeverity) {
				return summary[i].PolicyID < summary[j].PolicyID
			}
			return sevRank(summary[i].HighestSeverity) > sevRank(summary[j].HighestSeverity)
		}
		return summary[i].Count > summary[j].Count
	})

	if len(summary) > limit {
		summary = summary[:limit]
	}

	return summary
}

func summarizeRemediationActions(findings []map[string]interface{}, limit int) []remediationActionSummary {
	if limit <= 0 || len(findings) == 0 {
		return nil
	}

	type aggregate struct {
		summary   remediationActionSummary
		policySet map[string]struct{}
	}

	aggregates := make(map[string]*aggregate)
	for _, finding := range findings {
		remediation := strings.TrimSpace(toString(finding["remediation"]))
		if remediation == "" {
			continue
		}

		key := strings.ToLower(remediation)
		agg := aggregates[key]
		if agg == nil {
			agg = &aggregate{
				summary: remediationActionSummary{
					Remediation:     remediation,
					HighestSeverity: strings.ToUpper(strings.TrimSpace(toString(finding["severity"]))),
				},
				policySet: make(map[string]struct{}),
			}
			aggregates[key] = agg
		}

		agg.summary.Count++
		severity := strings.ToUpper(strings.TrimSpace(toString(finding["severity"])))
		if sevRank(severity) > sevRank(agg.summary.HighestSeverity) {
			agg.summary.HighestSeverity = severity
		}

		if policyID := strings.TrimSpace(toString(finding["policy_id"])); policyID != "" {
			agg.policySet[policyID] = struct{}{}
		}

		if agg.summary.ExampleResource == "" {
			resourceLabel := strings.TrimSpace(toString(finding["resource_name"]))
			if resourceLabel == "" {
				resourceLabel = normalizeResourceID(toString(finding["resource_id"]))
			}
			agg.summary.ExampleResource = resourceLabel
		}
	}

	if len(aggregates) == 0 {
		return nil
	}

	summary := make([]remediationActionSummary, 0, len(aggregates))
	for _, agg := range aggregates {
		policyIDs := make([]string, 0, len(agg.policySet))
		for policyID := range agg.policySet {
			policyIDs = append(policyIDs, policyID)
		}
		sort.Strings(policyIDs)
		if len(policyIDs) > defaultRemediationPolicyIDLimit {
			policyIDs = policyIDs[:defaultRemediationPolicyIDLimit]
		}
		agg.summary.PolicyIDs = policyIDs
		summary = append(summary, agg.summary)
	}

	sort.Slice(summary, func(i, j int) bool {
		if summary[i].Count == summary[j].Count {
			if sevRank(summary[i].HighestSeverity) == sevRank(summary[j].HighestSeverity) {
				return summary[i].Remediation < summary[j].Remediation
			}
			return sevRank(summary[i].HighestSeverity) > sevRank(summary[j].HighestSeverity)
		}
		return summary[i].Count > summary[j].Count
	})

	if len(summary) > limit {
		summary = summary[:limit]
	}

	return summary
}

func policyFindingToMap(f policy.Finding, source string, extras map[string]interface{}) map[string]interface{} {
	finding := map[string]interface{}{
		"id":              strings.TrimSpace(f.ID),
		"policy_id":       strings.TrimSpace(f.PolicyID),
		"policy_name":     strings.TrimSpace(f.PolicyName),
		"title":           strings.TrimSpace(f.Title),
		"description":     strings.TrimSpace(f.Description),
		"severity":        strings.TrimSpace(f.Severity),
		"resource_type":   strings.TrimSpace(f.ResourceType),
		"resource_id":     strings.TrimSpace(f.ResourceID),
		"resource_name":   strings.TrimSpace(f.ResourceName),
		"risk_categories": f.RiskCategories,
		"remediation":     strings.TrimSpace(f.Remediation),
		"control_id":      strings.TrimSpace(f.ControlID),
		"source":          strings.TrimSpace(source),
	}
	if len(f.Frameworks) > 0 {
		finding["frameworks"] = f.Frameworks
	}
	if len(f.MitreAttack) > 0 {
		finding["mitre_attack"] = f.MitreAttack
	}
	for key, value := range extras {
		finding[key] = value
	}
	return compactMap(finding)
}

func compactMap(input map[string]interface{}) map[string]interface{} {
	if len(input) == 0 {
		return map[string]interface{}{}
	}

	output := make(map[string]interface{}, len(input))
	for key, value := range input {
		switch v := value.(type) {
		case nil:
			continue
		case string:
			if strings.TrimSpace(v) == "" {
				continue
			}
		case []string:
			if len(v) == 0 {
				continue
			}
		case []interface{}:
			if len(v) == 0 {
				continue
			}
		}
		output[key] = value
	}

	return output
}

func findingRiskString(finding map[string]interface{}) string {
	if risks := strings.TrimSpace(toString(finding["risks"])); risks != "" {
		return risks
	}
	categories := extractRiskCategories(finding)
	if len(categories) == 0 {
		return ""
	}
	return strings.Join(categories, ", ")
}

func severityLabel(severity string) string {
	sev := strings.ToUpper(strings.TrimSpace(severity))
	if sev == "" {
		sev = "UNKNOWN"
	}
	var colorCode string
	switch sev {
	case "CRITICAL":
		colorCode = colorRed
	case "HIGH":
		colorCode = colorYellow
	case "MEDIUM":
		colorCode = colorBlue
	case "LOW":
		colorCode = colorGray
	default:
		colorCode = colorCyan
	}
	return color(colorCode, "["+sev+"]")
}

func summarizeToxicCombos(findings []map[string]interface{}) toxicComboSummary {
	summary := toxicComboSummary{
		SeverityCounts: map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0},
	}
	unique := make(map[string]struct{})
	resources := make(map[string]*toxicComboResourceSummary)
	for _, f := range findings {
		tc, _ := f["toxic_combo"].(bool)
		if !tc {
			continue
		}
		resourceID := normalizeResourceID(toString(f["resource_id"]))
		if resourceID == "" {
			continue
		}
		riskSig := riskSignature(extractRiskCategories(f), toString(f["policy_id"]))
		if riskSig == "" {
			riskSig = strings.ToLower(strings.TrimSpace(toString(f["title"])))
		}
		if riskSig == "" {
			continue
		}
		key := resourceID + "|" + riskSig
		if _, ok := unique[key]; ok {
			continue
		}
		unique[key] = struct{}{}
		summary.Total++

		sev := strings.ToUpper(toString(f["severity"]))
		if sev == "" {
			sev = "UNKNOWN"
		}
		if _, ok := summary.SeverityCounts[sev]; ok {
			summary.SeverityCounts[sev]++
		} else {
			summary.SeverityCounts["UNKNOWN"]++
		}

		resource := resources[resourceID]
		if resource == nil {
			resource = &toxicComboResourceSummary{
				ResourceID:      resourceID,
				ResourceName:    strings.TrimSpace(toString(f["resource_name"])),
				HighestSeverity: sev,
				DevEnvironment:  isDevResource(resourceID),
			}
			resources[resourceID] = resource
		}
		resource.Count++
		if resource.ResourceName == "" {
			resource.ResourceName = strings.TrimSpace(toString(f["resource_name"]))
		}
		if sevRank(sev) > sevRank(resource.HighestSeverity) {
			resource.HighestSeverity = sev
		}
	}

	summary.ResourceCount = len(resources)
	if len(resources) == 0 {
		return summary
	}

	top := make([]toxicComboResourceSummary, 0, len(resources))
	for _, resource := range resources {
		top = append(top, *resource)
	}
	sort.Slice(top, func(i, j int) bool {
		if top[i].Count == top[j].Count {
			return sevRank(top[i].HighestSeverity) > sevRank(top[j].HighestSeverity)
		}
		return top[i].Count > top[j].Count
	})
	if len(top) > 5 {
		top = top[:5]
	}
	summary.TopResources = top
	return summary
}

func extractRiskCategories(f map[string]interface{}) []string {
	if raw := toString(f["risks"]); raw != "" {
		return parseRiskCategories(raw)
	}
	if raw, ok := f["risk_categories"]; ok {
		switch v := raw.(type) {
		case []string:
			return v
		case []interface{}:
			categories := make([]string, 0, len(v))
			for _, item := range v {
				if s := toString(item); s != "" {
					categories = append(categories, s)
				}
			}
			return categories
		default:
			if s := toString(raw); s != "" {
				return parseRiskCategories(s)
			}
		}
	}
	return nil
}

func riskSignature(categories []string, fallback string) string {
	canon := canonicalizeRiskCategories(categories)
	if len(canon) == 0 {
		return strings.ToLower(strings.TrimSpace(fallback))
	}
	keys := make([]string, 0, len(canon))
	for key := range canon {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return strings.Join(keys, "|")
}

func formatPathLengthDistribution(counts map[int]int) string {
	if len(counts) == 0 {
		return ""
	}
	keys := make([]int, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	sort.Ints(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		label := "hops"
		if key == 1 {
			label = "hop"
		}
		parts = append(parts, fmt.Sprintf("%d %s: %d", key, label, counts[key]))
	}
	return strings.Join(parts, ", ")
}

func topMissingTables(counts map[string]int, limit int) []string {
	if limit <= 0 || len(counts) == 0 {
		return nil
	}
	type entry struct {
		table string
		count int
	}
	entries := make([]entry, 0, len(counts))
	for table, count := range counts {
		entries = append(entries, entry{table: table, count: count})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].count == entries[j].count {
			return entries[i].table < entries[j].table
		}
		return entries[i].count > entries[j].count
	})
	if len(entries) > limit {
		entries = entries[:limit]
	}
	results := make([]string, 0, len(entries))
	for _, entry := range entries {
		results = append(results, fmt.Sprintf("%s (%d)", entry.table, entry.count))
	}
	return results
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

func toInt(v interface{}) int {
	if v == nil {
		return 0
	}
	switch val := v.(type) {
	case int:
		return val
	case int32:
		return int(val)
	case int64:
		return int(val)
	case float32:
		return int(val)
	case float64:
		return int(val)
	case string:
		if parsed, err := strconv.Atoi(val); err == nil {
			return parsed
		}
	}
	return 0
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

func retryCount(attempts int) int {
	if attempts > 1 {
		return attempts - 1
	}
	return 0
}

func relationshipFindingToMap(f scanner.RelationshipToxicFinding) map[string]interface{} {
	return map[string]interface{}{
		"severity":        f.Severity,
		"policy_id":       f.PolicyID,
		"title":           f.Title,
		"resource_id":     f.ResourceID,
		"resource_name":   f.ResourceName,
		"url":             f.URL,
		"service_account": f.ServiceAccount,
		"description":     f.Description,
		"risks":           f.Risks,
		"toxic_combo":     true,
		"source":          findingSourceToxicRelationship,
	}
}

func adjustAdaptiveConcurrency(limiter *scanner.AdaptiveLimiter, tuning app.ScanTuning, profile scanner.TableScanProfile) {
	limit := limiter.Limit()
	newLimit := limit
	slow := profile.TimedOut || profile.FetchErrors > 0 || profile.RetryAttempts > 0 || profile.Duration >= tuning.SlowTableThreshold
	fast := !slow && profile.Duration > 0 && profile.Duration <= tuning.FastTableThreshold
	if slow {
		newLimit = limit - 1
	} else if fast {
		newLimit = limit + 1
	}
	if newLimit == limit {
		return
	}
	adjusted := limiter.Adjust(newLimit)
	if adjusted == limit {
		return
	}
	Info("Adjusting scan concurrency: %d -> %d (table=%s, duration=%s, retries=%d, errors=%d)",
		limit,
		adjusted,
		profile.Table,
		profile.Duration.Round(time.Second),
		profile.RetryAttempts,
		profile.FetchErrors,
	)
}

func printScanProfiling(profiles []scanner.TableScanProfile, slowThreshold time.Duration) {
	if len(profiles) == 0 {
		return
	}
	sorted := scanner.SortTableProfilesByDuration(profiles)
	maxRows := 5
	if len(sorted) < maxRows {
		maxRows = len(sorted)
	}
	if maxRows == 0 {
		return
	}
	fmt.Println("\nScan profiling:")
	for i := 0; i < maxRows; i++ {
		profile := sorted[i]
		status := ""
		if profile.TimedOut {
			status = " (timeout)"
		}
		fmt.Printf("  %s: %s scanned=%d violations=%d retries=%d errors=%d%s\n",
			profile.Table,
			profile.Duration.Round(time.Second),
			profile.Scanned,
			profile.Violations,
			profile.RetryAttempts,
			profile.FetchErrors,
			status,
		)
	}
	slowTables := scanner.FilterSlowTables(profiles, slowThreshold)
	if len(slowTables) > 0 {
		names := make([]string, 0, len(slowTables))
		for _, profile := range slowTables {
			names = append(names, profile.Table)
		}
		fmt.Printf("  Slow tables (>%s): %s\n", slowThreshold, strings.Join(names, ", "))
	}
}

func scanProfilePayload(summary scanner.ScanProfileSummary, slowTables []scanner.TableScanProfile, slowThreshold time.Duration) map[string]interface{} {
	profiles := make([]map[string]interface{}, 0, len(summary.Tables))
	for _, profile := range summary.Tables {
		profiles = append(profiles, map[string]interface{}{
			"table":          profile.Table,
			"duration":       profile.Duration.String(),
			"scanned":        profile.Scanned,
			"violations":     profile.Violations,
			"cache_skipped":  profile.CacheSkipped,
			"batches":        profile.Batches,
			"retry_attempts": profile.RetryAttempts,
			"fetch_errors":   profile.FetchErrors,
			"scan_errors":    profile.ScanErrors,
			"timed_out":      profile.TimedOut,
		})
	}
	slow := make([]map[string]interface{}, 0, len(slowTables))
	for _, profile := range slowTables {
		slow = append(slow, map[string]interface{}{
			"table":     profile.Table,
			"duration":  profile.Duration.String(),
			"timed_out": profile.TimedOut,
		})
	}
	return map[string]interface{}{
		"total_scanned":    summary.TotalScanned,
		"total_violations": summary.TotalViolations,
		"total_skipped":    summary.TotalSkipped,
		"total_duration":   summary.TotalDuration.String(),
		"slow_threshold":   slowThreshold.String(),
		"tables":           profiles,
		"slow_tables":      slow,
	}
}

// scanOneTable fetches assets from one Snowflake table, evaluates policies, and returns results.
func scanOneTable(ctx context.Context, application *app.App, table string, full bool, limit int, toxicCombos, graphAvailable bool, tuning app.ScanTuning) (scanned, violations int64, findings []map[string]interface{}, profile scanner.TableScanProfile) {
	fmt.Printf("\n%s Scanning %s...\n", color(colorCyan, "→"), table)

	profile = scanner.TableScanProfile{Table: table}
	start := time.Now()

	tableCtx := ctx
	cancel := func() {}
	if tuning.TableTimeout > 0 {
		tableCtx, cancel = context.WithTimeout(ctx, tuning.TableTimeout)
	}
	defer cancel()
	defer func() {
		profile.Scanned = scanned
		profile.Violations = violations
		profile.Duration = time.Since(start)
		if errors.Is(tableCtx.Err(), context.DeadlineExceeded) {
			profile.TimedOut = true
		}
	}()

	columns := application.ScanColumnsForTable(tableCtx, table)
	limitActive := limit > 0
	batchSize := scanner.DefaultIncrementalConfig().BatchSize
	if limitActive && limit < batchSize {
		batchSize = limit
	}
	if batchSize <= 0 {
		batchSize = scanner.DefaultIncrementalConfig().BatchSize
	}

	filter := snowflake.AssetFilter{Limit: batchSize, Columns: columns}
	useCDC := false
	var cdcCursor time.Time
	var cdcIDs []string

	if !full && application.ScanWatermarks != nil {
		if wm := application.ScanWatermarks.GetWatermark(table); wm != nil {
			filter.Since = wm.LastScanTime
			filter.SinceID = wm.LastScanID

			cdcEvents, attempts, err := scanner.WithRetryValue(tableCtx, tuning.RetryOptions, func() ([]snowflake.CDCEvent, error) {
				return application.Snowflake.GetCDCEvents(tableCtx, table, wm.LastScanTime, batchSize)
			})
			profile.RetryAttempts += retryCount(attempts)
			if err != nil {
				profile.FetchErrors++
				Warning("Failed to query CDC events for %s, falling back to sync_time: %v", table, err)
			} else if len(cdcEvents) > 0 && len(cdcEvents) < batchSize {
				useCDC = true
				cdcIDs, cdcCursor = filterCDCEvents(cdcEvents)
			}
		}
	}

	remaining := int64(limit)
	var cursorTime time.Time
	var cursorID string

	if useCDC && !full {
		if len(cdcIDs) == 0 {
			if !cdcCursor.IsZero() && application.ScanWatermarks != nil {
				application.ScanWatermarks.SetWatermark(table, cdcCursor, "", 0)
			}
			fmt.Printf("  No assets to scan for CDC changes\n")
			return 0, 0, nil, profile
		}

		assets, attempts, err := scanner.WithRetryValue(tableCtx, tuning.RetryOptions, func() ([]map[string]interface{}, error) {
			return application.Snowflake.GetAssetsByIDs(tableCtx, table, cdcIDs, columns)
		})
		profile.RetryAttempts += retryCount(attempts)
		if err != nil {
			profile.FetchErrors++
			Warning("Failed to fetch %s: %v", table, err)
			return 0, 0, nil, profile
		}
		if len(assets) == 0 {
			fmt.Printf("  No new assets found\n")
			return 0, 0, nil, profile
		}

		result := application.Scanner.ScanAssets(tableCtx, assets)
		profile.Batches++
		profile.CacheSkipped += result.Skipped
		profile.ScanErrors += len(result.Errors)
		scanned += result.Scanned
		violations += result.Violations

		for _, f := range result.Findings {
			application.Findings.Upsert(tableCtx, f)
			findings = append(findings, policyFindingToMap(f, findingSourcePolicy, nil))
		}

		if toxicCombos && !graphAvailable {
			toxicFindings := application.Scanner.DetectToxicCombinations(tableCtx, assets)
			violations += int64(len(toxicFindings))
			for _, f := range toxicFindings {
				application.Findings.Upsert(tableCtx, f)
				findings = append(findings, policyFindingToMap(f, findingSourceToxicCombo, map[string]interface{}{
					"toxic_combo": true,
					"graph_based": false,
				}))
			}
		}

		cursorTime, cursorID = scanner.ExtractScanCursor(assets)
	} else {
		for !limitActive || remaining > 0 {
			if tableCtx.Err() != nil {
				break
			}
			if limitActive && remaining < int64(batchSize) {
				filter.Limit = int(remaining)
			} else {
				filter.Limit = batchSize
			}

			assets, attempts, err := scanner.WithRetryValue(tableCtx, tuning.RetryOptions, func() ([]map[string]interface{}, error) {
				return application.Snowflake.GetAssets(tableCtx, table, filter)
			})
			profile.RetryAttempts += retryCount(attempts)
			if err != nil {
				profile.FetchErrors++
				Warning("Failed to fetch %s: %v", table, err)
				break
			}
			if len(assets) == 0 {
				if scanned == 0 {
					fmt.Printf("  No new assets found\n")
				}
				break
			}

			result := application.Scanner.ScanAssets(tableCtx, assets)
			profile.Batches++
			profile.CacheSkipped += result.Skipped
			profile.ScanErrors += len(result.Errors)
			scanned += result.Scanned
			violations += result.Violations

			for _, f := range result.Findings {
				application.Findings.Upsert(tableCtx, f)
				findings = append(findings, policyFindingToMap(f, findingSourcePolicy, nil))
			}

			if toxicCombos && !graphAvailable {
				toxicFindings := application.Scanner.DetectToxicCombinations(tableCtx, assets)
				violations += int64(len(toxicFindings))
				for _, f := range toxicFindings {
					application.Findings.Upsert(tableCtx, f)
					findings = append(findings, policyFindingToMap(f, findingSourceToxicCombo, map[string]interface{}{
						"toxic_combo": true,
						"graph_based": false,
					}))
				}
			}

			batchTime, batchID := scanner.ExtractScanCursor(assets)
			if scanner.IsCursorAfter(batchTime, batchID, cursorTime, cursorID) {
				cursorTime = batchTime
				cursorID = batchID
			}

			// Advance cursor for next batch (keyset pagination)
			if !filter.Since.IsZero() {
				if batchTime.IsZero() {
					break
				}
				filter.Since = batchTime
				filter.SinceID = batchID
			} else {
				if batchTime.IsZero() {
					break
				}
				filter.CursorSyncTime = batchTime
				filter.CursorID = batchID
			}

			if limitActive {
				remaining -= result.Scanned
				if remaining <= 0 {
					break
				}
			}
			if len(assets) < filter.Limit {
				break
			}
		}
	}

	if scanned > 0 {
		fmt.Printf("  Scanned: %d, Violations: %d (%s)\n",
			scanned, violations, time.Since(start).Round(time.Millisecond))
	}
	if errors.Is(tableCtx.Err(), context.DeadlineExceeded) {
		profile.TimedOut = true
		Warning("Table %s timed out after %s", table, tuning.TableTimeout)
	}

	if application.ScanWatermarks != nil && scanned > 0 {
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

	return scanned, violations, findings, profile
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

// triageScoreForDevSeverity returns a numeric triage score (0-100) for
// dev/test environment findings. Lower score = lower operational priority.
func triageScoreForDevSeverity(severity string) int {
	switch severity {
	case "CRITICAL":
		return 15
	case "HIGH":
		return 10
	default:
		return 5
	}
}

func isRemovalEvent(changeType string) bool {
	switch strings.ToLower(changeType) {
	case "remove", "removed", "delete", "deleted":
		return true
	default:
		return false
	}
}
