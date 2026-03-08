package app

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/evalops/cerebro/internal/findings"
	"github.com/evalops/cerebro/internal/notifications"
	"github.com/evalops/cerebro/internal/scanner"
	"github.com/evalops/cerebro/internal/scheduler"
	"github.com/evalops/cerebro/internal/snowflake"
	nativesync "github.com/evalops/cerebro/internal/sync"
)

func (a *App) initScheduler(_ context.Context) {
	a.Scheduler = scheduler.NewScheduler(a.Logger)

	// Add scan job if interval configured
	if a.Config.ScanInterval != "" {
		interval, err := parseDuration(a.Config.ScanInterval)
		if err != nil {
			a.Logger.Warn("invalid scan interval", "value", a.Config.ScanInterval, "error", err)
			return
		}

		a.Scheduler.AddJob("policy-scan", interval, func(ctx context.Context) error {
			tables := a.resolveScanTables(ctx)
			if len(tables) == 0 {
				a.Logger.Info("no tables available for scheduled scan")
				return nil
			}
			return a.runScheduledScan(ctx, tables)
		})

		if a.Config.ScanTables != "" {
			a.Logger.Info("scheduled scanning enabled", "interval", interval, "tables", splitTables(a.Config.ScanTables))
		} else {
			a.Logger.Info("scheduled scanning enabled", "interval", interval, "table_source", "available_tables")
		}
	}

	// Add security digest job if interval configured
	if a.Config.SecurityDigestInterval != "" {
		interval, err := parseDuration(a.Config.SecurityDigestInterval)
		if err != nil {
			a.Logger.Warn("invalid security digest interval", "value", a.Config.SecurityDigestInterval, "error", err)
		} else {
			a.Scheduler.AddJob("security-digest", interval, func(ctx context.Context) error {
				return a.sendSecurityDigest(ctx)
			})
			a.Logger.Info("scheduled security digest enabled", "interval", interval)
		}
	}

	// Add graph rebuild job - rebuild hourly by default
	graphInterval := time.Hour
	if envInterval := getEnv("GRAPH_REBUILD_INTERVAL", ""); envInterval != "" {
		if parsed, err := parseDuration(envInterval); err == nil {
			graphInterval = parsed
		}
	}

	a.Scheduler.AddJob("graph-rebuild", graphInterval, func(ctx context.Context) error {
		if a.SecurityGraphBuilder == nil {
			return nil
		}

		if !a.SecurityGraphBuilder.HasChanges(ctx) {
			a.Logger.Info("security graph rebuild skipped - no data changes detected")
			return nil
		}

		summary, err := a.SecurityGraphBuilder.ApplyChanges(ctx, time.Time{})
		if err != nil {
			a.Logger.Warn("incremental graph apply failed, falling back to full rebuild", "error", err)
			if err := a.SecurityGraphBuilder.Build(ctx); err != nil {
				return err
			}
			a.SecurityGraph = a.SecurityGraphBuilder.Graph()
			meta := a.SecurityGraph.Metadata()
			a.Logger.Info("security graph rebuilt",
				"nodes", meta.NodeCount,
				"edges", meta.EdgeCount,
				"duration", meta.BuildDuration,
			)
			a.emitGraphRebuiltEvent(ctx, meta, meta.BuildDuration)
			a.emitGraphMutationEvent(ctx, a.SecurityGraphBuilder.LastMutation(), "scheduler_full_rebuild")
			return nil
		}

		if summary.EventsProcessed == 0 {
			a.Logger.Info("security graph rebuild skipped - no CDC events found")
			return nil
		}

		a.SecurityGraph = a.SecurityGraphBuilder.Graph()
		meta := a.SecurityGraph.Metadata()
		a.Logger.Info("security graph incrementally updated",
			"events", summary.EventsProcessed,
			"nodes_added", summary.NodesAdded,
			"nodes_updated", summary.NodesUpdated,
			"nodes_removed", summary.NodesRemoved,
			"nodes", meta.NodeCount,
			"edges", meta.EdgeCount,
			"duration", summary.Duration,
		)
		a.emitGraphMutationEvent(ctx, summary, "scheduler_incremental")
		return nil
	})
	a.Logger.Info("scheduled graph rebuild enabled", "interval", graphInterval)
}

func (a *App) runScheduledScan(ctx context.Context, tables []string) error {
	if a.Snowflake == nil {
		return fmt.Errorf("snowflake not configured")
	}

	scanStart := time.Now()

	tuning := a.ScanTuning()
	var tableProfiles []scanner.TableScanProfile
	var totalScanned int64
	var totalViolations int64
	var queryPolicyFindingCount int
	var queryPolicyErrorCount int
	var relationshipCount int
	var graphToxicCount int
	var graphPaths int
	const batchSize = 1000
	const maxWatermarkAge = 7 * 24 * time.Hour

	for _, table := range tables {
		tableProfile := scanner.TableScanProfile{Table: table}
		tableStart := time.Now()
		tableCtx := ctx
		cancel := func() {}
		if tuning.TableTimeout > 0 {
			tableCtx, cancel = context.WithTimeout(ctx, tuning.TableTimeout)
		}

		// Build filter with incremental scanning support
		columns := a.ScanColumnsForTable(tableCtx, table)
		filter := snowflake.AssetFilter{Limit: batchSize, Columns: columns}
		var cursorTime time.Time
		var cursorID string
		useCursorPaging := false

		// Use watermarks for incremental scanning
		if a.ScanWatermarks != nil {
			if !a.ScanWatermarks.ShouldFullScan(table, maxWatermarkAge) {
				if wm := a.ScanWatermarks.GetWatermark(table); wm != nil {
					filter.Since = wm.LastScanTime
					filter.SinceID = wm.LastScanID
					a.Logger.Debug("incremental scan", "table", table, "since", wm.LastScanTime)
					useCursorPaging = true
				}
			}
		}

		// Paginate through all assets
		tableScanned := int64(0)
		tableViolations := int64(0)
		offset := 0
		for tableCtx.Err() == nil {
			if !useCursorPaging {
				filter.Offset = offset
			}
			assets, attempts, err := scanner.WithRetryValue(tableCtx, tuning.RetryOptions, func() ([]map[string]interface{}, error) {
				return a.Snowflake.GetAssets(tableCtx, table, filter)
			})
			if attempts > 1 {
				tableProfile.RetryAttempts += attempts - 1
			}
			if err != nil {
				tableProfile.FetchErrors++
				a.Logger.Warn("failed to fetch assets", "table", table, "offset", offset, "error", err)
				break
			}

			if len(assets) == 0 {
				break
			}

			result := a.Scanner.ScanAssets(tableCtx, assets)
			tableProfile.Batches++
			tableProfile.CacheSkipped += result.Skipped
			tableProfile.ScanErrors += len(result.Errors)
			totalScanned += result.Scanned
			totalViolations += result.Violations
			tableScanned += result.Scanned
			tableViolations += result.Violations

			batchTime, batchID := scanner.ExtractScanCursor(assets)
			if scanner.IsCursorAfter(batchTime, batchID, cursorTime, cursorID) {
				cursorTime = batchTime
				cursorID = batchID
			}

			if useCursorPaging {
				if batchTime.IsZero() {
					break
				}
				filter.Since = batchTime
				filter.SinceID = batchID
			} else {
				offset += len(assets)
			}

			// Persist findings
			for _, f := range result.Findings {
				finding := a.upsertFindingAndRemediate(tableCtx, f)
				if finding == nil {
					continue
				}

				// Send notification for new critical/high findings
				if finding.FirstSeen.Equal(finding.LastSeen) && (f.Severity == "critical" || f.Severity == "high") {
					if err := a.Notifications.Send(tableCtx, notifications.Event{
						Type:     notifications.EventFindingCreated,
						Severity: f.Severity,
						Title:    fmt.Sprintf("New %s Finding: %s", f.Severity, f.PolicyName),
						Message:  f.Description,
						Data: map[string]interface{}{
							"finding_id": f.ID,
							"policy_id":  f.PolicyID,
							"resource":   f.Resource,
						},
					}); err != nil {
						a.Logger.Warn("failed to send finding notification", "finding_id", f.ID, "error", err)
					}
				}
			}

			dspmFindings := a.scanAndPersistDSPMFindings(tableCtx, table, assets)
			if dspmFindings > 0 {
				totalViolations += dspmFindings
				tableViolations += dspmFindings
			}

			// If we got fewer than batchSize, we're done with this table
			if len(assets) < batchSize {
				break
			}
		}

		if errors.Is(tableCtx.Err(), context.DeadlineExceeded) {
			tableProfile.TimedOut = true
			a.Logger.Warn("table scan timed out", "table", table, "timeout", tuning.TableTimeout)
		}
		tableProfile.Scanned = tableScanned
		tableProfile.Violations = tableViolations
		tableProfile.Duration = time.Since(tableStart)
		cancel()
		tableProfiles = append(tableProfiles, tableProfile)

		// Update watermark after successful scan
		if a.ScanWatermarks != nil && tableScanned > 0 {
			if cursorTime.IsZero() {
				cursorTime = time.Now().UTC()
			}
			a.ScanWatermarks.SetWatermark(table, cursorTime, cursorID, tableScanned)
		}
	}

	scanDuration := time.Since(scanStart)
	profileSummary := scanner.SummarizeTableProfiles(tableProfiles, scanDuration)
	slowTables := scanner.FilterSlowTables(tableProfiles, tuning.ProfileSlowThreshold)
	if len(tableProfiles) > 0 {
		sorted := scanner.SortTableProfilesByDuration(tableProfiles)
		maxRows := 5
		if len(sorted) < maxRows {
			maxRows = len(sorted)
		}
		entries := make([]map[string]interface{}, 0, maxRows)
		for i := 0; i < maxRows; i++ {
			profile := sorted[i]
			entries = append(entries, map[string]interface{}{
				"table":          profile.Table,
				"duration":       profile.Duration.String(),
				"scanned":        profile.Scanned,
				"violations":     profile.Violations,
				"retry_attempts": profile.RetryAttempts,
				"fetch_errors":   profile.FetchErrors,
				"timed_out":      profile.TimedOut,
			})
		}
		a.Logger.Info("scan profiling",
			"total_scanned", profileSummary.TotalScanned,
			"total_violations", profileSummary.TotalViolations,
			"slow_threshold", tuning.ProfileSlowThreshold,
			"slow_tables", len(slowTables),
			"top_tables", entries,
		)
	}

	queryPolicyResult := a.ScanQueryPolicies(ctx)
	queryPolicyFindingCount = len(queryPolicyResult.Findings)
	queryPolicyErrorCount = len(queryPolicyResult.Errors)
	for _, errMsg := range queryPolicyResult.Errors {
		a.Logger.Warn("query policy execution failed", "error", errMsg)
	}
	for _, f := range queryPolicyResult.Findings {
		finding := a.upsertFindingAndRemediate(ctx, f)
		if finding == nil {
			continue
		}
		if finding.FirstSeen.Equal(finding.LastSeen) && (f.Severity == "critical" || f.Severity == "high") {
			if err := a.Notifications.Send(ctx, notifications.Event{
				Type:     notifications.EventFindingCreated,
				Severity: f.Severity,
				Title:    fmt.Sprintf("New %s Finding: %s", f.Severity, f.PolicyName),
				Message:  f.Description,
				Data: map[string]interface{}{
					"finding_id": f.ID,
					"policy_id":  f.PolicyID,
					"resource":   f.Resource,
				},
			}); err != nil {
				a.Logger.Warn("failed to send query finding notification", "finding_id", f.ID, "error", err)
			}
		}
	}
	if queryPolicyFindingCount > 0 {
		totalViolations += int64(queryPolicyFindingCount)
	}

	sqlToxicRiskSets := make(map[string][]map[string]bool)
	if a.Snowflake != nil {
		var toxicCursor *scanner.ToxicScanCursor
		if a.ScanWatermarks != nil {
			if wm := a.ScanWatermarks.GetWatermark("_toxic_relationships"); wm != nil {
				toxicCursor = &scanner.ToxicScanCursor{SinceTime: wm.LastScanTime, SinceID: wm.LastScanID}
			}
		}
		toxicResult, err := scanner.DetectRelationshipToxicCombinations(ctx, a.Snowflake, toxicCursor)
		if err != nil {
			a.Logger.Warn("relationship toxic combo scan failed", "error", err)
		} else {
			relationshipCount = len(toxicResult.Findings)
			for _, f := range toxicResult.Findings {
				if rid := scanner.NormalizeResourceID(f.ResourceID); rid != "" {
					if risks := scanner.CanonicalizeRiskCategories(scanner.ParseRiskCategories(f.Risks)); len(risks) > 0 {
						sqlToxicRiskSets[rid] = append(sqlToxicRiskSets[rid], risks)
					}
				}
				if a.Findings != nil && f.PolicyID != "" && f.ResourceID != "" {
					a.upsertFindingAndRemediate(ctx, f.ToPolicyFinding())
				}
			}
			totalViolations += int64(relationshipCount)
		}
		if err == nil && a.ScanWatermarks != nil && !toxicResult.MaxSyncTime.IsZero() {
			a.ScanWatermarks.SetWatermark("_toxic_relationships", toxicResult.MaxSyncTime, toxicResult.MaxCursorID, int64(relationshipCount))
		}
	}

	if a.SecurityGraph != nil {
		graphCtx := ctx
		cancel := func() {}
		if tuning.GraphWaitTimeout > 0 {
			graphCtx, cancel = context.WithTimeout(ctx, tuning.GraphWaitTimeout)
		}
		graphReady := a.WaitForGraph(graphCtx)
		cancel()
		if graphReady {
			graphResult := a.Scanner.AnalyzeGraph(ctx, a.SecurityGraph)
			if graphResult != nil {
				graphPaths = graphResult.AttackPathStats.TotalPaths
				for _, f := range graphResult.ToxicCombinations {
					resourceID := scanner.NormalizeResourceID(f.ResourceID)
					graphRiskSet := scanner.CanonicalizeRiskCategories(f.RiskCategories)
					if scanner.ShouldSkipGraphToxicCombination(resourceID, graphRiskSet, sqlToxicRiskSets) {
						continue
					}
					a.upsertFindingAndRemediate(ctx, f)
					graphToxicCount++
				}
			}
		}
	}
	if graphToxicCount > 0 {
		totalViolations += int64(graphToxicCount)
	}
	if relationshipCount > 0 || graphToxicCount > 0 {
		a.Logger.Info("toxic combination analysis complete",
			"relationship_count", relationshipCount,
			"graph_count", graphToxicCount,
			"attack_paths", graphPaths,
		)
	}

	// Persist watermarks
	if a.ScanWatermarks != nil {
		if err := a.ScanWatermarks.PersistWatermarksWithRetry(ctx, scanner.DefaultWatermarkPersistOptions()); err != nil {
			a.Logger.Warn("failed to persist scan watermarks", "error", err)
		}
	}

	// Sync to Snowflake if available
	if a.SnowflakeFindings != nil {
		if err := a.SnowflakeFindings.Sync(ctx); err != nil {
			a.Logger.Warn("failed to sync findings to snowflake", "error", err)
		}
	}

	// Send scan completed notification
	if err := a.Notifications.Send(ctx, notifications.Event{
		Type:    notifications.EventScanCompleted,
		Title:   "Scheduled Scan Completed",
		Message: fmt.Sprintf("Scanned %d assets, found %d violations", totalScanned, totalViolations),
		Data: map[string]interface{}{
			"scanned":                  totalScanned,
			"violations":               totalViolations,
			"tables":                   tables,
			"query_policy_findings":    queryPolicyFindingCount,
			"query_policy_errors":      queryPolicyErrorCount,
			"relationship_toxic_count": relationshipCount,
			"graph_toxic_count":        graphToxicCount,
			"graph_attack_paths":       graphPaths,
			"scan_duration":            scanDuration.String(),
		},
	}); err != nil {
		a.Logger.Warn("failed to send scan completed notification", "error", err)
	}

	// Emit webhook
	if err := a.Webhooks.EmitScanCompleted(ctx, totalScanned, totalViolations, 0); err != nil {
		a.Logger.Warn("failed to emit scan completed webhook", "error", err)
	}

	return nil
}

func (a *App) sendSecurityDigest(ctx context.Context) error {
	if a.Findings == nil || a.Notifications == nil {
		return nil
	}

	openTotal := a.Findings.Count(findings.FindingFilter{Status: "open"})
	criticalOpen := a.Findings.Count(findings.FindingFilter{Severity: "critical", Status: "open"})
	highOpen := a.Findings.Count(findings.FindingFilter{Severity: "high", Status: "open"})
	mediumOpen := a.Findings.Count(findings.FindingFilter{Severity: "medium", Status: "open"})
	lowOpen := a.Findings.Count(findings.FindingFilter{Severity: "low", Status: "open"})

	highlights := append([]string{},
		formatDigestHighlights(a.Findings.List(findings.FindingFilter{Severity: "critical", Status: "open"}), "critical", 3)...,
	)
	highlights = append(highlights, formatDigestHighlights(a.Findings.List(findings.FindingFilter{Severity: "high", Status: "open"}), "high", 3)...)

	message := fmt.Sprintf(
		"Open findings: %d (critical: %d, high: %d, medium: %d, low: %d)",
		openTotal,
		criticalOpen,
		highOpen,
		mediumOpen,
		lowOpen,
	)
	if len(highlights) > 0 {
		message = fmt.Sprintf("%s. Top priorities: %s", message, strings.Join(highlights, "; "))
	}

	return a.Notifications.Send(ctx, notifications.Event{
		Type:     notifications.EventSecurityDigest,
		Severity: "info",
		Title:    "Scheduled Security Digest",
		Message:  message,
		Data: map[string]interface{}{
			"open_total": openTotal,
			"critical":   criticalOpen,
			"high":       highOpen,
			"medium":     mediumOpen,
			"low":        lowOpen,
			"highlights": highlights,
		},
	})
}

func formatDigestHighlights(list []*findings.Finding, severity string, limit int) []string {
	if len(list) == 0 || limit <= 0 {
		return nil
	}

	entries := make([]string, 0, len(list))
	for _, finding := range list {
		title := strings.TrimSpace(finding.PolicyName)
		if title == "" {
			title = strings.TrimSpace(finding.PolicyID)
		}
		if title == "" {
			title = finding.ID
		}
		entries = append(entries, fmt.Sprintf("%s (%s)", title, finding.ID))
	}
	sort.Strings(entries)
	if len(entries) > limit {
		entries = entries[:limit]
	}

	result := make([]string, 0, len(entries))
	for _, entry := range entries {
		result = append(result, fmt.Sprintf("%s: %s", severity, entry))
	}
	return result
}

func parseDuration(s string) (time.Duration, error) {
	return time.ParseDuration(s)
}

func splitTables(s string) []string {
	return splitCSV(s)
}

func defaultScanTables() []string {
	return nativesync.SupportedTableNames()
}

func (a *App) resolveScanTables(ctx context.Context) []string {
	var tables []string
	if a.Config.ScanTables != "" {
		tables = splitTables(a.Config.ScanTables)
	}

	available := a.AvailableTables
	if a.Snowflake != nil {
		if refreshed, err := a.Snowflake.ListAvailableTables(ctx); err == nil {
			a.AvailableTables = refreshed
			available = refreshed
		} else if ctx.Err() == nil {
			a.Logger.Warn("failed to refresh available tables", "error", err)
		}
	}

	if len(tables) == 0 && len(available) > 0 {
		tables = scannableTablesFromAvailable(available)
	}
	if len(tables) == 0 {
		tables = defaultScanTables()
	}

	filtered, skipped := filterTablesByAvailability(tables, available)
	if len(available) > 0 {
		if skipped > 0 {
			a.Logger.Info("skipped tables not present in snowflake", "skipped", skipped)
		}
		return filtered
	}

	return tables
}

func scannableTablesFromAvailable(available []string) []string {
	if len(available) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(available))
	result := make([]string, 0, len(available))
	for _, table := range available {
		name := strings.ToLower(strings.TrimSpace(table))
		if !isScannableTable(name) {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		result = append(result, name)
	}
	if len(result) == 0 {
		return nil
	}
	sort.Strings(result)
	return result
}

func isScannableTable(table string) bool {
	if table == "" {
		return false
	}
	if strings.HasPrefix(table, "cerebro_") {
		return false
	}
	if err := snowflake.ValidateTableNameStrict(table); err != nil {
		return false
	}
	return true
}

func filterTablesByAvailability(tables, available []string) ([]string, int) {
	if len(tables) == 0 || len(available) == 0 {
		return tables, 0
	}

	availableSet := make(map[string]struct{}, len(available))
	for _, table := range available {
		availableSet[strings.ToLower(table)] = struct{}{}
	}

	filtered := make([]string, 0, len(tables))
	skipped := 0
	for _, table := range tables {
		if _, ok := availableSet[strings.ToLower(table)]; ok {
			filtered = append(filtered, table)
		} else {
			skipped++
		}
	}

	return filtered, skipped
}

// New service initialization functions
