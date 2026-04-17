package scan

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/notifications"
	"github.com/writer/cerebro/internal/policy"
	"github.com/writer/cerebro/internal/scanner"
	"github.com/writer/cerebro/internal/scheduler"
	"github.com/writer/cerebro/internal/snowflake"
	nativesync "github.com/writer/cerebro/internal/sync"
)

func (r *Runtime) InitScheduler(_ context.Context) {
	if r == nil {
		return
	}

	logger := r.logger()
	cfg := r.config()
	if cfg == nil {
		cfg = &Config{}
	}

	schedulerRuntime := scheduler.NewScheduler(logger)
	r.SetScheduler(schedulerRuntime)

	if cfg.ScanInterval != "" {
		interval, err := ParseDuration(cfg.ScanInterval)
		if err != nil {
			logger.Warn("invalid scan interval", "value", cfg.ScanInterval, "error", err)
			return
		}

		schedulerRuntime.AddJob("policy-scan", interval, func(ctx context.Context) error {
			tables := r.ResolveScanTables(ctx)
			if len(tables) == 0 {
				logger.Info("no tables available for scheduled scan")
				return nil
			}
			return r.RunScheduledScan(ctx, tables)
		})

		if cfg.ScanTables != "" {
			logger.Info("scheduled scanning enabled", "interval", interval, "tables", SplitTables(cfg.ScanTables))
		} else {
			logger.Info("scheduled scanning enabled", "interval", interval, "table_source", "available_tables")
		}
	}

	if cfg.SecurityDigestInterval != "" {
		interval, err := ParseDuration(cfg.SecurityDigestInterval)
		if err != nil {
			logger.Warn("invalid security digest interval", "value", cfg.SecurityDigestInterval, "error", err)
		} else {
			schedulerRuntime.AddJob("security-digest", interval, func(ctx context.Context) error {
				return r.SendSecurityDigest(ctx)
			})
			logger.Info("scheduled security digest enabled", "interval", interval)
		}
	}

	graphInterval := r.graphRebuildInterval()
	schedulerRuntime.AddJob("graph-rebuild", graphInterval, func(ctx context.Context) error {
		builder := r.securityGraphBuilder()
		if builder == nil {
			return nil
		}
		if !builder.HasChanges(ctx) {
			logger.Info("security graph rebuild skipped - no data changes detected")
			return nil
		}
		_, err := r.applySecurityGraphChanges(ctx, "scheduler_incremental")
		return err
	})
	logger.Info("scheduled graph rebuild enabled", "interval", graphInterval)

	if r.RetentionEnabled() {
		interval := cfg.RetentionJobInterval
		if interval <= 0 {
			interval = 24 * time.Hour
		}
		schedulerRuntime.AddJob("data-retention", interval, func(ctx context.Context) error {
			return r.RunRetentionCleanup(ctx)
		})
		logger.Info("scheduled data retention cleanup enabled",
			"interval", interval,
			"audit_retention_days", maxRetentionDays(cfg.AuditRetentionDays),
			"session_retention_days", maxRetentionDays(cfg.SessionRetentionDays),
			"graph_retention_days", maxRetentionDays(cfg.GraphRetentionDays),
			"access_review_retention_days", maxRetentionDays(cfg.AccessReviewRetentionDays),
		)
	}
}

func (r *Runtime) RetentionEnabled() bool {
	cfg := r.config()
	if cfg == nil {
		return false
	}
	return maxRetentionDays(cfg.AuditRetentionDays) > 0 ||
		maxRetentionDays(cfg.SessionRetentionDays) > 0 ||
		maxRetentionDays(cfg.GraphRetentionDays) > 0 ||
		maxRetentionDays(cfg.AccessReviewRetentionDays) > 0
}

func maxRetentionDays(days int) int {
	if days < 0 {
		return 0
	}
	return days
}

func retentionCutoff(days int) time.Time {
	return time.Now().UTC().Add(-time.Duration(days) * 24 * time.Hour)
}

func (r *Runtime) RunRetentionCleanup(ctx context.Context) error {
	repo := r.retentionRepo()
	cfg := r.config()
	if repo == nil || cfg == nil || !r.RetentionEnabled() {
		return nil
	}

	var (
		auditDeleted           int64
		sessionDeleted         int64
		sessionMessagesDeleted int64
		graphPathsDeleted      int64
		graphEdgesDeleted      int64
		graphNodesDeleted      int64
		reviewsDeleted         int64
		reviewItemsDeleted     int64
	)

	if days := maxRetentionDays(cfg.AuditRetentionDays); days > 0 {
		deleted, err := repo.CleanupAuditLogs(ctx, retentionCutoff(days))
		if err != nil {
			return fmt.Errorf("cleanup audit logs: %w", err)
		}
		auditDeleted = deleted
	}

	if days := maxRetentionDays(cfg.SessionRetentionDays); days > 0 {
		sessions, messages, err := repo.CleanupAgentData(ctx, retentionCutoff(days))
		if err != nil {
			return fmt.Errorf("cleanup agent sessions: %w", err)
		}
		sessionDeleted = sessions
		sessionMessagesDeleted = messages
	}

	if days := maxRetentionDays(cfg.GraphRetentionDays); days > 0 {
		paths, edges, nodes, err := repo.CleanupGraphData(ctx, retentionCutoff(days))
		if err != nil {
			return fmt.Errorf("cleanup graph data: %w", err)
		}
		graphPathsDeleted = paths
		graphEdgesDeleted = edges
		graphNodesDeleted = nodes
	}

	if days := maxRetentionDays(cfg.AccessReviewRetentionDays); days > 0 {
		reviews, items, err := repo.CleanupAccessReviewData(ctx, retentionCutoff(days))
		if err != nil {
			return fmt.Errorf("cleanup access review data: %w", err)
		}
		reviewsDeleted = reviews
		reviewItemsDeleted = items
	}

	r.logger().Info("retention cleanup completed",
		"audit_deleted", auditDeleted,
		"agent_sessions_deleted", sessionDeleted,
		"agent_messages_deleted", sessionMessagesDeleted,
		"attack_paths_deleted", graphPathsDeleted,
		"attack_path_edges_deleted", graphEdgesDeleted,
		"attack_path_nodes_deleted", graphNodesDeleted,
		"access_reviews_deleted", reviewsDeleted,
		"review_items_deleted", reviewItemsDeleted,
	)

	return nil
}

func (r *Runtime) CurrentOrStoredScheduledScanGraphView(ctx context.Context, tuning Tuning) *graph.Graph {
	if r == nil {
		return nil
	}

	if live := r.currentLiveSecurityGraph(); live != nil {
		graphCtx := ctx
		cancel := func() {}
		if tuning.GraphWaitTimeout > 0 {
			graphCtx, cancel = context.WithTimeout(ctx, tuning.GraphWaitTimeout)
		}
		graphReady := r.waitForGraph(graphCtx)
		cancel()
		if !graphReady {
			return nil
		}
		return r.currentLiveSecurityGraph()
	}

	securityGraph, err := r.currentOrStoredSecurityGraphView()
	if err != nil {
		r.logger().Warn("scheduled scan graph resolution failed", "error", err)
		return nil
	}
	return securityGraph
}

func (r *Runtime) RunScheduledGraphAnalyses(ctx context.Context, tuning Tuning, sqlToxicRiskSets map[string][]map[string]bool) GraphAnalysisSummary {
	summary := GraphAnalysisSummary{}
	securityGraph := r.CurrentOrStoredScheduledScanGraphView(ctx, tuning)
	if securityGraph == nil {
		return summary
	}

	if scannerSvc := r.scanner(); scannerSvc != nil {
		graphResult := scannerSvc.AnalyzeGraph(ctx, securityGraph)
		if graphResult != nil {
			summary.GraphPaths = graphResult.AttackPathStats.TotalPaths
			for _, finding := range graphResult.ToxicCombinations {
				resourceID := scanner.NormalizeResourceID(finding.ResourceID)
				graphRiskSet := scanner.CanonicalizeRiskCategories(finding.RiskCategories)
				if scanner.ShouldSkipGraphToxicCombination(resourceID, graphRiskSet, sqlToxicRiskSets) {
					continue
				}
				r.upsertFindingAndRemediate(ctx, finding)
				summary.GraphToxicCount++
			}
		}
	}

	orgTopologyResult := r.scanOrgTopologyPolicies(ctx)
	summary.OrgTopologyFindingCount = len(orgTopologyResult.Findings)
	summary.OrgTopologyErrorCount = len(orgTopologyResult.Errors)
	for _, errMsg := range orgTopologyResult.Errors {
		r.logger().Warn("org topology policy execution failed", "error", errMsg)
	}
	for _, finding := range orgTopologyResult.Findings {
		r.upsertFindingAndRemediate(ctx, finding)
	}

	apiSurfaceResult := r.scanAPISurfaceFindings(ctx)
	summary.APISurfaceFindingCount = len(apiSurfaceResult.Findings)
	summary.APISurfaceErrorCount = len(apiSurfaceResult.Errors)
	for _, errMsg := range apiSurfaceResult.Errors {
		r.logger().Warn("api surface analysis failed", "error", errMsg)
	}
	for _, finding := range apiSurfaceResult.Findings {
		r.upsertFindingAndRemediate(ctx, finding)
	}

	return summary
}

func (r *Runtime) RunScheduledScan(ctx context.Context, tables []string) error {
	warehouseClient := r.warehouse()
	if warehouseClient == nil {
		return fmt.Errorf("snowflake not configured")
	}
	scannerSvc := r.scanner()
	if scannerSvc == nil {
		return fmt.Errorf("scanner not configured")
	}

	logger := r.logger()
	notificationsSvc := r.notifications()
	webhookSvc := r.webhooks()
	findingsStore := r.findingsStore()
	scanWatermarks := r.scanWatermarks()
	cfg := r.config()
	if cfg == nil {
		cfg = &Config{}
		_ = cfg
	}

	scanStart := time.Now()
	tuning := r.ScanTuning()
	var tableProfiles []scanner.TableScanProfile
	var totalScanned int64
	var totalViolations int64
	var queryPolicyFindingCount int
	var queryPolicyErrorCount int
	var orgTopologyFindingCount int
	var orgTopologyErrorCount int
	var apiSurfaceFindingCount int
	var apiSurfaceErrorCount int
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

		columns := r.ScanColumnsForTable(tableCtx, table)
		filter := snowflake.AssetFilter{Limit: batchSize, Columns: columns}
		var cursorTime time.Time
		var cursorID string
		useCursorPaging := false

		if scanWatermarks != nil {
			if !scanWatermarks.ShouldFullScan(table, maxWatermarkAge) {
				if wm := scanWatermarks.GetWatermark(table); wm != nil {
					filter.Since = wm.LastScanTime
					filter.SinceID = wm.LastScanID
					logger.Debug("incremental scan", "table", table, "since", wm.LastScanTime)
					useCursorPaging = true
				}
			}
		}

		tableScanned := int64(0)
		tableViolations := int64(0)
		offset := 0
		for tableCtx.Err() == nil {
			if !useCursorPaging {
				filter.Offset = offset
			}
			assets, attempts, err := scanner.WithRetryValue(tableCtx, tuning.RetryOptions, func() ([]map[string]interface{}, error) {
				return warehouseClient.GetAssets(tableCtx, table, filter)
			})
			if attempts > 1 {
				tableProfile.RetryAttempts += attempts - 1
			}
			if err != nil {
				tableProfile.FetchErrors++
				logger.Warn("failed to fetch assets", "table", table, "offset", offset, "error", err)
				break
			}
			if len(assets) == 0 {
				break
			}

			result := scannerSvc.ScanAssets(tableCtx, assets)
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

			for _, finding := range result.Findings {
				stored := r.upsertFindingAndRemediate(tableCtx, finding)
				r.notifyNewFinding(tableCtx, notificationsSvc, stored, finding, "failed to send finding notification")
			}

			dspmFindings := r.scanAndPersistDSPMFindings(tableCtx, table, assets)
			if dspmFindings > 0 {
				totalViolations += dspmFindings
				tableViolations += dspmFindings
			}

			if len(assets) < batchSize {
				break
			}
		}

		if errors.Is(tableCtx.Err(), context.DeadlineExceeded) {
			tableProfile.TimedOut = true
			logger.Warn("table scan timed out", "table", table, "timeout", tuning.TableTimeout)
		}
		tableProfile.Scanned = tableScanned
		tableProfile.Violations = tableViolations
		tableProfile.Duration = time.Since(tableStart)
		cancel()
		tableProfiles = append(tableProfiles, tableProfile)

		if scanWatermarks != nil && tableScanned > 0 {
			if cursorTime.IsZero() {
				cursorTime = time.Now().UTC()
			}
			scanWatermarks.SetWatermark(table, cursorTime, cursorID, tableScanned)
		}
	}

	scanDuration := time.Since(scanStart)
	profileSummary := scanner.SummarizeTableProfiles(tableProfiles, scanDuration)
	slowTables := scanner.FilterSlowTables(tableProfiles, tuning.ProfileSlowThreshold)
	if len(tableProfiles) > 0 {
		sortedProfiles := scanner.SortTableProfilesByDuration(tableProfiles)
		maxRows := 5
		if len(sortedProfiles) < maxRows {
			maxRows = len(sortedProfiles)
		}
		entries := make([]map[string]interface{}, 0, maxRows)
		for i := 0; i < maxRows; i++ {
			profile := sortedProfiles[i]
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
		logger.Info("scan profiling",
			"total_scanned", profileSummary.TotalScanned,
			"total_violations", profileSummary.TotalViolations,
			"slow_threshold", tuning.ProfileSlowThreshold,
			"slow_tables", len(slowTables),
			"top_tables", entries,
		)
	}

	queryPolicyResult := r.scanQueryPolicies(ctx)
	queryPolicyFindingCount = len(queryPolicyResult.Findings)
	queryPolicyErrorCount = len(queryPolicyResult.Errors)
	for _, errMsg := range queryPolicyResult.Errors {
		logger.Warn("query policy execution failed", "error", errMsg)
	}
	for _, finding := range queryPolicyResult.Findings {
		stored := r.upsertFindingAndRemediate(ctx, finding)
		r.notifyNewFinding(ctx, notificationsSvc, stored, finding, "failed to send query finding notification")
	}
	if queryPolicyFindingCount > 0 {
		totalViolations += int64(queryPolicyFindingCount)
	}

	sqlToxicRiskSets := make(map[string][]map[string]bool)
	if warehouseClient != nil {
		var toxicCursor *scanner.ToxicScanCursor
		if scanWatermarks != nil {
			if wm := scanWatermarks.GetWatermark("_toxic_relationships"); wm != nil {
				toxicCursor = &scanner.ToxicScanCursor{SinceTime: wm.LastScanTime, SinceID: wm.LastScanID}
			}
		}
		toxicResult, err := scanner.DetectRelationshipToxicCombinations(ctx, warehouseClient, toxicCursor)
		if err != nil {
			logger.Warn("relationship toxic combo scan failed", "error", err)
		} else if toxicResult != nil {
			relationshipCount = len(toxicResult.Findings)
			for _, finding := range toxicResult.Findings {
				if rid := scanner.NormalizeResourceID(finding.ResourceID); rid != "" {
					if risks := scanner.CanonicalizeRiskCategories(scanner.ParseRiskCategories(finding.Risks)); len(risks) > 0 {
						sqlToxicRiskSets[rid] = append(sqlToxicRiskSets[rid], risks)
					}
				}
				if findingsStore != nil && finding.PolicyID != "" && finding.ResourceID != "" {
					r.upsertFindingAndRemediate(ctx, finding.ToPolicyFinding())
				}
			}
			totalViolations += int64(relationshipCount)
			if scanWatermarks != nil && !toxicResult.MaxSyncTime.IsZero() {
				scanWatermarks.SetWatermark("_toxic_relationships", toxicResult.MaxSyncTime, toxicResult.MaxCursorID, int64(relationshipCount))
			}
		}
	}

	graphSummary := r.RunScheduledGraphAnalyses(ctx, tuning, sqlToxicRiskSets)
	graphToxicCount = graphSummary.GraphToxicCount
	graphPaths = graphSummary.GraphPaths
	orgTopologyFindingCount = graphSummary.OrgTopologyFindingCount
	orgTopologyErrorCount = graphSummary.OrgTopologyErrorCount
	apiSurfaceFindingCount = graphSummary.APISurfaceFindingCount
	apiSurfaceErrorCount = graphSummary.APISurfaceErrorCount
	if graphToxicCount > 0 {
		totalViolations += int64(graphToxicCount)
	}
	if orgTopologyFindingCount > 0 {
		totalViolations += int64(orgTopologyFindingCount)
	}
	if apiSurfaceFindingCount > 0 {
		totalViolations += int64(apiSurfaceFindingCount)
	}
	if relationshipCount > 0 || graphToxicCount > 0 {
		logger.Info("toxic combination analysis complete",
			"relationship_count", relationshipCount,
			"graph_count", graphToxicCount,
			"attack_paths", graphPaths,
		)
	}
	if orgTopologyFindingCount > 0 || orgTopologyErrorCount > 0 {
		logger.Info("org topology policy scan complete",
			"findings", orgTopologyFindingCount,
			"errors", orgTopologyErrorCount,
		)
	}
	if apiSurfaceFindingCount > 0 || apiSurfaceErrorCount > 0 {
		logger.Info("api surface analysis complete",
			"findings", apiSurfaceFindingCount,
			"errors", apiSurfaceErrorCount,
		)
	}

	if scanWatermarks != nil {
		if err := scanWatermarks.PersistWatermarksWithRetry(ctx, scanner.DefaultWatermarkPersistOptions()); err != nil {
			logger.Warn("failed to persist scan watermarks", "error", err)
		}
	}

	if syncer, ok := findingsStore.(interface{ Sync(context.Context) error }); ok {
		if err := syncer.Sync(ctx); err != nil {
			logger.Warn("failed to sync findings", "error", err)
		}
	}

	if notificationsSvc != nil {
		if err := notificationsSvc.Send(ctx, notifications.Event{
			Type:    notifications.EventScanCompleted,
			Title:   "Scheduled Scan Completed",
			Message: fmt.Sprintf("Scanned %d assets, found %d violations", totalScanned, totalViolations),
			Data: map[string]interface{}{
				"scanned":                  totalScanned,
				"violations":               totalViolations,
				"tables":                   tables,
				"query_policy_findings":    queryPolicyFindingCount,
				"query_policy_errors":      queryPolicyErrorCount,
				"org_topology_findings":    orgTopologyFindingCount,
				"org_topology_errors":      orgTopologyErrorCount,
				"api_surface_findings":     apiSurfaceFindingCount,
				"api_surface_errors":       apiSurfaceErrorCount,
				"relationship_toxic_count": relationshipCount,
				"graph_toxic_count":        graphToxicCount,
				"graph_attack_paths":       graphPaths,
				"scan_duration":            scanDuration.String(),
			},
		}); err != nil {
			logger.Warn("failed to send scan completed notification", "error", err)
		}
	}

	if webhookSvc != nil {
		if err := webhookSvc.EmitScanCompleted(ctx, totalScanned, totalViolations, 0); err != nil {
			logger.Warn("failed to emit scan completed webhook", "error", err)
		}
	}

	return nil
}

func (r *Runtime) SendSecurityDigest(ctx context.Context) error {
	findingsStore := r.findingsStore()
	notificationsSvc := r.notifications()
	if findingsStore == nil || notificationsSvc == nil {
		return nil
	}

	openTotal := findingsStore.Count(findings.FindingFilter{Status: "open"})
	criticalOpen := findingsStore.Count(findings.FindingFilter{Severity: "critical", Status: "open"})
	highOpen := findingsStore.Count(findings.FindingFilter{Severity: "high", Status: "open"})
	mediumOpen := findingsStore.Count(findings.FindingFilter{Severity: "medium", Status: "open"})
	lowOpen := findingsStore.Count(findings.FindingFilter{Severity: "low", Status: "open"})

	highlights := append([]string{},
		formatDigestHighlights(findingsStore.List(findings.FindingFilter{Severity: "critical", Status: "open"}), "critical", 3)...,
	)
	highlights = append(highlights, formatDigestHighlights(findingsStore.List(findings.FindingFilter{Severity: "high", Status: "open"}), "high", 3)...)

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

	return notificationsSvc.Send(ctx, notifications.Event{
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

func (r *Runtime) notifyNewFinding(ctx context.Context, notificationsSvc *notifications.Manager, stored *findings.Finding, finding policy.Finding, logMessage string) {
	if notificationsSvc == nil || stored == nil {
		return
	}
	if !stored.FirstSeen.Equal(stored.LastSeen) {
		return
	}
	if finding.Severity != "critical" && finding.Severity != "high" {
		return
	}

	if err := notificationsSvc.Send(ctx, notifications.Event{
		Type:     notifications.EventFindingCreated,
		Severity: finding.Severity,
		Title:    fmt.Sprintf("New %s Finding: %s", finding.Severity, finding.PolicyName),
		Message:  finding.Description,
		Data: map[string]interface{}{
			"finding_id": finding.ID,
			"policy_id":  finding.PolicyID,
			"resource":   finding.Resource,
		},
	}); err != nil {
		r.logger().Warn(logMessage, "finding_id", finding.ID, "error", err)
	}
}

func formatDigestHighlights(list []*findings.Finding, severity string, limit int) []string {
	if len(list) == 0 || limit <= 0 {
		return nil
	}

	entries := make([]string, 0, len(list))
	for _, finding := range list {
		if finding == nil {
			continue
		}
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

func ParseDuration(s string) (time.Duration, error) {
	return time.ParseDuration(s)
}

func SplitTables(s string) []string {
	return splitCSV(s)
}

func DefaultScanTables() []string {
	return nativesync.SupportedTableNames()
}

func (r *Runtime) ResolveScanTables(ctx context.Context) []string {
	cfg := r.config()
	if cfg == nil {
		cfg = &Config{}
	}

	var tables []string
	if cfg.ScanTables != "" {
		tables = SplitTables(cfg.ScanTables)
	}

	available := r.availableTables()
	warehouseClient := r.warehouse()
	if warehouseClient != nil {
		if refreshed, err := warehouseClient.ListAvailableTables(ctx); err == nil {
			r.setAvailableTables(refreshed)
			available = refreshed
		} else if ctx.Err() == nil {
			r.logger().Warn("failed to refresh available tables", "error", err)
		}
	}

	if len(tables) == 0 && len(available) > 0 {
		tables = scannableTablesFromAvailable(available)
	}
	if len(tables) == 0 {
		tables = DefaultScanTables()
	}

	filtered, skipped := filterTablesByAvailability(tables, available)
	if len(available) > 0 {
		if skipped > 0 {
			r.logger().Info("skipped tables not present in snowflake", "skipped", skipped)
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

func splitCSV(s string) []string {
	var result []string
	for _, table := range strings.Split(s, ",") {
		table = strings.TrimSpace(table)
		if table != "" {
			result = append(result, table)
		}
	}
	return result
}
