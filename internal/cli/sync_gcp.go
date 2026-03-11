package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	apiclient "github.com/writer/cerebro/internal/client"
	nativesync "github.com/writer/cerebro/internal/sync"
)

func runGCPPreflightOnly(ctx context.Context, start time.Time) error {
	report := syncPreflightReport{
		Mode:      "preflight",
		Provider:  "gcp",
		AuthMode:  syncAuthMode,
		AuthChain: describeCurrentGCPAuthChain(),
		StartedAt: start.UTC(),
	}

	checks := make([]syncPreflightCheck, 0, 16)
	errs := make([]error, 0)
	record := func(name, okDetail string, err error) {
		if err != nil {
			checks = append(checks, syncPreflightCheck{Name: name, Status: "failed", Detail: err.Error()})
			errs = append(errs, err)
			return
		}
		detail := strings.TrimSpace(okDetail)
		if detail == "" {
			detail = "ok"
		}
		checks = append(checks, syncPreflightCheck{Name: name, Status: "passed", Detail: detail})
	}

	spec := buildScheduledGCPSpecFromSyncFlags()
	authCfg, err := applyScheduledGCPAuthFn(spec)
	if err != nil {
		record("auth.setup", "", err)
		report.Checks = checks
		report.Duration = time.Since(start).Round(time.Millisecond).String()
		report.Success = false
		if outputErr := printSyncPreflightReport(report); outputErr != nil {
			return outputErr
		}
		return summarizeSyncRunErrors("GCP preflight", errs)
	}
	defer authCfg.Cleanup()
	record("auth.setup", authCfg.Summary, nil)

	if err := preflightScheduledGCPAuthFn(ctx, &SyncSchedule{Name: "sync-preflight-gcp", Provider: "gcp"}, spec, authCfg); err != nil {
		record("auth.token", "", err)
	} else {
		record("auth.token", "access token acquired", nil)
	}

	tableFilter := parseTableFilter(syncTable)
	_, securityFilter, runNativeSync, runSecuritySync, filterErr := resolveGCPTableFilters(tableFilter, syncSecurity)
	if filterErr != nil {
		record("table.filter", "", filterErr)
	}

	includeFilter := parseCommaSeparatedValues(syncProjectInclude)
	excludeFilter := parseCommaSeparatedValues(syncProjectExclude)
	requiresProjectProbe := filterErr == nil && (runNativeSync || (runSecuritySync && gcpSecurityFiltersRequireProject(securityFilter)))

	selectedProjects := make([]string, 0)
	if requiresProjectProbe {
		orgID := strings.TrimSpace(syncGCPOrg)
		if orgID != "" {
			projects, listErr := listOrganizationProjectsFn(ctx, orgID)
			if listErr != nil {
				record("projects.discovery", "", fmt.Errorf("list organization projects: %w", listErr))
			} else {
				selectedProjects = applyProjectFilters(projects, includeFilter, excludeFilter)
				if len(selectedProjects) == 0 {
					record("projects.discovery", "", fmt.Errorf("organization %s resolved zero projects after filters", orgID))
				} else {
					record("projects.discovery", fmt.Sprintf("%d projects selected", len(selectedProjects)), nil)
				}
			}
		} else {
			explicitProjects, resolveErr := resolveExplicitGCPProjects()
			if resolveErr != nil {
				record("projects.selection", "", resolveErr)
			} else if len(explicitProjects) > 0 {
				selectedProjects = explicitProjects
				record("projects.selection", fmt.Sprintf("%d projects selected", len(selectedProjects)), nil)
			} else {
				projectID := strings.TrimSpace(syncGCPProject)
				if projectID == "" {
					record("projects.selection", "", fmt.Errorf("missing project scope; set --gcp-project, --gcp-projects, --projects-file, --scope, or --gcp-org"))
				} else {
					selectedProjects = applyProjectFilters([]string{projectID}, includeFilter, excludeFilter)
					if len(selectedProjects) == 0 {
						record("projects.selection", "", fmt.Errorf("selected project %s was filtered out by include/exclude filters", projectID))
					} else {
						record("projects.selection", fmt.Sprintf("project %s selected", selectedProjects[0]), nil)
					}
				}
			}
		}
	}

	for _, projectID := range selectedProjects {
		if err := preflightGCPProjectAccessFn(ctx, gcpProjectPreflightSpec{
			ProjectID:      projectID,
			OrgID:          strings.TrimSpace(syncGCPOrg),
			RunNativeSync:  true,
			RunSecurity:    false,
			SecurityFilter: securityFilter,
			ClientOptions:  authCfg.ClientOptions,
		}); err != nil {
			record(fmt.Sprintf("project.%s", projectID), "", fmt.Errorf("project %s native access: %w", projectID, err))
			continue
		}
		record(fmt.Sprintf("project.%s", projectID), "cloud asset access confirmed", nil)
	}

	if filterErr == nil && runSecuritySync && gcpSecurityFilterIncludesSCC(securityFilter) {
		if err := preflightGCPProjectAccessFn(ctx, gcpProjectPreflightSpec{
			OrgID:          strings.TrimSpace(syncGCPOrg),
			RunNativeSync:  false,
			RunSecurity:    true,
			SecurityFilter: securityFilter,
			ClientOptions:  authCfg.ClientOptions,
		}); err != nil {
			record("org.scc", "", fmt.Errorf("security command center access: %w", err))
		} else {
			record("org.scc", "security command center access confirmed", nil)
		}
	}

	report.Checks = checks
	report.Duration = time.Since(start).Round(time.Millisecond).String()
	report.Success = len(errs) == 0
	if err := printSyncPreflightReport(report); err != nil {
		return err
	}
	if len(errs) > 0 {
		return summarizeSyncRunErrors("GCP preflight", errs)
	}
	return nil
}

func buildScheduledGCPSpecFromSyncFlags() scheduledSyncSpec {
	projects := normalizeProjectIDs(parseCommaSeparatedValues(syncGCPProjects))
	return scheduledSyncSpec{
		TableFilter:                  parseTableFilter(syncTable),
		GCPProjects:                  projects,
		GCPOrg:                       strings.TrimSpace(syncGCPOrg),
		GCPCredentialsFile:           strings.TrimSpace(syncGCPCredentialsFile),
		GCPImpersonateServiceAccount: strings.TrimSpace(syncGCPImpersonateSA),
		GCPImpersonateDelegates:      parseCommaSeparatedValues(syncGCPImpersonateDel),
		GCPImpersonateTokenLifetime:  strings.TrimSpace(syncGCPImpersonateTTL),
	}
}

func runGCPSync(ctx context.Context, start time.Time, projectID string) error {
	if strings.TrimSpace(projectID) == "" {
		Info("Starting GCP sync for organization scope")
	} else {
		Info("Starting GCP sync for project: %s", projectID)
	}
	tableFilter := parseTableFilter(syncTable)
	nativeTableFilter, securityTableFilter, runNativeSync, runSecuritySync, err := resolveGCPTableFilters(tableFilter, syncSecurity)
	if err != nil {
		return err
	}
	tableFilterSet := buildTableFilterSet(tableFilter)
	if len(tableFilter) > 0 {
		Info("Filtering GCP tables: %s", strings.Join(tableFilter, ", "))
		if len(nativeTableFilter) > 0 {
			Info("Native GCP table filter: %s", strings.Join(nativeTableFilter, ", "))
		}
		if len(securityTableFilter) > 0 {
			Info("GCP security table filter: %s", strings.Join(securityTableFilter, ", "))
		}
	}
	if syncValidate && !runNativeSync {
		return fmt.Errorf("validation for GCP security-only table filters is not supported; include at least one native table")
	}

	mode, err := loadCLIExecutionMode()
	if err != nil {
		return err
	}

	supportsAPI, apiReason := syncSupportsGCPAPIMode(projectID, runNativeSync, runSecuritySync)
	if mode != cliExecutionModeDirect && supportsAPI {
		apiClient, err := newCLIAPIClient()
		if err != nil {
			if mode == cliExecutionModeAPI {
				return err
			}
			Warning("API client configuration invalid; using direct mode: %v", err)
		} else {
			targetGroups := parseCommaSeparatedValues(syncGCPIAMGroups)
			resp, err := apiClient.RunGCPSync(ctx, apiclient.GCPSyncRequest{
				Project:                        projectID,
				Concurrency:                    syncConcurrency,
				Tables:                         nativeTableFilter,
				Validate:                       syncValidate,
				PermissionUsageLookbackDays:    syncPermissionLookback,
				PermissionRemovalThresholdDays: syncPermissionRemovalThreshold,
				GCPIAMTargetGroups:             targetGroups,
			})
			if err == nil {
				provider := "GCP"
				if syncValidate || (resp != nil && resp.Validate) {
					provider = "GCP (validate)"
				}
				var results []nativesync.SyncResult
				if resp != nil {
					results = resp.Results
				}
				if err := printSyncResults(results, start, provider); err != nil {
					return err
				}

				if !syncValidate {
					if len(tableFilterSet) > 0 {
						Info("Skipping relationship extraction because --table filter is set")
					} else if resp != nil {
						if reason := strings.TrimSpace(resp.RelationshipsSkippedReason); reason != "" {
							Info("Skipping relationship extraction: %s", reason)
						} else {
							Info("Extracted %d relationships", resp.RelationshipsExtracted)
						}
					}
				}
				return nil
			}
			if mode == cliExecutionModeAPI || !shouldFallbackToDirect(mode, err) {
				return fmt.Errorf("gcp sync via api failed: %w", err)
			}
			Warning("API unavailable; using direct mode: %v", err)
		}
	}

	if mode == cliExecutionModeAPI && !supportsAPI {
		return fmt.Errorf("gcp sync API mode unsupported: %s", apiReason)
	}
	if mode != cliExecutionModeDirect && !supportsAPI {
		Warning("API sync mode skipped; using direct mode: %s", apiReason)
	}

	return runGCPSyncDirectFn(ctx, start, projectID, tableFilter, nativeTableFilter, securityTableFilter, runNativeSync, runSecuritySync, tableFilterSet)
}

func syncSupportsGCPAPIMode(projectID string, runNativeSync, runSecuritySync bool) (bool, string) {
	if strings.TrimSpace(projectID) == "" {
		return false, "organization or multi-project scope requires direct mode"
	}
	if !runNativeSync {
		return false, "security-only sync requires direct mode"
	}
	if runSecuritySync {
		return false, "--security requires direct mode"
	}
	if syncUseAssetAPI {
		return false, "--asset-api requires direct mode"
	}
	if strings.TrimSpace(syncGCPCredentialsFile) != "" {
		return false, "--gcp-credentials-file requires direct mode"
	}
	if strings.TrimSpace(syncGCPImpersonateSA) != "" || strings.TrimSpace(syncGCPImpersonateDel) != "" || strings.TrimSpace(syncGCPImpersonateTTL) != "" {
		return false, "--gcp-impersonate-* flags require direct mode"
	}
	return true, ""
}

var runGCPSyncDirectFn = runGCPSyncDirect

func runGCPSyncDirect(
	ctx context.Context,
	start time.Time,
	projectID string,
	tableFilter []string,
	nativeTableFilter []string,
	securityTableFilter []string,
	runNativeSync bool,
	runSecuritySync bool,
	tableFilterSet map[string]struct{},
) error {
	client, err := createSnowflakeClient()
	if err != nil {
		return fmt.Errorf("create snowflake client: %w", err)
	}
	defer func() { _ = client.Close() }()

	if runNativeSync {
		if err := preflightGCPProjectAccessFn(ctx, gcpProjectPreflightSpec{
			ProjectID:      projectID,
			OrgID:          syncGCPOrg,
			RunNativeSync:  true,
			RunSecurity:    false,
			SecurityFilter: securityTableFilter,
		}); err != nil {
			return fmt.Errorf("project %s native preflight: %w", gcpProjectScopeLabel(projectID), err)
		}

		options := []nativesync.GCPEngineOption{nativesync.WithGCPProject(projectID)}
		if syncConcurrency > 0 {
			options = append(options, nativesync.WithGCPConcurrency(syncConcurrency))
		}
		if len(nativeTableFilter) > 0 {
			options = append(options, nativesync.WithGCPTableFilter(nativeTableFilter))
		}
		options = appendGCPPermissionUsageOptions(options)
		syncer := nativesync.NewGCPSyncEngine(client, slog.Default(), options...)
		if syncValidate {
			results, err := syncer.ValidateTables(ctx)
			if err != nil {
				return fmt.Errorf("validation failed: %w", err)
			}
			return printSyncResults(results, start, "GCP (validate)")
		}

		results, err := syncer.SyncAll(ctx)
		if err := handleSyncRunResults(results, start, "GCP", err); err != nil {
			return err
		}
	} else {
		Info("Skipping native GCP sync because --table filter targets only security tables")
	}

	if len(securityTableFilter) > 0 && !syncSecurity {
		Warning("Ignoring GCP security table filters without --security: %s", strings.Join(securityTableFilter, ", "))
	}

	// Sync security data if requested
	if runSecuritySync {
		if err := preflightGCPProjectAccessFn(ctx, gcpProjectPreflightSpec{
			ProjectID:      projectID,
			OrgID:          syncGCPOrg,
			RunNativeSync:  false,
			RunSecurity:    true,
			SecurityFilter: securityTableFilter,
		}); err != nil {
			if runNativeSync {
				Warning("Security preflight failed: %v", err)
			} else {
				return fmt.Errorf("project %s security preflight: %w", gcpProjectScopeLabel(projectID), err)
			}
		} else {
			Info("Syncing GCP security data (Container Analysis, Artifact Registry, SCC)...")
			secOptions := []nativesync.GCPSecurityOption{}
			if len(securityTableFilter) > 0 {
				secOptions = append(secOptions, nativesync.WithGCPSecurityTableFilter(securityTableFilter))
			}
			securitySyncer := nativesync.NewGCPSecuritySync(client, slog.Default(), projectID, syncGCPOrg, secOptions...)
			if secErr := securitySyncer.SyncAll(ctx); secErr != nil {
				Warning("Security sync failed: %v", secErr)
			} else {
				Success("Security data synced successfully")
			}
		}
	} else if syncSecurity && len(tableFilter) > 0 {
		Info("Skipping GCP security sync because --table filter does not include security tables")
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

func appendGCPPermissionUsageOptions(options []nativesync.GCPEngineOption) []nativesync.GCPEngineOption {
	options = append(options, nativesync.WithGCPPermissionUsageLookbackDays(syncPermissionLookback))
	options = append(options, nativesync.WithGCPPermissionRemovalThresholdDays(syncPermissionRemovalThreshold))
	targetGroups := parseCommaSeparatedValues(syncGCPIAMGroups)
	if len(targetGroups) > 0 {
		options = append(options, nativesync.WithGCPIAMTargetGroups(targetGroups))
	}
	return options
}

func runGCPOrgSync(ctx context.Context, start time.Time, orgID string) error {
	tableFilter := parseTableFilter(syncTable)
	_, securityTableFilter, runNativeSync, runSecuritySync, err := resolveGCPTableFilters(tableFilter, syncSecurity)
	if err != nil {
		return err
	}

	requiresProjectScope := runNativeSync || (runSecuritySync && gcpSecurityFiltersRequireProject(securityTableFilter))
	if !requiresProjectScope {
		Info("Skipping organization project discovery for SCC-only security table filters")
		if syncUseAssetAPI {
			Info("Skipping Cloud Asset Inventory API because selected filters are security-only")
		}
		return runGCPSync(ctx, start, "")
	}

	Info("Discovering projects in organization: %s", orgID)

	// List all projects in the organization using Cloud Asset Inventory
	projects, err := listOrganizationProjectsFn(ctx, orgID)
	if err != nil {
		return fmt.Errorf("list organization projects: %w", err)
	}
	projects = normalizeProjectIDs(projects)
	projects = applyProjectFilters(projects, parseCommaSeparatedValues(syncProjectInclude), parseCommaSeparatedValues(syncProjectExclude))
	if len(projects) == 0 {
		if strings.TrimSpace(syncProjectInclude) != "" || strings.TrimSpace(syncProjectExclude) != "" {
			return fmt.Errorf("no projects matched include/exclude filters for organization: %s", orgID)
		}
		return fmt.Errorf("no projects found in organization: %s", orgID)
	}

	Info("Found %d projects in organization", len(projects))

	if syncUseAssetAPI {
		return runGCPAssetAPISync(ctx, start, projects)
	}
	return runGCPMultiProjectSync(ctx, start, projects)
}

func runGCPMultiProjectSync(ctx context.Context, start time.Time, projects []string) error {
	projects = normalizeProjectIDs(projects)
	if len(projects) == 0 {
		return fmt.Errorf("no GCP projects provided for sync")
	}

	projectTimeout := defaultGCPProjectTimeout
	if timeoutSeconds, err := parseBoundedPositiveIntDirective(syncGCPProjectTimeout, "--gcp-project-timeout-seconds", minGCPProjectTimeoutSeconds, maxGCPProjectTimeoutSeconds); err != nil {
		return err
	} else if timeoutSeconds > 0 {
		projectTimeout = time.Duration(timeoutSeconds) * time.Second
	}

	Info("Starting GCP multi-project sync for %d projects...", len(projects))
	tableFilter := parseTableFilter(syncTable)
	nativeTableFilter, securityTableFilter, runNativeSync, runSecuritySync, err := resolveGCPTableFilters(tableFilter, syncSecurity)
	if err != nil {
		return err
	}
	if len(tableFilter) > 0 {
		Info("Filtering GCP tables: %s", strings.Join(tableFilter, ", "))
		if len(nativeTableFilter) > 0 {
			Info("Native GCP table filter: %s", strings.Join(nativeTableFilter, ", "))
		}
		if len(securityTableFilter) > 0 {
			Info("GCP security table filter: %s", strings.Join(securityTableFilter, ", "))
		}
	}
	if len(securityTableFilter) > 0 && !syncSecurity {
		Warning("Ignoring GCP security table filters without --security: %s", strings.Join(securityTableFilter, ", "))
	}
	if syncValidate && !runNativeSync {
		return fmt.Errorf("validation for GCP security-only table filters is not supported; include at least one native table")
	}

	client, err := createSnowflakeClient()
	if err != nil {
		return fmt.Errorf("create snowflake client: %w", err)
	}
	defer func() { _ = client.Close() }()

	if syncValidate {
		if len(projects) == 0 {
			return fmt.Errorf("no GCP projects provided for validation")
		}
		options := []nativesync.GCPEngineOption{nativesync.WithGCPProject(projects[0])}
		if syncConcurrency > 0 {
			options = append(options, nativesync.WithGCPConcurrency(syncConcurrency))
		}
		if len(nativeTableFilter) > 0 {
			options = append(options, nativesync.WithGCPTableFilter(nativeTableFilter))
		}
		options = appendGCPPermissionUsageOptions(options)
		syncer := nativesync.NewGCPSyncEngine(client, slog.Default(), options...)
		results, err := syncer.ValidateTables(ctx)
		if err != nil {
			return fmt.Errorf("validation failed: %w", err)
		}
		return printSyncResults(results, start, "GCP (validate)")
	}

	var allResults []nativesync.SyncResult
	var syncErrs []error
	for i, projectID := range projects {
		Info("[%d/%d] Syncing project: %s", i+1, len(projects), projectID)

		projectCtx, cancel := context.WithTimeout(ctx, projectTimeout)
		nativeTimedOut := false

		if runNativeSync {
			if err := preflightGCPProjectAccessFn(projectCtx, gcpProjectPreflightSpec{
				ProjectID:      projectID,
				OrgID:          syncGCPOrg,
				RunNativeSync:  true,
				RunSecurity:    false,
				SecurityFilter: securityTableFilter,
			}); err != nil {
				if errors.Is(err, context.DeadlineExceeded) || errors.Is(projectCtx.Err(), context.DeadlineExceeded) {
					syncErrs = append(syncErrs, fmt.Errorf("project %s native preflight timed out after %s", projectID, projectTimeout.Round(time.Second)))
				} else {
					syncErrs = append(syncErrs, fmt.Errorf("project %s native preflight: %w", projectID, err))
				}
				cancel()
				continue
			}

			options := []nativesync.GCPEngineOption{nativesync.WithGCPProject(projectID)}
			if syncConcurrency > 0 {
				options = append(options, nativesync.WithGCPConcurrency(syncConcurrency))
			}
			if len(nativeTableFilter) > 0 {
				options = append(options, nativesync.WithGCPTableFilter(nativeTableFilter))
			}
			options = appendGCPPermissionUsageOptions(options)
			syncer := nativesync.NewGCPSyncEngine(client, slog.Default(), options...)
			results, err := syncer.SyncAll(projectCtx)
			allResults = append(allResults, results...)
			if err != nil {
				Warning("Failed to sync project %s: %v", projectID, err)
				if errors.Is(err, context.DeadlineExceeded) || errors.Is(projectCtx.Err(), context.DeadlineExceeded) {
					nativeTimedOut = true
					syncErrs = append(syncErrs, fmt.Errorf("project %s native sync timed out after %s", projectID, projectTimeout.Round(time.Second)))
				} else {
					syncErrs = append(syncErrs, fmt.Errorf("project %s native sync: %w", projectID, err))
				}
			}
		}

		if runNativeSync && (nativeTimedOut || projectCtx.Err() != nil) {
			cancel()
			continue
		}

		if runSecuritySync {
			if err := preflightGCPProjectAccessFn(projectCtx, gcpProjectPreflightSpec{
				ProjectID:      projectID,
				OrgID:          syncGCPOrg,
				RunNativeSync:  false,
				RunSecurity:    true,
				SecurityFilter: securityTableFilter,
			}); err != nil {
				if errors.Is(err, context.DeadlineExceeded) || errors.Is(projectCtx.Err(), context.DeadlineExceeded) {
					syncErrs = append(syncErrs, fmt.Errorf("project %s security preflight timed out after %s", projectID, projectTimeout.Round(time.Second)))
				} else {
					syncErrs = append(syncErrs, fmt.Errorf("project %s security preflight: %w", projectID, err))
				}
				cancel()
				continue
			}

			secOptions := []nativesync.GCPSecurityOption{}
			if len(securityTableFilter) > 0 {
				secOptions = append(secOptions, nativesync.WithGCPSecurityTableFilter(securityTableFilter))
			}
			securitySyncer := nativesync.NewGCPSecuritySync(client, slog.Default(), projectID, syncGCPOrg, secOptions...)
			if secErr := securitySyncer.SyncAll(projectCtx); secErr != nil {
				Warning("Security sync failed for project %s: %v", projectID, secErr)
				if errors.Is(secErr, context.DeadlineExceeded) || errors.Is(projectCtx.Err(), context.DeadlineExceeded) {
					syncErrs = append(syncErrs, fmt.Errorf("project %s security sync timed out after %s", projectID, projectTimeout.Round(time.Second)))
				} else {
					syncErrs = append(syncErrs, fmt.Errorf("project %s security sync: %w", projectID, secErr))
				}
			}
		}

		cancel()
	}

	if runNativeSync {
		if len(syncErrs) > 0 && len(allResults) == 0 {
			Warning("%d project(s) had errors", len(syncErrs))
			return summarizeSyncRunErrors("GCP multi-project sync", syncErrs)
		}

		if err := printSyncResults(allResults, start, "GCP"); err != nil {
			return err
		}
	} else {
		Info("Skipped native GCP sync because --table filter targets only security tables")
	}

	if len(syncErrs) > 0 {
		Warning("%d project(s) had errors", len(syncErrs))
		return summarizeSyncRunErrors("GCP multi-project sync", syncErrs)
	}

	if runSecuritySync {
		Success("GCP security data synced for %d project(s)", len(projects))
	}

	return nil
}

func runGCPAssetAPISync(ctx context.Context, start time.Time, projects []string) error {
	projects = normalizeProjectIDs(projects)
	if len(projects) == 0 {
		return fmt.Errorf("no GCP projects provided for asset API sync")
	}

	Info("Starting GCP sync via Cloud Asset Inventory API for %d projects...", len(projects))
	tableFilter := parseTableFilter(syncTable)
	nativeTableFilter, securityTableFilter, runNativeSync, runSecuritySync, err := resolveGCPTableFilters(tableFilter, syncSecurity)
	if err != nil {
		return err
	}
	if len(tableFilter) > 0 {
		Info("Filtering GCP asset types: %s", strings.Join(tableFilter, ", "))
		if len(nativeTableFilter) > 0 {
			Info("Native GCP asset filter: %s", strings.Join(nativeTableFilter, ", "))
		}
		if len(securityTableFilter) > 0 {
			Info("GCP security table filter: %s", strings.Join(securityTableFilter, ", "))
		}
	}
	if len(securityTableFilter) > 0 && !syncSecurity {
		Warning("Ignoring GCP security table filters without --security: %s", strings.Join(securityTableFilter, ", "))
	}
	if syncValidate && !runNativeSync {
		return fmt.Errorf("validation for GCP security-only table filters is not supported; include at least one native table")
	}

	mode, err := loadCLIExecutionMode()
	if err != nil {
		return err
	}

	supportsAPI, apiReason := syncSupportsGCPAssetAPIMode(runNativeSync, runSecuritySync)
	if mode != cliExecutionModeDirect && supportsAPI {
		apiClient, err := newCLIAPIClient()
		if err != nil {
			if mode == cliExecutionModeAPI {
				return err
			}
			Warning("API client configuration invalid; using direct mode: %v", err)
		} else {
			resp, err := apiClient.RunGCPAssetSync(ctx, apiclient.GCPAssetSyncRequest{
				Projects:    projects,
				Concurrency: syncConcurrency,
				Tables:      nativeTableFilter,
				Validate:    syncValidate,
			})
			if err == nil {
				provider := "GCP (Asset API)"
				if syncValidate || (resp != nil && resp.Validate) {
					provider = "GCP (Asset API) (validate)"
				}
				var results []nativesync.SyncResult
				if resp != nil {
					results = resp.Results
				}
				return printSyncResults(results, start, provider)
			}
			if mode == cliExecutionModeAPI || !shouldFallbackToDirect(mode, err) {
				return fmt.Errorf("gcp asset sync via api failed: %w", err)
			}
			Warning("API unavailable; using direct mode: %v", err)
		}
	}

	if mode == cliExecutionModeAPI && !supportsAPI {
		return fmt.Errorf("gcp asset sync API mode unsupported: %s", apiReason)
	}
	if mode != cliExecutionModeDirect && !supportsAPI {
		Warning("API sync mode skipped; using direct mode: %s", apiReason)
	}

	return runGCPAssetAPISyncDirectFn(ctx, start, projects, tableFilter, nativeTableFilter, securityTableFilter, runNativeSync, runSecuritySync)
}

func syncSupportsGCPAssetAPIMode(runNativeSync, runSecuritySync bool) (bool, string) {
	if !runNativeSync {
		return false, "security-only sync requires direct mode"
	}
	if syncSecurity {
		return false, "--security requires direct mode"
	}
	if runSecuritySync {
		return false, "--security requires direct mode"
	}
	if strings.TrimSpace(syncGCPCredentialsFile) != "" {
		return false, "--gcp-credentials-file requires direct mode"
	}
	if strings.TrimSpace(syncGCPImpersonateSA) != "" || strings.TrimSpace(syncGCPImpersonateDel) != "" || strings.TrimSpace(syncGCPImpersonateTTL) != "" {
		return false, "--gcp-impersonate-* flags require direct mode"
	}
	return true, ""
}

var runGCPAssetAPISyncDirectFn = runGCPAssetAPISyncDirect

func runGCPAssetAPISyncDirect(
	ctx context.Context,
	start time.Time,
	projects []string,
	tableFilter []string,
	nativeTableFilter []string,
	securityTableFilter []string,
	runNativeSync bool,
	runSecuritySync bool,
) error {
	client, err := createSnowflakeClient()
	if err != nil {
		return fmt.Errorf("create snowflake client: %w", err)
	}
	defer func() { _ = client.Close() }()

	var syncErrs []error

	if runNativeSync {
		options := []nativesync.GCPAssetOption{nativesync.WithProjects(projects)}
		if syncConcurrency > 0 {
			options = append(options, nativesync.WithAssetConcurrency(syncConcurrency))
		}
		if len(nativeTableFilter) > 0 {
			options = append(options, nativesync.WithAssetTypeFilter(nativeTableFilter))
		}
		syncer := nativesync.NewGCPAssetInventoryEngine(client, slog.Default(), options...)
		if syncValidate {
			results, err := syncer.ValidateTables(ctx)
			if err != nil {
				return fmt.Errorf("validation failed: %w", err)
			}
			return printSyncResults(results, start, "GCP (Asset API) (validate)")
		}

		results, err := syncer.SyncAll(ctx)
		if runErr := handleSyncRunResults(results, start, "GCP (Asset API)", err); runErr != nil {
			syncErrs = append(syncErrs, runErr)
		}
	} else {
		Info("Skipping GCP asset sync because --table filter targets only security tables")
	}

	if runSecuritySync {
		for i, projectID := range projects {
			Info("[%d/%d] Syncing security tables for project: %s", i+1, len(projects), projectID)
			secOptions := []nativesync.GCPSecurityOption{}
			if len(securityTableFilter) > 0 {
				secOptions = append(secOptions, nativesync.WithGCPSecurityTableFilter(securityTableFilter))
			}
			securitySyncer := nativesync.NewGCPSecuritySync(client, slog.Default(), projectID, syncGCPOrg, secOptions...)
			if secErr := securitySyncer.SyncAll(ctx); secErr != nil {
				Warning("Security sync failed for project %s: %v", projectID, secErr)
				syncErrs = append(syncErrs, fmt.Errorf("project %s security sync: %w", projectID, secErr))
			}
		}
		if len(projects) > 0 {
			Success("GCP security data synced for %d project(s)", len(projects))
		}
	} else if syncSecurity && len(tableFilter) > 0 {
		Info("Skipping GCP security sync because --table filter does not include security tables")
	}

	return summarizeSyncRunErrors("GCP asset API sync", syncErrs)
}

func applyGCPAuthOverrides() (func(), error) {
	envSnapshots := make(map[string]envSnapshot)
	tempCredentialsFile := ""
	cleanup := func() {
		if tempCredentialsFile != "" {
			_ = os.Remove(tempCredentialsFile)
		}
		restoreEnvSnapshot(envSnapshots)
	}

	credentialsFile := strings.TrimSpace(syncGCPCredentialsFile)
	if credentialsFile != "" {
		if err := validateReadableFile(credentialsFile, "gcp credentials file"); err != nil {
			return cleanup, err
		}
	}

	impersonateServiceAccount := strings.TrimSpace(syncGCPImpersonateSA)
	delegates := parseCommaSeparatedValues(syncGCPImpersonateDel)
	tokenLifetimeSeconds, err := parseBoundedPositiveIntDirective(syncGCPImpersonateTTL, "--gcp-impersonate-token-lifetime-seconds", 600, 43200)
	if err != nil {
		return cleanup, err
	}

	if impersonateServiceAccount == "" {
		if len(delegates) > 0 {
			return cleanup, fmt.Errorf("--gcp-impersonate-delegates requires --gcp-impersonate-service-account")
		}
		if tokenLifetimeSeconds > 0 {
			return cleanup, fmt.Errorf("--gcp-impersonate-token-lifetime-seconds requires --gcp-impersonate-service-account")
		}
		if credentialsFile == "" {
			return cleanup, nil
		}

		if err := setEnvWithSnapshot(envSnapshots, "GOOGLE_APPLICATION_CREDENTIALS", credentialsFile); err != nil {
			return cleanup, fmt.Errorf("set GOOGLE_APPLICATION_CREDENTIALS: %w", err)
		}
		return cleanup, nil
	}

	sourcePath, err := resolveGCPSourceCredentialsPath(credentialsFile)
	if err != nil {
		return cleanup, err
	}

	sourceData, err := os.ReadFile(sourcePath) // #nosec G304,G703 -- sourcePath is validated by resolveGCPSourceCredentialsPath
	if err != nil {
		return cleanup, fmt.Errorf("read GCP source credentials %q: %w", sourcePath, err)
	}

	var sourceCredentials map[string]interface{}
	if err := json.Unmarshal(sourceData, &sourceCredentials); err != nil {
		return cleanup, fmt.Errorf("parse GCP source credentials %q: %w", sourcePath, err)
	}
	if len(sourceCredentials) == 0 {
		return cleanup, fmt.Errorf("GCP source credentials %q are empty", sourcePath)
	}

	impersonationURL := fmt.Sprintf("https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:generateAccessToken", url.PathEscape(impersonateServiceAccount))
	payload := map[string]interface{}{
		"type":                              "impersonated_service_account",
		"service_account_impersonation_url": impersonationURL,
		"source_credentials":                sourceCredentials,
	}
	if tokenLifetimeSeconds > 0 {
		payload["token_lifetime_seconds"] = tokenLifetimeSeconds
	}
	if len(delegates) > 0 {
		payload["delegates"] = delegates
	}

	encoded, err := json.Marshal(payload)
	if err != nil {
		return cleanup, fmt.Errorf("marshal impersonated GCP credentials: %w", err)
	}

	tmpFile, err := os.CreateTemp("", "cerebro-gcp-impersonated-*.json")
	if err != nil {
		return cleanup, fmt.Errorf("create temporary GCP impersonation credentials file: %w", err)
	}
	tempCredentialsFile = tmpFile.Name()
	if _, err := tmpFile.Write(encoded); err != nil {
		_ = tmpFile.Close()
		return cleanup, fmt.Errorf("write temporary GCP impersonation credentials file: %w", err)
	}
	if err := tmpFile.Chmod(0o600); err != nil {
		_ = tmpFile.Close()
		return cleanup, fmt.Errorf("set permissions on temporary GCP impersonation credentials file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return cleanup, fmt.Errorf("close temporary GCP impersonation credentials file: %w", err)
	}

	if err := setEnvWithSnapshot(envSnapshots, "GOOGLE_APPLICATION_CREDENTIALS", tempCredentialsFile); err != nil {
		cleanup()
		return func() {}, fmt.Errorf("set GOOGLE_APPLICATION_CREDENTIALS: %w", err)
	}

	return cleanup, nil
}

func resolveGCPSourceCredentialsPath(credentialsFile string) (string, error) {
	if credentialsFile != "" {
		return credentialsFile, nil
	}

	fromEnv := strings.TrimSpace(os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"))
	if fromEnv != "" {
		if err := validateReadableFile(fromEnv, "GOOGLE_APPLICATION_CREDENTIALS"); err != nil {
			return "", err
		}
		return fromEnv, nil
	}

	defaultPath := defaultGCPApplicationDefaultCredentialsPath()
	if defaultPath != "" {
		if err := validateReadableFile(defaultPath, "application default credentials"); err == nil {
			return defaultPath, nil
		}
	}

	return "", fmt.Errorf("gcp impersonation requires source credentials; provide --gcp-credentials-file or set GOOGLE_APPLICATION_CREDENTIALS")
}

func defaultGCPApplicationDefaultCredentialsPath() string {
	if appData := strings.TrimSpace(os.Getenv("APPDATA")); appData != "" {
		return filepath.Join(appData, "gcloud", "application_default_credentials.json")
	}

	homeDir, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(homeDir) == "" {
		return ""
	}

	return filepath.Join(homeDir, ".config", "gcloud", "application_default_credentials.json")
}

func resolveGCPTableFilters(tableFilter []string, securityEnabled bool) (native, security []string, runNative, runSecurity bool, err error) {
	native, security = splitGCPScheduledTableFilters(tableFilter)
	runNative = len(tableFilter) == 0 || len(native) > 0
	runSecurity = securityEnabled && (len(tableFilter) == 0 || len(security) > 0)

	if len(tableFilter) > 0 && len(native) == 0 && !securityEnabled {
		err = fmt.Errorf("--table filter targets only GCP security tables; rerun with --security")
	}

	return native, security, runNative, runSecurity, err
}
