package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/processcreds"
	"github.com/spf13/cobra"

	"github.com/writerinternal/cerebro/internal/app"
	"github.com/writerinternal/cerebro/internal/scanner"
	"github.com/writerinternal/cerebro/internal/snowflake"
	nativesync "github.com/writerinternal/cerebro/internal/sync"
)

var syncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Sync cloud assets to Snowflake",
	Long: `Sync cloud assets from AWS, GCP, Azure, or Kubernetes to Snowflake using Cerebro's native scanners.

Examples:
  cerebro sync                                    # Sync AWS (default)
  cerebro sync --gcp --gcp-project my-project    # Sync GCP
  cerebro sync --gcp --gcp-org 1234567890        # Sync all GCP projects in an org
  cerebro sync --azure                           # Sync Azure
  cerebro sync --k8s                             # Sync Kubernetes
  cerebro sync --scan-after                      # Scan after sync`,
	RunE: runSync,
}

var syncBackfillRelationshipsCmd = &cobra.Command{
	Use:   "backfill-relationships",
	Short: "Normalize relationship IDs in Snowflake",
	Long: `Normalize existing relationship IDs to remove JSON/map wrappers.

This command re-computes relationship IDs from normalized source/target IDs and
updates the RESOURCE_RELATIONSHIPS table in-place, removing duplicates.

Examples:
  cerebro sync backfill-relationships
  cerebro sync backfill-relationships --batch-size 500`,
	RunE: runBackfillRelationships,
}

var (
	syncScanAfter          bool
	syncGCP                bool
	syncGCPProject         string
	syncGCPProjects        string // comma-separated list of projects
	syncGCPOrg             string // organization ID for multi-project sync
	syncGCPProjectTimeout  string
	syncMultiRegion        bool
	syncRegion             string
	syncUseAssetAPI        bool   // use Cloud Asset Inventory API
	syncSecurity           bool   // sync security data (vulnerabilities, SCC findings)
	syncK8s                bool   // sync Kubernetes resources
	syncK8sKubeconfig      string // kubeconfig path
	syncK8sContext         string // kubeconfig context
	syncK8sNamespace       string // namespace to sync
	syncAzure              bool   // sync Azure resources
	syncAzureSubscription  string // Azure subscription ID
	syncConcurrency        int
	syncTable              string
	syncOutput             string
	syncValidate           bool
	syncGCPCredentialsFile string
	syncGCPImpersonateSA   string
	syncGCPImpersonateDel  string
	syncGCPImpersonateTTL  string
	syncAWSProfile         string
	syncAWSProfiles        string // comma-separated AWS SSO profiles
	syncAWSConfigFile      string
	syncAWSSharedCredsFile string
	syncAWSCredentialProc  string
	syncAWSWebIDTokenFile  string
	syncAWSWebIDRoleARN    string
	syncAWSRoleARN         string
	syncAWSRoleSession     string
	syncAWSRoleExternalID  string
	syncAWSRoleMFASerial   string
	syncAWSRoleMFAToken    string
	syncAWSRoleSourceID    string
	syncAWSRoleDuration    string
	syncAWSRoleTags        string
	syncAWSRoleTransitive  string
	syncAWSOrg             bool
	syncAWSOrgRole         string
	syncAWSOrgInclude      string
	syncAWSOrgExclude      string
	syncAWSOrgConcurrency  int
	syncBackfillBatchSize  int
)

func init() {
	syncCmd.Flags().BoolVar(&syncScanAfter, "scan-after", false, "Run policy scan after successful sync")
	syncCmd.Flags().BoolVar(&syncGCP, "gcp", false, "Sync GCP resources instead of AWS")
	syncCmd.Flags().StringVar(&syncGCPProject, "gcp-project", "", "GCP project ID to sync (required with --gcp unless using --gcp-org)")
	syncCmd.Flags().StringVar(&syncGCPProjects, "gcp-projects", "", "Comma-separated list of GCP project IDs to sync")
	syncCmd.Flags().StringVar(&syncGCPOrg, "gcp-org", "", "GCP organization ID for multi-project sync (syncs all projects)")
	syncCmd.Flags().StringVar(&syncGCPProjectTimeout, "gcp-project-timeout-seconds", "", "Per-project timeout in seconds for GCP multi-project sync (30-86400)")
	syncCmd.Flags().BoolVar(&syncMultiRegion, "multi-region", false, "Scan all major AWS regions (us-east-1, us-west-2, eu-west-1, etc.)")
	syncCmd.Flags().StringVarP(&syncRegion, "region", "r", "", "AWS region to sync when --multi-region is false")
	syncCmd.Flags().BoolVar(&syncUseAssetAPI, "asset-api", false, "Use GCP Cloud Asset Inventory API for efficient bulk fetching")
	syncCmd.Flags().BoolVar(&syncSecurity, "security", false, "Sync security data (Container Analysis vulnerabilities, SCC findings, Artifact Registry)")
	syncCmd.Flags().BoolVar(&syncK8s, "k8s", false, "Sync Kubernetes resources")
	syncCmd.Flags().StringVar(&syncK8sKubeconfig, "kubeconfig", "", "Path to kubeconfig file (defaults to KUBECONFIG)")
	syncCmd.Flags().StringVar(&syncK8sContext, "kube-context", "", "Kubernetes context name")
	syncCmd.Flags().StringVar(&syncK8sNamespace, "k8s-namespace", "", "Kubernetes namespace to sync (defaults to all)")
	syncCmd.Flags().BoolVar(&syncAzure, "azure", false, "Sync Azure resources")
	syncCmd.Flags().StringVar(&syncAzureSubscription, "azure-subscription", "", "Azure subscription ID (optional, will auto-discover if not set)")
	syncCmd.Flags().IntVar(&syncConcurrency, "concurrency", 20, "Max concurrent table syncs for native engines")
	syncCmd.Flags().StringVar(&syncTable, "table", "", "Sync only specific table(s), comma-separated (e.g., aws_iam_accounts)")
	syncCmd.Flags().StringVarP(&syncOutput, "output", "o", "table", "Output format (table, json)")
	syncCmd.Flags().BoolVar(&syncValidate, "validate", false, "Validate Snowflake tables without fetching resources")
	syncCmd.Flags().StringVar(&syncGCPCredentialsFile, "gcp-credentials-file", "", "Path to GCP credentials JSON file (service-account or external-account config)")
	syncCmd.Flags().StringVar(&syncGCPImpersonateSA, "gcp-impersonate-service-account", "", "Service account email to impersonate for GCP API calls")
	syncCmd.Flags().StringVar(&syncGCPImpersonateDel, "gcp-impersonate-delegates", "", "Comma-separated delegate service accounts for GCP impersonation chain")
	syncCmd.Flags().StringVar(&syncGCPImpersonateTTL, "gcp-impersonate-token-lifetime-seconds", "", "Access token lifetime in seconds for GCP impersonation (600-43200)")
	syncCmd.Flags().StringVar(&syncAWSProfile, "aws-profile", "", "AWS shared config profile for single-account sync")
	syncCmd.Flags().StringVar(&syncAWSProfiles, "aws-profiles", "", "Comma-separated AWS SSO profile names to sync multiple accounts")
	syncCmd.Flags().StringVar(&syncAWSConfigFile, "aws-config-file", "", "Path to AWS shared config file")
	syncCmd.Flags().StringVar(&syncAWSSharedCredsFile, "aws-shared-credentials-file", "", "Path to AWS shared credentials file")
	syncCmd.Flags().StringVar(&syncAWSCredentialProc, "aws-credential-process", "", "Credential process command (for example IAM Roles Anywhere credential helper)")
	syncCmd.Flags().StringVar(&syncAWSWebIDTokenFile, "aws-web-identity-token-file", "", "Path to OIDC token file for web identity auth")
	syncCmd.Flags().StringVar(&syncAWSWebIDRoleARN, "aws-web-identity-role-arn", "", "Role ARN to use with --aws-web-identity-token-file")
	syncCmd.Flags().StringVar(&syncAWSRoleARN, "aws-role-arn", "", "AWS role ARN to assume before syncing")
	syncCmd.Flags().StringVar(&syncAWSRoleSession, "aws-role-session-name", "cerebro-sync", "Session name to use with --aws-role-arn")
	syncCmd.Flags().StringVar(&syncAWSRoleExternalID, "aws-role-external-id", "", "External ID to use with --aws-role-arn")
	syncCmd.Flags().StringVar(&syncAWSRoleMFASerial, "aws-role-mfa-serial", "", "MFA serial/ARN to use with --aws-role-arn")
	syncCmd.Flags().StringVar(&syncAWSRoleMFAToken, "aws-role-mfa-token", "", "One-time MFA token code to use with --aws-role-arn")
	syncCmd.Flags().StringVar(&syncAWSRoleSourceID, "aws-role-source-identity", "", "Source identity to attach to --aws-role-arn sessions")
	syncCmd.Flags().StringVar(&syncAWSRoleDuration, "aws-role-duration-seconds", "", "Duration in seconds for --aws-role-arn sessions (900-43200)")
	syncCmd.Flags().StringVar(&syncAWSRoleTags, "aws-role-session-tags", "", "Comma-separated session tags (key=value) for --aws-role-arn")
	syncCmd.Flags().StringVar(&syncAWSRoleTransitive, "aws-role-transitive-tag-keys", "", "Comma-separated transitive tag keys for --aws-role-session-tags")
	syncCmd.Flags().BoolVar(&syncAWSOrg, "aws-org", false, "Sync all AWS organization accounts using assumed roles")
	syncCmd.Flags().StringVar(&syncAWSOrgRole, "aws-org-role", "OrganizationAccountAccessRole", "IAM role name (or ARN template with {account_id}) to assume in member accounts")
	syncCmd.Flags().StringVar(&syncAWSOrgInclude, "aws-org-include", "", "Comma-separated AWS account IDs to include when syncing org accounts")
	syncCmd.Flags().StringVar(&syncAWSOrgExclude, "aws-org-exclude", "", "Comma-separated AWS account IDs to exclude when syncing org accounts")
	syncCmd.Flags().IntVar(&syncAWSOrgConcurrency, "aws-org-concurrency", 4, "Max concurrent AWS organization account syncs")

	syncBackfillRelationshipsCmd.Flags().IntVar(&syncBackfillBatchSize, "batch-size", 200, "Batch size for relationship ID updates")
	syncCmd.AddCommand(syncBackfillRelationshipsCmd)
}

func runSync(cmd *cobra.Command, args []string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	start := time.Now()

	// Kubernetes sync
	if syncK8s {
		return runK8sSync(ctx, start)
	}

	// Azure sync
	if syncAzure {
		return runAzureSync(ctx, start)
	}

	// GCP sync
	if syncGCP {
		cleanup, err := applyGCPAuthOverrides()
		if err != nil {
			return err
		}
		defer cleanup()
		// Handle multi-project sync via organization
		if syncGCPOrg != "" {
			return runGCPOrgSync(ctx, start, syncGCPOrg)
		}
		// Handle multi-project sync via explicit list
		if syncGCPProjects != "" {
			projects := normalizeProjectIDs(parseCommaSeparatedValues(syncGCPProjects))
			if len(projects) == 0 {
				return fmt.Errorf("--gcp-projects did not include any valid project IDs")
			}
			return runGCPMultiProjectSync(ctx, start, projects)
		}
		// Handle single project sync
		projectID := strings.TrimSpace(syncGCPProject)
		if projectID == "" {
			return fmt.Errorf("--gcp-project, --gcp-projects, or --gcp-org is required with --gcp")
		}
		if syncUseAssetAPI {
			return runGCPAssetAPISync(ctx, start, []string{projectID})
		}
		return runGCPSync(ctx, start, projectID)
	}

	awsCleanup, err := applyAWSAuthOverrides()
	if err != nil {
		return err
	}
	defer awsCleanup()

	// Multi-account AWS sync via SSO profiles
	if syncAWSOrg {
		if syncAWSProfiles != "" {
			Warning("Ignoring --aws-profiles because --aws-org is set")
		}
		return runAWSOrgSync(ctx, start)
	}

	// Multi-account AWS sync via SSO profiles
	if syncAWSProfiles != "" {
		if syncAWSProfile != "" {
			Warning("Ignoring --aws-profile because --aws-profiles is set")
		}
		return runMultiAccountAWSSync(ctx, start)
	}

	return runNativeSync(ctx, start)
}

func runBackfillRelationships(cmd *cobra.Command, args []string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	client, err := createSnowflakeClient()
	if err != nil {
		return fmt.Errorf("create snowflake client: %w", err)
	}
	defer func() { _ = client.Close() }()

	extractor := nativesync.NewRelationshipExtractor(client, slog.Default())
	stats, err := extractor.BackfillNormalizedRelationshipIDs(ctx, syncBackfillBatchSize)
	if err != nil {
		return fmt.Errorf("backfill relationship IDs: %w", err)
	}

	Success("Relationship ID backfill complete (scanned %d, updated %d, deleted %d, skipped %d)", stats.Scanned, stats.Updated, stats.Deleted, stats.Skipped)
	return nil
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

	client, err := createSnowflakeClient()
	if err != nil {
		return fmt.Errorf("create snowflake client: %w", err)
	}
	defer func() { _ = client.Close() }()

	if runNativeSync {
		options := []nativesync.GCPEngineOption{nativesync.WithGCPProject(projectID)}
		if syncConcurrency > 0 {
			options = append(options, nativesync.WithGCPConcurrency(syncConcurrency))
		}
		if len(nativeTableFilter) > 0 {
			options = append(options, nativesync.WithGCPTableFilter(nativeTableFilter))
		}
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
	if len(projects) == 0 {
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
			options := []nativesync.GCPEngineOption{nativesync.WithGCPProject(projectID)}
			if syncConcurrency > 0 {
				options = append(options, nativesync.WithGCPConcurrency(syncConcurrency))
			}
			if len(nativeTableFilter) > 0 {
				options = append(options, nativesync.WithGCPTableFilter(nativeTableFilter))
			}
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

func runK8sSync(ctx context.Context, start time.Time) error {
	Info("Starting Kubernetes sync...")
	tableFilter := parseTableFilter(syncTable)
	if len(tableFilter) > 0 {
		Info("Filtering Kubernetes tables: %s", strings.Join(tableFilter, ", "))
	}

	client, err := createSnowflakeClient()
	if err != nil {
		return fmt.Errorf("create snowflake client: %w", err)
	}
	defer func() { _ = client.Close() }()

	opts := []nativesync.K8sEngineOption{}
	if syncK8sKubeconfig != "" {
		opts = append(opts, nativesync.WithK8sKubeconfig(syncK8sKubeconfig))
	}
	if syncK8sContext != "" {
		opts = append(opts, nativesync.WithK8sContext(syncK8sContext))
	}
	if syncK8sNamespace != "" {
		opts = append(opts, nativesync.WithK8sNamespace(syncK8sNamespace))
	}
	if syncConcurrency > 0 {
		opts = append(opts, nativesync.WithK8sConcurrency(syncConcurrency))
	}
	if len(tableFilter) > 0 {
		opts = append(opts, nativesync.WithK8sTableFilter(tableFilter))
	}

	syncer := nativesync.NewK8sSyncEngine(client, slog.Default(), opts...)
	if syncValidate {
		results, err := syncer.ValidateTables(ctx)
		if err != nil {
			return fmt.Errorf("validation failed: %w", err)
		}
		return printSyncResults(results, start, "Kubernetes (validate)")
	}

	results, err := syncer.SyncAll(ctx)
	if err := handleSyncRunResults(results, start, "Kubernetes", err); err != nil {
		return err
	}

	if syncScanAfter {
		Info("Triggering policy scan...")
		if err := runPostSyncScan(ctx, tableFilter); err != nil {
			Warning("Post-sync scan failed: %v", err)
		}
	}

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

	if syncValidate {
		results, err := syncer.ValidateTables(ctx)
		if err != nil {
			return fmt.Errorf("validation failed: %w", err)
		}
		return printSyncResults(results, start, "Azure (validate)")
	}

	results, err := syncer.SyncAll(ctx)
	if err := handleSyncRunResults(results, start, "Azure", err); err != nil {
		return err
	}

	if syncScanAfter {
		Info("Triggering policy scan...")
		if err := runPostSyncScan(ctx, tableFilter); err != nil {
			Warning("Post-sync scan failed: %v", err)
		}
	}

	return nil
}

func runMultiAccountAWSSync(ctx context.Context, start time.Time) error {
	profiles := parseCommaSeparatedValues(syncAWSProfiles)
	if len(profiles) == 0 {
		return fmt.Errorf("--aws-profiles did not include any valid profile names")
	}

	Info("Starting multi-account AWS sync (%d profiles)...", len(profiles))
	var totalResults []nativesync.SyncResult
	var syncErrs []error

	for _, profile := range profiles {
		Info("Syncing AWS profile: %s", profile)
		profileStart := time.Now()

		awsCfg, err := loadAWSConfig(ctx, profile)
		if err != nil {
			Warning("Failed to load config for profile %s: %v", profile, err)
			syncErrs = append(syncErrs, fmt.Errorf("profile %s: load config: %w", profile, err))
			continue
		}
		awsCfg, err = applyAWSAssumeRoleOverride(ctx, awsCfg)
		if err != nil {
			Warning("Failed to assume role for profile %s: %v", profile, err)
			syncErrs = append(syncErrs, fmt.Errorf("profile %s: %w", profile, err))
			continue
		}

		tableFilter := parseTableFilter(syncTable)
		region := syncRegion
		if region == "" {
			region = awsCfg.Region
		}
		if region == "" {
			region = "us-east-1"
		}

		sfClient, err := createSnowflakeClient()
		if err != nil {
			Warning("Failed to create Snowflake client for profile %s: %v", profile, err)
			syncErrs = append(syncErrs, fmt.Errorf("profile %s: create snowflake client: %w", profile, err))
			continue
		}

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

		syncer := nativesync.NewSyncEngine(sfClient, slog.Default(), opts...)
		results, err := syncer.SyncAllWithConfig(ctx, awsCfg)
		_ = sfClient.Close()
		totalResults = append(totalResults, results...)

		if err != nil {
			Warning("Sync failed for profile %s: %v", profile, err)
			syncErrs = append(syncErrs, fmt.Errorf("profile %s: %w", profile, err))
			continue
		}

		Success("Profile %s synced in %s", profile, time.Since(profileStart).Round(time.Second))
	}

	if len(syncErrs) > 0 {
		if len(totalResults) == 0 {
			Warning("%d profile(s) had errors", len(syncErrs))
			return summarizeSyncRunErrors("multi-account AWS sync", syncErrs)
		}
	}

	if err := printSyncResults(totalResults, start, fmt.Sprintf("AWS (%d profiles)", len(profiles))); err != nil {
		return err
	}

	if len(syncErrs) > 0 {
		Warning("%d profile(s) had errors", len(syncErrs))
		return summarizeSyncRunErrors("multi-account AWS sync", syncErrs)
	}

	return nil
}

func summarizeSyncRunErrors(scope string, errs []error) error {
	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf("%s completed with %d error(s): %w", scope, len(errs), errors.Join(errs...))
}

func handleSyncRunResults(results []nativesync.SyncResult, start time.Time, provider string, syncErr error) error {
	if len(results) > 0 || syncErr == nil {
		if err := printSyncResults(results, start, provider); err != nil {
			return err
		}
	}
	if syncErr != nil {
		return fmt.Errorf("sync failed: %w", syncErr)
	}
	return nil
}

func runNativeSync(ctx context.Context, start time.Time) error {
	awsCfg, err := loadAWSConfig(ctx, syncAWSProfile)
	if err != nil {
		return fmt.Errorf("load AWS config: %w", err)
	}
	awsCfg, err = applyAWSAssumeRoleOverride(ctx, awsCfg)
	if err != nil {
		return err
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
	if syncValidate {
		results, err := syncer.ValidateTablesWithConfig(ctx, awsCfg)
		if err != nil {
			return fmt.Errorf("validation failed: %w", err)
		}
		return printSyncResults(results, start, "AWS (validate)")
	}

	results, err := syncer.SyncAllWithConfig(ctx, awsCfg)
	if err := handleSyncRunResults(results, start, "AWS", err); err != nil {
		return err
	}

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

func loadAWSConfig(ctx context.Context, profile string) (aws.Config, error) {
	cleanup := sanitizeAWSAuthEnv()
	defer cleanup()

	trimmed := strings.TrimSpace(profile)
	loadOptions := make([]func(*config.LoadOptions) error, 0, 5)

	if trimmed != "" {
		loadOptions = append(loadOptions, config.WithSharedConfigProfile(trimmed))
	}

	configFile := strings.TrimSpace(syncAWSConfigFile)
	if configFile != "" {
		if err := validateReadableFile(configFile, "--aws-config-file"); err != nil {
			return aws.Config{}, err
		}
		loadOptions = append(loadOptions, config.WithSharedConfigFiles([]string{configFile}))
	}

	credentialsFile := strings.TrimSpace(syncAWSSharedCredsFile)
	if credentialsFile != "" {
		if err := validateReadableFile(credentialsFile, "--aws-shared-credentials-file"); err != nil {
			return aws.Config{}, err
		}
		loadOptions = append(loadOptions, config.WithSharedCredentialsFiles([]string{credentialsFile}))
	}

	credentialProcess := strings.TrimSpace(syncAWSCredentialProc)
	if credentialProcess != "" {
		if err := validateAWSCredentialProcess(credentialProcess, "--aws-credential-process"); err != nil {
			return aws.Config{}, err
		}
		loadOptions = append(loadOptions, config.WithCredentialsProvider(aws.NewCredentialsCache(processcreds.NewProvider(credentialProcess))))
	}

	return config.LoadDefaultConfig(ctx, loadOptions...)
}

func sanitizeAWSAuthEnv() func() {
	envSnapshots := make(map[string]envSnapshot)

	keys := []string{
		"AWS_ACCESS_KEY_ID",
		"AWS_SECRET_ACCESS_KEY",
		"AWS_SESSION_TOKEN",
		"AWS_PROFILE",
		"AWS_ROLE_ARN",
		"AWS_WEB_IDENTITY_TOKEN_FILE",
		"AWS_CONFIG_FILE",
		"AWS_SHARED_CREDENTIALS_FILE",
	}

	removed := 0
	for _, key := range keys {
		value, present := os.LookupEnv(key)
		if !present {
			continue
		}

		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}

		if !shouldSanitizeAWSEnvValue(key, trimmed) {
			continue
		}

		envSnapshots[key] = envSnapshot{value: value, present: true}
		_ = os.Unsetenv(key)
		removed++
	}

	if removed > 0 {
		Warning("Ignoring %d placeholder/invalid AWS auth env var(s) during config load", removed)
	}

	return func() {
		restoreEnvSnapshot(envSnapshots)
	}
}

func shouldSanitizeAWSEnvValue(key, value string) bool {
	if looksLikePlaceholderValue(value) {
		return true
	}

	switch key {
	case "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE", "AWS_WEB_IDENTITY_TOKEN_FILE":
		if _, err := os.Stat(value); err != nil {
			return true
		}
	}

	return false
}

func looksLikePlaceholderValue(value string) bool {
	normalized := strings.ToUpper(strings.TrimSpace(value))
	if normalized == "" {
		return false
	}

	return strings.Contains(normalized, "PLACEHOLDER") ||
		strings.Contains(normalized, "REPLACE_ME") ||
		strings.Contains(normalized, "CHANGE_ME") ||
		strings.Contains(normalized, "CHANGEME")
}

type envSnapshot struct {
	value   string
	present bool
}

func applyAWSAuthOverrides() (func(), error) {
	envSnapshots := make(map[string]envSnapshot)
	cleanup := func() {
		restoreEnvSnapshot(envSnapshots)
	}

	if profile := strings.TrimSpace(syncAWSProfile); profile != "" {
		if err := setEnvWithSnapshot(envSnapshots, "AWS_PROFILE", profile); err != nil {
			return cleanup, fmt.Errorf("set AWS_PROFILE: %w", err)
		}
	}

	webIdentityToken := strings.TrimSpace(syncAWSWebIDTokenFile)
	webIdentityRole := strings.TrimSpace(syncAWSWebIDRoleARN)
	if webIdentityToken == "" && webIdentityRole == "" {
		return cleanup, nil
	}
	if webIdentityToken == "" || webIdentityRole == "" {
		return cleanup, fmt.Errorf("--aws-web-identity-token-file and --aws-web-identity-role-arn must be set together")
	}
	if err := validateReadableFile(webIdentityToken, "--aws-web-identity-token-file"); err != nil {
		return cleanup, err
	}

	if err := setEnvWithSnapshot(envSnapshots, "AWS_WEB_IDENTITY_TOKEN_FILE", webIdentityToken); err != nil {
		return cleanup, fmt.Errorf("set AWS_WEB_IDENTITY_TOKEN_FILE: %w", err)
	}
	if err := setEnvWithSnapshot(envSnapshots, "AWS_ROLE_ARN", webIdentityRole); err != nil {
		return cleanup, fmt.Errorf("set AWS_ROLE_ARN: %w", err)
	}

	roleSession := strings.TrimSpace(syncAWSRoleSession)
	if roleSession != "" {
		if err := setEnvWithSnapshot(envSnapshots, "AWS_ROLE_SESSION_NAME", roleSession); err != nil {
			return cleanup, fmt.Errorf("set AWS_ROLE_SESSION_NAME: %w", err)
		}
	}

	return cleanup, nil
}

func applyAWSAssumeRoleOverride(ctx context.Context, cfg aws.Config) (aws.Config, error) {
	roleARN := strings.TrimSpace(syncAWSRoleARN)
	sourceIdentity := strings.TrimSpace(syncAWSRoleSourceID)
	durationRaw := strings.TrimSpace(syncAWSRoleDuration)
	roleTags := parseCommaSeparatedValues(syncAWSRoleTags)
	transitiveTagKeys := parseCommaSeparatedValues(syncAWSRoleTransitive)
	if roleARN == "" {
		if durationRaw != "" || len(roleTags) > 0 || len(transitiveTagKeys) > 0 || sourceIdentity != "" {
			return cfg, fmt.Errorf("--aws-role-duration-seconds/--aws-role-session-tags/--aws-role-transitive-tag-keys/--aws-role-source-identity require --aws-role-arn")
		}
		return cfg, nil
	}

	mfaSerial := strings.TrimSpace(syncAWSRoleMFASerial)
	mfaToken := strings.TrimSpace(syncAWSRoleMFAToken)
	if mfaToken != "" && mfaSerial == "" {
		return cfg, fmt.Errorf("--aws-role-mfa-token requires --aws-role-mfa-serial")
	}

	durationSeconds, err := parseBoundedPositiveIntDirective(syncAWSRoleDuration, "--aws-role-duration-seconds", 900, 43200)
	if err != nil {
		return cfg, err
	}

	tags, transitiveTagKeys, err := parseAWSSessionTagDirectives(roleTags, transitiveTagKeys)
	if err != nil {
		return cfg, err
	}

	assumedCfg, err := assumeRoleConfigWithScheduledOptions(
		ctx,
		cfg,
		roleARN,
		strings.TrimSpace(syncAWSRoleSession),
		strings.TrimSpace(syncAWSRoleExternalID),
		mfaSerial,
		mfaToken,
		sourceIdentity,
		durationSeconds,
		tags,
		transitiveTagKeys,
	)
	if err != nil {
		return cfg, fmt.Errorf("assume AWS role %q: %w", roleARN, err)
	}

	return assumedCfg, nil
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
		if err := validateReadableFile(credentialsFile, "--gcp-credentials-file"); err != nil {
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

	sourceData, err := os.ReadFile(sourcePath)
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

func setEnvWithSnapshot(snapshots map[string]envSnapshot, key, value string) error {
	if _, ok := snapshots[key]; !ok {
		previous, present := os.LookupEnv(key)
		snapshots[key] = envSnapshot{value: previous, present: present}
	}
	return os.Setenv(key, value)
}

func restoreEnvSnapshot(snapshots map[string]envSnapshot) {
	for key, snapshot := range snapshots {
		if snapshot.present {
			_ = os.Setenv(key, snapshot.value)
			continue
		}
		_ = os.Unsetenv(key)
	}
}

func validateReadableFile(path, source string) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("%s must not be empty", source)
	}

	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("read %s %q: %w", source, path, err)
	}
	if info.IsDir() {
		return fmt.Errorf("%s must point to a file: %q", source, path)
	}

	return nil
}

func validateAWSCredentialProcess(command, source string) error {
	trimmed := strings.TrimSpace(command)
	if trimmed == "" {
		return fmt.Errorf("%s must not be empty", source)
	}

	if strings.ContainsAny(trimmed, "\n\r|&;<>`") {
		return fmt.Errorf("%s contains disallowed shell operators", source)
	}

	executable := firstCommandToken(trimmed)
	if executable == "" {
		return fmt.Errorf("%s must include an executable path", source)
	}
	if !filepath.IsAbs(executable) {
		return fmt.Errorf("%s must use an absolute executable path", source)
	}
	if err := validateReadableFile(executable, fmt.Sprintf("%s executable", source)); err != nil {
		return err
	}

	allowlist := parseCommaSeparatedValues(firstNonEmptyEnv("CEREBRO_AWS_CREDENTIAL_PROCESS_ALLOWLIST", "AWS_CREDENTIAL_PROCESS_ALLOWLIST"))
	if len(allowlist) == 0 {
		return nil
	}

	normalizedExecutable := filepath.Clean(executable)
	for _, rawAllowed := range allowlist {
		allowed := filepath.Clean(strings.TrimSpace(rawAllowed))
		if allowed == "" {
			continue
		}
		if normalizedExecutable == allowed || strings.HasPrefix(normalizedExecutable, allowed+string(os.PathSeparator)) {
			return nil
		}
	}

	return fmt.Errorf("%s executable %q is not permitted by CEREBRO_AWS_CREDENTIAL_PROCESS_ALLOWLIST", source, executable)
}

func firstCommandToken(command string) string {
	trimmed := strings.TrimSpace(command)
	if trimmed == "" {
		return ""
	}

	if trimmed[0] == '\'' || trimmed[0] == '"' {
		quote := trimmed[0]
		for i := 1; i < len(trimmed); i++ {
			if trimmed[i] == quote {
				return strings.TrimSpace(trimmed[1:i])
			}
		}
		return ""
	}

	parts := strings.Fields(trimmed)
	if len(parts) == 0 {
		return ""
	}
	return strings.TrimSpace(parts[0])
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

func parseTableFilter(value string) []string {
	values := parseCommaSeparatedValues(value)
	if len(values) == 0 {
		return nil
	}

	return values
}

func parseCommaSeparatedValues(value string) []string {
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
	if len(filtered) == 0 {
		return nil
	}

	return filtered
}

func normalizeProjectIDs(values []string) []string {
	if len(values) == 0 {
		return nil
	}

	normalized := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		key := strings.ToLower(trimmed)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		normalized = append(normalized, trimmed)
	}
	if len(normalized) == 0 {
		return nil
	}

	return normalized
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

func resolveGCPTableFilters(tableFilter []string, securityEnabled bool) (native, security []string, runNative, runSecurity bool, err error) {
	native, security = splitGCPScheduledTableFilters(tableFilter)
	runNative = len(tableFilter) == 0 || len(native) > 0
	runSecurity = securityEnabled && (len(tableFilter) == 0 || len(security) > 0)

	if len(tableFilter) > 0 && len(native) == 0 && !securityEnabled {
		err = fmt.Errorf("--table filter targets only GCP security tables; rerun with --security")
	}

	return native, security, runNative, runSecurity, err
}

func filterAvailableTables(tables, available []string) ([]string, int) {
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

func printSyncResults(results []nativesync.SyncResult, start time.Time, provider string) error {
	if syncOutput == FormatJSON {
		summary := buildSyncSummary(results, start, provider)
		return JSONOutput(summary)
	}

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

		name := r.Table
		if r.Region != "" {
			name = fmt.Sprintf("%s (%s)", r.Table, r.Region)
		}
		errorInfo := fmt.Sprintf(", errors=%d", r.Errors)
		fmt.Printf("  %s %-30s %4d resources (%s%s)%s\n", status, name, r.Synced, r.Duration.Round(time.Millisecond), errorInfo, changeInfo)
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

	return nil
}

type syncSummary struct {
	Provider      string             `json:"provider"`
	StartedAt     time.Time          `json:"started_at"`
	Duration      string             `json:"duration"`
	TotalSynced   int                `json:"total_synced"`
	TotalErrors   int                `json:"total_errors"`
	TotalAdded    int                `json:"total_added"`
	TotalModified int                `json:"total_modified"`
	TotalRemoved  int                `json:"total_removed"`
	Results       []syncTableSummary `json:"results"`
}

type syncTableSummary struct {
	Table    string           `json:"table"`
	Region   string           `json:"region,omitempty"`
	Synced   int              `json:"synced"`
	Errors   int              `json:"errors"`
	Error    string           `json:"error,omitempty"`
	Duration string           `json:"duration"`
	Changes  *syncChangeStats `json:"changes,omitempty"`
}

type syncChangeStats struct {
	Added    int `json:"added"`
	Modified int `json:"modified"`
	Removed  int `json:"removed"`
}

func buildSyncSummary(results []nativesync.SyncResult, start time.Time, provider string) syncSummary {
	summary := syncSummary{
		Provider:  provider,
		StartedAt: start,
		Duration:  time.Since(start).String(),
	}

	for _, r := range results {
		row := syncTableSummary{
			Table:    r.Table,
			Region:   r.Region,
			Synced:   r.Synced,
			Errors:   r.Errors,
			Error:    r.Error,
			Duration: r.Duration.String(),
		}
		if r.Changes != nil {
			row.Changes = &syncChangeStats{
				Added:    len(r.Changes.Added),
				Modified: len(r.Changes.Modified),
				Removed:  len(r.Changes.Removed),
			}
			summary.TotalAdded += row.Changes.Added
			summary.TotalModified += row.Changes.Modified
			summary.TotalRemoved += row.Changes.Removed
		}

		summary.Results = append(summary.Results, row)
		summary.TotalSynced += r.Synced
		summary.TotalErrors += r.Errors
	}

	return summary
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
	filterSet := buildTableFilterSet(tableFilter)

	application, err := app.New(ctx)
	if err != nil {
		return fmt.Errorf("failed to initialize app: %w", err)
	}
	defer func() { _ = application.Close() }()

	if application.Snowflake == nil {
		return fmt.Errorf("snowflake not configured: set SNOWFLAKE_PRIVATE_KEY/ACCOUNT/USER or SNOWFLAKE_CONNECTION_STRING")
	}

	availableTables := application.AvailableTables
	if application.Snowflake != nil {
		if refreshed, err := application.Snowflake.ListAvailableTables(ctx); err == nil {
			application.AvailableTables = refreshed
			availableTables = refreshed
		} else {
			Warning("Failed to list available tables: %v", err)
		}
	}

	tables := scannableTablesFromAvailable(availableTables)
	if len(tables) == 0 {
		tables = nativesync.SupportedTableNames()
	}
	if len(filterSet) > 0 {
		filtered := make([]string, 0, len(tables))
		for _, table := range tables {
			if tableFilterMatches(filterSet, table) {
				filtered = append(filtered, table)
			}
		}
		if len(filtered) == 0 {
			fmt.Println("Scanning synced assets...")
			fmt.Printf("Filtering scan tables: %s\n", strings.Join(tableFilter, ", "))
			fmt.Println("No tables to scan for selected filter")
			return nil
		}
		tables = filtered
	}

	tables, skipped := filterAvailableTables(tables, availableTables)
	if skipped > 0 {
		Info("Skipped %d tables not present in Snowflake", skipped)
	}

	fmt.Println("Scanning synced assets...")
	if len(filterSet) > 0 {
		fmt.Printf("Filtering scan tables: %s\n", strings.Join(tableFilter, ", "))
	}

	if len(tables) == 0 {
		fmt.Println("No tables to scan")
		return nil
	}

	policies := application.Policy.ListPolicies()
	fmt.Printf("Scanning %d tables with %d policies\n", len(tables), len(policies))

	tuning := application.ScanTuning()
	var tableProfiles []scanner.TableScanProfile
	var totalScanned int64
	var totalViolations int64
	const batchSize = 1000

	for _, table := range tables {
		tableProfile := scanner.TableScanProfile{Table: table}
		tableStart := time.Now()
		tableCtx := ctx
		cancel := func() {}
		if tuning.TableTimeout > 0 {
			tableCtx, cancel = context.WithTimeout(ctx, tuning.TableTimeout)
		}

		columns := application.ScanColumnsForTable(tableCtx, table)
		filter := snowflake.AssetFilter{Limit: batchSize, Columns: columns}
		var cursorTime time.Time
		var cursorID string
		useCursorPaging := false

		// Use watermarks for incremental scanning if available
		if application.ScanWatermarks != nil {
			if wm := application.ScanWatermarks.GetWatermark(table); wm != nil {
				filter.Since = wm.LastScanTime
				filter.SinceID = wm.LastScanID
				fmt.Printf("  %s: incremental scan (since %s)\n", table, wm.LastScanTime.Format(time.RFC3339))
				useCursorPaging = true
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
				return application.Snowflake.GetAssets(tableCtx, table, filter)
			})
			tableProfile.RetryAttempts += retryCount(attempts)
			if err != nil {
				tableProfile.FetchErrors++
				Warning("Failed to fetch %s: %v", table, err)
				break
			}

			if len(assets) == 0 {
				break
			}

			result := application.Scanner.ScanAssets(tableCtx, assets)
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
				application.Findings.Upsert(tableCtx, f)
			}

			if len(assets) < batchSize {
				break
			}
		}

		if errors.Is(tableCtx.Err(), context.DeadlineExceeded) {
			tableProfile.TimedOut = true
			Warning("Table %s timed out after %s", table, tuning.TableTimeout)
		}
		tableProfile.Scanned = tableScanned
		tableProfile.Violations = tableViolations
		tableProfile.Duration = time.Since(tableStart)
		cancel()
		tableProfiles = append(tableProfiles, tableProfile)

		// Update watermark
		if application.ScanWatermarks != nil && tableScanned > 0 {
			if cursorTime.IsZero() {
				cursorTime = time.Now().UTC()
			}
			application.ScanWatermarks.SetWatermark(table, cursorTime, cursorID, tableScanned)
		}

		if tableScanned > 0 {
			fmt.Printf("  %s: scanned %d assets\n", table, tableScanned)
		}
	}

	queryPolicyResult := application.ScanQueryPolicies(ctx)
	queryPolicyFindingCount := len(queryPolicyResult.Findings)
	queryPolicyErrorCount := len(queryPolicyResult.Errors)
	for _, errMsg := range queryPolicyResult.Errors {
		Warning("Query policy execution failed: %s", errMsg)
	}
	for _, f := range queryPolicyResult.Findings {
		application.Findings.Upsert(ctx, f)
	}
	if queryPolicyFindingCount > 0 {
		totalViolations += int64(queryPolicyFindingCount)
		fmt.Printf("Query-policy findings: %d\n", queryPolicyFindingCount)
	}
	if queryPolicyErrorCount > 0 {
		fmt.Printf("Query-policy errors: %d\n", queryPolicyErrorCount)
	}

	printScanProfiling(tableProfiles, tuning.ProfileSlowThreshold)

	sqlToxicRiskSets := make(map[string][]map[string]bool)
	relationshipCount := 0
	if application.Snowflake != nil {
		toxicFindings, err := scanner.DetectRelationshipToxicCombinations(ctx, application.Snowflake)
		if err != nil {
			Warning("Failed to detect toxic combinations from relationships: %v", err)
		} else {
			relationshipCount = len(toxicFindings)
			for _, f := range toxicFindings {
				if rid := scanner.NormalizeResourceID(f.ResourceID); rid != "" {
					if risks := scanner.CanonicalizeRiskCategories(scanner.ParseRiskCategories(f.Risks)); len(risks) > 0 {
						sqlToxicRiskSets[rid] = append(sqlToxicRiskSets[rid], risks)
					}
				}
				if application.Findings != nil && f.PolicyID != "" && f.ResourceID != "" {
					application.Findings.Upsert(ctx, f.ToPolicyFinding())
				}
			}
			totalViolations += int64(relationshipCount)
		}
	}

	graphToxicCount := 0
	graphPaths := 0
	if application.SecurityGraph != nil {
		graphCtx := ctx
		cancel := func() {}
		if tuning.GraphWaitTimeout > 0 {
			graphCtx, cancel = context.WithTimeout(ctx, tuning.GraphWaitTimeout)
		}
		graphReady := application.WaitForGraph(graphCtx)
		cancel()
		if graphReady {
			graphResult := application.Scanner.AnalyzeGraph(ctx, application.SecurityGraph)
			if graphResult != nil {
				graphPaths = graphResult.AttackPathStats.TotalPaths
				for _, f := range graphResult.ToxicCombinations {
					resourceID := scanner.NormalizeResourceID(f.ResourceID)
					graphRiskSet := scanner.CanonicalizeRiskCategories(f.RiskCategories)
					if scanner.ShouldSkipGraphToxicCombination(resourceID, graphRiskSet, sqlToxicRiskSets) {
						continue
					}
					application.Findings.Upsert(ctx, f)
					graphToxicCount++
				}
			}
		}
	}
	if graphToxicCount > 0 {
		totalViolations += int64(graphToxicCount)
	}
	if relationshipCount > 0 || graphToxicCount > 0 {
		fmt.Printf("Toxic combinations: %d (relationship), %d (graph), attack paths: %d\n", relationshipCount, graphToxicCount, graphPaths)
	}

	// Persist watermarks
	if application.ScanWatermarks != nil {
		if err := application.ScanWatermarks.PersistWatermarksWithRetry(ctx, scanner.DefaultWatermarkPersistOptions()); err != nil {
			Warning("Failed to persist scan watermarks: %v", err)
		}
	}

	// Sync findings to persistent storage
	if err := application.Findings.Sync(ctx); err != nil {
		Warning("Failed to sync findings: %v", err)
	}

	fmt.Printf("\nPost-sync scan complete: %d assets scanned, %d violations found\n", totalScanned, totalViolations)
	return nil
}
