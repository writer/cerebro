package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/api/option"

	"github.com/writer/cerebro/internal/app"
	apiclient "github.com/writer/cerebro/internal/client"
	"github.com/writer/cerebro/internal/scanner"
	"github.com/writer/cerebro/internal/snowflake"
	nativesync "github.com/writer/cerebro/internal/sync"
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
	syncPreflightOnly      bool
	syncStrictExit         bool
	syncGCP                bool
	syncGCPProject         string
	syncGCPProjects        string // comma-separated list of projects
	syncScope              string
	syncProjectsFile       string
	syncProjectInclude     string
	syncProjectExclude     string
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
	syncReportFile         string
	syncValidate           bool
	syncAuthMode           string
	syncShowAuthChain      bool
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

const (
	syncAuthModeAuto          = "auto"
	syncAuthModeCredentials   = "credentials"
	syncAuthModeImpersonation = "impersonation"
	syncAuthModeWIF           = "wif"
	syncAuthModeADC           = "adc"
)

func init() {
	syncCmd.Flags().BoolVar(&syncScanAfter, "scan-after", false, "Run policy scan after successful sync")
	syncCmd.Flags().BoolVar(&syncPreflightOnly, "preflight-only", false, "Run auth and API access checks without writing sync data")
	syncCmd.Flags().BoolVar(&syncStrictExit, "strict-exit", false, "Return non-zero exit if any table reports errors")
	syncCmd.Flags().BoolVar(&syncGCP, "gcp", false, "Sync GCP resources instead of AWS")
	syncCmd.Flags().StringVar(&syncGCPProject, "gcp-project", "", "GCP project ID to sync (required with --gcp unless using --gcp-org)")
	syncCmd.Flags().StringVar(&syncGCPProjects, "gcp-projects", "", "Comma-separated list of GCP project IDs to sync")
	syncCmd.Flags().StringVar(&syncScope, "scope", "", "Provider scope selector: org:<id>, project:<id>, or projects-file:<path> (currently GCP)")
	syncCmd.Flags().StringVar(&syncProjectsFile, "projects-file", "", "Path to newline/comma-delimited project IDs for multi-project GCP sync")
	syncCmd.Flags().StringVar(&syncProjectInclude, "project-include", "", "Comma-separated project IDs to include after scope resolution")
	syncCmd.Flags().StringVar(&syncProjectExclude, "project-exclude", "", "Comma-separated project IDs to exclude after scope resolution")
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
	syncCmd.Flags().StringVar(&syncReportFile, "report-file", "", "Write sync/preflight JSON summary to a file path")
	syncCmd.Flags().BoolVar(&syncValidate, "validate", false, "Validate Snowflake tables without fetching resources")
	syncCmd.Flags().StringVar(&syncAuthMode, "auth-mode", "auto", "Auth mode: auto, credentials, impersonation, wif, adc")
	syncCmd.Flags().BoolVar(&syncShowAuthChain, "show-auth-chain", false, "Print resolved authentication chain before execution")
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

	if err := validateSyncOutputFormat(); err != nil {
		return err
	}

	if err := applySyncScopeDirectives(); err != nil {
		return err
	}

	// Kubernetes sync
	if syncK8s {
		if syncPreflightOnly {
			return fmt.Errorf("--preflight-only is currently supported for AWS and GCP sync")
		}
		return runK8sSync(ctx, start)
	}

	// Azure sync
	if syncAzure {
		if syncPreflightOnly {
			return fmt.Errorf("--preflight-only is currently supported for AWS and GCP sync")
		}
		return runAzureSync(ctx, start)
	}

	// GCP sync
	if syncGCP {
		if err := validateSyncAuthMode("gcp"); err != nil {
			return err
		}

		if syncShowAuthChain {
			Info("GCP auth chain: %s", describeCurrentGCPAuthChain())
		}

		if syncPreflightOnly {
			return runGCPPreflightOnly(ctx, start)
		}

		cleanup, err := applyGCPAuthOverrides()
		if err != nil {
			return err
		}
		defer cleanup()

		// Handle multi-project sync via organization
		if syncGCPOrg != "" {
			return runGCPOrgSync(ctx, start, syncGCPOrg)
		}

		projects, err := resolveExplicitGCPProjects()
		if err != nil {
			return err
		}
		if len(projects) > 0 {
			if len(projects) == 1 && !syncUseAssetAPI {
				return runGCPSync(ctx, start, projects[0])
			}
			if syncUseAssetAPI {
				return runGCPAssetAPISync(ctx, start, projects)
			}
			return runGCPMultiProjectSync(ctx, start, projects)
		}

		// Handle multi-project sync via explicit list
		// Handle single project sync
		projectID := strings.TrimSpace(syncGCPProject)
		if projectID == "" {
			return fmt.Errorf("--gcp-project, --gcp-projects, --projects-file, --scope, or --gcp-org is required with --gcp")
		}
		filteredProject := applyProjectFilters([]string{projectID}, parseCommaSeparatedValues(syncProjectInclude), parseCommaSeparatedValues(syncProjectExclude))
		if len(filteredProject) == 0 {
			return fmt.Errorf("selected project %q was filtered out by --project-include/--project-exclude", projectID)
		}
		projectID = filteredProject[0]
		if syncUseAssetAPI {
			return runGCPAssetAPISync(ctx, start, []string{projectID})
		}
		return runGCPSync(ctx, start, projectID)
	}

	if err := validateSyncAuthMode("aws"); err != nil {
		return err
	}

	if syncShowAuthChain {
		Info("AWS auth chain: %s", describeCurrentAWSAuthChain())
	}

	if syncPreflightOnly {
		return runAWSPreflightOnly(ctx, start)
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

func validateSyncOutputFormat() error {
	format := strings.ToLower(strings.TrimSpace(syncOutput))
	if format == "" {
		format = FormatTable
	}
	if format != FormatTable && format != FormatJSON {
		return fmt.Errorf("--output must be one of: %s, %s", FormatTable, FormatJSON)
	}
	syncOutput = format
	return nil
}

func applySyncScopeDirectives() error {
	if !syncGCP {
		if strings.TrimSpace(syncScope) != "" || strings.TrimSpace(syncProjectsFile) != "" || strings.TrimSpace(syncProjectInclude) != "" || strings.TrimSpace(syncProjectExclude) != "" {
			return fmt.Errorf("--scope/--projects-file/--project-include/--project-exclude are currently supported only with --gcp")
		}
		return nil
	}

	scope := strings.TrimSpace(syncScope)
	projectsFile := strings.TrimSpace(syncProjectsFile)
	if scope == "" {
		if projectsFile != "" && strings.TrimSpace(syncGCPOrg) != "" {
			return fmt.Errorf("--projects-file cannot be combined with --gcp-org")
		}
		if projectsFile != "" && strings.TrimSpace(syncGCPProject) != "" {
			return fmt.Errorf("--projects-file cannot be combined with --gcp-project")
		}
		return nil
	}

	if strings.TrimSpace(syncGCPProject) != "" || strings.TrimSpace(syncGCPProjects) != "" || strings.TrimSpace(syncGCPOrg) != "" || projectsFile != "" {
		return fmt.Errorf("--scope cannot be combined with --gcp-project, --gcp-projects, --gcp-org, or --projects-file")
	}

	lowerScope := strings.ToLower(scope)
	switch {
	case strings.HasPrefix(lowerScope, "org:"):
		value := strings.TrimSpace(scope[len("org:"):])
		if value == "" {
			return fmt.Errorf("--scope org:<id> requires an organization ID")
		}
		syncGCPOrg = value
	case strings.HasPrefix(lowerScope, "project:"):
		value := strings.TrimSpace(scope[len("project:"):])
		if value == "" {
			return fmt.Errorf("--scope project:<id> requires a project ID")
		}
		syncGCPProject = value
	case strings.HasPrefix(lowerScope, "projects-file:"):
		value := strings.TrimSpace(scope[len("projects-file:"):])
		if value == "" {
			return fmt.Errorf("--scope projects-file:<path> requires a file path")
		}
		syncProjectsFile = value
	default:
		return fmt.Errorf("--scope must use org:<id>, project:<id>, or projects-file:<path>")
	}

	return nil
}

func resolveExplicitGCPProjects() ([]string, error) {
	projects := normalizeProjectIDs(parseCommaSeparatedValues(syncGCPProjects))
	if path := strings.TrimSpace(syncProjectsFile); path != "" {
		fileProjects, err := loadProjectIDsFromFile(path)
		if err != nil {
			return nil, err
		}
		projects = append(projects, fileProjects...)
	}

	projects = normalizeProjectIDs(projects)
	projects = applyProjectFilters(projects, parseCommaSeparatedValues(syncProjectInclude), parseCommaSeparatedValues(syncProjectExclude))

	if (strings.TrimSpace(syncGCPProjects) != "" || strings.TrimSpace(syncProjectsFile) != "") && len(projects) == 0 {
		return nil, fmt.Errorf("--gcp-projects/--projects-file did not include any valid projects after filters")
	}

	return projects, nil
}

func loadProjectIDsFromFile(path string) ([]string, error) {
	trimmedPath := strings.TrimSpace(path)
	if trimmedPath == "" {
		return nil, nil
	}
	if err := validateReadableFile(trimmedPath, "--projects-file"); err != nil {
		return nil, err
	}

	file, err := os.Open(trimmedPath) // #nosec G304,G703 -- path is validated by validateReadableFile
	if err != nil {
		return nil, fmt.Errorf("read --projects-file %q: %w", trimmedPath, err)
	}
	defer func() { _ = file.Close() }()

	var projects []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = line[:idx]
		}
		parts := parseCommaSeparatedValues(line)
		if len(parts) == 0 {
			continue
		}
		projects = append(projects, parts...)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan --projects-file %q: %w", trimmedPath, err)
	}

	return normalizeProjectIDs(projects), nil
}

func applyProjectFilters(projects, include, exclude []string) []string {
	projects = normalizeProjectIDs(projects)
	if len(projects) == 0 {
		return nil
	}

	includeSet := buildLowerStringSet(include)
	excludeSet := buildLowerStringSet(exclude)
	filtered := make([]string, 0, len(projects))
	for _, project := range projects {
		key := strings.ToLower(strings.TrimSpace(project))
		if key == "" {
			continue
		}
		if len(includeSet) > 0 {
			if _, ok := includeSet[key]; !ok {
				continue
			}
		}
		if _, blocked := excludeSet[key]; blocked {
			continue
		}
		filtered = append(filtered, project)
	}

	return filtered
}

func buildLowerStringSet(values []string) map[string]struct{} {
	if len(values) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		trimmed := strings.ToLower(strings.TrimSpace(value))
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

func validateSyncAuthMode(provider string) error {
	mode := strings.ToLower(strings.TrimSpace(syncAuthMode))
	if mode == "" {
		mode = syncAuthModeAuto
	}
	if mode != syncAuthModeAuto && mode != syncAuthModeCredentials && mode != syncAuthModeImpersonation && mode != syncAuthModeWIF && mode != syncAuthModeADC {
		return fmt.Errorf("--auth-mode must be one of: %s, %s, %s, %s, %s", syncAuthModeAuto, syncAuthModeCredentials, syncAuthModeImpersonation, syncAuthModeWIF, syncAuthModeADC)
	}
	syncAuthMode = mode

	if provider == "gcp" {
		return validateGCPSyncAuthMode(mode)
	}
	return validateAWSSyncAuthMode(mode)
}

func validateGCPSyncAuthMode(mode string) error {
	sourcePath := strings.TrimSpace(syncGCPCredentialsFile)
	impersonationTarget := strings.TrimSpace(syncGCPImpersonateSA)

	switch mode {
	case syncAuthModeAuto:
		return nil
	case syncAuthModeADC:
		if sourcePath != "" || impersonationTarget != "" {
			return fmt.Errorf("--auth-mode=adc cannot be combined with --gcp-credentials-file or --gcp-impersonate-service-account")
		}
		return nil
	case syncAuthModeCredentials:
		if sourcePath == "" {
			return fmt.Errorf("--auth-mode=credentials requires --gcp-credentials-file")
		}
		if impersonationTarget != "" {
			return fmt.Errorf("--auth-mode=credentials cannot be combined with --gcp-impersonate-service-account")
		}
		return nil
	case syncAuthModeImpersonation:
		if impersonationTarget == "" {
			return fmt.Errorf("--auth-mode=impersonation requires --gcp-impersonate-service-account")
		}
		return nil
	case syncAuthModeWIF:
		resolvedPath, err := resolveGCPSourceCredentialsPath(sourcePath)
		if err != nil {
			return fmt.Errorf("--auth-mode=wif requires a resolvable external account credentials file: %w", err)
		}
		raw, err := os.ReadFile(resolvedPath) // #nosec G304,G703 -- resolved path is validated before read
		if err != nil {
			return fmt.Errorf("read GCP credentials file %q: %w", resolvedPath, err)
		}
		credType, err := detectGCPCredentialsType(raw, resolvedPath)
		if err != nil {
			return fmt.Errorf("detect GCP credentials type for %q: %w", resolvedPath, err)
		}
		if credType != option.ExternalAccount {
			return fmt.Errorf("--auth-mode=wif requires external-account credentials (got %q from %s)", credType, resolvedPath)
		}
		return nil
	default:
		return nil
	}
}

func validateAWSSyncAuthMode(mode string) error {
	switch mode {
	case syncAuthModeAuto:
		return nil
	case syncAuthModeADC:
		return fmt.Errorf("--auth-mode=adc is only supported with --gcp")
	case syncAuthModeCredentials:
		if strings.TrimSpace(syncAWSProfile) == "" && strings.TrimSpace(syncAWSProfiles) == "" && strings.TrimSpace(syncAWSConfigFile) == "" && strings.TrimSpace(syncAWSSharedCredsFile) == "" && strings.TrimSpace(syncAWSCredentialProc) == "" {
			return fmt.Errorf("--auth-mode=credentials requires at least one explicit AWS credential source flag")
		}
		return nil
	case syncAuthModeImpersonation:
		if strings.TrimSpace(syncAWSRoleARN) == "" && !syncAWSOrg {
			return fmt.Errorf("--auth-mode=impersonation requires --aws-role-arn or --aws-org")
		}
		return nil
	case syncAuthModeWIF:
		if strings.TrimSpace(syncAWSWebIDTokenFile) == "" || strings.TrimSpace(syncAWSWebIDRoleARN) == "" {
			return fmt.Errorf("--auth-mode=wif requires both --aws-web-identity-token-file and --aws-web-identity-role-arn")
		}
		return nil
	default:
		return nil
	}
}

func describeCurrentGCPAuthChain() string {
	if target := strings.TrimSpace(syncGCPImpersonateSA); target != "" {
		source := "default-application-credentials"
		if path, err := resolveGCPSourceCredentialsPath(syncGCPCredentialsFile); err == nil {
			source = describeGCPCredentialsPath(path)
		}
		delegates := parseCommaSeparatedValues(syncGCPImpersonateDel)
		return fmt.Sprintf("impersonation: source=%s target=%s delegates=%d", source, target, len(delegates))
	}

	if path := strings.TrimSpace(syncGCPCredentialsFile); path != "" {
		return fmt.Sprintf("credentials_file: %s", describeGCPCredentialsPath(path))
	}

	if path := strings.TrimSpace(os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")); path != "" {
		return fmt.Sprintf("adc_env: %s", describeGCPCredentialsPath(path))
	}

	return "adc_default_chain"
}

func describeGCPCredentialsPath(path string) string {
	trimmedPath := strings.TrimSpace(path)
	if trimmedPath == "" {
		return "<unset>"
	}
	raw, err := os.ReadFile(trimmedPath) // #nosec G304,G703 -- path is from explicit credentials config/ADC locations
	if err != nil {
		return trimmedPath
	}
	credType, err := detectGCPCredentialsType(raw, trimmedPath)
	if err != nil {
		return trimmedPath
	}
	return fmt.Sprintf("%s (%s)", trimmedPath, credType)
}

func describeCurrentAWSAuthChain() string {
	if role := strings.TrimSpace(syncAWSWebIDRoleARN); role != "" {
		return fmt.Sprintf("web_identity: role=%s token_file=%s", role, strings.TrimSpace(syncAWSWebIDTokenFile))
	}

	if role := strings.TrimSpace(syncAWSRoleARN); role != "" {
		base := "default"
		if profile := strings.TrimSpace(syncAWSProfile); profile != "" {
			base = fmt.Sprintf("profile:%s", profile)
		}
		if proc := strings.TrimSpace(syncAWSCredentialProc); proc != "" {
			base = fmt.Sprintf("credential_process:%s", strings.Fields(proc)[0])
		}
		return fmt.Sprintf("assume_role: base=%s role=%s", base, role)
	}

	if proc := strings.TrimSpace(syncAWSCredentialProc); proc != "" {
		parts := strings.Fields(proc)
		execName := proc
		if len(parts) > 0 {
			execName = parts[0]
		}
		return fmt.Sprintf("credential_process: %s", execName)
	}

	if profile := strings.TrimSpace(syncAWSProfile); profile != "" {
		return fmt.Sprintf("profile: %s", profile)
	}

	if profiles := parseCommaSeparatedValues(syncAWSProfiles); len(profiles) > 0 {
		return fmt.Sprintf("multi_profile: %d profiles", len(profiles))
	}

	return "aws_default_chain"
}

func runBackfillRelationships(cmd *cobra.Command, args []string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	mode, err := loadCLIExecutionMode()
	if err != nil {
		return err
	}

	if mode != cliExecutionModeDirect {
		apiClient, err := newCLIAPIClient()
		if err != nil {
			if mode == cliExecutionModeAPI {
				return err
			}
			Warning("API client configuration invalid; using direct mode: %v", err)
		} else {
			stats, err := apiClient.BackfillRelationshipIDs(ctx, syncBackfillBatchSize)
			if err == nil {
				renderBackfillRelationshipStats(stats)
				return nil
			}
			if mode == cliExecutionModeAPI || !shouldFallbackToDirect(mode, err) {
				return fmt.Errorf("backfill relationship IDs via api failed: %w", err)
			}
			Warning("API unavailable; using direct mode: %v", err)
		}
	}

	return runBackfillRelationshipsDirectFn(cmd, args)
}

var runBackfillRelationshipsDirectFn = runBackfillRelationshipsDirect

func runBackfillRelationshipsDirect(cmd *cobra.Command, args []string) error {
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

	renderBackfillRelationshipStats(&apiclient.RelationshipBackfillStats{
		Scanned: int64(stats.Scanned),
		Updated: int64(stats.Updated),
		Deleted: int64(stats.Deleted),
		Skipped: int64(stats.Skipped),
	})
	return nil
}

func renderBackfillRelationshipStats(stats *apiclient.RelationshipBackfillStats) {
	if stats == nil {
		stats = &apiclient.RelationshipBackfillStats{}
	}
	Success("Relationship ID backfill complete (scanned %d, updated %d, deleted %d, skipped %d)", stats.Scanned, stats.Updated, stats.Deleted, stats.Skipped)
}

type envSnapshot struct {
	value   string
	present bool
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

	info, err := os.Stat(path) // #nosec G304,G703 -- this helper validates caller-provided file paths before use
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
		return fmt.Errorf("snowflake not configured: set SNOWFLAKE_PRIVATE_KEY, SNOWFLAKE_ACCOUNT, and SNOWFLAKE_USER")
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
		var toxicCursor *scanner.ToxicScanCursor
		if application.ScanWatermarks != nil {
			if wm := application.ScanWatermarks.GetWatermark("_toxic_relationships"); wm != nil {
				toxicCursor = &scanner.ToxicScanCursor{SinceTime: wm.LastScanTime, SinceID: wm.LastScanID}
			}
		}
		toxicResult, err := scanner.DetectRelationshipToxicCombinations(ctx, application.Snowflake, toxicCursor)
		if err != nil {
			Warning("Failed to detect toxic combinations from relationships: %v", err)
		} else {
			relationshipCount = len(toxicResult.Findings)
			for _, f := range toxicResult.Findings {
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
		if err == nil && application.ScanWatermarks != nil && !toxicResult.MaxSyncTime.IsZero() {
			application.ScanWatermarks.SetWatermark("_toxic_relationships", toxicResult.MaxSyncTime, toxicResult.MaxCursorID, int64(relationshipCount))
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
