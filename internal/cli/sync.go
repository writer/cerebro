package cli

import (
	"bufio"
	"context"
	"encoding/json"
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

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/processcreds"
	"github.com/spf13/cobra"
	"google.golang.org/api/option"

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

	// #nosec G304 -- path is from CLI flag and validated before use
	file, err := os.Open(trimmedPath)
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
		// #nosec G304 -- path is resolved from CLI configuration and validated before use
		raw, err := os.ReadFile(resolvedPath)
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
	// #nosec G304 G703 -- path from CLI flag, validated
	raw, err := os.ReadFile(trimmedPath)
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

type syncPreflightCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

type syncPreflightReport struct {
	Mode      string               `json:"mode"`
	Provider  string               `json:"provider"`
	AuthMode  string               `json:"auth_mode"`
	AuthChain string               `json:"auth_chain,omitempty"`
	StartedAt time.Time            `json:"started_at"`
	Duration  string               `json:"duration"`
	Success   bool                 `json:"success"`
	Checks    []syncPreflightCheck `json:"checks"`
}

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

func runAWSPreflightOnly(ctx context.Context, start time.Time) error {
	report := syncPreflightReport{
		Mode:      "preflight",
		Provider:  "aws",
		AuthMode:  syncAuthMode,
		AuthChain: describeCurrentAWSAuthChain(),
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

	profiles := []string{strings.TrimSpace(syncAWSProfile)}
	if syncAWSProfiles != "" {
		profiles = parseCommaSeparatedValues(syncAWSProfiles)
		if len(profiles) == 0 {
			record("profiles", "", fmt.Errorf("--aws-profiles did not include any valid profile names"))
		}
		if strings.TrimSpace(syncAWSProfile) != "" {
			record("profiles", "", fmt.Errorf("--aws-profile cannot be combined with --aws-profiles"))
		}
	}
	if len(profiles) == 0 {
		profiles = []string{""}
	}

	for _, profile := range profiles {
		spec := buildScheduledAWSSpecFromSyncFlags(profile)
		profileLabel := strings.TrimSpace(profile)
		if profileLabel == "" {
			profileLabel = "default"
		}

		awsCfg, err := loadScheduledAWSConfigFn(ctx, spec)
		if err != nil {
			record(fmt.Sprintf("profile.%s.config", profileLabel), "", fmt.Errorf("load config: %w", err))
			continue
		}
		record(fmt.Sprintf("profile.%s.config", profileLabel), "config loaded", nil)

		schedule := &SyncSchedule{Name: fmt.Sprintf("sync-preflight-aws-%s", profileLabel), Provider: "aws"}
		if err := preflightScheduledAWSAuthFn(ctx, schedule, spec, awsCfg); err != nil {
			record(fmt.Sprintf("profile.%s.identity", profileLabel), "", err)
			continue
		}
		record(fmt.Sprintf("profile.%s.identity", profileLabel), "caller identity confirmed", nil)

		if syncAWSOrg {
			includeSet := buildStringSet(parseTableFilter(syncAWSOrgInclude))
			excludeSet := buildStringSet(parseTableFilter(syncAWSOrgExclude))
			orgCfg := awsCfg.Copy()
			if strings.TrimSpace(orgCfg.Region) == "" {
				orgCfg.Region = "us-east-1"
			}
			accounts, err := listAWSOrgAccounts(ctx, orgCfg, includeSet, excludeSet)
			if err != nil {
				record(fmt.Sprintf("profile.%s.organizations", profileLabel), "", fmt.Errorf("list organization accounts: %w", err))
				continue
			}
			if len(accounts) == 0 {
				record(fmt.Sprintf("profile.%s.organizations", profileLabel), "", fmt.Errorf("no AWS organization accounts matched filters"))
				continue
			}
			record(fmt.Sprintf("profile.%s.organizations", profileLabel), fmt.Sprintf("%d organization accounts accessible", len(accounts)), nil)
		}
	}

	report.Checks = checks
	report.Duration = time.Since(start).Round(time.Millisecond).String()
	report.Success = len(errs) == 0
	if err := printSyncPreflightReport(report); err != nil {
		return err
	}
	if len(errs) > 0 {
		return summarizeSyncRunErrors("AWS preflight", errs)
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

func buildScheduledAWSSpecFromSyncFlags(profile string) scheduledSyncSpec {
	resolvedProfile := strings.TrimSpace(profile)
	if resolvedProfile == "" {
		resolvedProfile = strings.TrimSpace(syncAWSProfile)
	}
	return scheduledSyncSpec{
		TableFilter:              parseTableFilter(syncTable),
		AWSProfile:               resolvedProfile,
		AWSConfigFile:            strings.TrimSpace(syncAWSConfigFile),
		AWSSharedCredentialsFile: strings.TrimSpace(syncAWSSharedCredsFile),
		AWSCredentialProcess:     strings.TrimSpace(syncAWSCredentialProc),
		AWSWebIdentityTokenFile:  strings.TrimSpace(syncAWSWebIDTokenFile),
		AWSWebIdentityRoleARN:    strings.TrimSpace(syncAWSWebIDRoleARN),
		AWSRoleARN:               strings.TrimSpace(syncAWSRoleARN),
		AWSRoleSession:           strings.TrimSpace(syncAWSRoleSession),
		AWSRoleExternalID:        strings.TrimSpace(syncAWSRoleExternalID),
		AWSRoleMFASerial:         strings.TrimSpace(syncAWSRoleMFASerial),
		AWSRoleMFAToken:          strings.TrimSpace(syncAWSRoleMFAToken),
		AWSRoleSourceIdentity:    strings.TrimSpace(syncAWSRoleSourceID),
		AWSRoleDurationSeconds:   strings.TrimSpace(syncAWSRoleDuration),
		AWSRoleSessionTags:       parseCommaSeparatedValues(syncAWSRoleTags),
		AWSRoleTransitiveTagKeys: parseCommaSeparatedValues(syncAWSRoleTransitive),
	}
}

func printSyncPreflightReport(report syncPreflightReport) error {
	if err := writeSyncReport(report); err != nil {
		return err
	}

	if syncOutput == FormatJSON {
		return JSONOutput(report)
	}

	fmt.Println()
	fmt.Printf("%s Preflight Results:\n", strings.ToUpper(report.Provider))
	fmt.Println("─────────────────────────────────────────")
	fmt.Printf("  Auth mode:  %s\n", report.AuthMode)
	if strings.TrimSpace(report.AuthChain) != "" {
		fmt.Printf("  Auth chain: %s\n", report.AuthChain)
	}
	fmt.Println()
	for _, check := range report.Checks {
		status := "✓"
		if check.Status != "passed" {
			status = "✗"
		}
		fmt.Printf("  %s %-30s %s\n", status, check.Name, check.Detail)
	}
	fmt.Println("─────────────────────────────────────────")
	fmt.Printf("  Duration: %s\n", report.Duration)
	if report.Success {
		Success("Preflight completed successfully")
	} else {
		Warning("Preflight detected failures")
	}
	return nil
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
	return ApplyGCPAuth(context.Background(), GCPAuthConfigFromFlags())
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

	// #nosec G703 -- path is from CLI flag, validated before use
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
	summary := buildSyncSummary(results, start, provider)
	if err := writeSyncReport(summary); err != nil {
		return err
	}

	if syncOutput == FormatJSON {
		if err := JSONOutput(summary); err != nil {
			return err
		}
		return strictSyncSummaryError(summary)
	}

	fmt.Println()
	fmt.Printf("%s Sync Results:\n", provider)
	fmt.Println("─────────────────────────────────────────")

	for _, r := range results {
		status := "✓"
		if r.Errors > 0 {
			status = "✗"
		}

		changeInfo := ""
		if r.Changes != nil && r.Changes.HasChanges() {
			changeInfo = fmt.Sprintf(" [%s]", r.Changes.Summary())
		}

		name := r.Table
		if r.Region != "" {
			name = fmt.Sprintf("%s (%s)", r.Table, r.Region)
		}
		errorInfo := fmt.Sprintf(", errors=%d", r.Errors)
		fmt.Printf("  %s %-30s %4d resources (%s%s)%s\n", status, name, r.Synced, r.Duration.Round(time.Millisecond), errorInfo, changeInfo)
	}

	fmt.Println("─────────────────────────────────────────")
	fmt.Printf("  Total: %d resources synced in %s\n", summary.TotalSynced, time.Since(start).Round(time.Second))

	if summary.TotalAdded > 0 || summary.TotalModified > 0 || summary.TotalRemoved > 0 {
		fmt.Printf("  Changes: +%d added, ~%d modified, -%d removed\n", summary.TotalAdded, summary.TotalModified, summary.TotalRemoved)
	}

	if summary.TotalErrors > 0 {
		Warning("%d tables had errors", summary.TotalErrors)
	} else {
		Success("Sync completed successfully")
	}

	return strictSyncSummaryError(summary)
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

func strictSyncSummaryError(summary syncSummary) error {
	if !syncStrictExit || summary.TotalErrors == 0 {
		return nil
	}
	return fmt.Errorf("strict-exit enabled: %d table errors reported", summary.TotalErrors)
}

func writeSyncReport(report interface{}) error {
	path := strings.TrimSpace(syncReportFile)
	if path == "" {
		return nil
	}

	payload, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal sync report: %w", err)
	}
	payload = append(payload, '\n')

	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return fmt.Errorf("create report directory %q: %w", dir, err)
		}
	}

	if err := os.WriteFile(path, payload, 0o600); err != nil {
		return fmt.Errorf("write sync report %q: %w", path, err)
	}
	Info("Wrote sync report: %s", path)
	return nil
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
