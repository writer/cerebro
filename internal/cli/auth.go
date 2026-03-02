package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
)

var authCmd = &cobra.Command{
	Use:   "auth",
	Short: "Authentication diagnostics and tooling",
	Long:  "Authentication diagnostics for supported providers.",
}

var authDoctorCmd = &cobra.Command{
	Use:   "doctor [aws|gcp]",
	Short: "Diagnose auth chain and required permissions",
	Long:  "Runs authentication preflight checks and API permission probes for AWS or GCP.",
	Args:  cobra.ExactArgs(1),
	RunE:  runAuthDoctor,
}

var (
	authDoctorOutput string

	authDoctorProject      string
	authDoctorProjects     string
	authDoctorProjectsFile string
	authDoctorOrg          string
	authDoctorSecurity     bool
	authDoctorMaxProjects  int

	authDoctorGCPCredentialsFile string
	authDoctorGCPImpersonateSA   string
	authDoctorGCPImpersonateDel  string
	authDoctorGCPImpersonateTTL  string

	authDoctorAWSProfile         string
	authDoctorAWSConfigFile      string
	authDoctorAWSSharedCredsFile string
	authDoctorAWSCredentialProc  string
	authDoctorAWSWebIDTokenFile  string
	authDoctorAWSWebIDRoleARN    string
	authDoctorAWSRoleARN         string
	authDoctorAWSRoleSession     string
	authDoctorAWSRoleExternalID  string
	authDoctorAWSRoleMFASerial   string
	authDoctorAWSRoleMFAToken    string
	authDoctorAWSRoleSourceID    string
	authDoctorAWSRoleDuration    string
	authDoctorAWSRoleTags        string
	authDoctorAWSRoleTransitive  string
	authDoctorAWSCheckOrg        bool
	authDoctorAWSOrgInclude      string
	authDoctorAWSOrgExclude      string
)

type authDoctorCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
	Hint   string `json:"hint,omitempty"`
}

type authDoctorReport struct {
	Provider  string            `json:"provider"`
	AuthMode  string            `json:"auth_mode"`
	AuthChain string            `json:"auth_chain,omitempty"`
	StartedAt time.Time         `json:"started_at"`
	Duration  string            `json:"duration"`
	Success   bool              `json:"success"`
	Checks    []authDoctorCheck `json:"checks"`
}

func init() {
	authDoctorCmd.Flags().StringVarP(&authDoctorOutput, "output", "o", FormatTable, "Output format (table,json)")

	authDoctorCmd.Flags().StringVar(&authDoctorProject, "project", "", "Single GCP project ID to probe")
	authDoctorCmd.Flags().StringVar(&authDoctorProjects, "projects", "", "Comma-separated GCP project IDs to probe")
	authDoctorCmd.Flags().StringVar(&authDoctorProjectsFile, "projects-file", "", "Path to newline/comma-delimited GCP project IDs to probe")
	authDoctorCmd.Flags().StringVar(&authDoctorOrg, "org", "", "GCP organization ID (required for SCC permission checks)")
	authDoctorCmd.Flags().BoolVar(&authDoctorSecurity, "security", false, "Probe Security Command Center access (requires --org)")
	authDoctorCmd.Flags().IntVar(&authDoctorMaxProjects, "max-project-checks", 5, "Maximum number of discovered org projects to probe")

	authDoctorCmd.Flags().StringVar(&authDoctorGCPCredentialsFile, "gcp-credentials-file", "", "Path to GCP credentials JSON file")
	authDoctorCmd.Flags().StringVar(&authDoctorGCPImpersonateSA, "gcp-impersonate-service-account", "", "Service account email to impersonate")
	authDoctorCmd.Flags().StringVar(&authDoctorGCPImpersonateDel, "gcp-impersonate-delegates", "", "Comma-separated delegate service accounts for impersonation")
	authDoctorCmd.Flags().StringVar(&authDoctorGCPImpersonateTTL, "gcp-impersonate-token-lifetime-seconds", "", "Impersonation token lifetime in seconds (600-43200)")

	authDoctorCmd.Flags().StringVar(&authDoctorAWSProfile, "aws-profile", "", "AWS shared config profile")
	authDoctorCmd.Flags().StringVar(&authDoctorAWSConfigFile, "aws-config-file", "", "Path to AWS shared config file")
	authDoctorCmd.Flags().StringVar(&authDoctorAWSSharedCredsFile, "aws-shared-credentials-file", "", "Path to AWS shared credentials file")
	authDoctorCmd.Flags().StringVar(&authDoctorAWSCredentialProc, "aws-credential-process", "", "Credential process command")
	authDoctorCmd.Flags().StringVar(&authDoctorAWSWebIDTokenFile, "aws-web-identity-token-file", "", "Path to OIDC token file for web identity")
	authDoctorCmd.Flags().StringVar(&authDoctorAWSWebIDRoleARN, "aws-web-identity-role-arn", "", "Role ARN for web identity auth")
	authDoctorCmd.Flags().StringVar(&authDoctorAWSRoleARN, "aws-role-arn", "", "Role ARN to assume")
	authDoctorCmd.Flags().StringVar(&authDoctorAWSRoleSession, "aws-role-session-name", "cerebro-auth-doctor", "Role session name")
	authDoctorCmd.Flags().StringVar(&authDoctorAWSRoleExternalID, "aws-role-external-id", "", "External ID for role assumption")
	authDoctorCmd.Flags().StringVar(&authDoctorAWSRoleMFASerial, "aws-role-mfa-serial", "", "MFA serial/ARN for role assumption")
	authDoctorCmd.Flags().StringVar(&authDoctorAWSRoleMFAToken, "aws-role-mfa-token", "", "MFA token code for role assumption")
	authDoctorCmd.Flags().StringVar(&authDoctorAWSRoleSourceID, "aws-role-source-identity", "", "Source identity for role sessions")
	authDoctorCmd.Flags().StringVar(&authDoctorAWSRoleDuration, "aws-role-duration-seconds", "", "Role session duration in seconds (900-43200)")
	authDoctorCmd.Flags().StringVar(&authDoctorAWSRoleTags, "aws-role-session-tags", "", "Comma-separated role session tags (key=value)")
	authDoctorCmd.Flags().StringVar(&authDoctorAWSRoleTransitive, "aws-role-transitive-tag-keys", "", "Comma-separated transitive tag keys")
	authDoctorCmd.Flags().BoolVar(&authDoctorAWSCheckOrg, "aws-check-org", false, "Probe AWS Organizations account listing access")
	authDoctorCmd.Flags().StringVar(&authDoctorAWSOrgInclude, "aws-org-include", "", "Comma-separated AWS account IDs to include for org probe")
	authDoctorCmd.Flags().StringVar(&authDoctorAWSOrgExclude, "aws-org-exclude", "", "Comma-separated AWS account IDs to exclude for org probe")

	authCmd.AddCommand(authDoctorCmd)
}

func runAuthDoctor(cmd *cobra.Command, args []string) error {
	provider := strings.ToLower(strings.TrimSpace(args[0]))
	if provider != "aws" && provider != "gcp" {
		return fmt.Errorf("provider must be one of: aws, gcp")
	}

	if err := validateAuthDoctorOutput(); err != nil {
		return err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	start := time.Now()

	if provider == "aws" {
		report, err := runAuthDoctorAWS(ctx, start)
		if outputErr := printAuthDoctorReport(report); outputErr != nil {
			return outputErr
		}
		return err
	}

	report, err := runAuthDoctorGCP(ctx, start)
	if outputErr := printAuthDoctorReport(report); outputErr != nil {
		return outputErr
	}
	return err
}

func validateAuthDoctorOutput() error {
	output := strings.ToLower(strings.TrimSpace(authDoctorOutput))
	if output == "" {
		output = FormatTable
	}
	if output != FormatTable && output != FormatJSON {
		return fmt.Errorf("--output must be one of: %s, %s", FormatTable, FormatJSON)
	}
	authDoctorOutput = output
	return nil
}

func runAuthDoctorAWS(ctx context.Context, start time.Time) (authDoctorReport, error) {
	report := authDoctorReport{
		Provider:  "aws",
		StartedAt: start.UTC(),
		AuthMode:  "auto",
		Checks:    make([]authDoctorCheck, 0, 8),
	}

	if strings.TrimSpace(authDoctorAWSRoleARN) != "" {
		report.AuthMode = "impersonation"
	} else if strings.TrimSpace(authDoctorAWSWebIDRoleARN) != "" {
		report.AuthMode = "wif"
	} else if strings.TrimSpace(authDoctorAWSProfile) != "" || strings.TrimSpace(authDoctorAWSCredentialProc) != "" {
		report.AuthMode = "credentials"
	}

	spec := scheduledSyncSpec{
		AWSProfile:               strings.TrimSpace(authDoctorAWSProfile),
		AWSConfigFile:            strings.TrimSpace(authDoctorAWSConfigFile),
		AWSSharedCredentialsFile: strings.TrimSpace(authDoctorAWSSharedCredsFile),
		AWSCredentialProcess:     strings.TrimSpace(authDoctorAWSCredentialProc),
		AWSWebIdentityTokenFile:  strings.TrimSpace(authDoctorAWSWebIDTokenFile),
		AWSWebIdentityRoleARN:    strings.TrimSpace(authDoctorAWSWebIDRoleARN),
		AWSRoleARN:               strings.TrimSpace(authDoctorAWSRoleARN),
		AWSRoleSession:           strings.TrimSpace(authDoctorAWSRoleSession),
		AWSRoleExternalID:        strings.TrimSpace(authDoctorAWSRoleExternalID),
		AWSRoleMFASerial:         strings.TrimSpace(authDoctorAWSRoleMFASerial),
		AWSRoleMFAToken:          strings.TrimSpace(authDoctorAWSRoleMFAToken),
		AWSRoleSourceIdentity:    strings.TrimSpace(authDoctorAWSRoleSourceID),
		AWSRoleDurationSeconds:   strings.TrimSpace(authDoctorAWSRoleDuration),
		AWSRoleSessionTags:       parseCommaSeparatedValues(authDoctorAWSRoleTags),
		AWSRoleTransitiveTagKeys: parseCommaSeparatedValues(authDoctorAWSRoleTransitive),
	}
	report.AuthChain = describeAuthDoctorAWSChain(spec)

	errs := make([]error, 0)
	record := func(name, detail string, err error) {
		if err != nil {
			report.Checks = append(report.Checks, authDoctorCheck{
				Name:   name,
				Status: "failed",
				Detail: err.Error(),
				Hint:   authDoctorHint("aws", name, err),
			})
			errs = append(errs, err)
			return
		}
		report.Checks = append(report.Checks, authDoctorCheck{Name: name, Status: "passed", Detail: detail})
	}

	awsCfg, err := loadScheduledAWSConfigFn(ctx, spec)
	if err != nil {
		record("auth.load_config", "", err)
		report.Success = false
		report.Duration = time.Since(start).Round(time.Millisecond).String()
		return report, summarizeSyncRunErrors("auth doctor aws", errs)
	}
	record("auth.load_config", "configuration loaded", nil)

	schedule := &SyncSchedule{Name: "auth-doctor-aws", Provider: "aws"}
	if err := preflightScheduledAWSAuthFn(ctx, schedule, spec, awsCfg); err != nil {
		record("auth.identity", "", err)
	} else {
		record("auth.identity", "caller identity retrieved", nil)
	}

	if authDoctorAWSCheckOrg {
		includeSet := buildStringSet(parseTableFilter(authDoctorAWSOrgInclude))
		excludeSet := buildStringSet(parseTableFilter(authDoctorAWSOrgExclude))
		orgCfg := awsCfg.Copy()
		if strings.TrimSpace(orgCfg.Region) == "" {
			orgCfg.Region = "us-east-1"
		}
		accounts, err := listAWSOrgAccounts(ctx, orgCfg, includeSet, excludeSet)
		if err != nil {
			record("organizations.list_accounts", "", err)
		} else if len(accounts) == 0 {
			record("organizations.list_accounts", "", fmt.Errorf("no organization accounts matched filters"))
		} else {
			record("organizations.list_accounts", fmt.Sprintf("%d organization accounts accessible", len(accounts)), nil)
		}
	}

	report.Success = len(errs) == 0
	report.Duration = time.Since(start).Round(time.Millisecond).String()
	if len(errs) > 0 {
		return report, summarizeSyncRunErrors("auth doctor aws", errs)
	}
	return report, nil
}

func runAuthDoctorGCP(ctx context.Context, start time.Time) (authDoctorReport, error) {
	report := authDoctorReport{
		Provider:  "gcp",
		StartedAt: start.UTC(),
		AuthMode:  "auto",
		Checks:    make([]authDoctorCheck, 0, 16),
	}

	spec := scheduledSyncSpec{
		GCPCredentialsFile:           strings.TrimSpace(authDoctorGCPCredentialsFile),
		GCPImpersonateServiceAccount: strings.TrimSpace(authDoctorGCPImpersonateSA),
		GCPImpersonateDelegates:      parseCommaSeparatedValues(authDoctorGCPImpersonateDel),
		GCPImpersonateTokenLifetime:  strings.TrimSpace(authDoctorGCPImpersonateTTL),
	}
	report.AuthChain = describeAuthDoctorGCPChain(spec)

	errs := make([]error, 0)
	record := func(name, detail string, err error) {
		if err != nil {
			report.Checks = append(report.Checks, authDoctorCheck{
				Name:   name,
				Status: "failed",
				Detail: err.Error(),
				Hint:   authDoctorHint("gcp", name, err),
			})
			errs = append(errs, err)
			return
		}
		report.Checks = append(report.Checks, authDoctorCheck{Name: name, Status: "passed", Detail: detail})
	}

	authCfg, err := applyScheduledGCPAuthFn(spec)
	if err != nil {
		record("auth.setup", "", err)
		report.Success = false
		report.Duration = time.Since(start).Round(time.Millisecond).String()
		return report, summarizeSyncRunErrors("auth doctor gcp", errs)
	}
	defer authCfg.Cleanup()

	report.AuthMode = scheduledGCPAuthMethod(spec, authCfg)
	record("auth.setup", authCfg.Summary, nil)

	schedule := &SyncSchedule{Name: "auth-doctor-gcp", Provider: "gcp"}
	if err := preflightScheduledGCPAuthFn(ctx, schedule, spec, authCfg); err != nil {
		record("auth.token", "", err)
	} else {
		record("auth.token", "access token acquired", nil)
	}

	projects, err := resolveAuthDoctorProjects(ctx)
	if err != nil {
		record("projects.resolve", "", err)
	} else if len(projects) > 0 {
		record("projects.resolve", fmt.Sprintf("%d project(s) selected", len(projects)), nil)
	}

	for _, projectID := range projects {
		if err := preflightGCPProjectAccessFn(ctx, gcpProjectPreflightSpec{
			ProjectID:      projectID,
			OrgID:          strings.TrimSpace(authDoctorOrg),
			RunNativeSync:  true,
			RunSecurity:    false,
			ClientOptions:  authCfg.ClientOptions,
			SecurityFilter: nil,
		}); err != nil {
			record(fmt.Sprintf("project.%s.asset_access", projectID), "", err)
			continue
		}
		record(fmt.Sprintf("project.%s.asset_access", projectID), "cloud asset access confirmed", nil)
	}

	if authDoctorSecurity {
		orgID := strings.TrimSpace(authDoctorOrg)
		if orgID == "" {
			record("org.scc", "", fmt.Errorf("--security requires --org for Security Command Center checks"))
		} else {
			if err := preflightGCPProjectAccessFn(ctx, gcpProjectPreflightSpec{
				OrgID:          orgID,
				RunNativeSync:  false,
				RunSecurity:    true,
				SecurityFilter: []string{"scc_findings"},
				ClientOptions:  authCfg.ClientOptions,
			}); err != nil {
				record("org.scc", "", err)
			} else {
				record("org.scc", "security command center access confirmed", nil)
			}
		}
	}

	report.Success = len(errs) == 0
	report.Duration = time.Since(start).Round(time.Millisecond).String()
	if len(errs) > 0 {
		return report, summarizeSyncRunErrors("auth doctor gcp", errs)
	}
	return report, nil
}

func resolveAuthDoctorProjects(ctx context.Context) ([]string, error) {
	projects := make([]string, 0)
	if project := strings.TrimSpace(authDoctorProject); project != "" {
		projects = append(projects, project)
	}
	projects = append(projects, parseCommaSeparatedValues(authDoctorProjects)...)

	if path := strings.TrimSpace(authDoctorProjectsFile); path != "" {
		fromFile, err := loadProjectIDsFromFile(path)
		if err != nil {
			return nil, err
		}
		projects = append(projects, fromFile...)
	}

	projects = normalizeProjectIDs(projects)
	if len(projects) > 0 {
		return projects, nil
	}

	orgID := strings.TrimSpace(authDoctorOrg)
	if orgID == "" {
		return nil, nil
	}

	projectList, err := listOrganizationProjectsFn(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("list organization projects: %w", err)
	}
	projectList = normalizeProjectIDs(projectList)
	if len(projectList) == 0 {
		return nil, fmt.Errorf("organization %s returned no projects", orgID)
	}

	maxProjects := authDoctorMaxProjects
	if maxProjects <= 0 {
		maxProjects = len(projectList)
	}
	if maxProjects < len(projectList) {
		projectList = projectList[:maxProjects]
	}

	return projectList, nil
}

func describeAuthDoctorAWSChain(spec scheduledSyncSpec) string {
	if strings.TrimSpace(spec.AWSWebIdentityRoleARN) != "" {
		return fmt.Sprintf("web_identity: role=%s token_file=%s", spec.AWSWebIdentityRoleARN, spec.AWSWebIdentityTokenFile)
	}
	if strings.TrimSpace(spec.AWSRoleARN) != "" {
		base := "default"
		if strings.TrimSpace(spec.AWSProfile) != "" {
			base = fmt.Sprintf("profile:%s", spec.AWSProfile)
		}
		if strings.TrimSpace(spec.AWSCredentialProcess) != "" {
			parts := strings.Fields(spec.AWSCredentialProcess)
			if len(parts) > 0 {
				base = fmt.Sprintf("credential_process:%s", parts[0])
			} else {
				base = "credential_process"
			}
		}
		return fmt.Sprintf("assume_role: base=%s role=%s", base, spec.AWSRoleARN)
	}
	if strings.TrimSpace(spec.AWSCredentialProcess) != "" {
		parts := strings.Fields(spec.AWSCredentialProcess)
		if len(parts) > 0 {
			return fmt.Sprintf("credential_process: %s", parts[0])
		}
		return "credential_process"
	}
	if strings.TrimSpace(spec.AWSProfile) != "" {
		return fmt.Sprintf("profile: %s", spec.AWSProfile)
	}
	return "aws_default_chain"
}

func describeAuthDoctorGCPChain(spec scheduledSyncSpec) string {
	if strings.TrimSpace(spec.GCPImpersonateServiceAccount) != "" {
		source := "default-application-credentials"
		if path, err := resolveGCPSourceCredentialsPath(spec.GCPCredentialsFile); err == nil {
			source = describeGCPCredentialsPath(path)
		}
		return fmt.Sprintf("impersonation: source=%s target=%s", source, spec.GCPImpersonateServiceAccount)
	}
	if strings.TrimSpace(spec.GCPCredentialsFile) != "" {
		return fmt.Sprintf("credentials_file: %s", describeGCPCredentialsPath(spec.GCPCredentialsFile))
	}
	if path := strings.TrimSpace(os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")); path != "" {
		return fmt.Sprintf("adc_env: %s", describeGCPCredentialsPath(path))
	}
	return "adc_default_chain"
}

func authDoctorHint(provider, checkName string, err error) string {
	message := strings.ToLower(err.Error())

	switch provider {
	case "aws":
		switch {
		case strings.Contains(message, "accessdenied") && strings.Contains(checkName, "identity"):
			return "Verify credentials are valid and allowed to call sts:GetCallerIdentity."
		case strings.Contains(message, "assumerole") || strings.Contains(message, "not authorized to perform: sts:assumerole"):
			return "Ensure the principal can call sts:AssumeRole and the target role trust policy allows this principal."
		case strings.Contains(checkName, "organizations") && strings.Contains(message, "accessdenied"):
			return "Grant organizations:ListAccounts on the management account role/user used for this check."
		}
	case "gcp":
		switch {
		case strings.Contains(message, "iam.serviceaccounts.getaccesstoken"):
			return "Grant roles/iam.serviceAccountTokenCreator on impersonation target (and delegate chain if used)."
		case strings.Contains(message, "cloudasset.assets.searchallresources"):
			return "Grant roles/cloudasset.viewer on each project being scanned."
		case strings.Contains(message, "securitycenter.findings.list"):
			return "Grant roles/securitycenter.findingsViewer at the organization level."
		case strings.Contains(checkName, "projects.resolve") && strings.Contains(message, "permission"):
			return "Grant project discovery/list access (for example resourcemanager.projects.list on the organization)."
		}
	}

	return ""
}

func printAuthDoctorReport(report authDoctorReport) error {
	if authDoctorOutput == FormatJSON {
		return JSONOutput(report)
	}

	fmt.Println()
	fmt.Printf("AUTH DOCTOR (%s)\n", strings.ToUpper(report.Provider))
	fmt.Println(strings.Repeat("=", 56))
	fmt.Printf("Auth mode:  %s\n", report.AuthMode)
	if strings.TrimSpace(report.AuthChain) != "" {
		fmt.Printf("Auth chain: %s\n", report.AuthChain)
	}
	fmt.Printf("Duration:   %s\n", report.Duration)
	fmt.Println()

	tw := NewTableWriter(os.Stdout, "Check", "Status", "Detail", "Hint")
	for _, check := range report.Checks {
		status := ""
		if check.Status == "passed" {
			status = statusColor("healthy")
		} else {
			status = statusColor("failed")
		}
		tw.AddRow(check.Name, status, check.Detail, check.Hint)
	}
	tw.Render()

	fmt.Println()
	if report.Success {
		Success("Auth doctor checks passed")
	} else {
		Warning("Auth doctor found failures")
	}

	return nil
}
