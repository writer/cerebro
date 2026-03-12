package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	azpolicy "github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/spf13/cobra"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/writer/cerebro/internal/connectors"
	"github.com/writer/cerebro/internal/textutil"
)

var connectorCmd = &cobra.Command{
	Use:   "connector",
	Short: "Generate and validate cloud connector provisioning bundles",
	Long: `Generate provider-specific provisioning artifacts and validate the cloud permissions required for agentless workload scanning.

Examples:
  cerebro connector catalog -o json
  cerebro connector scaffold aws --output-dir ./out --aws-principal-arn arn:aws:iam::111122223333:role/Cerebro
  cerebro connector validate gcp --gcp-project my-project --dry-run
  cerebro connector validate azure --azure-subscription <subscription-id> --dry-run`,
}

var connectorCatalogCmd = &cobra.Command{
	Use:   "catalog",
	Short: "Print the built-in connector provisioning catalog",
	RunE:  runConnectorCatalog,
}

var connectorScaffoldCmd = &cobra.Command{
	Use:       "scaffold [aws|gcp|azure]",
	Short:     "Write provider-specific provisioning artifacts to disk",
	ValidArgs: []string{"aws", "gcp", "azure"},
	Args:      cobra.ExactArgs(1),
	RunE:      runConnectorScaffold,
}

var connectorValidateCmd = &cobra.Command{
	Use:       "validate [aws|gcp|azure]",
	Short:     "Validate connector permissions against the current cloud auth chain",
	ValidArgs: []string{"aws", "gcp", "azure"},
	Args:      cobra.ExactArgs(1),
	RunE:      runConnectorValidate,
}

var (
	connectorOutput string

	connectorScaffoldOutputDir string
	connectorValidateDryRun    bool

	connectorAWSPrincipalARN string
	connectorAWSExternalID   string
	connectorAWSRoleName     string
	connectorAWSTagKey       string
	connectorAWSTagValue     string
	connectorAWSRegion       string
	connectorAWSVolumeID     string
	connectorAWSSnapshotID   string
	connectorAWSInstanceID   string

	connectorGCPProjectID        string
	connectorGCPServiceAccountID string
	connectorGCPCustomRoleID     string
	connectorGCPEnableWIF        bool
	connectorGCPWIFPoolID        string
	connectorGCPWIFProviderID    string
	connectorGCPWIFIssuerURI     string
	connectorGCPWIFAudience      string
	connectorGCPPrincipalSubject string

	connectorAzureSubscriptionID string
	connectorAzureTenantID       string
	connectorAzureLocation       string
	connectorAzureDisplayName    string
	connectorAzureCustomRoleName string

	runAWSConnectorValidateFn   = runAWSConnectorValidate
	runGCPConnectorValidateFn   = runGCPConnectorValidate
	runAzureConnectorValidateFn = runAzureConnectorValidate
)

type connectorValidationReport struct {
	Provider    string                     `json:"provider"`
	DryRun      bool                       `json:"dry_run,omitempty"`
	StartedAt   time.Time                  `json:"started_at"`
	CompletedAt time.Time                  `json:"completed_at"`
	Duration    string                     `json:"duration"`
	Success     bool                       `json:"success"`
	Principal   string                     `json:"principal,omitempty"`
	Checks      []connectorValidationCheck `json:"checks"`
}

type connectorValidationCheck struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

type azurePermissionResponse struct {
	Value []struct {
		Actions    []string `json:"actions"`
		NotActions []string `json:"notActions"`
	} `json:"value"`
}

type gcpTestIAMPermissionsRequest struct {
	Permissions []string `json:"permissions"`
}

type gcpTestIAMPermissionsResponse struct {
	Permissions []string `json:"permissions"`
}

const awsDescribeProbeMaxResults = 5

const (
	connectorScaffoldDirPerm  = 0o750
	connectorScaffoldFilePerm = 0o600
)

func init() {
	connectorCatalogCmd.Flags().StringVarP(&connectorOutput, "output", "o", FormatTable, "Output format (table,json)")
	connectorScaffoldCmd.Flags().StringVarP(&connectorOutput, "output", "o", FormatTable, "Output format (table,json)")
	connectorValidateCmd.Flags().StringVarP(&connectorOutput, "output", "o", FormatTable, "Output format (table,json)")

	connectorScaffoldCmd.Flags().StringVar(&connectorScaffoldOutputDir, "output-dir", filepath.Join(".cerebro", "connectors"), "Directory where generated connector artifacts will be written")

	connectorScaffoldCmd.Flags().StringVar(&connectorAWSPrincipalARN, "aws-principal-arn", "", "Principal ARN trusted by the generated AWS role")
	connectorScaffoldCmd.Flags().StringVar(&connectorAWSExternalID, "aws-external-id", "", "External ID required by the generated AWS role")
	connectorScaffoldCmd.Flags().StringVar(&connectorAWSRoleName, "aws-role-name", "CerebroScanRole", "AWS role name for the generated connector")
	connectorScaffoldCmd.Flags().StringVar(&connectorAWSTagKey, "aws-managed-tag-key", "CerebroManagedBy", "Tag key used to scope AWS snapshot and volume mutations")
	connectorScaffoldCmd.Flags().StringVar(&connectorAWSTagValue, "aws-managed-tag-value", "cerebro", "Tag value used to scope AWS snapshot and volume mutations")

	connectorScaffoldCmd.Flags().StringVar(&connectorGCPProjectID, "gcp-project", "", "GCP project ID for the generated module")
	connectorScaffoldCmd.Flags().StringVar(&connectorGCPServiceAccountID, "gcp-service-account-id", "cerebro-workload-scan", "Service account ID for the generated GCP module")
	connectorScaffoldCmd.Flags().StringVar(&connectorGCPCustomRoleID, "gcp-custom-role-id", "cerebroWorkloadSnapshot", "Custom role ID for the generated GCP module")
	connectorScaffoldCmd.Flags().BoolVar(&connectorGCPEnableWIF, "gcp-enable-wif", false, "Enable Workload Identity Federation resources in the generated GCP module")
	connectorScaffoldCmd.Flags().StringVar(&connectorGCPWIFPoolID, "gcp-wif-pool-id", "cerebro-workload-pool", "Workload Identity Pool ID for the generated GCP module")
	connectorScaffoldCmd.Flags().StringVar(&connectorGCPWIFProviderID, "gcp-wif-provider-id", "cerebro-oidc", "Workload Identity Provider ID for the generated GCP module")
	connectorScaffoldCmd.Flags().StringVar(&connectorGCPWIFIssuerURI, "gcp-wif-issuer-uri", "", "OIDC issuer URI for GCP WIF generation")
	connectorScaffoldCmd.Flags().StringVar(&connectorGCPWIFAudience, "gcp-wif-audience", "", "Expected audience for the GCP WIF provider")
	connectorScaffoldCmd.Flags().StringVar(&connectorGCPPrincipalSubject, "gcp-principal-subject", "", "Principal subject allowed to impersonate the GCP service account via WIF")

	connectorScaffoldCmd.Flags().StringVar(&connectorAzureSubscriptionID, "azure-subscription", "", "Azure subscription ID for the generated bundle")
	connectorScaffoldCmd.Flags().StringVar(&connectorAzureTenantID, "azure-tenant-id", "", "Azure tenant ID for the generated bundle")
	connectorScaffoldCmd.Flags().StringVar(&connectorAzureLocation, "azure-location", "eastus", "Azure location for generated templates")
	connectorScaffoldCmd.Flags().StringVar(&connectorAzureDisplayName, "azure-display-name", "cerebro-workload-scan", "Azure service principal display name for the generated Terraform module")
	connectorScaffoldCmd.Flags().StringVar(&connectorAzureCustomRoleName, "azure-custom-role-name", "Cerebro Snapshot Operator", "Azure custom role name for the generated bundle")

	connectorValidateCmd.Flags().BoolVar(&connectorValidateDryRun, "dry-run", false, "Run safe non-mutating permission probes where the provider supports them")
	connectorValidateCmd.Flags().StringVar(&syncAWSProfile, "aws-profile", "", "AWS shared config profile for connector validation")
	connectorValidateCmd.Flags().StringVar(&syncAWSConfigFile, "aws-config-file", "", "Path to AWS shared config file")
	connectorValidateCmd.Flags().StringVar(&syncAWSSharedCredsFile, "aws-shared-credentials-file", "", "Path to AWS shared credentials file")
	connectorValidateCmd.Flags().StringVar(&syncAWSCredentialProc, "aws-credential-process", "", "Credential process command for AWS validation")
	connectorValidateCmd.Flags().StringVar(&syncAWSWebIDTokenFile, "aws-web-identity-token-file", "", "OIDC token file for AWS web-identity auth")
	connectorValidateCmd.Flags().StringVar(&syncAWSWebIDRoleARN, "aws-web-identity-role-arn", "", "Role ARN for AWS web-identity auth")
	connectorValidateCmd.Flags().StringVar(&syncAWSRoleARN, "aws-role-arn", "", "AWS role ARN to assume before validation")
	connectorValidateCmd.Flags().StringVar(&syncAWSRoleSession, "aws-role-session-name", "cerebro-connector-validate", "Session name for AWS role assumption")
	connectorValidateCmd.Flags().StringVar(&syncAWSRoleExternalID, "aws-role-external-id", "", "External ID for AWS role assumption")
	connectorValidateCmd.Flags().StringVar(&syncAWSRoleSourceID, "aws-role-source-identity", "", "Source identity for AWS role assumption")
	connectorValidateCmd.Flags().StringVarP(&connectorAWSRegion, "region", "r", "us-east-1", "AWS region for validation")
	connectorValidateCmd.Flags().StringVar(&connectorAWSVolumeID, "aws-volume-id", "", "Sample EBS volume ID used for AWS dry-run mutation checks")
	connectorValidateCmd.Flags().StringVar(&connectorAWSSnapshotID, "aws-snapshot-id", "", "Sample snapshot ID used for AWS dry-run mutation checks")
	connectorValidateCmd.Flags().StringVar(&connectorAWSInstanceID, "aws-instance-id", "", "Optional sample instance ID to confirm read access context")

	connectorValidateCmd.Flags().StringVar(&syncGCPCredentialsFile, "gcp-credentials-file", "", "Path to GCP credentials JSON file")
	connectorValidateCmd.Flags().StringVar(&syncGCPImpersonateSA, "gcp-impersonate-service-account", "", "Service account email to impersonate for GCP validation")
	connectorValidateCmd.Flags().StringVar(&syncGCPImpersonateDel, "gcp-impersonate-delegates", "", "Comma-separated delegates for GCP impersonation")
	connectorValidateCmd.Flags().StringVar(&syncGCPImpersonateTTL, "gcp-impersonate-token-lifetime-seconds", "", "Impersonated token lifetime in seconds for GCP validation")
	connectorValidateCmd.Flags().StringVar(&connectorGCPProjectID, "gcp-project", "", "Target GCP project ID for validation")

	connectorValidateCmd.Flags().StringVar(&syncAzureSubscription, "azure-subscription", "", "Azure subscription ID for validation")
	connectorValidateCmd.Flags().StringVar(&connectorAzureTenantID, "azure-tenant-id", "", "Azure tenant ID override for validation")

	connectorCmd.AddCommand(connectorCatalogCmd)
	connectorCmd.AddCommand(connectorScaffoldCmd)
	connectorCmd.AddCommand(connectorValidateCmd)
	rootCmd.AddCommand(connectorCmd)
}

func runConnectorCatalog(cmd *cobra.Command, _ []string) error {
	if err := validateConnectorOutputFormat(); err != nil {
		return err
	}
	catalog := connectors.BuiltInCatalog()
	if connectorOutput == FormatJSON {
		return JSONOutput(catalog)
	}
	fmt.Println("Connector Provisioning Catalog")
	fmt.Println("─────────────────────────────────────────────────────────────────────────────")
	for _, provider := range catalog.Providers {
		fmt.Printf("%s\n", strings.ToUpper(string(provider.ID)))
		fmt.Printf("  %s\n", provider.Summary)
		fmt.Printf("  Artifacts: %s\n", joinArtifactKinds(provider.Artifacts))
		fmt.Printf("  Validation: %s\n\n", joinValidationModes(provider.ValidationChecks))
	}
	return nil
}

func runConnectorScaffold(cmd *cobra.Command, args []string) error {
	if err := validateConnectorOutputFormat(); err != nil {
		return err
	}
	provider := connectors.NormalizeProviderID(args[0])
	if _, ok := connectors.ProviderByID(provider); !ok {
		return fmt.Errorf("unsupported connector provider %q", args[0])
	}
	var (
		bundle connectors.Bundle
		err    error
	)
	outputDir := filepath.Clean(strings.TrimSpace(connectorScaffoldOutputDir))
	if outputDir == "" || outputDir == "." {
		return fmt.Errorf("--output-dir must not be empty")
	}
	switch provider {
	case string(connectors.ProviderAWS):
		bundle, err = connectors.RenderAWSBundle(connectors.AWSRenderOptions{RoleName: connectorAWSRoleName, PrincipalARN: connectorAWSPrincipalARN, ExternalID: connectorAWSExternalID, ManagedTagKey: connectorAWSTagKey, ManagedTagVal: connectorAWSTagValue})
	case string(connectors.ProviderGCP):
		bundle, err = connectors.RenderGCPBundle(connectors.GCPRenderOptions{ProjectID: connectorGCPProjectID, ServiceAccountID: connectorGCPServiceAccountID, CustomRoleID: connectorGCPCustomRoleID, EnableWIF: connectorGCPEnableWIF, WorkloadIdentityPoolID: connectorGCPWIFPoolID, WorkloadIdentityProviderID: connectorGCPWIFProviderID, WorkloadIdentityIssuerURI: connectorGCPWIFIssuerURI, WorkloadIdentityAudience: connectorGCPWIFAudience, PrincipalSubject: connectorGCPPrincipalSubject})
	case string(connectors.ProviderAzure):
		bundle, err = connectors.RenderAzureBundle(connectors.AzureRenderOptions{SubscriptionID: textutil.FirstNonEmptyTrimmed(strings.TrimSpace(connectorAzureSubscriptionID), strings.TrimSpace(syncAzureSubscription)), TenantID: connectorAzureTenantID, Location: connectorAzureLocation, PrincipalDisplayName: connectorAzureDisplayName, CustomRoleName: connectorAzureCustomRoleName})
	default:
		return fmt.Errorf("unsupported connector provider %q", args[0])
	}
	if err != nil {
		return err
	}
	written, err := writeGeneratedBundle(outputDir, bundle)
	if err != nil {
		return err
	}
	if connectorOutput == FormatJSON {
		return JSONOutput(map[string]any{"provider": provider, "output_dir": outputDir, "files": written})
	}
	fmt.Printf("Generated %s connector bundle in %s\n", strings.ToUpper(provider), outputDir)
	for _, file := range written {
		fmt.Printf("- %s\n", file)
	}
	return nil
}

func runConnectorValidate(cmd *cobra.Command, args []string) error {
	if err := validateConnectorOutputFormat(); err != nil {
		return err
	}
	baseCtx := context.Background()
	if cmd != nil && cmd.Context() != nil {
		baseCtx = cmd.Context()
	}
	ctx, cancel := context.WithTimeout(baseCtx, 2*time.Minute)
	defer cancel()

	provider := connectors.NormalizeProviderID(args[0])
	if _, ok := connectors.ProviderByID(provider); !ok {
		return fmt.Errorf("unsupported connector provider %q", args[0])
	}
	var (
		report connectorValidationReport
		err    error
	)
	switch provider {
	case string(connectors.ProviderAWS):
		report, err = runAWSConnectorValidateFn(ctx)
	case string(connectors.ProviderGCP):
		report, err = runGCPConnectorValidateFn(ctx)
	case string(connectors.ProviderAzure):
		report, err = runAzureConnectorValidateFn(ctx)
	default:
		return fmt.Errorf("unsupported connector provider %q", args[0])
	}
	if !report.StartedAt.IsZero() {
		if connectorOutput == FormatJSON {
			if outputErr := JSONOutput(report); outputErr != nil {
				return outputErr
			}
		} else if outputErr := printConnectorValidationReport(report); outputErr != nil {
			return outputErr
		}
	}
	if err != nil {
		return err
	}
	return nil
}

func runAWSConnectorValidate(ctx context.Context) (connectorValidationReport, error) {
	report := connectorValidationReport{Provider: "aws", DryRun: connectorValidateDryRun, StartedAt: time.Now().UTC()}
	checks := make([]connectorValidationCheck, 0, 8)
	finish := func(err error) (connectorValidationReport, error) {
		report.CompletedAt = time.Now().UTC()
		report.Duration = report.CompletedAt.Sub(report.StartedAt).Round(time.Millisecond).String()
		report.Checks = checks
		report.Success = err == nil && allConnectorChecksPassed(checks)
		return report, err
	}

	cfg, err := loadAWSConfig(ctx, syncAWSProfile)
	if err != nil {
		checks = append(checks, connectorValidationCheck{ID: "auth", Status: "failed", Detail: fmt.Sprintf("load AWS config: %v", err)})
		return finish(fmt.Errorf("aws connector auth: %w", err))
	}
	cfg, err = applyAWSAssumeRoleOverride(ctx, cfg)
	if err != nil {
		checks = append(checks, connectorValidationCheck{ID: "auth", Status: "failed", Detail: fmt.Sprintf("assume AWS role: %v", err)})
		return finish(fmt.Errorf("aws connector auth: %w", err))
	}
	if region := strings.TrimSpace(connectorAWSRegion); region != "" {
		cfg.Region = region
	}
	stsClient := sts.NewFromConfig(cfg)
	ident, err := stsClient.GetCallerIdentity(ctx, nil)
	if err != nil {
		checks = append(checks, connectorValidationCheck{ID: "auth", Status: "failed", Detail: fmt.Sprintf("sts:GetCallerIdentity failed: %v", err)})
		return finish(fmt.Errorf("aws connector auth: %w", err))
	}
	report.Principal = textutil.FirstNonEmptyTrimmed(aws.ToString(ident.Arn), aws.ToString(ident.UserId))
	checks = append(checks, connectorValidationCheck{ID: "auth", Status: "passed", Detail: fmt.Sprintf("caller=%s account=%s", report.Principal, aws.ToString(ident.Account))})

	ec2Client := ec2.NewFromConfig(cfg)
	if err := awsDescribeProbe(ctx, ec2Client, connectorAWSInstanceID); err != nil {
		checks = append(checks, connectorValidationCheck{ID: "describe", Status: "failed", Detail: err.Error()})
		return finish(fmt.Errorf("aws describe probe: %w", err))
	}
	checks = append(checks, connectorValidationCheck{ID: "describe", Status: "passed", Detail: fmt.Sprintf("ec2 describe access confirmed in %s", cfg.Region)})

	if !connectorValidateDryRun {
		checks = append(checks, connectorValidationCheck{ID: "snapshot_dry_run", Status: "skipped", Detail: "set --dry-run and provide sample resources to probe snapshot mutations without creating resources"})
		return finish(nil)
	}
	detail := make([]string, 0, 3)
	status := "passed"
	if strings.TrimSpace(connectorAWSVolumeID) != "" {
		probeErr := awsDryRunCreateSnapshot(ctx, ec2Client, strings.TrimSpace(connectorAWSVolumeID), connectorAWSTagKey, connectorAWSTagValue)
		checkStatus, checkDetail := classifyAWSDryRunResult(probeErr, "ec2:CreateSnapshot")
		status = foldConnectorStatus(status, checkStatus)
		detail = append(detail, checkDetail)
	} else {
		status = foldConnectorStatus(status, "skipped")
		detail = append(detail, "create snapshot skipped: set --aws-volume-id")
	}
	if strings.TrimSpace(connectorAWSSnapshotID) != "" {
		probeErr := awsDryRunCopySnapshot(ctx, ec2Client, strings.TrimSpace(connectorAWSSnapshotID), connectorAWSTagKey, connectorAWSTagValue)
		checkStatus, checkDetail := classifyAWSDryRunResult(probeErr, "ec2:CopySnapshot")
		status = foldConnectorStatus(status, checkStatus)
		detail = append(detail, checkDetail)
	} else {
		status = foldConnectorStatus(status, "skipped")
		detail = append(detail, "copy snapshot skipped: set --aws-snapshot-id")
	}
	checks = append(checks, connectorValidationCheck{ID: "snapshot_dry_run", Status: status, Detail: strings.Join(detail, "; ")})
	return finish(nil)
}

func runGCPConnectorValidate(ctx context.Context) (connectorValidationReport, error) {
	report := connectorValidationReport{Provider: "gcp", DryRun: connectorValidateDryRun, StartedAt: time.Now().UTC()}
	checks := make([]connectorValidationCheck, 0, 4)
	finish := func(err error) (connectorValidationReport, error) {
		report.CompletedAt = time.Now().UTC()
		report.Duration = report.CompletedAt.Sub(report.StartedAt).Round(time.Millisecond).String()
		report.Checks = checks
		report.Success = err == nil && allConnectorChecksPassed(checks)
		return report, err
	}

	projectID := strings.TrimSpace(connectorGCPProjectID)
	if projectID == "" {
		return finish(fmt.Errorf("--gcp-project is required for GCP connector validation"))
	}
	spec := buildScheduledGCPSpecFromSyncFlags()
	authCfg, err := applyScheduledGCPAuthFn(spec)
	if err != nil {
		checks = append(checks, connectorValidationCheck{ID: "auth", Status: "failed", Detail: err.Error()})
		return finish(fmt.Errorf("gcp connector auth: %w", err))
	}
	if authCfg == nil {
		authCfg = &scheduledGCPAuthConfig{Cleanup: func() {}}
	}
	if authCfg.Cleanup != nil {
		defer authCfg.Cleanup()
	}
	credentials, err := connectorGCPCredentials(ctx, authCfg)
	if err != nil {
		checks = append(checks, connectorValidationCheck{ID: "auth", Status: "failed", Detail: err.Error()})
		return finish(fmt.Errorf("gcp connector auth: %w", err))
	}
	token, err := credentials.TokenSource.Token()
	if err != nil {
		checks = append(checks, connectorValidationCheck{ID: "auth", Status: "failed", Detail: fmt.Sprintf("token retrieval failed: %v", err)})
		return finish(fmt.Errorf("gcp connector auth token: %w", err))
	}
	report.Principal = scheduledGCPAuthMethod(spec, authCfg)
	checks = append(checks, connectorValidationCheck{ID: "auth", Status: "passed", Detail: fmt.Sprintf("auth=%s token_expiry=%s", report.Principal, token.Expiry.UTC().Format(time.RFC3339))})

	if err := probeGCPCloudAssetAccessFn(ctx, projectID, authCfg.ClientOptions); err != nil {
		checks = append(checks, connectorValidationCheck{ID: "project_read", Status: "failed", Detail: err.Error()})
		return finish(fmt.Errorf("gcp project read probe: %w", err))
	}
	checks = append(checks, connectorValidationCheck{ID: "project_read", Status: "passed", Detail: fmt.Sprintf("cloud asset read confirmed for %s", projectID)})

	if !connectorValidateDryRun {
		checks = append(checks, connectorValidationCheck{ID: "iam_permissions", Status: "skipped", Detail: "set --dry-run to invoke projects.testIamPermissions without creating resources"})
		return finish(nil)
	}
	allowed, missing, err := gcpProjectPermissionProbe(ctx, credentials, projectID, []string{
		"compute.disks.createSnapshot",
		"compute.snapshots.get",
		"compute.snapshots.delete",
		"compute.snapshots.setIamPolicy",
		"compute.instances.get",
	})
	if err != nil {
		checks = append(checks, connectorValidationCheck{ID: "iam_permissions", Status: "failed", Detail: err.Error()})
		return finish(fmt.Errorf("gcp permission probe: %w", err))
	}
	if len(missing) > 0 {
		checks = append(checks, connectorValidationCheck{ID: "iam_permissions", Status: "failed", Detail: fmt.Sprintf("missing permissions: %s (granted: %s)", strings.Join(missing, ", "), strings.Join(allowed, ", "))})
		return finish(fmt.Errorf("gcp permission probe missing permissions"))
	}
	checks = append(checks, connectorValidationCheck{ID: "iam_permissions", Status: "passed", Detail: fmt.Sprintf("all required permissions granted: %s", strings.Join(allowed, ", "))})
	return finish(nil)
}

func runAzureConnectorValidate(ctx context.Context) (connectorValidationReport, error) {
	report := connectorValidationReport{Provider: "azure", DryRun: connectorValidateDryRun, StartedAt: time.Now().UTC()}
	checks := make([]connectorValidationCheck, 0, 4)
	finish := func(err error) (connectorValidationReport, error) {
		report.CompletedAt = time.Now().UTC()
		report.Duration = report.CompletedAt.Sub(report.StartedAt).Round(time.Millisecond).String()
		report.Checks = checks
		report.Success = err == nil && allConnectorChecksPassed(checks)
		return report, err
	}

	subscriptionID := textutil.FirstNonEmptyTrimmed(strings.TrimSpace(syncAzureSubscription), strings.TrimSpace(connectorAzureSubscriptionID))
	if subscriptionID == "" {
		return finish(fmt.Errorf("--azure-subscription is required for Azure connector validation"))
	}
	cred, err := azidentity.NewDefaultAzureCredential(&azidentity.DefaultAzureCredentialOptions{TenantID: strings.TrimSpace(connectorAzureTenantID)})
	if err != nil {
		checks = append(checks, connectorValidationCheck{ID: "auth", Status: "failed", Detail: err.Error()})
		return finish(fmt.Errorf("azure connector auth: %w", err))
	}
	token, err := cred.GetToken(ctx, policyTokenRequestOptions())
	if err != nil {
		checks = append(checks, connectorValidationCheck{ID: "auth", Status: "failed", Detail: err.Error()})
		return finish(fmt.Errorf("azure connector auth token: %w", err))
	}
	report.Principal = textutil.FirstNonEmptyTrimmed(strings.TrimSpace(connectorAzureTenantID), "default_credential")
	checks = append(checks, connectorValidationCheck{ID: "auth", Status: "passed", Detail: fmt.Sprintf("management token acquired exp=%s", token.ExpiresOn.UTC().Format(time.RFC3339))})

	if err := azureSubscriptionReadProbe(ctx, token.Token, subscriptionID); err != nil {
		checks = append(checks, connectorValidationCheck{ID: "subscription_read", Status: "failed", Detail: err.Error()})
		return finish(fmt.Errorf("azure subscription read probe: %w", err))
	}
	checks = append(checks, connectorValidationCheck{ID: "subscription_read", Status: "passed", Detail: fmt.Sprintf("subscription %s readable", subscriptionID)})

	if !connectorValidateDryRun {
		checks = append(checks, connectorValidationCheck{ID: "permissions", Status: "skipped", Detail: "set --dry-run to inspect effective subscription permissions"})
		return finish(nil)
	}
	allowed, missing, err := azurePermissionProbe(ctx, token.Token, subscriptionID, []string{
		"Microsoft.Resources/subscriptions/resourceGroups/read",
		"Microsoft.Compute/virtualMachines/read",
		"Microsoft.Compute/disks/read",
		"Microsoft.Compute/snapshots/write",
		"Microsoft.Compute/snapshots/delete",
	})
	if err != nil {
		checks = append(checks, connectorValidationCheck{ID: "permissions", Status: "failed", Detail: err.Error()})
		return finish(fmt.Errorf("azure permissions probe: %w", err))
	}
	if len(missing) > 0 {
		checks = append(checks, connectorValidationCheck{ID: "permissions", Status: "failed", Detail: fmt.Sprintf("missing permissions: %s (matched: %s)", strings.Join(missing, ", "), strings.Join(allowed, ", "))})
		return finish(fmt.Errorf("azure permissions probe missing permissions"))
	}
	checks = append(checks, connectorValidationCheck{ID: "permissions", Status: "passed", Detail: fmt.Sprintf("all required permissions granted: %s", strings.Join(allowed, ", "))})
	return finish(nil)
}

func writeGeneratedBundle(root string, bundle connectors.Bundle) ([]string, error) {
	files := make([]string, 0, len(bundle.Files))
	for _, file := range bundle.Files {
		target := filepath.Join(root, filepath.FromSlash(file.Path))
		if err := os.MkdirAll(filepath.Dir(target), connectorScaffoldDirPerm); err != nil {
			return nil, fmt.Errorf("mkdir %s: %w", filepath.Dir(target), err)
		}
		if err := os.WriteFile(target, []byte(file.Content), connectorScaffoldFilePerm); err != nil {
			return nil, fmt.Errorf("write %s: %w", target, err)
		}
		files = append(files, filepath.ToSlash(target))
	}
	sort.Strings(files)
	return files, nil
}

func printConnectorValidationReport(report connectorValidationReport) error {
	fmt.Printf("%s connector validation\n", strings.ToUpper(report.Provider))
	fmt.Println("─────────────────────────────────────────────────────────────────────────────")
	fmt.Printf("Success: %t\n", report.Success)
	if report.Principal != "" {
		fmt.Printf("Principal: %s\n", report.Principal)
	}
	fmt.Printf("Duration: %s\n", report.Duration)
	for _, check := range report.Checks {
		fmt.Printf("- [%s] %s: %s\n", strings.ToUpper(check.Status), check.ID, check.Detail)
	}
	return nil
}

func validateConnectorOutputFormat() error {
	if connectorOutput != FormatTable && connectorOutput != FormatJSON {
		return fmt.Errorf("--output must be one of: %s, %s", FormatTable, FormatJSON)
	}
	return nil
}

func joinArtifactKinds(artifacts []connectors.ArtifactSpec) string {
	parts := make([]string, 0, len(artifacts))
	for _, artifact := range artifacts {
		parts = append(parts, string(artifact.Kind))
	}
	return strings.Join(parts, ", ")
}

func joinValidationModes(checks []connectors.ValidationCheckSpec) string {
	parts := make([]string, 0, len(checks))
	for _, check := range checks {
		parts = append(parts, string(check.Mode))
	}
	return strings.Join(parts, ", ")
}

func allConnectorChecksPassed(checks []connectorValidationCheck) bool {
	for _, check := range checks {
		if connectorStatusRank(check.Status) >= connectorStatusRank("failed") {
			return false
		}
	}
	return true
}

func awsDescribeProbe(ctx context.Context, client *ec2.Client, instanceID string) error {
	if _, err := client.DescribeVolumes(ctx, &ec2.DescribeVolumesInput{MaxResults: aws.Int32(awsDescribeProbeMaxResults)}); err != nil {
		return fmt.Errorf("ec2:DescribeVolumes failed: %w", err)
	}
	if _, err := client.DescribeSnapshots(ctx, &ec2.DescribeSnapshotsInput{MaxResults: aws.Int32(awsDescribeProbeMaxResults), OwnerIds: []string{"self"}}); err != nil {
		return fmt.Errorf("ec2:DescribeSnapshots failed: %w", err)
	}
	input := awsDescribeInstancesInput(instanceID)
	if _, err := client.DescribeInstances(ctx, input); err != nil {
		return fmt.Errorf("ec2:DescribeInstances failed: %w", err)
	}
	return nil
}

func awsDescribeInstancesInput(instanceID string) *ec2.DescribeInstancesInput {
	if strings.TrimSpace(instanceID) != "" {
		return &ec2.DescribeInstancesInput{InstanceIds: []string{strings.TrimSpace(instanceID)}}
	}
	return &ec2.DescribeInstancesInput{MaxResults: aws.Int32(awsDescribeProbeMaxResults)}
}

func awsDryRunCreateSnapshot(ctx context.Context, client *ec2.Client, volumeID, tagKey, tagValue string) error {
	_, err := client.CreateSnapshot(ctx, &ec2.CreateSnapshotInput{
		VolumeId:    aws.String(volumeID),
		Description: aws.String("cerebro connector validate"),
		DryRun:      aws.Bool(true),
		TagSpecifications: []ec2types.TagSpecification{{
			ResourceType: ec2types.ResourceTypeSnapshot,
			Tags:         []ec2types.Tag{{Key: aws.String(textutil.FirstNonEmptyTrimmed(strings.TrimSpace(tagKey), "CerebroManagedBy")), Value: aws.String(textutil.FirstNonEmptyTrimmed(strings.TrimSpace(tagValue), "cerebro"))}},
		}},
	})
	return err
}

func awsDryRunCopySnapshot(ctx context.Context, client *ec2.Client, snapshotID, tagKey, tagValue string) error {
	_, err := client.CopySnapshot(ctx, &ec2.CopySnapshotInput{
		SourceRegion:      aws.String(textutil.FirstNonEmptyTrimmed(strings.TrimSpace(connectorAWSRegion), "us-east-1")),
		SourceSnapshotId:  aws.String(snapshotID),
		Description:       aws.String("cerebro connector validate"),
		DryRun:            aws.Bool(true),
		TagSpecifications: []ec2types.TagSpecification{{ResourceType: ec2types.ResourceTypeSnapshot, Tags: []ec2types.Tag{{Key: aws.String(textutil.FirstNonEmptyTrimmed(strings.TrimSpace(tagKey), "CerebroManagedBy")), Value: aws.String(textutil.FirstNonEmptyTrimmed(strings.TrimSpace(tagValue), "cerebro"))}}}},
	})
	return err
}

func classifyAWSDryRunResult(err error, action string) (string, string) {
	if err == nil {
		return "passed", action + " succeeded without mutation"
	}
	message := err.Error()
	switch {
	case strings.Contains(message, "DryRunOperation"):
		return "passed", action + " permission confirmed via DryRunOperation"
	case strings.Contains(message, "UnauthorizedOperation"), strings.Contains(message, "AccessDenied"):
		return "failed", action + " denied: " + message
	default:
		return "skipped", action + " inconclusive: " + message
	}
}

func foldConnectorStatus(current, next string) string {
	if connectorStatusRank(next) > connectorStatusRank(current) {
		return next
	}
	return current
}

func connectorStatusRank(status string) int {
	switch strings.TrimSpace(status) {
	case "passed":
		return 0
	case "skipped":
		return 1
	case "failed":
		return 2
	default:
		return 3
	}
}

func connectorGCPCredentials(ctx context.Context, authCfg *scheduledGCPAuthConfig) (*google.Credentials, error) {
	if authCfg != nil && len(authCfg.CredentialsJSON) > 0 {
		return google.CredentialsFromJSON(ctx, authCfg.CredentialsJSON, "https://www.googleapis.com/auth/cloud-platform")
	}
	if authCfg != nil && strings.TrimSpace(authCfg.CredentialsFile) != "" {
		encoded, err := os.ReadFile(strings.TrimSpace(authCfg.CredentialsFile))
		if err != nil {
			return nil, fmt.Errorf("read credentials file %q: %w", authCfg.CredentialsFile, err)
		}
		return google.CredentialsFromJSON(ctx, encoded, "https://www.googleapis.com/auth/cloud-platform")
	}
	return google.FindDefaultCredentials(ctx, "https://www.googleapis.com/auth/cloud-platform")
}

func gcpProjectPermissionProbe(ctx context.Context, creds *google.Credentials, projectID string, required []string) ([]string, []string, error) {
	body, err := json.Marshal(gcpTestIAMPermissionsRequest{Permissions: required})
	if err != nil {
		return nil, nil, err
	}
	client := oauthHTTPClient(ctx, creds)
	url := fmt.Sprintf("https://cloudresourcemanager.googleapis.com/v1/projects/%s:testIamPermissions", projectID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	payload, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		return nil, nil, fmt.Errorf("projects.testIamPermissions failed: %s", strings.TrimSpace(string(payload)))
	}
	var parsed gcpTestIAMPermissionsResponse
	if err := json.Unmarshal(payload, &parsed); err != nil {
		return nil, nil, fmt.Errorf("decode projects.testIamPermissions response: %w", err)
	}
	allowedSet := make(map[string]struct{}, len(parsed.Permissions))
	for _, permission := range parsed.Permissions {
		allowedSet[permission] = struct{}{}
	}
	allowed := make([]string, 0, len(parsed.Permissions))
	missing := make([]string, 0)
	for _, permission := range required {
		if _, ok := allowedSet[permission]; ok {
			allowed = append(allowed, permission)
			continue
		}
		missing = append(missing, permission)
	}
	return allowed, missing, nil
}

func oauthHTTPClient(ctx context.Context, creds *google.Credentials) *http.Client {
	return oauth2.NewClient(ctx, creds.TokenSource)
}

func azureSubscriptionReadProbe(ctx context.Context, token, subscriptionID string) error {
	url := fmt.Sprintf("https://management.azure.com/subscriptions/%s?api-version=2020-01-01", subscriptionID)
	_, err := doAzureRequest(ctx, token, url)
	return err
}

func azurePermissionProbe(ctx context.Context, token, subscriptionID string, required []string) ([]string, []string, error) {
	url := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.Authorization/permissions?api-version=2022-04-01", subscriptionID)
	payload, err := doAzureRequest(ctx, token, url)
	if err != nil {
		return nil, nil, err
	}
	var parsed azurePermissionResponse
	if err := json.Unmarshal(payload, &parsed); err != nil {
		return nil, nil, fmt.Errorf("decode Azure permissions response: %w", err)
	}
	allowed := make([]string, 0, len(required))
	missing := make([]string, 0)
	for _, permission := range required {
		if azurePermissionAllowed(permission, parsed.Value) {
			allowed = append(allowed, permission)
			continue
		}
		missing = append(missing, permission)
	}
	return allowed, missing, nil
}

func doAzureRequest(ctx context.Context, token, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	payload, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("azure management request failed: %s", strings.TrimSpace(string(payload)))
	}
	return payload, nil
}

func azurePermissionAllowed(required string, grants []struct {
	Actions    []string `json:"actions"`
	NotActions []string `json:"notActions"`
}) bool {
	for _, grant := range grants {
		matched := false
		for _, action := range grant.Actions {
			if azureActionMatches(action, required) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		for _, action := range grant.NotActions {
			if azureActionMatches(action, required) {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}
	return false
}

func azureActionMatches(pattern, required string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	required = strings.ToLower(strings.TrimSpace(required))
	if pattern == "*" {
		return true
	}
	expr := "^" + strings.ReplaceAll(regexp.QuoteMeta(pattern), "\\*", ".*") + "$"
	ok, err := regexp.MatchString(expr, required)
	return err == nil && ok
}

func policyTokenRequestOptions() azpolicy.TokenRequestOptions {
	return azpolicy.TokenRequestOptions{Scopes: []string{"https://management.azure.com/.default"}}
}
