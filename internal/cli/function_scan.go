package cli

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/writer/cerebro/internal/app"
	"github.com/writer/cerebro/internal/functionscan"
)

var functionScanCmd = &cobra.Command{
	Use:   "function-scan",
	Short: "Run and inspect durable serverless function package scans",
}

var functionScanListCmd = &cobra.Command{
	Use:   "list",
	Short: "List persisted function scan runs",
	RunE:  runFunctionScanList,
}

var functionScanRunCmd = &cobra.Command{
	Use:   "run",
	Short: "Run a serverless function package scan",
}

var functionScanRunAWSCmd = &cobra.Command{
	Use:   "aws",
	Short: "Run an AWS Lambda package scan",
	RunE:  runFunctionScanAWS,
}

var functionScanRunGCPCmd = &cobra.Command{
	Use:   "gcp",
	Short: "Run a Google Cloud Function package scan",
	RunE:  runFunctionScanGCP,
}

var functionScanRunAzureCmd = &cobra.Command{
	Use:   "azure",
	Short: "Run an Azure Functions package scan",
	RunE:  runFunctionScanAzure,
}

var (
	functionScanOutput         string
	functionScanStateFile      string
	functionScanRootFSBasePath string
	functionScanCleanupTimeout time.Duration
	functionScanTrivyBinary    string
	functionScanGitleaksBinary string
	functionScanClamAVBinary   string
	functionScanListStatuses   string
	functionScanListLimit      int
	functionScanRequestedBy    string
	functionScanDryRun         bool
	functionScanKeepFilesystem bool
	functionScanMetadataPairs  []string

	functionScanAWSRegion      string
	functionScanAWSAccountID   string
	functionScanAWSFunction    string
	functionScanAWSFunctionARN string

	functionScanGCPProjectID    string
	functionScanGCPLocation     string
	functionScanGCPFunctionName string

	functionScanAzureSubscriptionID string
	functionScanAzureResourceGroup  string
	functionScanAzureAppName        string
)

func init() {
	functionScanCmd.PersistentFlags().StringVarP(&functionScanOutput, "output", "o", FormatTable, "Output format (table,json)")
	functionScanCmd.PersistentFlags().StringVar(&functionScanStateFile, "state-file", "", "Override function scan SQLite state path")
	functionScanCmd.PersistentFlags().StringVar(&functionScanRootFSBasePath, "rootfs-base", "", "Override function scan rootfs materialization path")
	functionScanCmd.PersistentFlags().DurationVar(&functionScanCleanupTimeout, "cleanup-timeout", 0, "Override function scan cleanup timeout")
	functionScanCmd.PersistentFlags().StringVar(&functionScanTrivyBinary, "trivy-binary", "", "Override trivy binary path")
	functionScanCmd.PersistentFlags().StringVar(&functionScanGitleaksBinary, "gitleaks-binary", "", "Optional gitleaks binary path for expanded secret scanning")
	functionScanCmd.PersistentFlags().StringVar(&functionScanClamAVBinary, "clamav-binary", "", "Optional ClamAV clamscan binary path for malware scanning")

	functionScanListCmd.Flags().StringVar(&functionScanListStatuses, "status", "", "Optional comma-separated status filter")
	functionScanListCmd.Flags().IntVar(&functionScanListLimit, "limit", 20, "Maximum runs to list")

	functionScanRunCmd.PersistentFlags().StringVar(&functionScanRequestedBy, "requested-by", "", "Optional operator identity recorded on the run")
	functionScanRunCmd.PersistentFlags().BoolVar(&functionScanDryRun, "dry-run", false, "Resolve metadata only; do not materialize or analyze packages")
	functionScanRunCmd.PersistentFlags().BoolVar(&functionScanKeepFilesystem, "keep-filesystem", false, "Retain the materialized filesystem after completion")
	functionScanRunCmd.PersistentFlags().StringSliceVar(&functionScanMetadataPairs, "metadata", nil, "Optional metadata entries (key=value)")

	functionScanRunAWSCmd.Flags().StringVar(&functionScanAWSRegion, "region", "", "AWS region containing the target Lambda function")
	functionScanRunAWSCmd.Flags().StringVar(&functionScanAWSAccountID, "account-id", "", "Optional AWS account ID owning the target Lambda function")
	functionScanRunAWSCmd.Flags().StringVar(&functionScanAWSFunction, "function-name", "", "Lambda function name")
	functionScanRunAWSCmd.Flags().StringVar(&functionScanAWSFunctionARN, "function-arn", "", "Optional Lambda function ARN override")
	_ = functionScanRunAWSCmd.MarkFlagRequired("region")

	functionScanRunGCPCmd.Flags().StringVar(&functionScanGCPProjectID, "project-id", "", "GCP project ID for the target function")
	functionScanRunGCPCmd.Flags().StringVar(&functionScanGCPLocation, "location", "", "GCP location for the target function")
	functionScanRunGCPCmd.Flags().StringVar(&functionScanGCPFunctionName, "function-name", "", "Cloud Function name")
	_ = functionScanRunGCPCmd.MarkFlagRequired("project-id")
	_ = functionScanRunGCPCmd.MarkFlagRequired("location")
	_ = functionScanRunGCPCmd.MarkFlagRequired("function-name")

	functionScanRunAzureCmd.Flags().StringVar(&functionScanAzureSubscriptionID, "subscription-id", "", "Azure subscription ID for the target Function App")
	functionScanRunAzureCmd.Flags().StringVar(&functionScanAzureResourceGroup, "resource-group", "", "Azure resource group for the target Function App")
	functionScanRunAzureCmd.Flags().StringVar(&functionScanAzureAppName, "app-name", "", "Azure Function App name")
	_ = functionScanRunAzureCmd.MarkFlagRequired("subscription-id")
	_ = functionScanRunAzureCmd.MarkFlagRequired("resource-group")
	_ = functionScanRunAzureCmd.MarkFlagRequired("app-name")

	functionScanCmd.AddCommand(functionScanListCmd)
	functionScanRunCmd.AddCommand(functionScanRunAWSCmd)
	functionScanRunCmd.AddCommand(functionScanRunGCPCmd)
	functionScanRunCmd.AddCommand(functionScanRunAzureCmd)
	functionScanCmd.AddCommand(functionScanRunCmd)
}

func runFunctionScanList(cmd *cobra.Command, _ []string) error {
	cfg := app.LoadConfig()
	store, err := functionscan.NewSQLiteRunStore(resolveFunctionScanStateFile(cfg))
	if err != nil {
		return err
	}
	defer func() { _ = store.Close() }()

	statuses, err := parseFunctionRunStatuses(functionScanListStatuses)
	if err != nil {
		return err
	}
	runs, err := store.ListRuns(cmd.Context(), functionscan.RunListOptions{
		Statuses: statuses,
		Limit:    functionScanListLimit,
	})
	if err != nil {
		return err
	}
	return renderFunctionRuns(runs)
}

func runFunctionScanAWS(cmd *cobra.Command, _ []string) error {
	target := functionscan.FunctionTarget{
		Provider:     functionscan.ProviderAWS,
		AccountID:    strings.TrimSpace(functionScanAWSAccountID),
		Region:       strings.TrimSpace(functionScanAWSRegion),
		FunctionName: strings.TrimSpace(functionScanAWSFunction),
		FunctionARN:  strings.TrimSpace(functionScanAWSFunctionARN),
	}
	return runFunctionScan(cmd.Context(), target, func(ctx context.Context) (functionscan.Provider, error) {
		return functionscan.NewAWSProvider(ctx, target.Region)
	})
}

func runFunctionScanGCP(cmd *cobra.Command, _ []string) error {
	target := functionscan.FunctionTarget{
		Provider:     functionscan.ProviderGCP,
		ProjectID:    strings.TrimSpace(functionScanGCPProjectID),
		Location:     strings.TrimSpace(functionScanGCPLocation),
		FunctionName: strings.TrimSpace(functionScanGCPFunctionName),
	}
	return runFunctionScan(cmd.Context(), target, func(ctx context.Context) (functionscan.Provider, error) {
		return functionscan.NewGCPProvider(ctx)
	})
}

func runFunctionScanAzure(cmd *cobra.Command, _ []string) error {
	target := functionscan.FunctionTarget{
		Provider:       functionscan.ProviderAzure,
		SubscriptionID: strings.TrimSpace(functionScanAzureSubscriptionID),
		ResourceGroup:  strings.TrimSpace(functionScanAzureResourceGroup),
		AppName:        strings.TrimSpace(functionScanAzureAppName),
	}
	return runFunctionScan(cmd.Context(), target, func(context.Context) (functionscan.Provider, error) {
		return functionscan.NewAzureProvider(target.SubscriptionID)
	})
}

func runFunctionScan(parent context.Context, target functionscan.FunctionTarget, providerFactory func(context.Context) (functionscan.Provider, error)) error {
	ctx, cancel := signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
	defer cancel()

	cfg := app.LoadConfig()
	policyEvaluator, err := loadScanPolicyEvaluator(cfg)
	if err != nil {
		return err
	}
	store, err := functionscan.NewSQLiteRunStore(resolveFunctionScanStateFile(cfg))
	if err != nil {
		return err
	}
	defer func() { _ = store.Close() }()

	emitter, err := newWorkloadScanEmitter(cfg, slog.Default())
	if err != nil {
		return err
	}
	defer func() { _ = emitter.Close() }()
	filesystemAnalyzer, vulnDBCloser, err := buildFilesystemAnalyzer(cfg, resolveFunctionScanTrivyBinary(cfg), resolveFunctionScanGitleaksBinary(cfg), resolveFunctionScanClamAVBinary(cfg))
	if err != nil {
		return err
	}
	defer func() { _ = vulnDBCloser.Close() }()

	provider, err := providerFactory(ctx)
	if err != nil {
		return err
	}
	if closer, ok := provider.(interface{ Close() error }); ok {
		defer func() { _ = closer.Close() }()
	}

	runner := functionscan.NewRunner(functionscan.RunnerOptions{
		Store:           store,
		Providers:       []functionscan.Provider{provider},
		Materializer:    functionscan.NewLocalMaterializer(resolveFunctionScanRootFSBasePath(cfg)),
		Analyzer:        functionscan.FilesystemAnalyzer{Analyzer: filesystemAnalyzer},
		Events:          emitter,
		CleanupTimeout:  resolveFunctionScanCleanupTimeout(cfg),
		PolicyEvaluator: policyEvaluator,
	})

	run, runErr := runner.RunFunctionScan(ctx, functionscan.ScanRequest{
		RequestedBy:    functionScanRequestedBy,
		Target:         target,
		DryRun:         functionScanDryRun,
		KeepFilesystem: functionScanKeepFilesystem,
		Metadata:       parseMetadataPairs(functionScanMetadataPairs),
		SubmittedAt:    time.Now().UTC(),
	})
	if run != nil {
		if err := renderFunctionRun(*run); err != nil {
			return err
		}
	}
	return runErr
}

func renderFunctionRuns(runs []functionscan.RunRecord) error {
	if functionScanOutput == FormatJSON {
		return JSONOutput(runs)
	}
	if len(runs) == 0 {
		fmt.Println("No function scan runs found.")
		return nil
	}
	tw := NewTableWriter(os.Stdout, "Run ID", "Provider", "Status", "Stage", "Target", "Runtime", "Findings", "Updated")
	for _, run := range runs {
		runtime := ""
		findings := 0
		if run.Descriptor != nil {
			runtime = run.Descriptor.Runtime
		}
		if run.Analysis != nil {
			findings = len(run.Analysis.Result.Findings) + len(run.Analysis.Result.Vulnerabilities)
		}
		tw.AddRow(run.ID, string(run.Provider), statusColor(string(run.Status)), string(run.Stage), run.Target.Identity(), runtime, fmt.Sprintf("%d", findings), run.UpdatedAt.Format(time.RFC3339))
	}
	tw.Render()
	return nil
}

func renderFunctionRun(run functionscan.RunRecord) error {
	if functionScanOutput == FormatJSON {
		return JSONOutput(run)
	}
	fmt.Printf("Run ID:      %s\n", run.ID)
	fmt.Printf("Provider:    %s\n", run.Provider)
	fmt.Printf("Target:      %s\n", run.Target.Identity())
	fmt.Printf("Status:      %s\n", statusColor(string(run.Status)))
	fmt.Printf("Stage:       %s\n", run.Stage)
	if run.Descriptor != nil {
		fmt.Printf("Runtime:     %s\n", run.Descriptor.Runtime)
		fmt.Printf("EntryPoint:  %s\n", run.Descriptor.EntryPoint)
		fmt.Printf("Artifacts:   %d\n", len(run.Descriptor.Artifacts))
	}
	if run.Filesystem != nil {
		fmt.Printf("Filesystem:  %s\n", run.Filesystem.Path)
	}
	if run.Analysis != nil {
		fmt.Printf("Analyzer:    %s\n", run.Analysis.Analyzer)
		fmt.Printf("Vulns:       %d (critical=%d high=%d medium=%d low=%d)\n",
			len(run.Analysis.Result.Vulnerabilities),
			run.Analysis.Result.Summary.Critical,
			run.Analysis.Result.Summary.High,
			run.Analysis.Result.Summary.Medium,
			run.Analysis.Result.Summary.Low,
		)
		fmt.Printf("Secrets:     env=%d code=%d\n", run.Analysis.EnvironmentSecretCount, run.Analysis.CodeSecretCount)
		if run.Analysis.RuntimeDeprecated {
			fmt.Printf("Runtime EOL: true\n")
		}
	}
	if run.Error != "" {
		fmt.Printf("Error:       %s\n", run.Error)
	}
	return nil
}

func parseFunctionRunStatuses(raw string) ([]functionscan.RunStatus, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	parts := strings.Split(raw, ",")
	statuses := make([]functionscan.RunStatus, 0, len(parts))
	for _, part := range parts {
		status := functionscan.RunStatus(strings.TrimSpace(part))
		switch status {
		case functionscan.RunStatusQueued, functionscan.RunStatusRunning, functionscan.RunStatusSucceeded, functionscan.RunStatusFailed:
			statuses = append(statuses, status)
		default:
			return nil, fmt.Errorf("invalid function scan status %q", part)
		}
	}
	return statuses, nil
}

func resolveFunctionScanStateFile(cfg *app.Config) string {
	if strings.TrimSpace(functionScanStateFile) != "" {
		return strings.TrimSpace(functionScanStateFile)
	}
	if cfg != nil && strings.TrimSpace(cfg.FunctionScanStateFile) != "" {
		return strings.TrimSpace(cfg.FunctionScanStateFile)
	}
	return ".cerebro/executions.db"
}

func resolveFunctionScanRootFSBasePath(cfg *app.Config) string {
	if strings.TrimSpace(functionScanRootFSBasePath) != "" {
		return strings.TrimSpace(functionScanRootFSBasePath)
	}
	if cfg != nil && strings.TrimSpace(cfg.FunctionScanRootFSBasePath) != "" {
		return strings.TrimSpace(cfg.FunctionScanRootFSBasePath)
	}
	return ".cerebro/function-scan/rootfs"
}

func resolveFunctionScanCleanupTimeout(cfg *app.Config) time.Duration {
	if functionScanCleanupTimeout > 0 {
		return functionScanCleanupTimeout
	}
	if cfg != nil && cfg.FunctionScanCleanupTimeout > 0 {
		return cfg.FunctionScanCleanupTimeout
	}
	return 2 * time.Minute
}

func resolveFunctionScanTrivyBinary(cfg *app.Config) string {
	if strings.TrimSpace(functionScanTrivyBinary) != "" {
		return strings.TrimSpace(functionScanTrivyBinary)
	}
	if cfg != nil && strings.TrimSpace(cfg.FunctionScanTrivyBinary) != "" {
		return strings.TrimSpace(cfg.FunctionScanTrivyBinary)
	}
	return "trivy"
}

func resolveFunctionScanGitleaksBinary(cfg *app.Config) string {
	if strings.TrimSpace(functionScanGitleaksBinary) != "" {
		return strings.TrimSpace(functionScanGitleaksBinary)
	}
	if cfg != nil && strings.TrimSpace(cfg.FunctionScanGitleaksBinary) != "" {
		return strings.TrimSpace(cfg.FunctionScanGitleaksBinary)
	}
	return ""
}

func resolveFunctionScanClamAVBinary(cfg *app.Config) string {
	if strings.TrimSpace(functionScanClamAVBinary) != "" {
		return strings.TrimSpace(functionScanClamAVBinary)
	}
	if cfg != nil && strings.TrimSpace(cfg.FunctionScanClamAVBinary) != "" {
		return strings.TrimSpace(cfg.FunctionScanClamAVBinary)
	}
	return ""
}
