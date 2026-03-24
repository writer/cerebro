package cli

import (
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/writer/cerebro/internal/app"
	"github.com/writer/cerebro/internal/reposcan"
	"github.com/writer/cerebro/internal/scanner"
	"github.com/writer/cerebro/internal/scm"
)

var repoScanCmd = &cobra.Command{
	Use:   "repo-scan",
	Short: "Run and inspect durable repository IaC scans",
}

var repoScanListCmd = &cobra.Command{
	Use:   "list",
	Short: "List persisted repository scan runs",
	RunE:  runRepoScanList,
}

var repoScanRunCmd = &cobra.Command{
	Use:   "run",
	Short: "Run a repository IaC scan",
	RunE:  runRepoScan,
}

var (
	repoScanOutput           string
	repoScanStateFile        string
	repoScanCheckoutBasePath string
	repoScanListStatuses     string
	repoScanListLimit        int
	repoScanRequestedBy      string
	repoScanDryRun           bool
	repoScanKeepCheckout     bool
	repoScanMetadataPairs    []string
	repoScanRepoURL          string
	repoScanRef              string
)

func init() {
	repoScanCmd.PersistentFlags().StringVarP(&repoScanOutput, "output", "o", FormatTable, "Output format (table,json)")
	repoScanCmd.PersistentFlags().StringVar(&repoScanStateFile, "state-file", "", "Override repository scan SQLite state path")
	repoScanCmd.PersistentFlags().StringVar(&repoScanCheckoutBasePath, "checkout-base", "", "Override repository scan checkout base path")

	repoScanListCmd.Flags().StringVar(&repoScanListStatuses, "status", "", "Optional comma-separated status filter")
	repoScanListCmd.Flags().IntVar(&repoScanListLimit, "limit", 20, "Maximum runs to list")

	repoScanRunCmd.Flags().StringVar(&repoScanRepoURL, "repo-url", "", "Git repository URL or local path to clone")
	repoScanRunCmd.Flags().StringVar(&repoScanRef, "ref", "", "Optional branch, tag, or commit to scan")
	repoScanRunCmd.Flags().StringVar(&repoScanRequestedBy, "requested-by", "", "Optional operator identity recorded on the run")
	repoScanRunCmd.Flags().BoolVar(&repoScanDryRun, "dry-run", false, "Clone and resolve revision only; skip IaC analysis")
	repoScanRunCmd.Flags().BoolVar(&repoScanKeepCheckout, "keep-checkout", false, "Retain the cloned checkout after completion")
	repoScanRunCmd.Flags().StringSliceVar(&repoScanMetadataPairs, "metadata", nil, "Optional metadata entries (key=value)")
	_ = repoScanRunCmd.MarkFlagRequired("repo-url")

	repoScanCmd.AddCommand(repoScanListCmd)
	repoScanCmd.AddCommand(repoScanRunCmd)
}

func runRepoScanList(cmd *cobra.Command, _ []string) error {
	cfg := app.LoadConfig()
	store, err := reposcan.NewSQLiteRunStore(resolveRepoScanStateFile(cfg))
	if err != nil {
		return err
	}
	defer func() { _ = store.Close() }()

	statuses, err := parseRepoScanRunStatuses(repoScanListStatuses)
	if err != nil {
		return err
	}
	runs, err := store.ListRuns(cmd.Context(), reposcan.RunListOptions{
		Statuses: statuses,
		Limit:    repoScanListLimit,
	})
	if err != nil {
		return err
	}
	return renderRepoScanRuns(runs)
}

func runRepoScan(cmd *cobra.Command, _ []string) error {
	ctx, cancel := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	cfg := app.LoadConfig()
	policyEvaluator, err := loadScanPolicyEvaluator(cfg)
	if err != nil {
		return err
	}
	store, err := reposcan.NewSQLiteRunStore(resolveRepoScanStateFile(cfg))
	if err != nil {
		return err
	}
	defer func() { _ = store.Close() }()

	runner := reposcan.NewRunner(reposcan.RunnerOptions{
		Store:           store,
		Materializer:    reposcan.NewLocalMaterializer(resolveRepoScanCheckoutBasePath(), scm.NewLocalClient("")),
		Analyzer:        reposcan.FilesystemAnalyzer{ConfigScanner: scanner.NewTrivyConfigScanner("")},
		PolicyEvaluator: policyEvaluator,
	})

	run, runErr := runner.RunRepositoryScan(ctx, reposcan.ScanRequest{
		RequestedBy:  repoScanRequestedBy,
		Target:       reposcan.ScanTarget{RepoURL: strings.TrimSpace(repoScanRepoURL), Ref: strings.TrimSpace(repoScanRef)},
		DryRun:       repoScanDryRun,
		KeepCheckout: repoScanKeepCheckout,
		Metadata:     parseMetadataPairs(repoScanMetadataPairs),
		SubmittedAt:  time.Now().UTC(),
	})
	if run != nil {
		if err := renderRepoScanRun(*run); err != nil {
			return err
		}
	}
	return runErr
}

func renderRepoScanRuns(runs []reposcan.RunRecord) error {
	if repoScanOutput == FormatJSON {
		return JSONOutput(runs)
	}
	if len(runs) == 0 {
		fmt.Println("No repository scan runs found.")
		return nil
	}
	tw := NewTableWriter(os.Stdout, "Run ID", "Status", "Stage", "Repository", "Commit", "IaC", "Misconfigs", "Updated")
	for _, run := range runs {
		commit := ""
		iacCount := 0
		misconfigCount := 0
		if run.Descriptor != nil {
			commit = shortCommit(run.Descriptor.CommitSHA)
		}
		if run.Analysis != nil {
			iacCount = run.Analysis.IaCArtifactCount
			misconfigCount = run.Analysis.MisconfigurationCount
		}
		tw.AddRow(
			run.ID,
			statusColor(string(run.Status)),
			string(run.Stage),
			run.Target.Identity(),
			commit,
			fmt.Sprintf("%d", iacCount),
			fmt.Sprintf("%d", misconfigCount),
			run.UpdatedAt.Format(time.RFC3339),
		)
	}
	tw.Render()
	return nil
}

func renderRepoScanRun(run reposcan.RunRecord) error {
	if repoScanOutput == FormatJSON {
		return JSONOutput(run)
	}
	fmt.Printf("Run ID:      %s\n", run.ID)
	fmt.Printf("Repository:  %s\n", run.Target.Identity())
	fmt.Printf("Status:      %s\n", statusColor(string(run.Status)))
	fmt.Printf("Stage:       %s\n", run.Stage)
	if run.Descriptor != nil {
		fmt.Printf("Commit:      %s\n", run.Descriptor.CommitSHA)
		if run.Descriptor.ResolvedRef != "" {
			fmt.Printf("ResolvedRef: %s\n", run.Descriptor.ResolvedRef)
		}
	}
	if run.Checkout != nil {
		fmt.Printf("Checkout:    %s\n", run.Checkout.Path)
	}
	if run.Analysis != nil {
		fmt.Printf("Analyzer:    %s\n", run.Analysis.Analyzer)
		fmt.Printf("IaC:         %d\n", run.Analysis.IaCArtifactCount)
		fmt.Printf("Misconfigs:  %d\n", run.Analysis.MisconfigurationCount)
	}
	if run.Error != "" {
		fmt.Printf("Error:       %s\n", run.Error)
	}
	return nil
}

func parseRepoScanRunStatuses(raw string) ([]reposcan.RunStatus, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	parts := strings.Split(raw, ",")
	statuses := make([]reposcan.RunStatus, 0, len(parts))
	for _, part := range parts {
		status := reposcan.RunStatus(strings.TrimSpace(part))
		switch status {
		case reposcan.RunStatusQueued, reposcan.RunStatusRunning, reposcan.RunStatusSucceeded, reposcan.RunStatusFailed:
			statuses = append(statuses, status)
		default:
			return nil, fmt.Errorf("invalid repo scan status %q", part)
		}
	}
	return statuses, nil
}

func resolveRepoScanStateFile(cfg *app.Config) string {
	if strings.TrimSpace(repoScanStateFile) != "" {
		return strings.TrimSpace(repoScanStateFile)
	}
	if cfg != nil && strings.TrimSpace(cfg.ExecutionStoreFile) != "" {
		return strings.TrimSpace(cfg.ExecutionStoreFile)
	}
	return ".cerebro/executions.db"
}

func resolveRepoScanCheckoutBasePath() string {
	if strings.TrimSpace(repoScanCheckoutBasePath) != "" {
		return strings.TrimSpace(repoScanCheckoutBasePath)
	}
	return ".cerebro/repo-scan/checkouts"
}

func shortCommit(commit string) string {
	trimmed := strings.TrimSpace(commit)
	if len(trimmed) <= 12 {
		return trimmed
	}
	return trimmed[:12]
}
