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
	"github.com/writer/cerebro/internal/filesystemanalyzer"
	"github.com/writer/cerebro/internal/repohistoryscan"
	"github.com/writer/cerebro/internal/scm"
)

var repoSecretScanCmd = &cobra.Command{
	Use:   "repo-secret-scan",
	Short: "Run and inspect durable git history secret scans",
}

var repoSecretScanListCmd = &cobra.Command{
	Use:   "list",
	Short: "List persisted repository history secret scan runs",
	RunE:  runRepoSecretScanList,
}

var repoSecretScanRunCmd = &cobra.Command{
	Use:   "run",
	Short: "Run a git history secret scan for a repository",
	RunE:  runRepoSecretScan,
}

var (
	repoSecretScanOutput           string
	repoSecretScanStateFile        string
	repoSecretScanCheckoutBasePath string
	repoSecretScanGitleaksBinary   string
	repoSecretScanTruffleHogBinary string
	repoSecretScanListStatuses     string
	repoSecretScanListLimit        int
	repoSecretScanRequestedBy      string
	repoSecretScanDryRun           bool
	repoSecretScanKeepCheckout     bool
	repoSecretScanMetadataPairs    []string
	repoSecretScanRepoURL          string
	repoSecretScanRef              string
	repoSecretScanSinceCommit      string
)

func init() {
	repoSecretScanCmd.PersistentFlags().StringVarP(&repoSecretScanOutput, "output", "o", FormatTable, "Output format (table,json)")
	repoSecretScanCmd.PersistentFlags().StringVar(&repoSecretScanStateFile, "state-file", "", "Override repository history scan SQLite state path")
	repoSecretScanCmd.PersistentFlags().StringVar(&repoSecretScanCheckoutBasePath, "checkout-base", "", "Override repository history scan checkout base path")
	repoSecretScanCmd.PersistentFlags().StringVar(&repoSecretScanGitleaksBinary, "gitleaks-binary", "", "Override gitleaks binary path")
	repoSecretScanCmd.PersistentFlags().StringVar(&repoSecretScanTruffleHogBinary, "trufflehog-binary", "", "Override trufflehog binary path")

	repoSecretScanListCmd.Flags().StringVar(&repoSecretScanListStatuses, "status", "", "Optional comma-separated status filter")
	repoSecretScanListCmd.Flags().IntVar(&repoSecretScanListLimit, "limit", 20, "Maximum runs to list")

	repoSecretScanRunCmd.Flags().StringVar(&repoSecretScanRepoURL, "repo-url", "", "Git repository URL or local path to clone")
	repoSecretScanRunCmd.Flags().StringVar(&repoSecretScanRef, "ref", "", "Optional branch, tag, or commit to scan")
	repoSecretScanRunCmd.Flags().StringVar(&repoSecretScanSinceCommit, "since-commit", "", "Optional last-scanned commit; only findings from newer commits are retained")
	repoSecretScanRunCmd.Flags().StringVar(&repoSecretScanRequestedBy, "requested-by", "", "Optional operator identity recorded on the run")
	repoSecretScanRunCmd.Flags().BoolVar(&repoSecretScanDryRun, "dry-run", false, "Clone and resolve revision only; skip history scanning")
	repoSecretScanRunCmd.Flags().BoolVar(&repoSecretScanKeepCheckout, "keep-checkout", false, "Retain the cloned checkout after completion")
	repoSecretScanRunCmd.Flags().StringSliceVar(&repoSecretScanMetadataPairs, "metadata", nil, "Optional metadata entries (key=value)")
	_ = repoSecretScanRunCmd.MarkFlagRequired("repo-url")

	repoSecretScanCmd.AddCommand(repoSecretScanListCmd)
	repoSecretScanCmd.AddCommand(repoSecretScanRunCmd)
}

func runRepoSecretScanList(cmd *cobra.Command, _ []string) error {
	cfg := app.LoadConfig()
	store, err := repohistoryscan.NewSQLiteRunStore(resolveRepoSecretScanStateFile(cfg))
	if err != nil {
		return err
	}
	defer func() { _ = store.Close() }()

	statuses, err := parseRepoSecretScanRunStatuses(repoSecretScanListStatuses)
	if err != nil {
		return err
	}
	runs, err := store.ListRuns(cmd.Context(), repohistoryscan.RunListOptions{
		Statuses: statuses,
		Limit:    repoSecretScanListLimit,
	})
	if err != nil {
		return err
	}
	return renderRepoSecretScanRuns(runs)
}

func runRepoSecretScan(cmd *cobra.Command, _ []string) error {
	ctx, cancel := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	cfg := app.LoadConfig()
	policyEvaluator, err := loadScanPolicyEvaluator(cfg)
	if err != nil {
		return err
	}
	store, err := repohistoryscan.NewSQLiteRunStore(resolveRepoSecretScanStateFile(cfg))
	if err != nil {
		return err
	}
	defer func() { _ = store.Close() }()

	scmClient := scm.NewAutoClient(scm.NewConfiguredClient(
		cfg.GitHubToken,
		cfg.GitLabToken,
		cfg.GitLabBaseURL,
	))
	runner := repohistoryscan.NewRunner(repohistoryscan.RunnerOptions{
		Store:        store,
		Materializer: repohistoryscan.NewLocalMaterializer(resolveRepoSecretScanCheckoutBasePath(), scmClient),
		Scanner: filesystemanalyzer.NewCompositeGitHistoryScanner(
			filesystemanalyzer.NewGitleaksGitScanner(resolveRepoSecretScanGitleaksBinary()),
			filesystemanalyzer.NewTruffleHogGitScanner(resolveRepoSecretScanTruffleHogBinary()),
		),
		PolicyEvaluator: policyEvaluator,
	})

	run, runErr := runner.RunRepositoryHistoryScan(ctx, repohistoryscan.ScanRequest{
		RequestedBy:  repoSecretScanRequestedBy,
		Target:       repohistoryscan.ScanTarget{RepoURL: strings.TrimSpace(repoSecretScanRepoURL), Ref: strings.TrimSpace(repoSecretScanRef), SinceCommit: strings.TrimSpace(repoSecretScanSinceCommit)},
		DryRun:       repoSecretScanDryRun,
		KeepCheckout: repoSecretScanKeepCheckout,
		Metadata:     parseMetadataPairs(repoSecretScanMetadataPairs),
		SubmittedAt:  time.Now().UTC(),
	})
	if run != nil {
		if err := renderRepoSecretScanRun(*run); err != nil {
			return err
		}
	}
	return runErr
}

func renderRepoSecretScanRuns(runs []repohistoryscan.RunRecord) error {
	if repoSecretScanOutput == FormatJSON {
		return JSONOutput(runs)
	}
	if len(runs) == 0 {
		fmt.Println("No repository history secret scan runs found.")
		return nil
	}
	tw := NewTableWriter(os.Stdout, "Run ID", "Status", "Stage", "Repository", "Commit", "Findings", "Verified", "Updated")
	for _, run := range runs {
		commit := ""
		findings := 0
		verified := 0
		if run.Descriptor != nil {
			commit = shortCommit(run.Descriptor.CommitSHA)
		}
		if run.Analysis != nil {
			findings = run.Analysis.TotalFindings
			verified = run.Analysis.VerifiedFindings
		}
		tw.AddRow(
			run.ID,
			statusColor(string(run.Status)),
			string(run.Stage),
			run.Target.Identity(),
			commit,
			fmt.Sprintf("%d", findings),
			fmt.Sprintf("%d", verified),
			run.UpdatedAt.Format(time.RFC3339),
		)
	}
	tw.Render()
	return nil
}

func renderRepoSecretScanRun(run repohistoryscan.RunRecord) error {
	if repoSecretScanOutput == FormatJSON {
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
	if run.Analysis != nil {
		fmt.Printf("Engine:      %s\n", run.Analysis.Engine)
		fmt.Printf("Findings:    %d\n", run.Analysis.TotalFindings)
		fmt.Printf("Verified:    %d\n", run.Analysis.VerifiedFindings)
	}
	if run.Error != "" {
		fmt.Printf("Error:       %s\n", run.Error)
	}
	return nil
}

func parseRepoSecretScanRunStatuses(raw string) ([]repohistoryscan.RunStatus, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	parts := strings.Split(raw, ",")
	statuses := make([]repohistoryscan.RunStatus, 0, len(parts))
	for _, part := range parts {
		status := repohistoryscan.RunStatus(strings.TrimSpace(part))
		switch status {
		case repohistoryscan.RunStatusQueued, repohistoryscan.RunStatusRunning, repohistoryscan.RunStatusSucceeded, repohistoryscan.RunStatusFailed:
			statuses = append(statuses, status)
		default:
			return nil, fmt.Errorf("invalid repo secret scan status %q", part)
		}
	}
	return statuses, nil
}

func resolveRepoSecretScanStateFile(cfg *app.Config) string {
	if strings.TrimSpace(repoSecretScanStateFile) != "" {
		return strings.TrimSpace(repoSecretScanStateFile)
	}
	if cfg != nil && strings.TrimSpace(cfg.ExecutionStoreFile) != "" {
		return strings.TrimSpace(cfg.ExecutionStoreFile)
	}
	return ".cerebro/executions.db"
}

func resolveRepoSecretScanCheckoutBasePath() string {
	if strings.TrimSpace(repoSecretScanCheckoutBasePath) != "" {
		return strings.TrimSpace(repoSecretScanCheckoutBasePath)
	}
	return ".cerebro/repo-history-scan"
}

func resolveRepoSecretScanGitleaksBinary() string {
	if strings.TrimSpace(repoSecretScanGitleaksBinary) != "" {
		return strings.TrimSpace(repoSecretScanGitleaksBinary)
	}
	return "gitleaks"
}

func resolveRepoSecretScanTruffleHogBinary() string {
	if strings.TrimSpace(repoSecretScanTruffleHogBinary) != "" {
		return strings.TrimSpace(repoSecretScanTruffleHogBinary)
	}
	return "trufflehog"
}
