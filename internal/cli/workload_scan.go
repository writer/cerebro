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
	"github.com/writer/cerebro/internal/events"
	"github.com/writer/cerebro/internal/webhooks"
	"github.com/writer/cerebro/internal/workloadscan"
)

var workloadScanCmd = &cobra.Command{
	Use:   "workload-scan",
	Short: "Run and reconcile agentless workload snapshot scans",
}

var workloadScanListCmd = &cobra.Command{
	Use:   "list",
	Short: "List persisted workload scan runs",
	RunE:  runWorkloadScanList,
}

var workloadScanRunCmd = &cobra.Command{
	Use:   "run",
	Short: "Run a workload snapshot scan",
}

var workloadScanRunAWSCmd = &cobra.Command{
	Use:   "aws",
	Short: "Run an AWS VM snapshot scan",
	RunE:  runWorkloadScanAWS,
}

var workloadScanReconcileCmd = &cobra.Command{
	Use:   "reconcile",
	Short: "Reconcile leaked workload scan artifacts",
}

var workloadScanReconcileAWSCmd = &cobra.Command{
	Use:   "aws",
	Short: "Reconcile leaked AWS VM snapshot scan artifacts",
	RunE:  reconcileWorkloadScanAWS,
}

var (
	workloadScanOutput              string
	workloadScanStateFile           string
	workloadScanMountBasePath       string
	workloadScanMaxConcurrent       int
	workloadScanCleanupTimeout      time.Duration
	workloadScanReconcileOlderThan  time.Duration
	workloadScanTrivyBinary         string
	workloadScanListStatuses        string
	workloadScanListLimit           int
	workloadScanAWSRegion           string
	workloadScanAWSInstanceID       string
	workloadScanAWSAccountID        string
	workloadScanAWSScannerInstance  string
	workloadScanAWSScannerAccountID string
	workloadScanAWSScannerZone      string
	workloadScanRequestedBy         string
	workloadScanDryRun              bool
	workloadScanMetadataPairs       []string
)

func init() {
	workloadScanCmd.PersistentFlags().StringVarP(&workloadScanOutput, "output", "o", FormatTable, "Output format (table,json)")
	workloadScanCmd.PersistentFlags().StringVar(&workloadScanStateFile, "state-file", "", "Override workload scan SQLite state path")
	workloadScanCmd.PersistentFlags().StringVar(&workloadScanMountBasePath, "mount-base", "", "Override workload scan mount base path")
	workloadScanCmd.PersistentFlags().IntVar(&workloadScanMaxConcurrent, "max-concurrent-snapshots", 0, "Override max concurrent snapshots per scan")
	workloadScanCmd.PersistentFlags().DurationVar(&workloadScanCleanupTimeout, "cleanup-timeout", 0, "Override cleanup timeout")
	workloadScanCmd.PersistentFlags().DurationVar(&workloadScanReconcileOlderThan, "reconcile-older-than", 0, "Override minimum run age before reconciliation")
	workloadScanCmd.PersistentFlags().StringVar(&workloadScanTrivyBinary, "trivy-binary", "", "Override trivy binary path")

	workloadScanListCmd.Flags().StringVar(&workloadScanListStatuses, "status", "", "Optional comma-separated status filter")
	workloadScanListCmd.Flags().IntVar(&workloadScanListLimit, "limit", 20, "Maximum runs to list")

	workloadScanRunAWSCmd.Flags().StringVar(&workloadScanAWSRegion, "region", "", "AWS region containing the target instance")
	workloadScanRunAWSCmd.Flags().StringVar(&workloadScanAWSInstanceID, "instance-id", "", "Target EC2 instance ID")
	workloadScanRunAWSCmd.Flags().StringVar(&workloadScanAWSAccountID, "account-id", "", "Optional target AWS account ID")
	workloadScanRunAWSCmd.Flags().StringVar(&workloadScanAWSScannerInstance, "scanner-instance-id", "", "Scanner EC2 instance ID that receives attached inspection volumes")
	workloadScanRunAWSCmd.Flags().StringVar(&workloadScanAWSScannerAccountID, "scanner-account-id", "", "Optional scanner AWS account ID for cross-account snapshot sharing")
	workloadScanRunAWSCmd.Flags().StringVar(&workloadScanAWSScannerZone, "scanner-zone", "", "Scanner EC2 availability zone for inspection volumes")
	workloadScanRunAWSCmd.Flags().StringVar(&workloadScanRequestedBy, "requested-by", "", "Optional operator identity recorded on the run")
	workloadScanRunAWSCmd.Flags().BoolVar(&workloadScanDryRun, "dry-run", false, "Inventory only; do not snapshot, attach, or mount volumes")
	workloadScanRunAWSCmd.Flags().StringSliceVar(&workloadScanMetadataPairs, "metadata", nil, "Optional metadata entries (key=value)")
	_ = workloadScanRunAWSCmd.MarkFlagRequired("region")
	_ = workloadScanRunAWSCmd.MarkFlagRequired("instance-id")
	_ = workloadScanRunAWSCmd.MarkFlagRequired("scanner-instance-id")
	_ = workloadScanRunAWSCmd.MarkFlagRequired("scanner-zone")

	workloadScanReconcileAWSCmd.Flags().StringVar(&workloadScanAWSRegion, "region", "", "AWS region containing the target workload scan artifacts")
	_ = workloadScanReconcileAWSCmd.MarkFlagRequired("region")

	workloadScanCmd.AddCommand(workloadScanListCmd)
	workloadScanRunCmd.AddCommand(workloadScanRunAWSCmd)
	workloadScanCmd.AddCommand(workloadScanRunCmd)
	workloadScanReconcileCmd.AddCommand(workloadScanReconcileAWSCmd)
	workloadScanCmd.AddCommand(workloadScanReconcileCmd)
}

func runWorkloadScanList(cmd *cobra.Command, args []string) error {
	cfg := app.LoadConfig()
	store, err := workloadscan.NewSQLiteRunStore(resolveWorkloadScanStateFile(cfg))
	if err != nil {
		return err
	}
	defer func() { _ = store.Close() }()

	statuses, err := parseWorkloadRunStatuses(workloadScanListStatuses)
	if err != nil {
		return err
	}
	runs, err := store.ListRuns(cmd.Context(), workloadscan.RunListOptions{
		Statuses: statuses,
		Limit:    workloadScanListLimit,
	})
	if err != nil {
		return err
	}
	return renderWorkloadRuns(runs)
}

func runWorkloadScanAWS(cmd *cobra.Command, args []string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	cfg := app.LoadConfig()
	store, err := workloadscan.NewSQLiteRunStore(resolveWorkloadScanStateFile(cfg))
	if err != nil {
		return err
	}
	defer func() { _ = store.Close() }()

	emitter, err := newWorkloadScanEmitter(cfg, slog.Default())
	if err != nil {
		return err
	}
	defer func() { _ = emitter.Close() }()
	filesystemAnalyzer, vulnDBCloser, err := buildFilesystemAnalyzer(cfg, resolveWorkloadScanTrivyBinary(cfg))
	if err != nil {
		return err
	}
	defer func() { _ = vulnDBCloser.Close() }()

	provider, err := workloadscan.NewAWSProvider(ctx, strings.TrimSpace(workloadScanAWSRegion))
	if err != nil {
		return err
	}
	runner := workloadscan.NewRunner(workloadscan.RunnerOptions{
		Store:                  store,
		Providers:              []workloadscan.Provider{provider},
		Mounter:                workloadscan.NewLocalMounter(resolveWorkloadScanMountBasePath(cfg)),
		Analyzer:               workloadscan.FilesystemAnalyzer{Analyzer: filesystemAnalyzer},
		Events:                 emitter,
		MaxConcurrentSnapshots: resolveWorkloadScanMaxConcurrent(cfg),
		CleanupTimeout:         resolveWorkloadScanCleanupTimeout(cfg),
	})

	run, runErr := runner.RunVMScan(ctx, workloadscan.ScanRequest{
		RequestedBy: workloadScanRequestedBy,
		Target: workloadscan.VMTarget{
			Provider:   workloadscan.ProviderAWS,
			AccountID:  strings.TrimSpace(workloadScanAWSAccountID),
			Region:     strings.TrimSpace(workloadScanAWSRegion),
			InstanceID: strings.TrimSpace(workloadScanAWSInstanceID),
		},
		ScannerHost: workloadscan.ScannerHost{
			HostID:    strings.TrimSpace(workloadScanAWSScannerInstance),
			AccountID: strings.TrimSpace(workloadScanAWSScannerAccountID),
			Region:    strings.TrimSpace(workloadScanAWSRegion),
			Zone:      strings.TrimSpace(workloadScanAWSScannerZone),
		},
		MaxConcurrentSnapshots: resolveWorkloadScanMaxConcurrent(cfg),
		DryRun:                 workloadScanDryRun,
		Metadata:               parseMetadataPairs(workloadScanMetadataPairs),
		SubmittedAt:            time.Now().UTC(),
	})
	if run != nil {
		if err := renderWorkloadRun(*run); err != nil {
			return err
		}
	}
	return runErr
}

func reconcileWorkloadScanAWS(cmd *cobra.Command, args []string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	cfg := app.LoadConfig()
	store, err := workloadscan.NewSQLiteRunStore(resolveWorkloadScanStateFile(cfg))
	if err != nil {
		return err
	}
	defer func() { _ = store.Close() }()

	emitter, err := newWorkloadScanEmitter(cfg, slog.Default())
	if err != nil {
		return err
	}
	defer func() { _ = emitter.Close() }()

	provider, err := workloadscan.NewAWSProvider(ctx, strings.TrimSpace(workloadScanAWSRegion))
	if err != nil {
		return err
	}
	runner := workloadscan.NewRunner(workloadscan.RunnerOptions{
		Store:          store,
		Providers:      []workloadscan.Provider{provider},
		Mounter:        workloadscan.NewLocalMounter(resolveWorkloadScanMountBasePath(cfg)),
		Events:         emitter,
		CleanupTimeout: resolveWorkloadScanCleanupTimeout(cfg),
	})

	reconciled, err := runner.Reconcile(ctx, resolveWorkloadScanReconcileOlderThan(cfg))
	if err != nil {
		return err
	}
	return renderWorkloadRuns(reconciled)
}

func newWorkloadScanEmitter(cfg *app.Config, logger *slog.Logger) (*webhooks.Service, error) {
	service := webhooks.NewService()
	if cfg == nil || !cfg.NATSJetStreamEnabled {
		return service, nil
	}
	publisher, err := events.NewJetStreamPublisher(events.JetStreamConfig{
		URLs:                  cfg.NATSJetStreamURLs,
		Stream:                cfg.NATSJetStreamStream,
		SubjectPrefix:         cfg.NATSJetStreamSubjectPrefix,
		Source:                cfg.NATSJetStreamSource,
		OutboxPath:            cfg.NATSJetStreamOutboxPath,
		OutboxDLQPath:         cfg.NATSJetStreamOutboxDLQPath,
		OutboxMaxRecords:      cfg.NATSJetStreamOutboxMaxItems,
		OutboxMaxAge:          cfg.NATSJetStreamOutboxMaxAge,
		OutboxMaxAttempts:     cfg.NATSJetStreamOutboxMaxRetry,
		OutboxWarnPercent:     cfg.NATSJetStreamOutboxWarnPercent,
		OutboxCriticalPercent: cfg.NATSJetStreamOutboxCriticalPercent,
		OutboxWarnAge:         cfg.NATSJetStreamOutboxWarnAge,
		OutboxCriticalAge:     cfg.NATSJetStreamOutboxCriticalAge,
		PublishTimeout:        cfg.NATSJetStreamPublishTimeout,
		RetryAttempts:         cfg.NATSJetStreamRetryAttempts,
		RetryBackoff:          cfg.NATSJetStreamRetryBackoff,
		FlushInterval:         cfg.NATSJetStreamFlushInterval,
		ConnectTimeout:        cfg.NATSJetStreamConnectTimeout,
		AuthMode:              cfg.NATSJetStreamAuthMode,
		Username:              cfg.NATSJetStreamUsername,
		Password:              cfg.NATSJetStreamPassword,
		NKeySeed:              cfg.NATSJetStreamNKeySeed,
		UserJWT:               cfg.NATSJetStreamUserJWT,
		TLSEnabled:            cfg.NATSJetStreamTLSEnabled,
		TLSCAFile:             cfg.NATSJetStreamTLSCAFile,
		TLSCertFile:           cfg.NATSJetStreamTLSCertFile,
		TLSKeyFile:            cfg.NATSJetStreamTLSKeyFile,
		TLSServerName:         cfg.NATSJetStreamTLSServerName,
		TLSInsecureSkipVerify: cfg.NATSJetStreamTLSInsecure,
	}, logger)
	if err != nil {
		return nil, fmt.Errorf("initialize workload scan event publisher: %w", err)
	}
	service.SetEventPublisher(publisher)
	return service, nil
}

func renderWorkloadRuns(runs []workloadscan.RunRecord) error {
	if workloadScanOutput == FormatJSON {
		return JSONOutput(runs)
	}
	tw := NewTableWriter(os.Stdout, "Run ID", "Provider", "Status", "Stage", "Target", "Volumes", "Findings", "Updated")
	for _, run := range runs {
		tw.AddRow(
			run.ID,
			string(run.Provider),
			statusColor(string(run.Status)),
			string(run.Stage),
			run.Target.Identity(),
			fmt.Sprintf("%d", run.Summary.VolumeCount),
			fmt.Sprintf("%d", run.Summary.Findings),
			run.UpdatedAt.UTC().Format(time.RFC3339),
		)
	}
	tw.Render()
	return nil
}

func renderWorkloadRun(run workloadscan.RunRecord) error {
	if workloadScanOutput == FormatJSON {
		return JSONOutput(run)
	}
	fmt.Println(bold("Workload Scan Run"))
	fmt.Printf("  ID:        %s\n", run.ID)
	fmt.Printf("  Provider:  %s\n", run.Provider)
	fmt.Printf("  Status:    %s\n", statusColor(string(run.Status)))
	fmt.Printf("  Stage:     %s\n", run.Stage)
	fmt.Printf("  Target:    %s\n", run.Target.Identity())
	fmt.Printf("  Volumes:   %d (ok=%d failed=%d)\n", run.Summary.VolumeCount, run.Summary.SucceededVolumes, run.Summary.FailedVolumes)
	fmt.Printf("  Findings:  %d\n", run.Summary.Findings)
	fmt.Printf("  Snapshot:  %.4f GiB-hours\n", run.Summary.SnapshotGiBHours)
	fmt.Printf("  Volume:    %.4f GiB-hours\n", run.Summary.VolumeGiBHours)
	if run.Error != "" {
		fmt.Printf("  Error:     %s\n", run.Error)
	}
	fmt.Println()
	tw := NewTableWriter(os.Stdout, "Volume", "Status", "Stage", "Snapshot", "Inspection", "Mount", "Cleanup")
	for _, volume := range run.Volumes {
		snapshotID := ""
		if volume.Snapshot != nil {
			snapshotID = volume.Snapshot.ID
		}
		inspectionID := ""
		if volume.Inspection != nil {
			inspectionID = volume.Inspection.ID
		}
		mountPath := ""
		if volume.Mount != nil {
			mountPath = volume.Mount.MountPath
		}
		cleanup := "pending"
		if volume.Cleanup.DeletedSnapshot && volume.Cleanup.DeletedVolume && volume.Cleanup.Detached && volume.Cleanup.Unmounted {
			cleanup = "complete"
		}
		tw.AddRow(volume.Source.ID, statusColor(string(volume.Status)), string(volume.Stage), snapshotID, inspectionID, mountPath, cleanup)
	}
	tw.Render()
	return nil
}

func resolveWorkloadScanStateFile(cfg *app.Config) string {
	if strings.TrimSpace(workloadScanStateFile) != "" {
		return strings.TrimSpace(workloadScanStateFile)
	}
	if cfg != nil {
		return strings.TrimSpace(cfg.WorkloadScanStateFile)
	}
	return ""
}

func resolveWorkloadScanMountBasePath(cfg *app.Config) string {
	if strings.TrimSpace(workloadScanMountBasePath) != "" {
		return strings.TrimSpace(workloadScanMountBasePath)
	}
	if cfg != nil {
		return strings.TrimSpace(cfg.WorkloadScanMountBasePath)
	}
	return ""
}

func resolveWorkloadScanMaxConcurrent(cfg *app.Config) int {
	if workloadScanMaxConcurrent > 0 {
		return workloadScanMaxConcurrent
	}
	if cfg != nil {
		return cfg.WorkloadScanMaxConcurrentSnapshots
	}
	return 0
}

func resolveWorkloadScanCleanupTimeout(cfg *app.Config) time.Duration {
	if workloadScanCleanupTimeout > 0 {
		return workloadScanCleanupTimeout
	}
	if cfg != nil {
		return cfg.WorkloadScanCleanupTimeout
	}
	return 0
}

func resolveWorkloadScanReconcileOlderThan(cfg *app.Config) time.Duration {
	if workloadScanReconcileOlderThan > 0 {
		return workloadScanReconcileOlderThan
	}
	if cfg != nil {
		return cfg.WorkloadScanReconcileOlderThan
	}
	return 0
}

func resolveWorkloadScanTrivyBinary(cfg *app.Config) string {
	if strings.TrimSpace(workloadScanTrivyBinary) != "" {
		return strings.TrimSpace(workloadScanTrivyBinary)
	}
	if cfg != nil {
		return strings.TrimSpace(cfg.WorkloadScanTrivyBinary)
	}
	return "trivy"
}

func parseMetadataPairs(values []string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]string, len(values))
	for _, entry := range values {
		parts := strings.SplitN(strings.TrimSpace(entry), "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		if key == "" || value == "" {
			continue
		}
		out[key] = value
	}
	return out
}

func parseWorkloadRunStatuses(raw string) ([]workloadscan.RunStatus, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	parts := strings.Split(raw, ",")
	statuses := make([]workloadscan.RunStatus, 0, len(parts))
	for _, part := range parts {
		status := workloadscan.RunStatus(strings.TrimSpace(part))
		switch status {
		case workloadscan.RunStatusQueued, workloadscan.RunStatusRunning, workloadscan.RunStatusSucceeded, workloadscan.RunStatusFailed:
			statuses = append(statuses, status)
		default:
			return nil, fmt.Errorf("invalid workload scan status %q", part)
		}
	}
	return statuses, nil
}
