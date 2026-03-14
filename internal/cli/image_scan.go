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
	"github.com/writer/cerebro/internal/imagescan"
	"github.com/writer/cerebro/internal/scanner"
)

var imageScanCmd = &cobra.Command{
	Use:   "image-scan",
	Short: "Run and inspect durable container image scans",
}

var imageScanListCmd = &cobra.Command{
	Use:   "list",
	Short: "List persisted image scan runs",
	RunE:  runImageScanList,
}

var imageScanRunCmd = &cobra.Command{
	Use:   "run",
	Short: "Run a container image scan",
}

var imageScanRunECRCmd = &cobra.Command{
	Use:   "ecr",
	Short: "Run an ECR image scan",
	RunE:  runImageScanECR,
}

var imageScanRunGCRCmd = &cobra.Command{
	Use:   "gcr",
	Short: "Run a GCR or Artifact Registry image scan",
	RunE:  runImageScanGCR,
}

var imageScanRunACRCmd = &cobra.Command{
	Use:   "acr",
	Short: "Run an Azure Container Registry image scan",
	RunE:  runImageScanACR,
}

var (
	imageScanOutput            string
	imageScanStateFile         string
	imageScanRootFSBasePath    string
	imageScanCleanupTimeout    time.Duration
	imageScanTrivyBinary       string
	imageScanGitleaksBinary    string
	imageScanClamAVBinary      string
	imageScanListStatuses      string
	imageScanListLimit         int
	imageScanRequestedBy       string
	imageScanDryRun            bool
	imageScanKeepFilesystem    bool
	imageScanMetadataPairs     []string
	imageScanRepository        string
	imageScanTag               string
	imageScanDigest            string
	imageScanECRRegion         string
	imageScanECRAccountID      string
	imageScanGCRProjectID      string
	imageScanGCRHost           string
	imageScanGCRAccessToken    string
	imageScanACRRegistryName   string
	imageScanACRUsername       string
	imageScanACRPassword       string
	imageScanACRBaseURL        string
	imageScanACRSubscriptionID string
)

func init() {
	imageScanCmd.PersistentFlags().StringVarP(&imageScanOutput, "output", "o", FormatTable, "Output format (table,json)")
	imageScanCmd.PersistentFlags().StringVar(&imageScanStateFile, "state-file", "", "Override image scan SQLite state path")
	imageScanCmd.PersistentFlags().StringVar(&imageScanRootFSBasePath, "rootfs-base", "", "Override image scan rootfs materialization path")
	imageScanCmd.PersistentFlags().DurationVar(&imageScanCleanupTimeout, "cleanup-timeout", 0, "Override image scan cleanup timeout")
	imageScanCmd.PersistentFlags().StringVar(&imageScanTrivyBinary, "trivy-binary", "", "Override trivy binary path")
	imageScanCmd.PersistentFlags().StringVar(&imageScanGitleaksBinary, "gitleaks-binary", "", "Optional gitleaks binary path for expanded secret scanning")
	imageScanCmd.PersistentFlags().StringVar(&imageScanClamAVBinary, "clamav-binary", "", "Optional ClamAV clamscan binary path for malware scanning")

	imageScanListCmd.Flags().StringVar(&imageScanListStatuses, "status", "", "Optional comma-separated status filter")
	imageScanListCmd.Flags().IntVar(&imageScanListLimit, "limit", 20, "Maximum runs to list")

	imageScanRunCmd.PersistentFlags().StringVar(&imageScanRequestedBy, "requested-by", "", "Optional operator identity recorded on the run")
	imageScanRunCmd.PersistentFlags().BoolVar(&imageScanDryRun, "dry-run", false, "Resolve manifest only; do not materialize or analyze")
	imageScanRunCmd.PersistentFlags().BoolVar(&imageScanKeepFilesystem, "keep-filesystem", false, "Retain the materialized rootfs after completion")
	imageScanRunCmd.PersistentFlags().StringSliceVar(&imageScanMetadataPairs, "metadata", nil, "Optional metadata entries (key=value)")

	imageScanRunECRCmd.Flags().StringVar(&imageScanECRRegion, "region", "", "AWS region containing the target ECR repository")
	imageScanRunECRCmd.Flags().StringVar(&imageScanECRAccountID, "account-id", "", "Optional AWS account ID owning the target registry")
	bindImageReferenceFlags(imageScanRunECRCmd)
	_ = imageScanRunECRCmd.MarkFlagRequired("region")
	_ = imageScanRunECRCmd.MarkFlagRequired("repository")

	imageScanRunGCRCmd.Flags().StringVar(&imageScanGCRProjectID, "project-id", "", "GCP project ID for the target repository")
	imageScanRunGCRCmd.Flags().StringVar(&imageScanGCRHost, "host", "", "Optional registry host override (for example us-docker.pkg.dev)")
	imageScanRunGCRCmd.Flags().StringVar(&imageScanGCRAccessToken, "access-token", "", "Optional bearer token for private registry access")
	bindImageReferenceFlags(imageScanRunGCRCmd)
	_ = imageScanRunGCRCmd.MarkFlagRequired("project-id")
	_ = imageScanRunGCRCmd.MarkFlagRequired("repository")

	imageScanRunACRCmd.Flags().StringVar(&imageScanACRRegistryName, "registry-name", "", "Azure Container Registry name")
	imageScanRunACRCmd.Flags().StringVar(&imageScanACRUsername, "username", "", "Optional registry username")
	imageScanRunACRCmd.Flags().StringVar(&imageScanACRPassword, "password", "", "Optional registry password")
	imageScanRunACRCmd.Flags().StringVar(&imageScanACRBaseURL, "base-url", "", "Optional registry base URL override")
	imageScanRunACRCmd.Flags().StringVar(&imageScanACRSubscriptionID, "subscription-id", "", "Optional Azure subscription ID")
	bindImageReferenceFlags(imageScanRunACRCmd)
	_ = imageScanRunACRCmd.MarkFlagRequired("registry-name")
	_ = imageScanRunACRCmd.MarkFlagRequired("repository")

	imageScanCmd.AddCommand(imageScanListCmd)
	imageScanRunCmd.AddCommand(imageScanRunECRCmd)
	imageScanRunCmd.AddCommand(imageScanRunGCRCmd)
	imageScanRunCmd.AddCommand(imageScanRunACRCmd)
	imageScanCmd.AddCommand(imageScanRunCmd)
}

func bindImageReferenceFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&imageScanRepository, "repository", "", "Image repository name")
	cmd.Flags().StringVar(&imageScanTag, "tag", "latest", "Image tag")
	cmd.Flags().StringVar(&imageScanDigest, "digest", "", "Optional image digest (overrides tag for manifest resolution)")
}

func imageScanTargetFromFlags(cmd *cobra.Command, registry imagescan.RegistryKind, registryHost string) imagescan.ScanTarget {
	tag := strings.TrimSpace(imageScanTag)
	digest := strings.TrimSpace(imageScanDigest)
	if digest != "" && cmd != nil && !cmd.Flags().Changed("tag") {
		tag = ""
	}
	return imagescan.ScanTarget{
		Registry:     registry,
		RegistryHost: registryHost,
		Repository:   strings.TrimSpace(imageScanRepository),
		Tag:          tag,
		Digest:       digest,
	}
}

func runImageScanList(cmd *cobra.Command, args []string) error {
	cfg := app.LoadConfig()
	store, err := imagescan.NewSQLiteRunStore(resolveImageScanStateFile(cfg))
	if err != nil {
		return err
	}
	defer func() { _ = store.Close() }()

	statuses, err := parseImageRunStatuses(imageScanListStatuses)
	if err != nil {
		return err
	}
	runs, err := store.ListRuns(cmd.Context(), imagescan.RunListOptions{
		Statuses: statuses,
		Limit:    imageScanListLimit,
	})
	if err != nil {
		return err
	}
	return renderImageRuns(runs)
}

func runImageScanECR(cmd *cobra.Command, args []string) error {
	client := scanner.NewECRClient(strings.TrimSpace(imageScanECRRegion), strings.TrimSpace(imageScanECRAccountID))
	return runImageScan(cmd.Context(), imageScanTargetFromFlags(cmd, imagescan.RegistryECR, client.RegistryHost()), client)
}

func runImageScanGCR(cmd *cobra.Command, args []string) error {
	client := scanner.NewGCRClient(strings.TrimSpace(imageScanGCRProjectID))
	client.SetRegistryHost(strings.TrimSpace(imageScanGCRHost))
	client.SetAccessToken(strings.TrimSpace(imageScanGCRAccessToken))
	return runImageScan(cmd.Context(), imageScanTargetFromFlags(cmd, imagescan.RegistryGCR, client.RegistryHost()), client)
}

func runImageScanACR(cmd *cobra.Command, args []string) error {
	client := scanner.NewACRClient(strings.TrimSpace(imageScanACRRegistryName), strings.TrimSpace(imageScanACRSubscriptionID))
	client.SetCredentials(strings.TrimSpace(imageScanACRUsername), strings.TrimSpace(imageScanACRPassword))
	client.SetBaseURL(strings.TrimSpace(imageScanACRBaseURL))
	return runImageScan(cmd.Context(), imageScanTargetFromFlags(cmd, imagescan.RegistryACR, client.RegistryHost()), client)
}

func runImageScan(parent context.Context, target imagescan.ScanTarget, client scanner.RegistryClient) error {
	ctx, cancel := signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
	defer cancel()

	cfg := app.LoadConfig()
	store, err := imagescan.NewSQLiteRunStore(resolveImageScanStateFile(cfg))
	if err != nil {
		return err
	}
	defer func() { _ = store.Close() }()

	emitter, err := newWorkloadScanEmitter(cfg, slog.Default())
	if err != nil {
		return err
	}
	defer func() { _ = emitter.Close() }()
	filesystemAnalyzer, vulnDBCloser, err := buildFilesystemAnalyzer(cfg, resolveImageScanTrivyBinary(cfg), resolveImageScanGitleaksBinary(cfg), resolveImageScanClamAVBinary(cfg))
	if err != nil {
		return err
	}
	defer func() { _ = vulnDBCloser.Close() }()

	runner := imagescan.NewRunner(imagescan.RunnerOptions{
		Store:          store,
		Registries:     []scanner.RegistryClient{client},
		Materializer:   imagescan.NewLocalMaterializer(resolveImageScanRootFSBasePath(cfg)),
		Analyzer:       imagescan.FilesystemAnalyzer{Analyzer: filesystemAnalyzer},
		Events:         emitter,
		CleanupTimeout: resolveImageScanCleanupTimeout(cfg),
	})

	run, runErr := runner.RunImageScan(ctx, imagescan.ScanRequest{
		RequestedBy:    imageScanRequestedBy,
		Target:         target,
		DryRun:         imageScanDryRun,
		KeepFilesystem: imageScanKeepFilesystem,
		Metadata:       parseMetadataPairs(imageScanMetadataPairs),
		SubmittedAt:    time.Now().UTC(),
	})
	if run != nil {
		if err := renderImageRun(*run); err != nil {
			return err
		}
	}
	return runErr
}

func renderImageRuns(runs []imagescan.RunRecord) error {
	if imageScanOutput == FormatJSON {
		return JSONOutput(runs)
	}
	if len(runs) == 0 {
		fmt.Println("No image scan runs found.")
		return nil
	}
	fmt.Printf("%-36s  %-4s  %-10s  %-12s  %s\n", "RUN ID", "REG", "STATUS", "STAGE", "IMAGE")
	for _, run := range runs {
		fmt.Printf("%-36s  %-4s  %-10s  %-12s  %s\n",
			run.ID,
			run.Registry,
			run.Status,
			run.Stage,
			run.Target.Reference(),
		)
	}
	return nil
}

func renderImageRun(run imagescan.RunRecord) error {
	if imageScanOutput == FormatJSON {
		return JSONOutput(run)
	}
	fmt.Printf("Run ID:      %s\n", run.ID)
	fmt.Printf("Registry:    %s\n", run.Registry)
	fmt.Printf("Image:       %s\n", run.Target.Reference())
	fmt.Printf("Status:      %s\n", run.Status)
	fmt.Printf("Stage:       %s\n", run.Stage)
	if run.Manifest != nil {
		fmt.Printf("Digest:      %s\n", run.Manifest.Digest)
		fmt.Printf("Layers:      %d\n", len(run.Manifest.Layers))
		fmt.Printf("Base image:  %s\n", run.Manifest.BaseImageRef)
	}
	if run.Analysis != nil {
		fmt.Printf("Analyzer:    %s\n", run.Analysis.Analyzer)
		fmt.Printf("Vulns:       %d total (%d native, %d filesystem)\n",
			run.Analysis.Result.Summary.Total,
			run.Analysis.NativeVulnerabilityCount,
			run.Analysis.FilesystemVulnerabilityCount,
		)
	}
	if run.Filesystem != nil {
		fmt.Printf("Rootfs:      %s\n", run.Filesystem.Path)
	}
	if run.Error != "" {
		fmt.Printf("Error:       %s\n", run.Error)
	}
	return nil
}

func parseImageRunStatuses(raw string) ([]imagescan.RunStatus, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	parts := strings.Split(raw, ",")
	statuses := make([]imagescan.RunStatus, 0, len(parts))
	for _, part := range parts {
		status := imagescan.RunStatus(strings.TrimSpace(part))
		switch status {
		case imagescan.RunStatusQueued, imagescan.RunStatusRunning, imagescan.RunStatusSucceeded, imagescan.RunStatusFailed:
			statuses = append(statuses, status)
		default:
			return nil, fmt.Errorf("invalid image scan status %q", part)
		}
	}
	return statuses, nil
}

func resolveImageScanStateFile(cfg *app.Config) string {
	if strings.TrimSpace(imageScanStateFile) != "" {
		return strings.TrimSpace(imageScanStateFile)
	}
	if cfg != nil && strings.TrimSpace(cfg.ImageScanStateFile) != "" {
		return strings.TrimSpace(cfg.ImageScanStateFile)
	}
	return ".cerebro/executions.db"
}

func resolveImageScanRootFSBasePath(cfg *app.Config) string {
	if strings.TrimSpace(imageScanRootFSBasePath) != "" {
		return strings.TrimSpace(imageScanRootFSBasePath)
	}
	if cfg != nil && strings.TrimSpace(cfg.ImageScanRootFSBasePath) != "" {
		return strings.TrimSpace(cfg.ImageScanRootFSBasePath)
	}
	return ".cerebro/image-scan/rootfs"
}

func resolveImageScanCleanupTimeout(cfg *app.Config) time.Duration {
	if imageScanCleanupTimeout > 0 {
		return imageScanCleanupTimeout
	}
	if cfg != nil && cfg.ImageScanCleanupTimeout > 0 {
		return cfg.ImageScanCleanupTimeout
	}
	return 2 * time.Minute
}

func resolveImageScanTrivyBinary(cfg *app.Config) string {
	if strings.TrimSpace(imageScanTrivyBinary) != "" {
		return strings.TrimSpace(imageScanTrivyBinary)
	}
	if cfg != nil && strings.TrimSpace(cfg.ImageScanTrivyBinary) != "" {
		return strings.TrimSpace(cfg.ImageScanTrivyBinary)
	}
	return "trivy"
}

func resolveImageScanGitleaksBinary(cfg *app.Config) string {
	if strings.TrimSpace(imageScanGitleaksBinary) != "" {
		return strings.TrimSpace(imageScanGitleaksBinary)
	}
	if cfg != nil && strings.TrimSpace(cfg.ImageScanGitleaksBinary) != "" {
		return strings.TrimSpace(cfg.ImageScanGitleaksBinary)
	}
	return ""
}

func resolveImageScanClamAVBinary(cfg *app.Config) string {
	if strings.TrimSpace(imageScanClamAVBinary) != "" {
		return strings.TrimSpace(imageScanClamAVBinary)
	}
	if cfg != nil && strings.TrimSpace(cfg.ImageScanClamAVBinary) != "" {
		return strings.TrimSpace(cfg.ImageScanClamAVBinary)
	}
	return ""
}
