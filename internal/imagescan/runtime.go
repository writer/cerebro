package imagescan

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/evalops/cerebro/internal/filesystemanalyzer"
	"github.com/evalops/cerebro/internal/scanner"
	"github.com/evalops/cerebro/internal/webhooks"
)

const defaultCleanupTimeout = 2 * time.Minute

var embeddedURLPattern = regexp.MustCompile(`https?://[^\s"'<>]+`)

type EventEmitter interface {
	EmitWithErrors(ctx context.Context, eventType webhooks.EventType, data map[string]interface{}) error
}

type Analyzer interface {
	Analyze(ctx context.Context, input AnalysisInput) (*AnalysisReport, error)
}

type NoopAnalyzer struct{}

func (NoopAnalyzer) Analyze(_ context.Context, input AnalysisInput) (*AnalysisReport, error) {
	result := scanner.ContainerScanResult{
		Repository:   input.Target.Repository,
		Tag:          input.Target.Tag,
		Digest:       input.Target.Digest,
		Registry:     string(input.Target.Registry),
		ScanTime:     time.Now().UTC(),
		OS:           input.Manifest.Config.OS,
		Architecture: input.Manifest.Config.Architecture,
	}
	return &AnalysisReport{
		Analyzer: "noop",
		Result:   result,
	}, nil
}

type FilesystemAnalyzer struct {
	Scanner       scanner.FilesystemScanner
	SecretScanner filesystemanalyzer.SecretScanner
	Analyzer      *filesystemanalyzer.Analyzer
}

func (a FilesystemAnalyzer) Analyze(ctx context.Context, input AnalysisInput) (*AnalysisReport, error) {
	analyzer := a.Analyzer
	if analyzer == nil && a.Scanner != nil {
		analyzer = filesystemanalyzer.New(filesystemanalyzer.Options{
			VulnerabilityScanner: a.Scanner,
			SecretScanner:        a.SecretScanner,
		})
	}
	if analyzer == nil {
		return NoopAnalyzer{}.Analyze(ctx, input)
	}
	if input.Filesystem == nil || strings.TrimSpace(input.Filesystem.Path) == "" {
		return nil, fmt.Errorf("filesystem artifact is required for filesystem analysis")
	}
	catalog, err := analyzer.Analyze(ctx, input.Filesystem.Path)
	if err != nil {
		return nil, err
	}
	result := scanner.ContainerScanResult{}
	if catalog != nil {
		result.Vulnerabilities = append(result.Vulnerabilities, catalog.Vulnerabilities...)
		result.Findings = append(result.Findings, catalog.Findings...)
		result.OS = firstNonEmpty(catalog.OS.PrettyName, catalog.OS.Name, input.Manifest.Config.OS)
		result.Architecture = firstNonEmpty(catalog.OS.Architecture, input.Manifest.Config.Architecture)
		result.Summary = summarizeVulnerabilities(result.Vulnerabilities)
	}
	return &AnalysisReport{
		Analyzer:                     "filesystem",
		FilesystemVulnerabilityCount: len(result.Vulnerabilities),
		Catalog:                      catalog,
		Result:                       result,
	}, nil
}

type RunnerOptions struct {
	Store          RunStore
	Registries     []scanner.RegistryClient
	Materializer   Materializer
	Analyzer       Analyzer
	Events         EventEmitter
	Logger         *slog.Logger
	CleanupTimeout time.Duration
	Now            func() time.Time
}

type Runner struct {
	store          RunStore
	registries     map[RegistryKind]scanner.RegistryClient
	materializer   Materializer
	analyzer       Analyzer
	events         EventEmitter
	logger         *slog.Logger
	cleanupTimeout time.Duration
	now            func() time.Time
}

func NewRunner(opts RunnerOptions) *Runner {
	registries := make(map[RegistryKind]scanner.RegistryClient, len(opts.Registries))
	for _, client := range opts.Registries {
		if client == nil {
			continue
		}
		registries[RegistryKind(client.Name())] = client
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	analyzer := opts.Analyzer
	if analyzer == nil {
		analyzer = NoopAnalyzer{}
	}
	cleanupTimeout := opts.CleanupTimeout
	if cleanupTimeout <= 0 {
		cleanupTimeout = defaultCleanupTimeout
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &Runner{
		store:          opts.Store,
		registries:     registries,
		materializer:   opts.Materializer,
		analyzer:       analyzer,
		events:         opts.Events,
		logger:         logger,
		cleanupTimeout: cleanupTimeout,
		now:            now,
	}
}

func (r *Runner) RunImageScan(ctx context.Context, req ScanRequest) (*RunRecord, error) {
	if r == nil {
		return nil, fmt.Errorf("image scan runner is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := validateRequest(req); err != nil {
		return nil, err
	}
	if strings.TrimSpace(req.ID) == "" {
		req.ID = "image_scan:" + uuid.NewString()
	}
	if req.SubmittedAt.IsZero() {
		req.SubmittedAt = r.now().UTC()
	}
	client, ok := r.registries[req.Target.Registry]
	if !ok {
		return nil, fmt.Errorf("no registry client configured for %s", req.Target.Registry)
	}

	run := &RunRecord{
		ID:             req.ID,
		Registry:       req.Target.Registry,
		Status:         RunStatusQueued,
		Stage:          RunStageQueued,
		Target:         req.Target,
		RequestedBy:    strings.TrimSpace(req.RequestedBy),
		DryRun:         req.DryRun,
		KeepFilesystem: req.KeepFilesystem,
		Metadata:       cloneStringMap(req.Metadata),
		SubmittedAt:    req.SubmittedAt.UTC(),
		UpdatedAt:      req.SubmittedAt.UTC(),
	}
	if err := r.saveRun(ctx, run); err != nil {
		return nil, err
	}
	r.recordRunEvent(ctx, run, RunStatusQueued, RunStageQueued, "image scan queued", nil)

	started := r.now().UTC()
	run.Status = RunStatusRunning
	run.Stage = RunStageManifest
	run.StartedAt = &started
	run.UpdatedAt = started
	if err := r.saveRun(ctx, run); err != nil {
		return nil, err
	}
	r.recordRunEvent(ctx, run, RunStatusRunning, RunStageManifest, "loading image manifest", nil)
	r.emitLifecycleEvent(ctx, webhooks.EventSecurityImageScanStarted, run, nil)

	manifest, err := client.GetManifest(ctx, req.Target.Repository, req.Target.ManifestReference())
	if err != nil {
		return r.failRun(ctx, run, RunStageManifest, fmt.Errorf("get manifest: %w", err))
	}
	run.Manifest = manifest
	if strings.TrimSpace(run.Target.Digest) == "" {
		run.Target.Digest = strings.TrimSpace(manifest.Digest)
	}
	run.UpdatedAt = r.now().UTC()
	if err := r.saveRun(ctx, run); err != nil {
		return nil, err
	}

	if req.DryRun {
		return r.completeRun(ctx, run, "image scan dry-run completed")
	}

	if fetcher, ok := client.(scanner.BlobFetcher); ok && r.materializer != nil && len(manifest.Layers) > 0 {
		run.Stage = RunStageMaterialize
		run.UpdatedAt = r.now().UTC()
		if err := r.saveRun(ctx, run); err != nil {
			return nil, err
		}
		r.recordRunEvent(ctx, run, RunStatusRunning, RunStageMaterialize, "materializing image filesystem", map[string]any{
			"layer_count": len(manifest.Layers),
		})
		artifact, layers, err := r.materializer.Materialize(ctx, run.ID, manifest, func(ctx context.Context, digest string) (io.ReadCloser, error) {
			return fetcher.DownloadBlob(ctx, req.Target.Repository, digest)
		})
		if err != nil {
			return r.failRun(ctx, run, RunStageMaterialize, err)
		}
		run.Filesystem = artifact
		run.Layers = layers
		run.UpdatedAt = r.now().UTC()
		if err := r.saveRun(ctx, run); err != nil {
			return nil, err
		}
	}

	run.Stage = RunStageAnalyze
	run.UpdatedAt = r.now().UTC()
	if err := r.saveRun(ctx, run); err != nil {
		return nil, err
	}
	r.recordRunEvent(ctx, run, RunStatusRunning, RunStageAnalyze, "analyzing image", nil)
	report, err := r.analyze(ctx, client, run)
	if err != nil {
		cleanupFilesystem(ctx, r.materializer, run.Filesystem, run, r.now)
		return r.failRun(ctx, run, RunStageAnalyze, err)
	}
	run.Analysis = report
	run.UpdatedAt = r.now().UTC()
	if err := r.saveRun(ctx, run); err != nil {
		return nil, err
	}

	if run.Filesystem != nil && !run.KeepFilesystem && r.materializer != nil {
		run.Stage = RunStageCleanup
		run.UpdatedAt = r.now().UTC()
		if err := r.saveRun(ctx, run); err != nil {
			return nil, err
		}
		cleanupCtx, cancel := context.WithTimeout(ctx, r.cleanupTimeout)
		cleanupErr := r.materializer.Cleanup(cleanupCtx, *run.Filesystem)
		cancel()
		if cleanupErr != nil {
			r.logger.Warn("image scan cleanup failed", "run_id", run.ID, "path", run.Filesystem.Path, "error", cleanupErr)
		} else {
			cleanedAt := r.now().UTC()
			run.Filesystem.CleanedUpAt = &cleanedAt
		}
		run.UpdatedAt = r.now().UTC()
		if err := r.saveRun(ctx, run); err != nil {
			return nil, err
		}
	}

	return r.completeRun(ctx, run, "image scan completed")
}

func (r *Runner) analyze(ctx context.Context, client scanner.RegistryClient, run *RunRecord) (*AnalysisReport, error) {
	input := AnalysisInput{
		RunID:      run.ID,
		Target:     run.Target,
		Filesystem: run.Filesystem,
		Metadata:   cloneStringMap(run.Metadata),
	}
	if run.Manifest != nil {
		input.Manifest = *run.Manifest
	}
	report, err := r.analyzer.Analyze(ctx, input)
	if err != nil {
		return nil, err
	}
	if report == nil {
		report = &AnalysisReport{
			Analyzer: "noop",
		}
	}
	if report.FilesystemVulnerabilityCount == 0 && len(report.Result.Vulnerabilities) > 0 {
		report.FilesystemVulnerabilityCount = len(report.Result.Vulnerabilities)
	}
	report.Result.Repository = run.Target.Repository
	report.Result.Tag = run.Target.Tag
	report.Result.Digest = run.Target.Digest
	report.Result.Registry = string(run.Target.Registry)
	report.Result.OS = firstNonEmpty(report.Result.OS, input.Manifest.Config.OS)
	report.Result.Architecture = firstNonEmpty(report.Result.Architecture, input.Manifest.Config.Architecture)
	report.Result.ScanTime = r.now().UTC()

	if strings.TrimSpace(run.Target.Tag) != "" {
		nativeVulns, err := client.GetVulnerabilities(ctx, run.Target.Repository, run.Target.Tag)
		if err == nil {
			report.NativeVulnerabilityCount = len(nativeVulns)
			report.Result.Vulnerabilities = mergeVulnerabilities(nativeVulns, report.Result.Vulnerabilities)
		} else {
			if report.Metadata == nil {
				report.Metadata = map[string]any{}
			}
			report.Metadata["native_scan_error"] = err.Error()
		}
	}
	report.Result.Summary = summarizeVulnerabilities(report.Result.Vulnerabilities)
	return report, nil
}

func (r *Runner) completeRun(ctx context.Context, run *RunRecord, message string) (*RunRecord, error) {
	completed := r.now().UTC()
	run.Status = RunStatusSucceeded
	run.Stage = RunStageCompleted
	run.CompletedAt = &completed
	run.UpdatedAt = completed
	if err := r.saveRun(ctx, run); err != nil {
		return nil, err
	}
	r.recordRunEvent(ctx, run, run.Status, run.Stage, message, nil)
	r.emitLifecycleEvent(ctx, webhooks.EventSecurityImageScanCompleted, run, nil)
	return run, nil
}

func (r *Runner) failRun(ctx context.Context, run *RunRecord, stage RunStage, err error) (*RunRecord, error) {
	failedAt := r.now().UTC()
	safeError := operatorSafeErrorMessage(err)
	run.Status = RunStatusFailed
	run.Stage = stage
	run.Error = safeError
	run.CompletedAt = &failedAt
	run.UpdatedAt = failedAt
	if saveErr := r.saveRun(ctx, run); saveErr != nil {
		return nil, saveErr
	}
	r.recordRunEvent(ctx, run, run.Status, run.Stage, safeError, nil)
	r.emitLifecycleEvent(ctx, webhooks.EventSecurityImageScanFailed, run, map[string]any{"error": safeError})
	return run, err
}

func (r *Runner) saveRun(ctx context.Context, run *RunRecord) error {
	if r == nil || r.store == nil {
		return nil
	}
	return r.store.SaveRun(ctx, run)
}

func (r *Runner) recordRunEvent(ctx context.Context, run *RunRecord, status RunStatus, stage RunStage, message string, data map[string]any) {
	if r == nil || r.store == nil || run == nil {
		return
	}
	_, err := r.store.AppendEvent(ctx, run.ID, RunEvent{
		Status:     status,
		Stage:      stage,
		Message:    strings.TrimSpace(message),
		Data:       cloneAnyMap(data),
		RecordedAt: r.now().UTC(),
	})
	if err != nil {
		r.logger.Warn("persist image scan event failed", "run_id", run.ID, "error", err)
	}
}

func (r *Runner) emitLifecycleEvent(ctx context.Context, eventType webhooks.EventType, run *RunRecord, data map[string]any) {
	if r == nil || r.events == nil || run == nil {
		return
	}
	payload := map[string]any{
		"run_id":       run.ID,
		"registry":     run.Registry,
		"repository":   run.Target.Repository,
		"tag":          run.Target.Tag,
		"digest":       run.Target.Digest,
		"status":       run.Status,
		"stage":        run.Stage,
		"submitted_at": run.SubmittedAt.UTC().Format(time.RFC3339Nano),
	}
	for key, value := range data {
		payload[key] = value
	}
	if err := r.events.EmitWithErrors(ctx, eventType, payload); err != nil {
		r.logger.Warn("emit image scan lifecycle event failed", "run_id", run.ID, "event_type", eventType, "error", err)
	}
}

func validateRequest(req ScanRequest) error {
	if req.Target.Registry == "" {
		return fmt.Errorf("image scan registry is required")
	}
	if strings.TrimSpace(req.Target.Repository) == "" {
		return fmt.Errorf("image scan repository is required")
	}
	if strings.TrimSpace(req.Target.Tag) == "" && strings.TrimSpace(req.Target.Digest) == "" {
		return fmt.Errorf("image scan tag or digest is required")
	}
	return nil
}

func cleanupFilesystem(ctx context.Context, materializer Materializer, artifact *FilesystemArtifact, run *RunRecord, now func() time.Time) {
	if materializer == nil || artifact == nil || run == nil || run.KeepFilesystem {
		return
	}
	cleanupCtx, cancel := context.WithTimeout(ctx, defaultCleanupTimeout)
	defer cancel()
	if err := materializer.Cleanup(cleanupCtx, *artifact); err == nil {
		cleanedAt := now().UTC()
		artifact.CleanedUpAt = &cleanedAt
	}
}

func mergeVulnerabilities(primary, secondary []scanner.ImageVulnerability) []scanner.ImageVulnerability {
	merged := make([]scanner.ImageVulnerability, 0, len(primary)+len(secondary))
	seen := make(map[string]struct{}, len(primary)+len(secondary))
	appendSet := func(vulns []scanner.ImageVulnerability) {
		for _, vuln := range vulns {
			key := strings.Join([]string{
				strings.TrimSpace(vuln.CVE),
				strings.TrimSpace(vuln.Package),
				strings.TrimSpace(vuln.InstalledVersion),
				strings.TrimSpace(vuln.FixedVersion),
			}, "|")
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			merged = append(merged, vuln)
		}
	}
	appendSet(primary)
	appendSet(secondary)
	return merged
}

func summarizeVulnerabilities(vulns []scanner.ImageVulnerability) scanner.VulnerabilitySummary {
	summary := scanner.VulnerabilitySummary{}
	for _, vuln := range vulns {
		summary.Total++
		if strings.TrimSpace(vuln.FixedVersion) != "" {
			summary.Fixable++
		}
		switch strings.ToLower(strings.TrimSpace(vuln.Severity)) {
		case "critical":
			summary.Critical++
		case "high":
			summary.High++
		case "medium":
			summary.Medium++
		case "low":
			summary.Low++
		default:
			summary.Unknown++
		}
	}
	return summary
}

func cloneStringMap(src map[string]string) map[string]string {
	if len(src) == 0 {
		return nil
	}
	out := make(map[string]string, len(src))
	for key, value := range src {
		out[key] = value
	}
	return out
}

func cloneAnyMap(src map[string]any) map[string]any {
	if len(src) == 0 {
		return nil
	}
	out := make(map[string]any, len(src))
	for key, value := range src {
		out[key] = value
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func operatorSafeErrorMessage(err error) string {
	if err == nil {
		return ""
	}
	message := strings.TrimSpace(err.Error())
	if message == "" {
		return "image scan failed"
	}
	return embeddedURLPattern.ReplaceAllStringFunc(message, sanitizeEmbeddedURL)
}

func sanitizeEmbeddedURL(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		if idx := strings.Index(raw, "?"); idx >= 0 {
			return raw[:idx]
		}
		return raw
	}
	parsed.RawQuery = ""
	parsed.Fragment = ""
	parsed.User = nil
	return parsed.String()
}
