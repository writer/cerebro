package functionscan

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

	"github.com/writer/cerebro/internal/filesystemanalyzer"
	"github.com/writer/cerebro/internal/scanner"
	"github.com/writer/cerebro/internal/scanpolicy"
	"github.com/writer/cerebro/internal/webhooks"
)

const defaultCleanupTimeout = 2 * time.Minute

const redactedSecretValue = "<redacted>"

var (
	embeddedURLPattern   = regexp.MustCompile(`https?://[^\s"'<>]+`)
	envSecretKeyPattern  = regexp.MustCompile(`(?i)(secret|token|password|passwd|api[_-]?key|credential|private[_-]?key|connection[_-]?string)`)
	awsAccessKeyPattern  = regexp.MustCompile(`AKIA[0-9A-Z]{16}`)
	githubTokenPattern   = regexp.MustCompile(`gh[pousr]_[A-Za-z0-9_]{20,}`)
	slackTokenPattern    = regexp.MustCompile(`xox[baprs]-[A-Za-z0-9-]{10,}`)
	privateKeyPattern    = regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----`)
	inlineSecretPattern  = regexp.MustCompile(`(?i)(password|passwd|pwd|secret|token|api[_-]?key)\s*[:=]`)
	persistedSafeEnvKeys = map[string]struct{}{
		"AWS_DEFAULT_REGION":          {},
		"AWS_REGION":                  {},
		"FUNCTIONS_EXTENSION_VERSION": {},
		"FUNCTIONS_WORKER_RUNTIME":    {},
		"FUNCTION_SIGNATURE_TYPE":     {},
		"FUNCTION_TARGET":             {},
		"GOOGLE_ENTRYPOINT":           {},
		"GOOGLE_RUNTIME":              {},
		"K_CONFIGURATION":             {},
		"K_REVISION":                  {},
		"K_SERVICE":                   {},
		"LOG_LEVEL":                   {},
		"NODE_ENV":                    {},
		"PORT":                        {},
		"WEBSITE_SITE_NAME":           {},
	}
)

type EventEmitter interface {
	EmitWithErrors(ctx context.Context, eventType webhooks.EventType, data map[string]interface{}) error
}

type Provider interface {
	Kind() ProviderKind
	DescribeFunction(ctx context.Context, target FunctionTarget) (*FunctionDescriptor, error)
	OpenArtifact(ctx context.Context, target FunctionTarget, artifact ArtifactRef) (io.ReadCloser, error)
}

type Analyzer interface {
	Analyze(ctx context.Context, input AnalysisInput) (*AnalysisReport, error)
}

type NoopAnalyzer struct{}

func (NoopAnalyzer) Analyze(_ context.Context, input AnalysisInput) (*AnalysisReport, error) {
	result := scanner.ContainerScanResult{
		Repository:   input.Target.Identity(),
		Tag:          input.Descriptor.CodeSHA256,
		Digest:       input.Descriptor.CodeSHA256,
		Registry:     string(input.Target.Provider),
		ScanTime:     time.Now().UTC(),
		OS:           input.Descriptor.Runtime,
		Architecture: strings.Join(input.Descriptor.Architectures, ","),
	}
	return &AnalysisReport{Analyzer: "noop", Result: result}, nil
}

type FilesystemAnalyzer struct {
	Scanner       scanner.FilesystemScanner
	SecretScanner filesystemanalyzer.SecretScanner
	Analyzer      *filesystemanalyzer.Analyzer
}

func (a FilesystemAnalyzer) Analyze(ctx context.Context, input AnalysisInput) (*AnalysisReport, error) {
	report, err := NoopAnalyzer{}.Analyze(ctx, input)
	if err != nil {
		return nil, err
	}
	report.Analyzer = "filesystem"
	analyzer := a.Analyzer
	if analyzer == nil && a.Scanner != nil {
		analyzer = filesystemanalyzer.New(filesystemanalyzer.Options{
			VulnerabilityScanner: a.Scanner,
			SecretScanner:        a.SecretScanner,
		})
	}
	if analyzer != nil && input.Filesystem != nil && strings.TrimSpace(input.Filesystem.Path) != "" {
		catalog, err := analyzer.Analyze(ctx, input.Filesystem.Path)
		if err != nil {
			return nil, err
		}
		report.Catalog = catalog
		report.Result.Vulnerabilities = append(report.Result.Vulnerabilities, catalog.Vulnerabilities...)
		report.Result.Findings = append(report.Result.Findings, catalog.Findings...)
		report.Result.OS = firstNonEmpty(catalog.OS.PrettyName, catalog.OS.Name, input.Descriptor.Runtime)
		report.Result.Architecture = firstNonEmpty(catalog.OS.Architecture, strings.Join(input.Descriptor.Architectures, ","))
		report.FilesystemVulnerabilityCount = len(catalog.Vulnerabilities)
	}
	envFindings, envCount := detectEnvironmentSecrets(input.Descriptor)
	codeCount := 0
	if report.Catalog != nil {
		codeCount = len(report.Catalog.Secrets)
	}
	report.EnvironmentSecretCount = envCount
	report.CodeSecretCount = codeCount
	if runtimeDeprecated(input.Target.Provider, input.Descriptor.Runtime) {
		report.RuntimeDeprecated = true
		report.Result.Findings = append(report.Result.Findings, scanner.ContainerFinding{
			ID:          "runtime_eol:" + sanitizeFindingID(input.Descriptor.Runtime),
			Type:        "runtime_eol",
			Severity:    "high",
			Title:       "Deprecated serverless runtime",
			Description: fmt.Sprintf("Runtime %s is on the curated deprecated runtime list", strings.TrimSpace(input.Descriptor.Runtime)),
			Remediation: "Upgrade the function runtime to a currently supported version.",
		})
	}
	report.Result.Findings = append(report.Result.Findings, envFindings...)
	report.Result.Summary = summarizeVulnerabilities(report.Result.Vulnerabilities)
	if report.Metadata == nil {
		report.Metadata = map[string]any{}
	}
	if report.Catalog != nil {
		report.Metadata["package_count"] = report.Catalog.Summary.PackageCount
		report.Metadata["sbom_format"] = report.Catalog.SBOM.Format
	}
	report.Metadata["deprecated_runtime_policy"] = "curated-2026-03"
	return report, nil
}

type RunnerOptions struct {
	Store           RunStore
	Providers       []Provider
	Materializer    Materializer
	Analyzer        Analyzer
	Events          EventEmitter
	Logger          *slog.Logger
	CleanupTimeout  time.Duration
	Now             func() time.Time
	PolicyEvaluator scanpolicy.Evaluator
}

type Runner struct {
	store           RunStore
	providers       map[ProviderKind]Provider
	materializer    Materializer
	analyzer        Analyzer
	events          EventEmitter
	logger          *slog.Logger
	cleanupTimeout  time.Duration
	now             func() time.Time
	policyEvaluator scanpolicy.Evaluator
}

func NewRunner(opts RunnerOptions) *Runner {
	providers := make(map[ProviderKind]Provider, len(opts.Providers))
	for _, provider := range opts.Providers {
		if provider == nil {
			continue
		}
		providers[provider.Kind()] = provider
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
		store:           opts.Store,
		providers:       providers,
		materializer:    opts.Materializer,
		analyzer:        analyzer,
		events:          opts.Events,
		logger:          logger,
		cleanupTimeout:  cleanupTimeout,
		now:             now,
		policyEvaluator: opts.PolicyEvaluator,
	}
}

func (r *Runner) RunFunctionScan(ctx context.Context, req ScanRequest) (*RunRecord, error) {
	if r == nil {
		return nil, fmt.Errorf("function scan runner is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := r.validateRequest(req); err != nil {
		return nil, err
	}
	if strings.TrimSpace(req.ID) == "" {
		req.ID = "function_scan:" + uuid.NewString()
	}
	if req.SubmittedAt.IsZero() {
		req.SubmittedAt = r.now().UTC()
	}
	provider, ok := r.providers[req.Target.Provider]
	if !ok {
		return nil, fmt.Errorf("no function scan provider configured for %s", req.Target.Provider)
	}
	run := &RunRecord{
		ID:             req.ID,
		Provider:       req.Target.Provider,
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
	r.recordRunEvent(ctx, run, RunStatusQueued, RunStageQueued, "function scan queued", nil)

	started := r.now().UTC()
	run.Status = RunStatusRunning
	run.Stage = RunStageDescribe
	run.StartedAt = &started
	run.UpdatedAt = started
	if err := r.saveRun(ctx, run); err != nil {
		return nil, err
	}
	r.recordRunEvent(ctx, run, RunStatusRunning, RunStageDescribe, "describing function package", nil)
	r.emitLifecycleEvent(ctx, webhooks.EventSecurityFunctionScanStarted, run, nil)

	descriptor, err := provider.DescribeFunction(ctx, req.Target)
	if err != nil {
		return r.failRun(ctx, run, RunStageDescribe, fmt.Errorf("describe function: %w", err))
	}
	analysisDescriptor := cloneFunctionDescriptor(descriptor)
	run.Descriptor = redactFunctionDescriptorSecrets(cloneFunctionDescriptor(descriptor))
	run.UpdatedAt = r.now().UTC()
	if err := r.saveRun(ctx, run); err != nil {
		return nil, err
	}

	if req.DryRun {
		return r.completeRun(ctx, run, "function scan dry-run completed")
	}

	if r.materializer != nil && analysisDescriptor != nil && len(analysisDescriptor.Artifacts) > 0 {
		run.Stage = RunStageMaterialize
		run.UpdatedAt = r.now().UTC()
		if err := r.saveRun(ctx, run); err != nil {
			return nil, err
		}
		r.recordRunEvent(ctx, run, RunStatusRunning, RunStageMaterialize, "materializing function package", map[string]any{"artifact_count": len(analysisDescriptor.Artifacts)})
		artifact, applied, err := r.materializer.Materialize(ctx, run.ID, analysisDescriptor, func(ctx context.Context, artifact ArtifactRef) (io.ReadCloser, error) {
			return provider.OpenArtifact(ctx, req.Target, artifact)
		})
		if err != nil {
			return r.failRun(ctx, run, RunStageMaterialize, err)
		}
		run.Filesystem = artifact
		run.AppliedArtifacts = applied
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
	r.recordRunEvent(ctx, run, RunStatusRunning, RunStageAnalyze, "analyzing function package", nil)
	report, err := r.analyze(ctx, run, analysisDescriptor)
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
			r.logger.Warn("function scan cleanup failed", "run_id", run.ID, "path", run.Filesystem.Path, "error", cleanupErr)
		} else {
			cleanedAt := r.now().UTC()
			run.Filesystem.CleanedUpAt = &cleanedAt
		}
		run.UpdatedAt = r.now().UTC()
		if err := r.saveRun(ctx, run); err != nil {
			return nil, err
		}
	}

	return r.completeRun(ctx, run, "function scan completed")
}

func (r *Runner) analyze(ctx context.Context, run *RunRecord, descriptor *FunctionDescriptor) (*AnalysisReport, error) {
	input := AnalysisInput{RunID: run.ID, Target: run.Target, Filesystem: run.Filesystem, Metadata: cloneStringMap(run.Metadata)}
	if descriptor != nil {
		input.Descriptor = *descriptor
	} else if run.Descriptor != nil {
		input.Descriptor = *run.Descriptor
	}
	report, err := r.analyzer.Analyze(ctx, input)
	if err != nil {
		return nil, err
	}
	if report == nil {
		report = &AnalysisReport{Analyzer: "noop"}
	}
	report.Result.Repository = run.Target.Identity()
	report.Result.Tag = input.Descriptor.CodeSHA256
	report.Result.Digest = input.Descriptor.CodeSHA256
	report.Result.Registry = string(run.Provider)
	report.Result.OS = firstNonEmpty(report.Result.OS, input.Descriptor.Runtime)
	report.Result.Architecture = firstNonEmpty(report.Result.Architecture, strings.Join(input.Descriptor.Architectures, ","))
	report.Result.ScanTime = r.now().UTC()
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
	r.emitLifecycleEvent(ctx, webhooks.EventSecurityFunctionScanCompleted, run, nil)
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
	r.emitLifecycleEvent(ctx, webhooks.EventSecurityFunctionScanFailed, run, map[string]any{"error": safeError})
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
	_, err := r.store.AppendEvent(ctx, run.ID, RunEvent{Status: status, Stage: stage, Message: strings.TrimSpace(message), Data: cloneAnyMap(data), RecordedAt: r.now().UTC()})
	if err != nil {
		r.logger.Warn("persist function scan event failed", "run_id", run.ID, "error", err)
	}
}

func (r *Runner) emitLifecycleEvent(ctx context.Context, eventType webhooks.EventType, run *RunRecord, data map[string]any) {
	if r == nil || r.events == nil || run == nil {
		return
	}
	payload := map[string]any{
		"run_id":       run.ID,
		"provider":     run.Provider,
		"target":       run.Target.Identity(),
		"status":       run.Status,
		"stage":        run.Stage,
		"submitted_at": run.SubmittedAt.UTC().Format(time.RFC3339Nano),
	}
	if run.Descriptor != nil {
		payload["runtime"] = run.Descriptor.Runtime
		payload["code_sha256"] = run.Descriptor.CodeSHA256
	}
	for key, value := range data {
		payload[key] = value
	}
	if err := r.events.EmitWithErrors(ctx, eventType, payload); err != nil {
		r.logger.Warn("emit function scan lifecycle event failed", "run_id", run.ID, "event_type", eventType, "error", err)
	}
}

func validateRequest(req ScanRequest) error {
	if req.Target.Provider == "" {
		return fmt.Errorf("function scan provider is required")
	}
	if strings.TrimSpace(req.Target.Identity()) == "" {
		return fmt.Errorf("function scan target identity is required")
	}
	return nil
}

func (r *Runner) validateRequest(req ScanRequest) error {
	if err := validateRequest(req); err != nil {
		return err
	}
	if r == nil || r.policyEvaluator == nil {
		return nil
	}
	return r.policyEvaluator.Validate(scanpolicy.Request{
		Kind:           scanpolicy.KindFunction,
		Team:           scanpolicy.TeamFromMetadata(req.Metadata),
		RequestedBy:    strings.TrimSpace(req.RequestedBy),
		Metadata:       cloneStringMap(req.Metadata),
		Provider:       string(req.Target.Provider),
		DryRun:         req.DryRun,
		KeepFilesystem: req.KeepFilesystem,
	})
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

func detectEnvironmentSecrets(descriptor FunctionDescriptor) ([]scanner.ContainerFinding, int) {
	findings := make([]scanner.ContainerFinding, 0)
	count := 0
	for key, value := range descriptor.Environment {
		trimmedKey := strings.TrimSpace(key)
		trimmedValue := strings.TrimSpace(value)
		if trimmedValue == "" {
			continue
		}
		if !envSecretKeyPattern.MatchString(trimmedKey) && !looksSensitiveValue(trimmedValue) {
			continue
		}
		if looksPlaceholderValue(trimmedValue) {
			continue
		}
		count++
		findings = append(findings, scanner.ContainerFinding{
			ID:          "env_secret:" + sanitizeFindingID(trimmedKey),
			Type:        "secret",
			Severity:    "high",
			Title:       "Potential secret in function environment",
			Description: fmt.Sprintf("Environment variable %s appears to contain sensitive material", trimmedKey),
			Remediation: "Move sensitive values to a secret manager or encrypted runtime configuration.",
		})
	}
	return findings, count
}

func runtimeDeprecated(provider ProviderKind, runtime string) bool {
	runtime = strings.ToLower(strings.TrimSpace(runtime))
	if runtime == "" {
		return false
	}
	deprecated := []string{
		"nodejs12", "nodejs14", "nodejs16",
		"python3.6", "python3.7", "python3.8",
		"ruby2.5", "ruby2.7",
		"dotnetcore2.1", "dotnet6",
		"java8", "go1.x",
		"node|14", "node|16", "python|3.8", "python|3.7",
	}
	for _, item := range deprecated {
		if strings.Contains(runtime, item) {
			return true
		}
	}
	_ = provider
	return false
}

func looksSensitiveValue(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	return awsAccessKeyPattern.MatchString(value) || githubTokenPattern.MatchString(value) || slackTokenPattern.MatchString(value) || privateKeyPattern.MatchString(value) || inlineSecretPattern.MatchString(value)
}

func looksPlaceholderValue(value string) bool {
	value = strings.TrimSpace(strings.ToLower(value))
	return value == "***" || value == "******" || value == "changeme" || value == "replace-me" || strings.HasPrefix(value, "${")
}

func sanitizeFindingID(raw string) string {
	raw = strings.TrimSpace(raw)
	replacer := strings.NewReplacer("/", "-", "\\", "-", ":", "-", " ", "-", ".", "-")
	return replacer.Replace(raw)
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

func cloneFunctionDescriptor(src *FunctionDescriptor) *FunctionDescriptor {
	if src == nil {
		return nil
	}
	cloned := *src
	cloned.Architectures = append([]string(nil), src.Architectures...)
	cloned.Environment = cloneStringMap(src.Environment)
	cloned.BuildEnvironment = cloneStringMap(src.BuildEnvironment)
	cloned.EventSources = append([]string(nil), src.EventSources...)
	cloned.Metadata = cloneAnyMap(src.Metadata)
	cloned.VpcConfig = cloneAnyMap(src.VpcConfig)
	if len(src.Artifacts) > 0 {
		cloned.Artifacts = make([]ArtifactRef, len(src.Artifacts))
		for i, artifact := range src.Artifacts {
			cloned.Artifacts[i] = artifact
			cloned.Artifacts[i].Metadata = cloneAnyMap(artifact.Metadata)
		}
	}
	if len(src.Layers) > 0 {
		cloned.Layers = make([]FunctionLayer, len(src.Layers))
		for i, layer := range src.Layers {
			cloned.Layers[i] = layer
			cloned.Layers[i].Architectures = append([]string(nil), layer.Architectures...)
			cloned.Layers[i].Metadata = cloneAnyMap(layer.Metadata)
		}
	}
	return &cloned
}

func redactFunctionDescriptorSecrets(src *FunctionDescriptor) *FunctionDescriptor {
	if src == nil {
		return nil
	}
	src.Environment = redactSensitiveEnv(src.Environment)
	src.BuildEnvironment = redactSensitiveEnv(src.BuildEnvironment)
	return src
}

func redactSensitiveEnv(src map[string]string) map[string]string {
	if len(src) == 0 {
		return nil
	}
	// Persisted run descriptors fail closed: only explicitly allowlisted
	// operational keys survive durable storage.
	out := make(map[string]string, len(src))
	for key, value := range src {
		trimmedKey := strings.ToUpper(strings.TrimSpace(key))
		trimmedValue := strings.TrimSpace(value)
		if trimmedValue == "" {
			out[key] = value
			continue
		}
		if _, ok := persistedSafeEnvKeys[trimmedKey]; ok {
			out[key] = value
			continue
		}
		out[key] = redactedSecretValue
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
		return "function scan failed"
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
