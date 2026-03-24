package reposcan

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/lineage"
	"github.com/writer/cerebro/internal/scanpolicy"
	"github.com/writer/cerebro/internal/scm"
)

type Analyzer interface {
	Analyze(ctx context.Context, input AnalysisInput) (*AnalysisReport, error)
}

type LineageResolver interface {
	GetLineageByCommit(commitSHA string) []*lineage.AssetLineage
	GetLineageByRepository(repo string) []*lineage.AssetLineage
}

type RunnerOptions struct {
	Store           RunStore
	Materializer    Materializer
	Analyzer        Analyzer
	Graph           *graph.Graph
	Lineage         LineageResolver
	Logger          *slog.Logger
	Now             func() time.Time
	PolicyEvaluator scanpolicy.Evaluator
}

type Runner struct {
	store           RunStore
	materializer    Materializer
	analyzer        Analyzer
	graph           *graph.Graph
	lineage         LineageResolver
	logger          *slog.Logger
	now             func() time.Time
	policyEvaluator scanpolicy.Evaluator
}

func NewRunner(opts RunnerOptions) *Runner {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	analyzer := opts.Analyzer
	if analyzer == nil {
		analyzer = FilesystemAnalyzer{}
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &Runner{
		store:           opts.Store,
		materializer:    opts.Materializer,
		analyzer:        analyzer,
		graph:           opts.Graph,
		lineage:         opts.Lineage,
		logger:          logger,
		now:             now,
		policyEvaluator: opts.PolicyEvaluator,
	}
}

func (r *Runner) RunRepositoryScan(ctx context.Context, req ScanRequest) (*RunRecord, error) {
	if r == nil {
		return nil, fmt.Errorf("repo scan runner is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := r.validateRequest(req); err != nil {
		return nil, err
	}
	if r.materializer == nil {
		return nil, fmt.Errorf("repo scan materializer is nil")
	}
	if strings.TrimSpace(req.ID) == "" {
		req.ID = "repo_scan:" + uuid.NewString()
	}
	if req.SubmittedAt.IsZero() {
		req.SubmittedAt = r.now().UTC()
	}
	if strings.TrimSpace(req.Target.SinceCommit) == "" {
		req.Target.SinceCommit = r.lastSuccessfulCommit(ctx, req.Target)
	}

	run := &RunRecord{
		ID:           req.ID,
		Status:       RunStatusQueued,
		Stage:        RunStageQueued,
		Target:       req.Target,
		RequestedBy:  strings.TrimSpace(req.RequestedBy),
		DryRun:       req.DryRun,
		KeepCheckout: req.KeepCheckout,
		Metadata:     cloneStringMap(req.Metadata),
		SubmittedAt:  req.SubmittedAt.UTC(),
		UpdatedAt:    req.SubmittedAt.UTC(),
	}
	if err := r.saveRun(ctx, run); err != nil {
		return nil, err
	}
	r.recordRunEvent(ctx, run, RunStatusQueued, RunStageQueued, "repository scan queued", nil)

	started := r.now().UTC()
	run.Status = RunStatusRunning
	run.Stage = RunStageClone
	run.StartedAt = &started
	run.UpdatedAt = started
	if err := r.saveRun(ctx, run); err != nil {
		return nil, err
	}
	r.recordRunEvent(ctx, run, RunStatusRunning, RunStageClone, "cloning repository", nil)

	descriptor, checkout, err := r.materializer.Materialize(ctx, run.ID, req.Target)
	if err != nil {
		return r.failRun(ctx, run, RunStageClone, fmt.Errorf("clone repository: %w", err))
	}
	run.Descriptor = descriptor
	run.Checkout = checkout
	run.UpdatedAt = r.now().UTC()
	if err := r.saveRun(ctx, run); err != nil {
		return nil, err
	}

	if !req.DryRun {
		run.Stage = RunStageAnalyze
		run.UpdatedAt = r.now().UTC()
		if err := r.saveRun(ctx, run); err != nil {
			return nil, err
		}
		changedPaths, err := r.changedPaths(ctx, run)
		if err != nil {
			r.cleanupCheckout(ctx, run)
			return r.failRun(ctx, run, RunStageAnalyze, err)
		}
		if strings.TrimSpace(run.Target.SinceCommit) != "" && run.Descriptor != nil && strings.TrimSpace(run.Descriptor.CommitSHA) == strings.TrimSpace(run.Target.SinceCommit) {
			report := &AnalysisReport{
				Analyzer:              "iac_trivy",
				IncrementalBaseCommit: strings.TrimSpace(run.Target.SinceCommit),
				Skipped:               true,
				Metadata: map[string]any{
					"repository":   run.Descriptor.Repository,
					"commit_sha":   run.Descriptor.CommitSHA,
					"since_commit": strings.TrimSpace(run.Target.SinceCommit),
					"scan_mode":    "incremental_noop",
				},
			}
			run.Analysis = report
			run.UpdatedAt = r.now().UTC()
			if err := r.saveRun(ctx, run); err != nil {
				return nil, err
			}
		} else {
			r.recordRunEvent(ctx, run, RunStatusRunning, RunStageAnalyze, "analyzing repository IaC", map[string]any{
				"since_commit":  strings.TrimSpace(run.Target.SinceCommit),
				"changed_paths": cloneStringSlice(changedPaths),
			})
			report, err := r.analyze(ctx, run, changedPaths)
			if err != nil {
				r.cleanupCheckout(ctx, run)
				return r.failRun(ctx, run, RunStageAnalyze, err)
			}
			run.Analysis = report
			run.UpdatedAt = r.now().UTC()
			if err := r.saveRun(ctx, run); err != nil {
				return nil, err
			}
		}
		if run.Analysis != nil {
			if integration, err := r.integrateGraph(ctx, run); err != nil {
				r.cleanupCheckout(ctx, run)
				return r.failRun(ctx, run, RunStageAnalyze, err)
			} else if integration != nil {
				run.Analysis.GraphIntegration = integration
				run.UpdatedAt = r.now().UTC()
				if err := r.saveRun(ctx, run); err != nil {
					return nil, err
				}
			}
		}
	}

	if run.Checkout != nil && !run.KeepCheckout {
		run.Stage = RunStageCleanup
		run.UpdatedAt = r.now().UTC()
		if err := r.saveRun(ctx, run); err != nil {
			return nil, err
		}
		r.recordRunEvent(ctx, run, RunStatusRunning, RunStageCleanup, "cleaning up repository checkout", nil)
		if err := r.materializer.Cleanup(ctx, run.Checkout); err != nil {
			r.logger.Warn("repo scan cleanup failed", "run_id", run.ID, "path", run.Checkout.Path, "error", err)
		} else {
			cleanedAt := r.now().UTC()
			run.Checkout.CleanedUpAt = &cleanedAt
		}
		run.UpdatedAt = r.now().UTC()
		if err := r.saveRun(ctx, run); err != nil {
			return nil, err
		}
	}

	message := "repository IaC scan completed"
	if req.DryRun {
		message = "repository scan dry-run completed"
	}
	return r.completeRun(ctx, run, message)
}

func (r *Runner) analyze(ctx context.Context, run *RunRecord, changedPaths []string) (*AnalysisReport, error) {
	report, err := r.analyzer.Analyze(ctx, AnalysisInput{
		RunID:        run.ID,
		Target:       run.Target,
		Checkout:     run.Checkout,
		Metadata:     cloneStringMap(run.Metadata),
		SinceCommit:  strings.TrimSpace(run.Target.SinceCommit),
		ChangedPaths: cloneStringSlice(changedPaths),
		Descriptor: func() RepositoryDescriptor {
			if run.Descriptor == nil {
				return RepositoryDescriptor{}
			}
			return *run.Descriptor
		}(),
	})
	if err != nil {
		return nil, err
	}
	if report == nil {
		return &AnalysisReport{Analyzer: "noop"}, nil
	}
	if report.IncrementalBaseCommit == "" {
		report.IncrementalBaseCommit = strings.TrimSpace(run.Target.SinceCommit)
	}
	if len(report.ChangedPaths) == 0 {
		report.ChangedPaths = cloneStringSlice(changedPaths)
	}
	if report.Catalog != nil {
		if report.IaCArtifactCount == 0 {
			report.IaCArtifactCount = len(report.Catalog.IaCArtifacts)
		}
		if report.MisconfigurationCount == 0 {
			report.MisconfigurationCount = len(report.Catalog.Misconfigurations)
		}
	}
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
	return run, nil
}

func (r *Runner) failRun(ctx context.Context, run *RunRecord, stage RunStage, err error) (*RunRecord, error) {
	failedAt := r.now().UTC()
	run.Status = RunStatusFailed
	run.Stage = stage
	run.Error = operatorSafeErrorMessage(err)
	run.CompletedAt = &failedAt
	run.UpdatedAt = failedAt
	if saveErr := r.saveRun(ctx, run); saveErr != nil {
		return nil, saveErr
	}
	r.recordRunEvent(ctx, run, run.Status, run.Stage, run.Error, nil)
	return run, err
}

func (r *Runner) cleanupCheckout(ctx context.Context, run *RunRecord) {
	if r == nil || r.materializer == nil || run == nil || run.Checkout == nil || run.KeepCheckout {
		return
	}
	if err := r.materializer.Cleanup(ctx, run.Checkout); err != nil {
		r.logger.Warn("repo scan cleanup failed", "run_id", run.ID, "path", run.Checkout.Path, "error", err)
		return
	}
	cleanedAt := r.now().UTC()
	run.Checkout.CleanedUpAt = &cleanedAt
	run.UpdatedAt = cleanedAt
	_ = r.saveRun(ctx, run)
}

func (r *Runner) saveRun(ctx context.Context, run *RunRecord) error {
	if r == nil || r.store == nil {
		return nil
	}
	sanitizeRunForPersistence(run)
	return r.store.SaveRun(ctx, run)
}

func (r *Runner) recordRunEvent(ctx context.Context, run *RunRecord, status RunStatus, stage RunStage, message string, data map[string]any) {
	if r == nil || r.store == nil || run == nil {
		return
	}
	if _, err := r.store.AppendEvent(ctx, run.ID, RunEvent{
		Status:     status,
		Stage:      stage,
		Message:    sanitizeMessage(message),
		Data:       cloneAnyMap(data),
		RecordedAt: r.now().UTC(),
	}); err != nil {
		r.logger.Warn("persist repo scan event failed", "run_id", run.ID, "error", err)
	}
}

func validateRequest(req ScanRequest) error {
	if strings.TrimSpace(req.Target.RepoURL) == "" {
		return fmt.Errorf("repo URL is required")
	}
	if err := scm.ValidateGitRef(req.Target.Ref); err != nil {
		return err
	}
	if err := scm.ValidateSinceCommit(req.Target.SinceCommit); err != nil {
		return err
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
		Kind:         scanpolicy.KindRepository,
		Team:         scanpolicy.TeamFromMetadata(req.Metadata),
		RequestedBy:  strings.TrimSpace(req.RequestedBy),
		Metadata:     cloneStringMap(req.Metadata),
		DryRun:       req.DryRun,
		KeepCheckout: req.KeepCheckout,
	})
}

func (r *Runner) lastSuccessfulCommit(ctx context.Context, target ScanTarget) string {
	if r == nil || r.store == nil {
		return ""
	}
	runs, err := r.store.ListRuns(ctx, RunListOptions{
		Statuses:           []RunStatus{RunStatusSucceeded},
		Limit:              200,
		OrderBySubmittedAt: true,
	})
	if err != nil {
		return ""
	}
	for _, candidate := range runs {
		if !sameRepositoryTarget(target, candidate.Target, candidate.Descriptor) {
			continue
		}
		if candidate.Descriptor == nil {
			continue
		}
		return strings.TrimSpace(candidate.Descriptor.CommitSHA)
	}
	return ""
}

func sameRepositoryTarget(current, previous ScanTarget, descriptor *RepositoryDescriptor) bool {
	currentValues := []string{
		strings.TrimSpace(current.RepoURL),
		strings.TrimSpace(current.Repository),
		inferRepositoryName(current.RepoURL),
	}
	previousValues := []string{
		strings.TrimSpace(previous.RepoURL),
		strings.TrimSpace(previous.Repository),
		inferRepositoryName(previous.RepoURL),
	}
	if descriptor != nil {
		previousValues = append(previousValues, strings.TrimSpace(descriptor.RepoURL), strings.TrimSpace(descriptor.Repository))
	}
	for _, currentValue := range currentValues {
		if currentValue == "" {
			continue
		}
		for _, previousValue := range previousValues {
			if previousValue != "" && strings.EqualFold(currentValue, previousValue) {
				return true
			}
		}
	}
	return false
}

func (r *Runner) changedPaths(ctx context.Context, run *RunRecord) ([]string, error) {
	if r == nil || run == nil || run.Checkout == nil || strings.TrimSpace(run.Checkout.Path) == "" {
		return nil, nil
	}
	sinceCommit := strings.TrimSpace(run.Target.SinceCommit)
	if sinceCommit == "" {
		return nil, nil
	}
	if run.Descriptor != nil && strings.TrimSpace(run.Descriptor.CommitSHA) == sinceCommit {
		return nil, nil
	}
	if err := scm.ValidateSinceCommit(sinceCommit); err != nil {
		return nil, err
	}
	out, err := exec.CommandContext(ctx, "git", "-C", run.Checkout.Path, "diff", "--name-only", sinceCommit+"..HEAD", "--").CombinedOutput() // #nosec G204 -- fixed binary/args
	if err != nil {
		return nil, fmt.Errorf("list files changed since %s: %s: %w", sinceCommit, strings.TrimSpace(string(out)), err)
	}
	paths := make([]string, 0)
	seen := make(map[string]struct{})
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		trimmed := normalizeRepoPath(line)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		paths = append(paths, trimmed)
	}
	return paths, nil
}

func cloneStringMap(input map[string]string) map[string]string {
	if len(input) == 0 {
		return nil
	}
	cloned := make(map[string]string, len(input))
	for key, value := range input {
		cloned[key] = value
	}
	return cloned
}

func cloneAnyMap(input map[string]any) map[string]any {
	if len(input) == 0 {
		return nil
	}
	cloned := make(map[string]any, len(input))
	for key, value := range input {
		cloned[key] = value
	}
	return cloned
}
