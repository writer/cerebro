package workloadscan

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/writer/cerebro/internal/filesystemanalyzer"
	"github.com/writer/cerebro/internal/metrics"
	"github.com/writer/cerebro/internal/scanner"
	"github.com/writer/cerebro/internal/scanpolicy"
	"github.com/writer/cerebro/internal/webhooks"
)

const (
	defaultMaxConcurrentSnapshots = 2
	defaultCleanupTimeout         = 2 * time.Minute
)

type EventEmitter interface {
	EmitWithErrors(ctx context.Context, eventType webhooks.EventType, data map[string]interface{}) error
}

type Provider interface {
	Kind() ProviderKind
	InventoryVolumes(ctx context.Context, target VMTarget) ([]SourceVolume, error)
	CreateSnapshot(ctx context.Context, target VMTarget, volume SourceVolume, metadata map[string]string) (*SnapshotArtifact, error)
	ShareSnapshot(ctx context.Context, target VMTarget, scannerHost ScannerHost, snapshot SnapshotArtifact) (*SnapshotArtifact, error)
	CreateInspectionVolume(ctx context.Context, target VMTarget, scannerHost ScannerHost, snapshot SnapshotArtifact) (*InspectionVolume, error)
	AttachInspectionVolume(ctx context.Context, target VMTarget, scannerHost ScannerHost, volume InspectionVolume, index int) (*VolumeAttachment, error)
	DetachInspectionVolume(ctx context.Context, attachment VolumeAttachment) error
	DeleteInspectionVolume(ctx context.Context, volume InspectionVolume) error
	DeleteSnapshot(ctx context.Context, snapshot SnapshotArtifact) error
}

type Mounter interface {
	Mount(ctx context.Context, attachment VolumeAttachment, source SourceVolume) (*MountedVolume, error)
	Unmount(ctx context.Context, mount MountedVolume) error
}

type Analyzer interface {
	Analyze(ctx context.Context, input AnalysisInput) (*AnalysisReport, error)
}

type ScannerProvisioner interface {
	ProvisionScannerHost(ctx context.Context, req ScanRequest) (ScannerHost, error)
	ReleaseScannerHost(ctx context.Context, host ScannerHost) error
}

type attachmentSlotProvider interface {
	MaxConcurrentAttachments() int
}

type NoopAnalyzer struct{}

func (NoopAnalyzer) Analyze(_ context.Context, input AnalysisInput) (*AnalysisReport, error) {
	return &AnalysisReport{
		Metadata: map[string]any{
			"analyzer":   "noop",
			"mount_path": input.Mount.MountPath,
		},
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
	catalog, err := analyzer.Analyze(ctx, input.Mount.MountPath)
	if err != nil {
		return nil, err
	}
	report := &AnalysisReport{
		FindingCount: int64(len(catalog.Findings)),
		Catalog:      catalog,
		Metadata: map[string]any{
			"analyzer":         "filesystem",
			"mount_path":       input.Mount.MountPath,
			"package_count":    catalog.Summary.PackageCount,
			"technology_count": catalog.Summary.TechnologyCount,
		},
	}
	if catalog.SBOM.Format != "" {
		report.SBOMRef = "embedded:" + catalog.SBOM.Format
	}
	return report, nil
}

type RunnerOptions struct {
	Store                  RunStore
	Providers              []Provider
	Mounter                Mounter
	Analyzer               Analyzer
	Events                 EventEmitter
	Logger                 *slog.Logger
	MaxConcurrentSnapshots int
	CleanupTimeout         time.Duration
	Retry                  scanner.RetryOptions
	Now                    func() time.Time
	PolicyEvaluator        scanpolicy.Evaluator
	Provisioner            ScannerProvisioner
}

type Runner struct {
	store                  RunStore
	providers              map[ProviderKind]Provider
	mounter                Mounter
	analyzer               Analyzer
	events                 EventEmitter
	logger                 *slog.Logger
	maxConcurrentSnapshots int
	cleanupTimeout         time.Duration
	retry                  scanner.RetryOptions
	now                    func() time.Time
	policyEvaluator        scanpolicy.Evaluator
	provisioner            ScannerProvisioner
}

func NewRunner(opts RunnerOptions) *Runner {
	providers := make(map[ProviderKind]Provider, len(opts.Providers))
	for _, provider := range opts.Providers {
		if provider == nil {
			continue
		}
		providers[provider.Kind()] = provider
	}
	maxConcurrent := opts.MaxConcurrentSnapshots
	if maxConcurrent <= 0 {
		maxConcurrent = defaultMaxConcurrentSnapshots
	}
	cleanupTimeout := opts.CleanupTimeout
	if cleanupTimeout <= 0 {
		cleanupTimeout = defaultCleanupTimeout
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	analyzer := opts.Analyzer
	if analyzer == nil {
		analyzer = NoopAnalyzer{}
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &Runner{
		store:                  opts.Store,
		providers:              providers,
		mounter:                opts.Mounter,
		analyzer:               analyzer,
		events:                 opts.Events,
		logger:                 logger,
		maxConcurrentSnapshots: maxConcurrent,
		cleanupTimeout:         cleanupTimeout,
		retry:                  defaultWorkloadRetryOptions(opts.Retry),
		now:                    now,
		policyEvaluator:        opts.PolicyEvaluator,
		provisioner:            opts.Provisioner,
	}
}

func (r *Runner) RunVMScan(ctx context.Context, req ScanRequest) (result *RunRecord, err error) {
	if r == nil {
		return nil, fmt.Errorf("workload scan runner is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if strings.TrimSpace(req.ID) == "" {
		req.ID = "workload_scan:" + uuid.NewString()
	}
	if req.SubmittedAt.IsZero() {
		req.SubmittedAt = r.now().UTC()
	}
	req, ephemeralScanner, err := r.ensureScannerHost(ctx, req)
	if err != nil {
		return nil, err
	}
	defer func() {
		if !ephemeralScanner {
			return
		}
		releaseErr := r.releaseScannerHost(context.Background(), req.ScannerHost)
		if releaseErr == nil {
			if result != nil {
				r.recordRunEvent(context.Background(), result, result.Status, RunStageCleanup, "ephemeral scanner host released", map[string]any{
					"scanner_host_id": req.ScannerHost.HostID,
				})
			}
			return
		}
		releaseErr = fmt.Errorf("release ephemeral scanner host %s: %w", req.ScannerHost.HostID, releaseErr)
		if result != nil {
			failedRun, failErr := r.failRun(context.Background(), result, RunStageCleanup, releaseErr)
			result = failedRun
			if failErr != nil {
				if err != nil {
					err = errors.Join(err, failErr)
				} else {
					err = failErr
				}
				return
			}
		}
		if err != nil {
			err = errors.Join(err, releaseErr)
		} else {
			err = releaseErr
		}
	}()
	if err := r.validateRequest(req); err != nil {
		return nil, err
	}
	provider, ok := r.providers[req.Target.Provider]
	if !ok {
		return nil, fmt.Errorf("no workload scan provider configured for %s", req.Target.Provider)
	}
	run := newRunRecordFromRequest(req)
	if err := r.saveRun(ctx, run); err != nil {
		return nil, err
	}
	if ephemeralScanner {
		r.recordRunEvent(ctx, run, run.Status, run.Stage, "ephemeral scanner host provisioned", map[string]any{
			"scanner_host_id": req.ScannerHost.HostID,
		})
	}
	r.recordRunEvent(ctx, run, RunStatusQueued, RunStageQueued, "workload scan queued", nil)
	return r.executeRun(ctx, provider, req, run, false)
}

func (r *Runner) RunClaimedRun(ctx context.Context, runID string) (result *RunRecord, err error) {
	if r == nil {
		return nil, fmt.Errorf("workload scan runner is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if r.store == nil {
		return nil, fmt.Errorf("workload scan store is not configured")
	}
	runID = strings.TrimSpace(runID)
	if runID == "" {
		return nil, fmt.Errorf("workload scan run id is required")
	}
	run, err := r.store.LoadRun(ctx, runID)
	if err != nil {
		return nil, err
	}
	if run == nil {
		return nil, fmt.Errorf("workload scan run not found: %s", runID)
	}
	if run.Status != RunStatusRunning || run.Stage != RunStageInventory {
		return nil, fmt.Errorf("workload scan run %s is not claimed for distributed execution", runID)
	}
	req := scanRequestFromRun(run)
	if err := r.validateRequest(req); err != nil {
		return r.failRun(ctx, run, run.Stage, err)
	}
	provider, ok := r.providers[run.Target.Provider]
	if !ok {
		return r.failRun(ctx, run, run.Stage, fmt.Errorf("no workload scan provider configured for %s", run.Target.Provider))
	}
	return r.executeRun(ctx, provider, req, run, true)
}

func (r *Runner) executeRun(ctx context.Context, provider Provider, req ScanRequest, run *RunRecord, alreadyClaimed bool) (result *RunRecord, err error) {
	started := r.now().UTC()
	run.Status = RunStatusRunning
	run.Stage = RunStageInventory
	if run.StartedAt == nil {
		run.StartedAt = &started
	}
	run.UpdatedAt = started
	if err := r.saveRun(ctx, run); err != nil {
		return nil, err
	}
	finishRunObservation := startRunObservation(run.Provider, req.DryRun)
	defer func() {
		if finishRunObservation != nil {
			status := run.Status
			if err != nil || !status.Terminal() {
				status = RunStatusFailed
			}
			finishRunObservation(status)
		}
	}()
	if alreadyClaimed && run.Distributed != nil && run.Distributed.ClaimedAt == nil {
		claimedAt := started
		run.Distributed.ClaimedAt = &claimedAt
	}
	r.recordRunEvent(ctx, run, RunStatusRunning, RunStageInventory, "inventorying attached volumes", nil)
	r.emitLifecycleEvent(ctx, webhooks.EventSecurityWorkloadScanStarted, run, nil)
	r.logger.Info("workload scan started",
		"run_id", run.ID,
		"provider", run.Provider,
		"target_id", run.Target.Identity(),
		"scanner_host_id", run.ScannerHost.HostID,
		"dry_run", run.DryRun,
	)

	finishInventoryObservation := startStageObservation(run.Provider, RunStageInventory, false)
	volumes, err := provider.InventoryVolumes(ctx, req.Target)
	if err != nil {
		finishInventoryObservation(RunStatusFailed)
		return r.failRun(ctx, run, RunStageInventory, fmt.Errorf("inventory volumes: %w", err))
	}
	finishInventoryObservation(RunStatusSucceeded)
	run.Summary.VolumeCount = len(volumes)
	run.Volumes = make([]VolumeScanRecord, len(volumes))
	now := r.now().UTC()
	for i, volume := range volumes {
		run.Volumes[i] = VolumeScanRecord{
			Source:    volume,
			Status:    RunStatusQueued,
			Stage:     RunStageInventory,
			StartedAt: now,
			UpdatedAt: now,
		}
	}
	recomputeSummary(run)
	if err := r.saveRun(ctx, run); err != nil {
		return nil, err
	}
	r.recordRunEvent(ctx, run, RunStatusRunning, RunStageInventory, "inventory complete", map[string]any{
		"volume_count": len(volumes),
	})
	r.logger.Info("workload scan inventory complete", "run_id", run.ID, "provider", run.Provider, "volume_count", len(volumes))

	if req.DryRun {
		completed := r.now().UTC()
		run.Status = RunStatusSucceeded
		run.Stage = RunStageCompleted
		run.CompletedAt = &completed
		run.UpdatedAt = completed
		recomputeSummary(run)
		if err := r.saveRun(ctx, run); err != nil {
			return nil, err
		}
		r.recordRunEvent(ctx, run, run.Status, run.Stage, "dry-run completed", nil)
		r.emitLifecycleEvent(ctx, webhooks.EventSecurityWorkloadScanCompleted, run, nil)
		r.emitGenericScanCompleted(ctx, run)
		r.releaseDistributedDedup(ctx, run)
		r.logger.Info("workload scan dry-run completed", "run_id", run.ID, "provider", run.Provider, "volume_count", run.Summary.VolumeCount)
		return run, nil
	}

	limit := req.MaxConcurrentSnapshots
	if limit <= 0 {
		limit = r.maxConcurrentSnapshots
	}
	sem := make(chan struct{}, limit)
	var attachmentSlots chan int
	if slotCapacity := attachmentSlotCapacity(provider); slotCapacity > 0 {
		attachmentSlots = make(chan int, slotCapacity)
		for slot := 0; slot < slotCapacity; slot++ {
			attachmentSlots <- slot
		}
	}
	var (
		runMu sync.Mutex
		wg    sync.WaitGroup
		errMu sync.Mutex
		errs  []error
	)
	for i := range run.Volumes {
		wg.Add(1)
		i := i
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				errMu.Lock()
				errs = append(errs, ctx.Err())
				errMu.Unlock()
				return
			}
			defer func() { <-sem }()
			if err := r.processVolume(ctx, provider, req, run, i, attachmentSlots, &runMu); err != nil {
				errMu.Lock()
				errs = append(errs, err)
				errMu.Unlock()
			}
		}()
	}
	wg.Wait()

	if len(errs) > 0 {
		return r.failRun(ctx, run, RunStageFailed, joinErrors(errs))
	}

	completed := r.now().UTC()
	run.Status = RunStatusSucceeded
	run.Stage = RunStageCompleted
	run.CompletedAt = &completed
	run.UpdatedAt = completed
	recomputeSummary(run)
	if err := r.saveRun(ctx, run); err != nil {
		return nil, err
	}
	r.recordRunEvent(ctx, run, run.Status, run.Stage, "workload scan completed", nil)
	r.emitLifecycleEvent(ctx, webhooks.EventSecurityWorkloadScanCompleted, run, nil)
	r.emitGenericScanCompleted(ctx, run)
	r.releaseDistributedDedup(ctx, run)
	r.logger.Info("workload scan completed",
		"run_id", run.ID,
		"provider", run.Provider,
		"volume_count", run.Summary.VolumeCount,
		"succeeded_volumes", run.Summary.SucceededVolumes,
		"failed_volumes", run.Summary.FailedVolumes,
		"finding_count", run.Summary.Findings,
	)
	return run, nil
}

func newRunRecordFromRequest(req ScanRequest) *RunRecord {
	return &RunRecord{
		ID:                     req.ID,
		Provider:               req.Target.Provider,
		Status:                 RunStatusQueued,
		Stage:                  RunStageQueued,
		Target:                 req.Target,
		ScannerHost:            req.ScannerHost,
		RequestedBy:            strings.TrimSpace(req.RequestedBy),
		DryRun:                 req.DryRun,
		MaxConcurrentSnapshots: req.MaxConcurrentSnapshots,
		Metadata:               cloneStringMap(req.Metadata),
		Priority:               ClonePriorityAssessment(req.Priority),
		SubmittedAt:            req.SubmittedAt.UTC(),
		UpdatedAt:              req.SubmittedAt.UTC(),
	}
}

func scanRequestFromRun(run *RunRecord) ScanRequest {
	if run == nil {
		return ScanRequest{}
	}
	return ScanRequest{
		ID:                     run.ID,
		RequestedBy:            strings.TrimSpace(run.RequestedBy),
		Target:                 run.Target,
		ScannerHost:            run.ScannerHost,
		MaxConcurrentSnapshots: run.MaxConcurrentSnapshots,
		DryRun:                 run.DryRun,
		Metadata:               cloneStringMap(run.Metadata),
		Priority:               ClonePriorityAssessment(run.Priority),
		SubmittedAt:            run.SubmittedAt,
	}
}

func (r *Runner) Reconcile(ctx context.Context, olderThan time.Duration) ([]RunRecord, error) {
	if r == nil || r.store == nil {
		return nil, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	reconciled := make([]RunRecord, 0)
	now := r.now().UTC()
	const reconcilePageSize = 500
	for offset := 0; ; offset += reconcilePageSize {
		runs, err := r.store.ListRuns(ctx, RunListOptions{
			Limit:              reconcilePageSize,
			Offset:             offset,
			OrderBySubmittedAt: true,
		})
		if err != nil {
			return reconciled, err
		}
		if len(runs) == 0 {
			break
		}
		for i := range runs {
			run := runs[i]
			if !runNeedsReconciliation(run) {
				continue
			}
			if olderThan > 0 && now.Sub(run.UpdatedAt.UTC()) < olderThan {
				continue
			}
			provider, ok := r.providers[run.Provider]
			if !ok {
				continue
			}
			changed := false
			for idx := range run.Volumes {
				if reconcileErr := r.reconcileVolume(ctx, provider, &run, idx); reconcileErr != nil {
					run.Error = reconcileErr.Error()
					run.Status = RunStatusFailed
					run.Stage = RunStageReconcile
				}
				if run.Volumes[idx].Cleanup.Reconciled {
					changed = true
				}
			}
			if !changed {
				continue
			}
			run.UpdatedAt = now
			recomputeSummary(&run)
			if allVolumesTerminal(run.Volumes) && run.Error == "" {
				run.Status = RunStatusSucceeded
				run.Stage = RunStageCompleted
				if run.CompletedAt == nil {
					completed := now
					run.CompletedAt = &completed
				}
			} else if run.Status != RunStatusFailed {
				run.Stage = RunStageReconcile
			}
			if err := r.saveRun(ctx, &run); err != nil {
				return reconciled, err
			}
			r.recordRunEvent(ctx, &run, run.Status, RunStageReconcile, "reconciled orphaned workload scan artifacts", nil)
			r.emitLifecycleEvent(ctx, webhooks.EventSecurityWorkloadScanReconciled, &run, nil)
			reconciled = append(reconciled, run)
		}
		if len(runs) < reconcilePageSize {
			break
		}
	}
	return reconciled, nil
}

func (r *Runner) processVolume(ctx context.Context, provider Provider, req ScanRequest, run *RunRecord, idx int, attachmentSlots chan int, runMu *sync.Mutex) (err error) {
	source := run.Volumes[idx].Source
	defer func() {
		if recovered := recover(); recovered != nil {
			stage := currentVolumeStage(run, idx, runMu)
			panicErr := fmt.Errorf("panic while scanning volume %s: %v", source.ID, recovered)
			cleanupErr := r.cleanupVolume(run, idx, provider, runMu)
			err = r.failVolume(ctx, run, idx, runMu, stage, joinErrors([]error{panicErr, cleanupErr}))
		}
	}()
	r.updateVolume(ctx, run, idx, runMu, func(volume *VolumeScanRecord) {
		volume.Status = RunStatusRunning
		volume.Stage = RunStageSnapshot
		volume.UpdatedAt = r.now().UTC()
	}, "creating point-in-time snapshot", nil)

	finishSnapshotObservation := startStageObservation(req.Target.Provider, RunStageSnapshot, true)
	snapshot, _, err := scanner.WithRetryValue(ctx, r.retry, func() (*SnapshotArtifact, error) {
		return provider.CreateSnapshot(ctx, req.Target, source, req.Metadata)
	})
	if err != nil {
		finishSnapshotObservation(RunStatusFailed)
		return r.failVolume(ctx, run, idx, runMu, RunStageSnapshot, fmt.Errorf("create snapshot for %s: %w", source.ID, err))
	}
	finishSnapshotObservation(RunStatusSucceeded)
	r.updateVolume(ctx, run, idx, runMu, func(volume *VolumeScanRecord) {
		volume.Stage = RunStageShare
		volume.Snapshot = snapshot
		volume.UpdatedAt = r.now().UTC()
	}, "snapshot ready", map[string]any{"snapshot_id": snapshot.ID})

	failWithCleanup := func(stage RunStage, err error) error {
		cleanupErr := r.cleanupVolume(run, idx, provider, runMu)
		return r.failVolume(ctx, run, idx, runMu, stage, joinErrors([]error{err, cleanupErr}))
	}

	finishShareObservation := startStageObservation(req.Target.Provider, RunStageShare, true)
	sharedSnapshot, _, err := scanner.WithRetryValue(ctx, r.retry, func() (*SnapshotArtifact, error) {
		return provider.ShareSnapshot(ctx, req.Target, req.ScannerHost, *snapshot)
	})
	if err != nil {
		finishShareObservation(RunStatusFailed)
		return failWithCleanup(RunStageShare, fmt.Errorf("share snapshot %s: %w", snapshot.ID, err))
	}
	finishShareObservation(RunStatusSucceeded)
	if sharedSnapshot != nil {
		snapshot = sharedSnapshot
	}
	r.updateVolume(ctx, run, idx, runMu, func(volume *VolumeScanRecord) {
		volume.Stage = RunStageVolumeCreate
		volume.Snapshot = snapshot
		if volume.Snapshot != nil {
			volume.Snapshot.Shared = true
		}
		volume.UpdatedAt = r.now().UTC()
	}, "snapshot share complete", map[string]any{"snapshot_id": snapshot.ID})

	finishVolumeCreateObservation := startStageObservation(req.Target.Provider, RunStageVolumeCreate, true)
	inspection, _, err := scanner.WithRetryValue(ctx, r.retry, func() (*InspectionVolume, error) {
		return provider.CreateInspectionVolume(ctx, req.Target, req.ScannerHost, *snapshot)
	})
	if err != nil {
		finishVolumeCreateObservation(RunStatusFailed)
		return failWithCleanup(RunStageVolumeCreate, fmt.Errorf("create inspection volume from snapshot %s: %w", snapshot.ID, err))
	}
	finishVolumeCreateObservation(RunStatusSucceeded)
	r.updateVolume(ctx, run, idx, runMu, func(volume *VolumeScanRecord) {
		volume.Stage = RunStageAttach
		volume.Inspection = inspection
		volume.UpdatedAt = r.now().UTC()
	}, "inspection volume ready", map[string]any{"inspection_volume_id": inspection.ID})
	finishAttachObservation := startStageObservation(req.Target.Provider, RunStageAttach, true)
	attachmentSlot := idx
	releaseAttachmentSlot := func() {}
	if attachmentSlots != nil {
		select {
		case attachmentSlot = <-attachmentSlots:
			releaseAttachmentSlot = func() {
				attachmentSlots <- attachmentSlot
			}
		case <-ctx.Done():
			finishAttachObservation(RunStatusFailed)
			return failWithCleanup(RunStageAttach, ctx.Err())
		}
	}
	defer releaseAttachmentSlot()
	attachment, _, err := scanner.WithRetryValue(ctx, r.retry, func() (*VolumeAttachment, error) {
		return provider.AttachInspectionVolume(ctx, req.Target, req.ScannerHost, *inspection, attachmentSlot)
	})
	if err != nil {
		finishAttachObservation(RunStatusFailed)
		return failWithCleanup(RunStageAttach, fmt.Errorf("attach inspection volume %s: %w", inspection.ID, err))
	}
	finishAttachObservation(RunStatusSucceeded)
	r.updateVolume(ctx, run, idx, runMu, func(volume *VolumeScanRecord) {
		volume.Stage = RunStageMount
		volume.Attachment = attachment
		volume.UpdatedAt = r.now().UTC()
	}, "inspection volume attached", map[string]any{"device_name": attachment.DeviceName})

	finishMountObservation := startStageObservation(req.Target.Provider, RunStageMount, true)
	mount, err := r.mounter.Mount(ctx, *attachment, source)
	if err != nil {
		finishMountObservation(RunStatusFailed)
		metrics.RecordWorkloadScanMountFailure(string(req.Target.Provider))
		return failWithCleanup(RunStageMount, fmt.Errorf("mount inspection volume %s: %w", inspection.ID, err))
	}
	finishMountObservation(RunStatusSucceeded)
	r.updateVolume(ctx, run, idx, runMu, func(volume *VolumeScanRecord) {
		volume.Stage = RunStageAnalyze
		volume.Mount = mount
		volume.UpdatedAt = r.now().UTC()
	}, "inspection volume mounted", map[string]any{"mount_path": mount.MountPath})

	finishAnalyzeObservation := startStageObservation(req.Target.Provider, RunStageAnalyze, true)
	report, analyzeErr := r.analyzer.Analyze(ctx, AnalysisInput{
		RunID:       run.ID,
		Target:      req.Target,
		ScannerHost: req.ScannerHost,
		Volume:      source,
		Mount:       *mount,
		Metadata:    cloneStringMap(req.Metadata),
	})
	if analyzeErr != nil {
		finishAnalyzeObservation(RunStatusFailed)
	} else {
		finishAnalyzeObservation(RunStatusSucceeded)
	}
	if analyzeErr == nil {
		r.updateVolume(ctx, run, idx, runMu, func(volume *VolumeScanRecord) {
			volume.Analysis = report
			volume.UpdatedAt = r.now().UTC()
		}, "analysis complete", map[string]any{"finding_count": report.FindingCount})
	}

	cleanupErr := r.cleanupVolume(run, idx, provider, runMu)
	if analyzeErr != nil {
		return r.failVolume(ctx, run, idx, runMu, RunStageAnalyze, fmt.Errorf("analyze mounted volume %s: %w", source.ID, joinErrors([]error{analyzeErr, cleanupErr})))
	}
	if cleanupErr != nil {
		return r.failVolume(ctx, run, idx, runMu, RunStageCleanup, cleanupErr)
	}

	r.updateVolume(ctx, run, idx, runMu, func(volume *VolumeScanRecord) {
		completed := r.now().UTC()
		volume.Status = RunStatusSucceeded
		volume.Stage = RunStageCompleted
		volume.CompletedAt = &completed
		volume.UpdatedAt = completed
	}, "volume scan completed", nil)
	return nil
}

func currentVolumeStage(run *RunRecord, idx int, runMu *sync.Mutex) RunStage {
	if run == nil || runMu == nil {
		return RunStageFailed
	}
	runMu.Lock()
	defer runMu.Unlock()
	if idx < 0 || idx >= len(run.Volumes) {
		return RunStageFailed
	}
	stage := run.Volumes[idx].Stage
	if stage == "" {
		return RunStageFailed
	}
	return stage
}

func (r *Runner) cleanupVolume(run *RunRecord, idx int, provider Provider, runMu *sync.Mutex) error {
	cleanupCtx, cancel := context.WithTimeout(context.Background(), r.cleanupTimeout)
	defer cancel()
	providerKind := ProviderKind("")
	if provider != nil {
		providerKind = provider.Kind()
	}
	if run != nil {
		providerKind = run.Provider
	}
	finishCleanupObservation := startStageObservation(providerKind, RunStageCleanup, true)

	var errs []error
	markAttempt := func(volume *VolumeScanRecord) {
		ts := r.now().UTC()
		volume.Cleanup.LastAttemptAt = &ts
		volume.Stage = RunStageCleanup
		volume.UpdatedAt = ts
	}
	r.updateVolume(cleanupCtx, run, idx, runMu, markAttempt, "cleanup started", nil)

	var (
		mount      *MountedVolume
		attachment *VolumeAttachment
		inspection *InspectionVolume
		snapshot   *SnapshotArtifact
	)
	runMu.Lock()
	if idx >= 0 && idx < len(run.Volumes) {
		volume := run.Volumes[idx]
		mount = volume.Mount
		attachment = volume.Attachment
		inspection = volume.Inspection
		snapshot = volume.Snapshot
	}
	runMu.Unlock()

	if mount != nil && mount.UnmountedAt == nil {
		if err := r.mounter.Unmount(cleanupCtx, *mount); err != nil {
			errs = append(errs, fmt.Errorf("unmount %s: %w", mount.MountPath, err))
		} else {
			r.updateVolume(cleanupCtx, run, idx, runMu, func(volume *VolumeScanRecord) {
				if volume.Mount != nil && volume.Mount.UnmountedAt == nil {
					ts := r.now().UTC()
					volume.Mount.UnmountedAt = &ts
				}
				volume.Cleanup.Unmounted = true
				volume.UpdatedAt = r.now().UTC()
			}, "mount cleaned up", nil)
		}
	}
	if attachment != nil && attachment.DetachedAt == nil {
		if err := provider.DetachInspectionVolume(cleanupCtx, *attachment); err != nil {
			errs = append(errs, fmt.Errorf("detach %s: %w", attachment.VolumeID, err))
		} else {
			r.updateVolume(cleanupCtx, run, idx, runMu, func(volume *VolumeScanRecord) {
				if volume.Attachment != nil && volume.Attachment.DetachedAt == nil {
					ts := r.now().UTC()
					volume.Attachment.DetachedAt = &ts
				}
				volume.Cleanup.Detached = true
				volume.UpdatedAt = r.now().UTC()
			}, "inspection volume detached", nil)
		}
	}
	if inspection != nil && inspection.DeletedAt == nil {
		if err := provider.DeleteInspectionVolume(cleanupCtx, *inspection); err != nil {
			errs = append(errs, fmt.Errorf("delete inspection volume %s: %w", inspection.ID, err))
		} else {
			r.updateVolume(cleanupCtx, run, idx, runMu, func(volume *VolumeScanRecord) {
				if volume.Inspection != nil && volume.Inspection.DeletedAt == nil {
					ts := r.now().UTC()
					volume.Inspection.DeletedAt = &ts
				}
				volume.Cleanup.DeletedVolume = true
				volume.UpdatedAt = r.now().UTC()
				updateVolumeCosts(volume)
			}, "inspection volume deleted", nil)
		}
	}
	if snapshot != nil && snapshot.DeletedAt == nil {
		if err := provider.DeleteSnapshot(cleanupCtx, *snapshot); err != nil {
			errs = append(errs, fmt.Errorf("delete snapshot %s: %w", snapshot.ID, err))
		} else {
			r.updateVolume(cleanupCtx, run, idx, runMu, func(volume *VolumeScanRecord) {
				if volume.Snapshot != nil && volume.Snapshot.DeletedAt == nil {
					ts := r.now().UTC()
					volume.Snapshot.DeletedAt = &ts
				}
				volume.Cleanup.DeletedSnapshot = true
				volume.UpdatedAt = r.now().UTC()
				updateVolumeCosts(volume)
			}, "snapshot deleted", nil)
		}
	}
	if len(errs) > 0 {
		finishCleanupObservation(RunStatusFailed)
		r.updateVolume(cleanupCtx, run, idx, runMu, func(volume *VolumeScanRecord) {
			volume.Cleanup.Error = joinErrors(errs).Error()
			volume.UpdatedAt = r.now().UTC()
		}, "cleanup failed", nil)
		if run != nil && idx >= 0 && idx < len(run.Volumes) {
			r.logger.Warn("workload scan cleanup failed",
				"run_id", run.ID,
				"provider", run.Provider,
				"volume_id", run.Volumes[idx].Source.ID,
				"error", joinErrors(errs),
			)
		}
		return joinErrors(errs)
	}
	finishCleanupObservation(RunStatusSucceeded)
	r.updateVolume(cleanupCtx, run, idx, runMu, func(volume *VolumeScanRecord) {
		volume.Cleanup.Error = ""
		volume.UpdatedAt = r.now().UTC()
		updateVolumeCosts(volume)
	}, "cleanup complete", nil)
	return nil
}

func (r *Runner) reconcileVolume(ctx context.Context, provider Provider, run *RunRecord, idx int) error {
	if idx < 0 || idx >= len(run.Volumes) {
		return nil
	}
	volume := &run.Volumes[idx]
	if volume.Cleanup.DeletedSnapshot && volume.Cleanup.DeletedVolume {
		return nil
	}
	tempRunner := &Runner{
		store:          r.store,
		providers:      r.providers,
		mounter:        r.mounter,
		analyzer:       r.analyzer,
		events:         r.events,
		logger:         r.logger,
		cleanupTimeout: r.cleanupTimeout,
		now:            r.now,
	}
	var runMu sync.Mutex
	if err := tempRunner.cleanupVolume(run, idx, provider, &runMu); err != nil {
		volume.Cleanup.Error = err.Error()
		volume.Cleanup.Reconciled = true
		return err
	}
	volume.Cleanup.Reconciled = true
	return nil
}

func (r *Runner) failRun(ctx context.Context, run *RunRecord, stage RunStage, err error) (*RunRecord, error) {
	failedAt := r.now().UTC()
	run.Status = RunStatusFailed
	run.Stage = stage
	run.Error = strings.TrimSpace(errorString(err))
	run.CompletedAt = &failedAt
	run.UpdatedAt = failedAt
	recomputeSummary(run)
	saveErr := r.saveRun(ctx, run)
	r.recordRunEvent(ctx, run, run.Status, stage, run.Error, nil)
	r.emitLifecycleEvent(ctx, webhooks.EventSecurityWorkloadScanFailed, run, map[string]any{
		"error": run.Error,
	})
	r.releaseDistributedDedup(ctx, run)
	if saveErr != nil {
		return run, errors.Join(err, saveErr)
	}
	r.logger.Warn("workload scan failed",
		"run_id", run.ID,
		"provider", run.Provider,
		"stage", stage,
		"target_id", run.Target.Identity(),
		"error", run.Error,
	)
	return run, err
}

func (r *Runner) failVolume(ctx context.Context, run *RunRecord, idx int, runMu *sync.Mutex, stage RunStage, err error) error {
	r.updateVolume(ctx, run, idx, runMu, func(volume *VolumeScanRecord) {
		completed := r.now().UTC()
		volume.Status = RunStatusFailed
		volume.Stage = stage
		volume.Error = strings.TrimSpace(errorString(err))
		volume.CompletedAt = &completed
		volume.UpdatedAt = completed
		updateVolumeCosts(volume)
	}, errorString(err), nil)
	if run != nil && idx >= 0 && idx < len(run.Volumes) {
		r.logger.Warn("workload scan volume failed",
			"run_id", run.ID,
			"provider", run.Provider,
			"volume_id", run.Volumes[idx].Source.ID,
			"stage", stage,
			"error", errorString(err),
		)
	}
	return err
}

func (r *Runner) updateVolume(ctx context.Context, run *RunRecord, idx int, runMu *sync.Mutex, apply func(*VolumeScanRecord), message string, data map[string]any) {
	if run == nil || runMu == nil {
		return
	}
	runMu.Lock()
	defer runMu.Unlock()
	if idx < 0 || idx >= len(run.Volumes) {
		return
	}
	apply(&run.Volumes[idx])
	recomputeSummary(run)
	run.UpdatedAt = r.now().UTC()
	if err := r.saveRun(ctx, run); err != nil {
		r.logger.Warn("failed to persist workload scan run update", "run_id", run.ID, "error", err)
	}
	if strings.TrimSpace(message) != "" {
		payload := cloneAnyMap(data)
		if payload == nil {
			payload = map[string]any{}
		}
		payload["volume_id"] = run.Volumes[idx].Source.ID
		r.recordRunEvent(ctx, run, run.Volumes[idx].Status, run.Volumes[idx].Stage, message, payload)
	}
}

func (r *Runner) saveRun(ctx context.Context, run *RunRecord) error {
	if r.store == nil {
		return nil
	}
	return r.store.SaveRun(ctx, run)
}

func (r *Runner) releaseDistributedDedup(ctx context.Context, run *RunRecord) {
	if r.store == nil || run == nil || run.Distributed == nil {
		return
	}
	if err := r.store.ReleaseDistributedDedup(ctx, run.Distributed.DedupKey); err != nil {
		r.logger.Warn("failed to release workload scan distributed dedup", "run_id", run.ID, "error", err)
	}
}

func (r *Runner) recordRunEvent(ctx context.Context, run *RunRecord, status RunStatus, stage RunStage, message string, data map[string]any) {
	if r.store == nil || run == nil {
		return
	}
	if _, err := r.store.AppendEvent(ctx, run.ID, RunEvent{
		Status:     status,
		Stage:      stage,
		Message:    strings.TrimSpace(message),
		Data:       cloneAnyMap(data),
		RecordedAt: r.now().UTC(),
	}); err != nil {
		r.logger.Warn("failed to persist workload scan event", "run_id", run.ID, "stage", stage, "error", err)
	}
}

func (r *Runner) emitLifecycleEvent(ctx context.Context, eventType webhooks.EventType, run *RunRecord, extra map[string]any) {
	if r.events == nil || run == nil {
		return
	}
	payload := map[string]any{
		"run_id":             run.ID,
		"provider":           run.Provider,
		"status":             run.Status,
		"stage":              run.Stage,
		"requested_by":       run.RequestedBy,
		"submitted_at":       run.SubmittedAt.UTC().Format(time.RFC3339),
		"dry_run":            run.DryRun,
		"target_id":          run.Target.Identity(),
		"target_region":      run.Target.Region,
		"target_zone":        run.Target.Zone,
		"scanner_host_id":    run.ScannerHost.HostID,
		"scanner_region":     run.ScannerHost.Region,
		"scanner_zone":       run.ScannerHost.Zone,
		"volume_count":       run.Summary.VolumeCount,
		"succeeded_volumes":  run.Summary.SucceededVolumes,
		"failed_volumes":     run.Summary.FailedVolumes,
		"finding_count":      run.Summary.Findings,
		"snapshot_gib_hours": run.Summary.SnapshotGiBHours,
		"volume_gib_hours":   run.Summary.VolumeGiBHours,
		"reconciled_volumes": run.Summary.ReconciledVolumes,
	}
	if run.StartedAt != nil {
		payload["started_at"] = run.StartedAt.UTC().Format(time.RFC3339)
	}
	if run.CompletedAt != nil {
		payload["completed_at"] = run.CompletedAt.UTC().Format(time.RFC3339)
	}
	if run.Error != "" {
		payload["error"] = run.Error
	}
	for key, value := range extra {
		payload[key] = value
	}
	if err := r.events.EmitWithErrors(ctx, eventType, payload); err != nil {
		r.logger.Warn("failed to emit workload scan lifecycle event", "run_id", run.ID, "event_type", eventType, "error", err)
	}
}

func (r *Runner) emitGenericScanCompleted(ctx context.Context, run *RunRecord) {
	if r.events == nil || run == nil {
		return
	}
	duration := int64(0)
	if run.StartedAt != nil && run.CompletedAt != nil {
		duration = run.CompletedAt.Sub(*run.StartedAt).Milliseconds()
	}
	if err := r.events.EmitWithErrors(ctx, webhooks.EventScanCompleted, map[string]interface{}{
		"scanned":            run.Summary.VolumeCount,
		"violations":         run.Summary.Findings,
		"duration_ms":        duration,
		"source_system":      "cerebro_workload_scan",
		"workload_kind":      "vm",
		"run_id":             run.ID,
		"provider":           run.Provider,
		"target_id":          run.Target.Identity(),
		"target_region":      run.Target.Region,
		"snapshot_gib_hours": run.Summary.SnapshotGiBHours,
		"volume_gib_hours":   run.Summary.VolumeGiBHours,
	}); err != nil {
		r.logger.Warn("failed to emit generic scan completed event", "run_id", run.ID, "error", err)
	}
}

func recomputeSummary(run *RunRecord) {
	if run == nil {
		return
	}
	summary := RunSummary{
		VolumeCount: len(run.Volumes),
	}
	for _, volume := range run.Volumes {
		switch volume.Status {
		case RunStatusSucceeded:
			summary.SucceededVolumes++
		case RunStatusFailed:
			summary.FailedVolumes++
		}
		if volume.Analysis != nil {
			summary.Findings += volume.Analysis.FindingCount
		}
		if volume.Cleanup.Reconciled {
			summary.ReconciledVolumes++
		}
		summary.SnapshotGiBHours += volume.Cost.SnapshotGiBHours
		summary.VolumeGiBHours += volume.Cost.VolumeGiBHours
	}
	run.Summary = summary
}

func updateVolumeCosts(volume *VolumeScanRecord) {
	if volume == nil {
		return
	}
	if volume.Snapshot != nil && volume.Snapshot.DeletedAt != nil {
		readyAt := volume.Snapshot.CreatedAt
		if volume.Snapshot.ReadyAt != nil {
			readyAt = *volume.Snapshot.ReadyAt
		}
		volume.Cost.SnapshotGiBHours = gibHours(volume.Snapshot.SizeGiB, readyAt, *volume.Snapshot.DeletedAt)
	}
	if volume.Inspection != nil && volume.Inspection.DeletedAt != nil {
		readyAt := volume.Inspection.CreatedAt
		if volume.Inspection.ReadyAt != nil {
			readyAt = *volume.Inspection.ReadyAt
		}
		volume.Cost.VolumeGiBHours = gibHours(volume.Inspection.SizeGiB, readyAt, *volume.Inspection.DeletedAt)
	}
}

func gibHours(sizeGiB int64, start, end time.Time) float64 {
	if sizeGiB <= 0 || start.IsZero() || end.IsZero() || !end.After(start) {
		return 0
	}
	return (float64(sizeGiB) * end.Sub(start).Hours())
}

func validateTarget(target VMTarget) error {
	if target.Provider == "" {
		return fmt.Errorf("target provider is required")
	}
	if strings.TrimSpace(target.Region) == "" {
		return fmt.Errorf("target region is required")
	}
	switch target.Provider {
	case ProviderAWS:
		if strings.TrimSpace(target.InstanceID) == "" {
			return fmt.Errorf("aws target instance id is required")
		}
	case ProviderGCP:
		if strings.TrimSpace(target.ProjectID) == "" || strings.TrimSpace(target.Zone) == "" || strings.TrimSpace(target.InstanceName) == "" {
			return fmt.Errorf("gcp target project id, zone, and instance name are required")
		}
	case ProviderAzure:
		if strings.TrimSpace(target.SubscriptionID) == "" || strings.TrimSpace(target.ResourceGroup) == "" || strings.TrimSpace(target.InstanceName) == "" {
			return fmt.Errorf("azure target subscription id, resource group, and instance name are required")
		}
	default:
		return fmt.Errorf("unsupported provider %s", target.Provider)
	}
	return nil
}

func validateScannerHost(target VMTarget, host ScannerHost) error {
	if strings.TrimSpace(host.HostID) == "" {
		return fmt.Errorf("scanner host id is required")
	}
	if strings.TrimSpace(host.Region) == "" {
		return fmt.Errorf("scanner host region is required")
	}
	if !strings.EqualFold(strings.TrimSpace(target.Region), strings.TrimSpace(host.Region)) {
		return fmt.Errorf("scanner host region %s must match target region %s", host.Region, target.Region)
	}
	switch target.Provider {
	case ProviderAWS:
	case ProviderGCP:
		if strings.TrimSpace(host.Zone) == "" {
			return fmt.Errorf("gcp scanner host zone is required")
		}
	case ProviderAzure:
		if strings.TrimSpace(host.ResourceGroup) == "" {
			return fmt.Errorf("azure scanner host resource group is required")
		}
	}
	return nil
}

func validateRequest(req ScanRequest) error {
	if err := validateTarget(req.Target); err != nil {
		return err
	}
	return validateScannerHost(req.Target, req.ScannerHost)
}

func (r *Runner) validateRequest(req ScanRequest) error {
	if err := validateRequest(req); err != nil {
		return err
	}
	if r == nil || r.policyEvaluator == nil {
		return nil
	}
	maxConcurrent := req.MaxConcurrentSnapshots
	if maxConcurrent <= 0 {
		maxConcurrent = r.maxConcurrentSnapshots
	}
	return r.policyEvaluator.Validate(scanpolicy.Request{
		Kind:                   scanpolicy.KindWorkload,
		Team:                   scanpolicy.TeamFromMetadata(req.Metadata),
		RequestedBy:            strings.TrimSpace(req.RequestedBy),
		Metadata:               cloneStringMap(req.Metadata),
		Provider:               string(req.Target.Provider),
		DryRun:                 req.DryRun,
		MaxConcurrentSnapshots: maxConcurrent,
	})
}

func (r *Runner) ensureScannerHost(ctx context.Context, req ScanRequest) (ScanRequest, bool, error) {
	if strings.TrimSpace(req.ScannerHost.HostID) != "" || req.DryRun {
		return req, false, nil
	}
	if r == nil || r.provisioner == nil {
		return req, false, nil
	}
	if err := validateTarget(req.Target); err != nil {
		return req, false, err
	}
	host, err := r.provisioner.ProvisionScannerHost(ctx, req)
	if err != nil {
		return req, false, fmt.Errorf("provision scanner host for %s target %s: %w", req.Target.Provider, req.Target.Identity(), err)
	}
	if strings.TrimSpace(host.Region) == "" {
		host.Region = strings.TrimSpace(req.Target.Region)
	}
	if strings.TrimSpace(host.AccountID) == "" {
		host.AccountID = strings.TrimSpace(req.Target.AccountID)
	}
	if strings.TrimSpace(host.ProjectID) == "" {
		host.ProjectID = strings.TrimSpace(req.Target.ProjectID)
	}
	if strings.TrimSpace(host.SubscriptionID) == "" {
		host.SubscriptionID = strings.TrimSpace(req.Target.SubscriptionID)
	}
	if strings.TrimSpace(host.ResourceGroup) == "" {
		host.ResourceGroup = strings.TrimSpace(req.Target.ResourceGroup)
	}
	req.ScannerHost = host
	return req, true, nil
}

func (r *Runner) releaseScannerHost(ctx context.Context, host ScannerHost) error {
	if r == nil || r.provisioner == nil || strings.TrimSpace(host.HostID) == "" {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	releaseCtx, cancel := context.WithTimeout(ctx, r.cleanupTimeout)
	defer cancel()
	return r.provisioner.ReleaseScannerHost(releaseCtx, host)
}

func allVolumesTerminal(volumes []VolumeScanRecord) bool {
	for _, volume := range volumes {
		if !volume.Status.Terminal() {
			return false
		}
	}
	return true
}

func runNeedsReconciliation(run RunRecord) bool {
	for _, volume := range run.Volumes {
		if volume.Snapshot != nil && !volume.Cleanup.DeletedSnapshot {
			return true
		}
		if volume.Inspection != nil && !volume.Cleanup.DeletedVolume {
			return true
		}
		if volume.Attachment != nil && !volume.Cleanup.Detached {
			return true
		}
		if volume.Mount != nil && !volume.Cleanup.Unmounted {
			return true
		}
	}
	return false
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

func attachmentSlotCapacity(provider Provider) int {
	slotProvider, ok := provider.(attachmentSlotProvider)
	if !ok || slotProvider == nil {
		return 0
	}
	if slots := slotProvider.MaxConcurrentAttachments(); slots > 0 {
		return slots
	}
	return 0
}

func defaultWorkloadRetryOptions(opts scanner.RetryOptions) scanner.RetryOptions {
	if opts.Attempts <= 0 && opts.BaseDelay <= 0 && opts.MaxDelay <= 0 && opts.Jitter <= 0 {
		return scanner.DefaultRetryOptions()
	}
	defaults := scanner.DefaultRetryOptions()
	if opts.Attempts <= 0 {
		opts.Attempts = defaults.Attempts
	}
	if opts.BaseDelay <= 0 {
		opts.BaseDelay = defaults.BaseDelay
	}
	if opts.MaxDelay <= 0 {
		opts.MaxDelay = defaults.MaxDelay
	}
	if opts.Jitter <= 0 {
		opts.Jitter = defaults.Jitter
	}
	return opts
}

func errorString(err error) string {
	if err == nil {
		return ""
	}
	return strings.TrimSpace(err.Error())
}

func joinErrors(errs []error) error {
	filtered := make([]error, 0, len(errs))
	for _, err := range errs {
		if err != nil {
			filtered = append(filtered, err)
		}
	}
	if len(filtered) == 0 {
		return nil
	}
	return errors.Join(filtered...)
}

func startRunObservation(provider ProviderKind, dryRun bool) func(RunStatus) {
	started := time.Now()
	metrics.AddWorkloadScanActiveRun(string(provider), 1)
	return func(status RunStatus) {
		metrics.AddWorkloadScanActiveRun(string(provider), -1)
		metrics.RecordWorkloadScanRun(string(provider), string(status), dryRun, time.Since(started))
	}
}

func startStageObservation(provider ProviderKind, stage RunStage, active bool) func(RunStatus) {
	started := time.Now()
	if active {
		metrics.AddWorkloadScanActiveVolumeOp(string(provider), string(stage), 1)
	}
	return func(status RunStatus) {
		if active {
			metrics.AddWorkloadScanActiveVolumeOp(string(provider), string(stage), -1)
		}
		metrics.RecordWorkloadScanStage(string(provider), string(stage), string(status), time.Since(started))
	}
}
