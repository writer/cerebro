package workloadscan

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/writer/cerebro/internal/filesystemanalyzer"
	"github.com/writer/cerebro/internal/metrics"
	"github.com/writer/cerebro/internal/scanpolicy"
	"github.com/writer/cerebro/internal/webhooks"
)

type fakeProvider struct {
	mu                    sync.Mutex
	volumes               []SourceVolume
	currentSnapshots      int
	maxConcurrentSnapshot int
	maxAttachmentSlots    int
	attachmentSlots       []int
	failShareSnapshot     int
	failCreateVolume      int
	failAttachVolume      int
	failDeleteVolume      int
	failDeleteSnapshot    int
	detachedVolumes       []string
	deletedVolumes        []string
	deletedSnapshots      []string
	sharedSnapshotSuffix  string
	lastInspectionSource  string
}

func (p *fakeProvider) Kind() ProviderKind { return ProviderAWS }

func (p *fakeProvider) InventoryVolumes(context.Context, VMTarget) ([]SourceVolume, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]SourceVolume, len(p.volumes))
	copy(out, p.volumes)
	return out, nil
}

func (p *fakeProvider) CreateSnapshot(_ context.Context, _ VMTarget, volume SourceVolume, _ map[string]string) (*SnapshotArtifact, error) {
	p.mu.Lock()
	p.currentSnapshots++
	if p.currentSnapshots > p.maxConcurrentSnapshot {
		p.maxConcurrentSnapshot = p.currentSnapshots
	}
	p.mu.Unlock()

	time.Sleep(10 * time.Millisecond)

	p.mu.Lock()
	p.currentSnapshots--
	p.mu.Unlock()

	now := time.Now().UTC()
	return &SnapshotArtifact{
		ID:        "snap-" + volume.ID,
		VolumeID:  volume.ID,
		SizeGiB:   volume.SizeGiB,
		CreatedAt: now,
		ReadyAt:   &now,
	}, nil
}

func (p *fakeProvider) ShareSnapshot(_ context.Context, _ VMTarget, _ ScannerHost, snapshot SnapshotArtifact) (*SnapshotArtifact, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.failShareSnapshot > 0 {
		p.failShareSnapshot--
		return nil, fmt.Errorf("share snapshot failed")
	}
	if p.sharedSnapshotSuffix == "" {
		return &snapshot, nil
	}
	shared := snapshot
	shared.ID = snapshot.ID + p.sharedSnapshotSuffix
	return &shared, nil
}

func (p *fakeProvider) CreateInspectionVolume(_ context.Context, _ VMTarget, _ ScannerHost, snapshot SnapshotArtifact) (*InspectionVolume, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.failCreateVolume > 0 {
		p.failCreateVolume--
		return nil, fmt.Errorf("create inspection volume failed")
	}
	p.lastInspectionSource = snapshot.ID
	now := time.Now().UTC()
	return &InspectionVolume{
		ID:         "vol-" + snapshot.ID,
		SnapshotID: snapshot.ID,
		SizeGiB:    snapshot.SizeGiB,
		CreatedAt:  now,
		ReadyAt:    &now,
	}, nil
}

func (p *fakeProvider) MaxConcurrentAttachments() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.maxAttachmentSlots
}

func (p *fakeProvider) AttachInspectionVolume(_ context.Context, _ VMTarget, scannerHost ScannerHost, volume InspectionVolume, index int) (*VolumeAttachment, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.failAttachVolume > 0 {
		p.failAttachVolume--
		return nil, fmt.Errorf("attach inspection volume failed")
	}
	p.attachmentSlots = append(p.attachmentSlots, index)
	return &VolumeAttachment{
		VolumeID:   volume.ID,
		HostID:     scannerHost.HostID,
		DeviceName: fmt.Sprintf("/dev/xvd%c", 'f'+rune(index)),
		ReadOnly:   true,
		AttachedAt: time.Now().UTC(),
	}, nil
}

func (p *fakeProvider) DetachInspectionVolume(_ context.Context, attachment VolumeAttachment) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.detachedVolumes = append(p.detachedVolumes, attachment.VolumeID)
	return nil
}

func (p *fakeProvider) DeleteInspectionVolume(_ context.Context, volume InspectionVolume) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.failDeleteVolume > 0 {
		p.failDeleteVolume--
		return fmt.Errorf("delete inspection volume failed")
	}
	p.deletedVolumes = append(p.deletedVolumes, volume.ID)
	return nil
}

func (p *fakeProvider) DeleteSnapshot(_ context.Context, snapshot SnapshotArtifact) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.failDeleteSnapshot > 0 {
		p.failDeleteSnapshot--
		return fmt.Errorf("delete snapshot failed")
	}
	p.deletedSnapshots = append(p.deletedSnapshots, snapshot.ID)
	return nil
}

type fakeMounter struct {
	mu        sync.Mutex
	failMount bool
	unmounted []string
	mountErr  error
	mountPath string
}

func (m *fakeMounter) Mount(_ context.Context, attachment VolumeAttachment, _ SourceVolume) (*MountedVolume, error) {
	if m.failMount {
		return nil, fmt.Errorf("mount %s failed", attachment.VolumeID)
	}
	if m.mountErr != nil {
		return nil, m.mountErr
	}
	mountPath := m.mountPath
	if mountPath == "" {
		mountPath = "/mnt/" + attachment.VolumeID
	}
	return &MountedVolume{
		VolumeID:   attachment.VolumeID,
		DevicePath: attachment.DeviceName,
		MountPath:  mountPath,
		MountedAt:  time.Now().UTC(),
	}, nil
}

func (m *fakeMounter) Unmount(_ context.Context, mount MountedVolume) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.unmounted = append(m.unmounted, mount.VolumeID)
	return nil
}

type fakeAnalyzer struct {
	fail         bool
	panicMessage string
}

func (a fakeAnalyzer) Analyze(_ context.Context, input AnalysisInput) (*AnalysisReport, error) {
	if a.panicMessage != "" {
		panic(a.panicMessage)
	}
	if a.fail {
		return nil, fmt.Errorf("analyze %s failed", input.Volume.ID)
	}
	return &AnalysisReport{
		FindingCount: 1,
		Metadata: map[string]any{
			"volume_id": input.Volume.ID,
		},
	}, nil
}

type fakeScannerProvisioner struct {
	mu             sync.Mutex
	host           ScannerHost
	provisionErr   error
	releaseErr     error
	provisionCalls int
	releaseCalls   int
	releasedHosts  []ScannerHost
}

func (p *fakeScannerProvisioner) ProvisionScannerHost(context.Context, ScanRequest) (ScannerHost, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.provisionCalls++
	if p.provisionErr != nil {
		return ScannerHost{}, p.provisionErr
	}
	return p.host, nil
}

func (p *fakeScannerProvisioner) ReleaseScannerHost(_ context.Context, host ScannerHost) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.releaseCalls++
	p.releasedHosts = append(p.releasedHosts, host)
	if p.releaseErr != nil {
		return p.releaseErr
	}
	return nil
}

type captureEmitter struct {
	mu     sync.Mutex
	events []webhooks.EventType
}

func (e *captureEmitter) EmitWithErrors(_ context.Context, eventType webhooks.EventType, _ map[string]interface{}) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.events = append(e.events, eventType)
	return nil
}

type failingRunStore struct {
	RunStore
	failCompletedRunSave bool
}

func (s *failingRunStore) SaveRun(ctx context.Context, run *RunRecord) error {
	if s.failCompletedRunSave && run != nil && run.Status == RunStatusSucceeded && run.Stage == RunStageCompleted {
		return fmt.Errorf("persist completed run failed")
	}
	return s.RunStore.SaveRun(ctx, run)
}

func TestSQLiteRunStoreRoundTripAndEvents(t *testing.T) {
	store, err := NewSQLiteRunStore(filepath.Join(t.TempDir(), "workload-scan.db"))
	if err != nil {
		t.Fatalf("new sqlite run store: %v", err)
	}
	defer func() { _ = store.Close() }()

	now := time.Now().UTC()
	run := &RunRecord{
		ID:          "workload_scan:test",
		Provider:    ProviderAWS,
		Status:      RunStatusRunning,
		Stage:       RunStageAnalyze,
		Target:      VMTarget{Provider: ProviderAWS, Region: "us-east-1", InstanceID: "i-123"},
		ScannerHost: ScannerHost{HostID: "i-scan", Region: "us-east-1"},
		SubmittedAt: now,
		UpdatedAt:   now,
	}
	if err := store.SaveRun(context.Background(), run); err != nil {
		t.Fatalf("save run: %v", err)
	}
	recorded, err := store.AppendEvent(context.Background(), run.ID, RunEvent{
		Status:     run.Status,
		Stage:      run.Stage,
		Message:    "analysis started",
		RecordedAt: now,
	})
	if err != nil {
		t.Fatalf("append event: %v", err)
	}
	if recorded.Sequence != 1 {
		t.Fatalf("expected first event sequence 1, got %d", recorded.Sequence)
	}
	loaded, err := store.LoadRun(context.Background(), run.ID)
	if err != nil {
		t.Fatalf("load run: %v", err)
	}
	if loaded == nil || loaded.ID != run.ID {
		t.Fatalf("expected loaded run %q, got %#v", run.ID, loaded)
	}
	runs, err := store.ListRuns(context.Background(), RunListOptions{Limit: 10})
	if err != nil {
		t.Fatalf("list runs: %v", err)
	}
	if len(runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(runs))
	}
	events, err := store.LoadEvents(context.Background(), run.ID)
	if err != nil {
		t.Fatalf("load events: %v", err)
	}
	if len(events) != 1 || events[0].Message != "analysis started" {
		t.Fatalf("expected one stored event, got %#v", events)
	}
}

func TestRunnerRunVMScanPersistsLifecycleAndCleanup(t *testing.T) {
	store, err := NewSQLiteRunStore(filepath.Join(t.TempDir(), "workload-scan.db"))
	if err != nil {
		t.Fatalf("new sqlite run store: %v", err)
	}
	defer func() { _ = store.Close() }()

	provider := &fakeProvider{
		volumes: []SourceVolume{
			{ID: "vol-a", SizeGiB: 10},
			{ID: "vol-b", SizeGiB: 20},
		},
	}
	emitter := &captureEmitter{}
	runner := NewRunner(RunnerOptions{
		Store:                  store,
		Providers:              []Provider{provider},
		Mounter:                &fakeMounter{},
		Analyzer:               fakeAnalyzer{},
		Events:                 emitter,
		MaxConcurrentSnapshots: 1,
	})

	run, err := runner.RunVMScan(context.Background(), ScanRequest{
		ID:          "workload_scan:success",
		Target:      VMTarget{Provider: ProviderAWS, Region: "us-east-1", InstanceID: "i-target"},
		ScannerHost: ScannerHost{HostID: "i-scan", Region: "us-east-1"},
	})
	if err != nil {
		t.Fatalf("run vm scan: %v", err)
	}
	if run.Status != RunStatusSucceeded {
		t.Fatalf("expected succeeded run, got %s", run.Status)
	}
	if run.Summary.VolumeCount != 2 || run.Summary.SucceededVolumes != 2 {
		t.Fatalf("unexpected run summary: %#v", run.Summary)
	}
	for _, volume := range run.Volumes {
		if !volume.Cleanup.DeletedSnapshot || !volume.Cleanup.DeletedVolume || !volume.Cleanup.Unmounted || !volume.Cleanup.Detached {
			t.Fatalf("expected cleanup to complete for %#v", volume)
		}
		if volume.Analysis == nil || volume.Analysis.FindingCount != 1 {
			t.Fatalf("expected analysis result on %#v", volume)
		}
	}
	if provider.maxConcurrentSnapshot != 1 {
		t.Fatalf("expected snapshot concurrency limit 1, got %d", provider.maxConcurrentSnapshot)
	}
	events, err := store.LoadEvents(context.Background(), run.ID)
	if err != nil {
		t.Fatalf("load stored events: %v", err)
	}
	if len(events) == 0 {
		t.Fatal("expected persisted lifecycle events")
	}
	if len(emitter.events) < 3 {
		t.Fatalf("expected workload lifecycle + generic scan events, got %v", emitter.events)
	}
}

func TestRunnerCleansUpArtifactsOnIntermediateVolumeFailures(t *testing.T) {
	tests := []struct {
		name                string
		configureProvider   func(*fakeProvider)
		configureMounter    func(*fakeMounter)
		wantStage           RunStage
		wantDeletedSnapshot bool
		wantDeletedVolume   bool
		wantDetachedVolume  bool
		wantUnmountedVolume bool
	}{
		{
			name: "share failure",
			configureProvider: func(provider *fakeProvider) {
				provider.failShareSnapshot = 1
			},
			wantStage:           RunStageShare,
			wantDeletedSnapshot: true,
		},
		{
			name: "volume create failure",
			configureProvider: func(provider *fakeProvider) {
				provider.failCreateVolume = 1
			},
			wantStage:           RunStageVolumeCreate,
			wantDeletedSnapshot: true,
		},
		{
			name: "attach failure",
			configureProvider: func(provider *fakeProvider) {
				provider.failAttachVolume = 1
			},
			wantStage:           RunStageAttach,
			wantDeletedSnapshot: true,
			wantDeletedVolume:   true,
		},
		{
			name: "mount failure",
			configureMounter: func(mounter *fakeMounter) {
				mounter.failMount = true
			},
			wantStage:           RunStageMount,
			wantDeletedSnapshot: true,
			wantDeletedVolume:   true,
			wantDetachedVolume:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store, err := NewSQLiteRunStore(filepath.Join(t.TempDir(), "workload-scan.db"))
			if err != nil {
				t.Fatalf("new sqlite run store: %v", err)
			}
			defer func() { _ = store.Close() }()

			provider := &fakeProvider{volumes: []SourceVolume{{ID: "vol-a", SizeGiB: 10}}}
			mounter := &fakeMounter{}
			if tc.configureProvider != nil {
				tc.configureProvider(provider)
			}
			if tc.configureMounter != nil {
				tc.configureMounter(mounter)
			}
			runner := NewRunner(RunnerOptions{
				Store:     store,
				Providers: []Provider{provider},
				Mounter:   mounter,
				Analyzer:  fakeAnalyzer{},
			})

			run, err := runner.RunVMScan(context.Background(), ScanRequest{
				ID:          "workload_scan:intermediate-failure",
				Target:      VMTarget{Provider: ProviderAWS, Region: "us-east-1", InstanceID: "i-target"},
				ScannerHost: ScannerHost{HostID: "i-scan", Region: "us-east-1"},
			})
			if err == nil {
				t.Fatal("expected scan failure")
			}
			if run == nil {
				t.Fatal("expected failed run record")
			}
			if run.Status != RunStatusFailed {
				t.Fatalf("expected failed run, got %s", run.Status)
			}
			volume := run.Volumes[0]
			if volume.Stage != tc.wantStage {
				t.Fatalf("expected failed volume stage %s, got %s", tc.wantStage, volume.Stage)
			}
			if volume.Cleanup.DeletedSnapshot != tc.wantDeletedSnapshot {
				t.Fatalf("expected deleted snapshot=%t, got %#v", tc.wantDeletedSnapshot, volume.Cleanup)
			}
			if volume.Cleanup.DeletedVolume != tc.wantDeletedVolume {
				t.Fatalf("expected deleted volume=%t, got %#v", tc.wantDeletedVolume, volume.Cleanup)
			}
			if volume.Cleanup.Detached != tc.wantDetachedVolume {
				t.Fatalf("expected detached volume=%t, got %#v", tc.wantDetachedVolume, volume.Cleanup)
			}
			if volume.Cleanup.Unmounted != tc.wantUnmountedVolume {
				t.Fatalf("expected unmounted volume=%t, got %#v", tc.wantUnmountedVolume, volume.Cleanup)
			}
		})
	}
}

func TestRunnerReconcileCleansUpAfterFailedCleanup(t *testing.T) {
	store, err := NewSQLiteRunStore(filepath.Join(t.TempDir(), "workload-scan.db"))
	if err != nil {
		t.Fatalf("new sqlite run store: %v", err)
	}
	defer func() { _ = store.Close() }()

	provider := &fakeProvider{
		volumes: []SourceVolume{
			{ID: "vol-a", SizeGiB: 10},
		},
		failDeleteVolume:   1,
		failDeleteSnapshot: 1,
	}
	emitter := &captureEmitter{}
	runner := NewRunner(RunnerOptions{
		Store:     store,
		Providers: []Provider{provider},
		Mounter:   &fakeMounter{},
		Analyzer:  fakeAnalyzer{},
		Events:    emitter,
	})

	run, err := runner.RunVMScan(context.Background(), ScanRequest{
		ID:          "workload_scan:needs-reconcile",
		Target:      VMTarget{Provider: ProviderAWS, Region: "us-east-1", InstanceID: "i-target"},
		ScannerHost: ScannerHost{HostID: "i-scan", Region: "us-east-1"},
	})
	if err == nil {
		t.Fatal("expected initial run to fail due to cleanup errors")
	}
	if run.Status != RunStatusFailed {
		t.Fatalf("expected failed run, got %s", run.Status)
	}
	if run.Volumes[0].Cleanup.DeletedSnapshot || run.Volumes[0].Cleanup.DeletedVolume {
		t.Fatalf("expected leaked artifacts after failed cleanup, got %#v", run.Volumes[0].Cleanup)
	}

	reconciled, err := runner.Reconcile(context.Background(), 0)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if len(reconciled) != 1 {
		t.Fatalf("expected one reconciled run, got %d", len(reconciled))
	}
	loaded, err := store.LoadRun(context.Background(), run.ID)
	if err != nil {
		t.Fatalf("reload reconciled run: %v", err)
	}
	if loaded == nil {
		t.Fatal("expected reconciled run to persist")
	}
	if !loaded.Volumes[0].Cleanup.DeletedSnapshot || !loaded.Volumes[0].Cleanup.DeletedVolume {
		t.Fatalf("expected reconciled cleanup flags, got %#v", loaded.Volumes[0].Cleanup)
	}
	if !loaded.Volumes[0].Cleanup.Reconciled {
		t.Fatalf("expected reconciled flag on volume cleanup, got %#v", loaded.Volumes[0].Cleanup)
	}
	if loaded.Volumes[0].Status != RunStatusFailed {
		t.Fatalf("expected reconciled volume to preserve failed status, got %#v", loaded.Volumes[0])
	}
}

func TestRunnerReconcilePagesOlderRuns(t *testing.T) {
	store, err := NewSQLiteRunStore(filepath.Join(t.TempDir(), "workload-scan.db"))
	if err != nil {
		t.Fatalf("new sqlite run store: %v", err)
	}
	defer func() { _ = store.Close() }()

	provider := &fakeProvider{}
	runner := NewRunner(RunnerOptions{
		Store:     store,
		Providers: []Provider{provider},
		Mounter:   &fakeMounter{},
		Analyzer:  fakeAnalyzer{},
	})

	base := time.Date(2026, 3, 11, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 505; i++ {
		run := &RunRecord{
			ID:          fmt.Sprintf("workload_scan:reconcile:%03d", i),
			Provider:    ProviderAWS,
			Status:      RunStatusFailed,
			Stage:       RunStageCleanup,
			Target:      VMTarget{Provider: ProviderAWS, Region: "us-east-1", InstanceID: fmt.Sprintf("i-%03d", i)},
			ScannerHost: ScannerHost{HostID: "i-scan", Region: "us-east-1"},
			SubmittedAt: base.Add(time.Duration(i) * time.Minute),
			UpdatedAt:   base.Add(time.Duration(i) * time.Minute),
			Volumes: []VolumeScanRecord{
				{
					Source:     SourceVolume{ID: fmt.Sprintf("source-%03d", i), SizeGiB: 10},
					Status:     RunStatusFailed,
					Stage:      RunStageCleanup,
					StartedAt:  base.Add(time.Duration(i) * time.Minute),
					UpdatedAt:  base.Add(time.Duration(i) * time.Minute),
					Snapshot:   &SnapshotArtifact{ID: fmt.Sprintf("snap-%03d", i), VolumeID: fmt.Sprintf("source-%03d", i)},
					Inspection: &InspectionVolume{ID: fmt.Sprintf("vol-%03d", i), SnapshotID: fmt.Sprintf("snap-%03d", i)},
					Attachment: &VolumeAttachment{VolumeID: fmt.Sprintf("vol-%03d", i), HostID: "i-scan"},
					Mount:      &MountedVolume{VolumeID: fmt.Sprintf("vol-%03d", i), MountPath: fmt.Sprintf("/mnt/vol-%03d", i)},
				},
			},
		}
		if err := store.SaveRun(context.Background(), run); err != nil {
			t.Fatalf("save run %d: %v", i, err)
		}
	}

	reconciled, err := runner.Reconcile(context.Background(), 0)
	if err != nil {
		t.Fatalf("reconcile paged runs: %v", err)
	}
	if len(reconciled) != 505 {
		t.Fatalf("expected 505 reconciled runs, got %d", len(reconciled))
	}
	if len(provider.deletedVolumes) != 505 || len(provider.deletedSnapshots) != 505 {
		t.Fatalf("expected all leaked artifacts to be cleaned up, got volumes=%d snapshots=%d", len(provider.deletedVolumes), len(provider.deletedSnapshots))
	}
}

func TestRunnerUsesAttachmentSlotsInsteadOfVolumeIndexes(t *testing.T) {
	store, err := NewSQLiteRunStore(filepath.Join(t.TempDir(), "workload-scan.db"))
	if err != nil {
		t.Fatalf("new sqlite run store: %v", err)
	}
	defer func() { _ = store.Close() }()

	provider := &fakeProvider{
		maxAttachmentSlots: 2,
		volumes: []SourceVolume{
			{ID: "vol-a", SizeGiB: 1},
			{ID: "vol-b", SizeGiB: 1},
			{ID: "vol-c", SizeGiB: 1},
			{ID: "vol-d", SizeGiB: 1},
			{ID: "vol-e", SizeGiB: 1},
		},
	}
	runner := NewRunner(RunnerOptions{
		Store:                  store,
		Providers:              []Provider{provider},
		Mounter:                &fakeMounter{},
		Analyzer:               fakeAnalyzer{},
		MaxConcurrentSnapshots: 5,
	})

	if _, err := runner.RunVMScan(context.Background(), ScanRequest{
		ID:          "workload_scan:attachment-slots",
		Target:      VMTarget{Provider: ProviderAWS, Region: "us-east-1", InstanceID: "i-target"},
		ScannerHost: ScannerHost{HostID: "i-scan", Region: "us-east-1"},
	}); err != nil {
		t.Fatalf("run vm scan with attachment slots: %v", err)
	}

	if len(provider.attachmentSlots) != len(provider.volumes) {
		t.Fatalf("expected %d attachment slot records, got %d", len(provider.volumes), len(provider.attachmentSlots))
	}
	for _, slot := range provider.attachmentSlots {
		if slot < 0 || slot >= provider.maxAttachmentSlots {
			t.Fatalf("expected attachment slot to stay within [0,%d), got %d", provider.maxAttachmentSlots, slot)
		}
	}
}

func TestRunnerUsesSharedSnapshotArtifactForInspectionVolumeCreation(t *testing.T) {
	store, err := NewSQLiteRunStore(filepath.Join(t.TempDir(), "workload-scan.db"))
	if err != nil {
		t.Fatalf("new sqlite run store: %v", err)
	}
	defer func() { _ = store.Close() }()

	provider := &fakeProvider{
		volumes:              []SourceVolume{{ID: "vol-a", SizeGiB: 10}},
		sharedSnapshotSuffix: "-shared",
	}
	runner := NewRunner(RunnerOptions{
		Store:     store,
		Providers: []Provider{provider},
		Mounter:   &fakeMounter{},
		Analyzer:  fakeAnalyzer{},
	})

	run, err := runner.RunVMScan(context.Background(), ScanRequest{
		ID:          "workload_scan:shared-snapshot",
		Target:      VMTarget{Provider: ProviderAWS, Region: "us-east-1", InstanceID: "i-target"},
		ScannerHost: ScannerHost{HostID: "i-scan", Region: "us-east-1"},
	})
	if err != nil {
		t.Fatalf("run vm scan: %v", err)
	}
	if got := run.Volumes[0].Snapshot.ID; got != "snap-vol-a-shared" {
		t.Fatalf("expected shared snapshot id to persist on run, got %s", got)
	}
	if got := provider.lastInspectionSource; got != "snap-vol-a-shared" {
		t.Fatalf("expected inspection volume to use shared snapshot id, got %s", got)
	}
}

func TestRunnerRunVMScanRecordsObservabilityMetrics(t *testing.T) {
	metrics.Register()

	store, err := NewSQLiteRunStore(filepath.Join(t.TempDir(), "workload-scan.db"))
	if err != nil {
		t.Fatalf("new sqlite run store: %v", err)
	}
	defer func() { _ = store.Close() }()

	provider := &fakeProvider{
		volumes: []SourceVolume{{ID: "vol-a", SizeGiB: 10}},
	}
	runner := NewRunner(RunnerOptions{
		Store:     store,
		Providers: []Provider{provider},
		Mounter:   &fakeMounter{},
		Analyzer:  fakeAnalyzer{},
	})

	beforeRuns := workloadCounterValue(t, metrics.WorkloadScanRunsTotal, "aws", "succeeded", "false")
	beforeInventory := workloadHistogramCount(t, metrics.WorkloadScanStageDuration, "aws", "inventory", "succeeded")
	beforeMount := workloadHistogramCount(t, metrics.WorkloadScanStageDuration, "aws", "mount", "succeeded")

	if _, err := runner.RunVMScan(context.Background(), ScanRequest{
		ID:          "workload_scan:metrics-success",
		Target:      VMTarget{Provider: ProviderAWS, Region: "us-east-1", InstanceID: "i-target"},
		ScannerHost: ScannerHost{HostID: "i-scan", Region: "us-east-1"},
	}); err != nil {
		t.Fatalf("run vm scan: %v", err)
	}

	if got := workloadCounterValue(t, metrics.WorkloadScanRunsTotal, "aws", "succeeded", "false"); got != beforeRuns+1 {
		t.Fatalf("expected workload run counter to increase by 1, got before=%v after=%v", beforeRuns, got)
	}
	if got := workloadHistogramCount(t, metrics.WorkloadScanStageDuration, "aws", "inventory", "succeeded"); got != beforeInventory+1 {
		t.Fatalf("expected inventory histogram count to increase by 1, got before=%v after=%v", beforeInventory, got)
	}
	if got := workloadHistogramCount(t, metrics.WorkloadScanStageDuration, "aws", "mount", "succeeded"); got != beforeMount+1 {
		t.Fatalf("expected mount histogram count to increase by 1, got before=%v after=%v", beforeMount, got)
	}
	if got := workloadGaugeVecValue(t, metrics.WorkloadScanActiveRuns, "aws"); got != 0 {
		t.Fatalf("expected active run gauge to return to 0, got %v", got)
	}
	if got := workloadGaugeVecValue(t, metrics.WorkloadScanActiveVolumeOps, "aws", "mount"); got != 0 {
		t.Fatalf("expected active volume ops gauge to return to 0, got %v", got)
	}
}

func TestRunnerRunVMScanRecordsMountFailureMetrics(t *testing.T) {
	metrics.Register()

	store, err := NewSQLiteRunStore(filepath.Join(t.TempDir(), "workload-scan.db"))
	if err != nil {
		t.Fatalf("new sqlite run store: %v", err)
	}
	defer func() { _ = store.Close() }()

	provider := &fakeProvider{
		volumes: []SourceVolume{{ID: "vol-a", SizeGiB: 10}},
	}
	runner := NewRunner(RunnerOptions{
		Store:     store,
		Providers: []Provider{provider},
		Mounter:   &fakeMounter{mountErr: fmt.Errorf("mount failed")},
		Analyzer:  fakeAnalyzer{},
	})

	beforeRuns := workloadCounterValue(t, metrics.WorkloadScanRunsTotal, "aws", "failed", "false")
	beforeMountFailures := workloadCounterValue(t, metrics.WorkloadScanMountFailuresTotal, "aws")
	beforeMount := workloadHistogramCount(t, metrics.WorkloadScanStageDuration, "aws", "mount", "failed")

	if _, err := runner.RunVMScan(context.Background(), ScanRequest{
		ID:          "workload_scan:metrics-mount-failure",
		Target:      VMTarget{Provider: ProviderAWS, Region: "us-east-1", InstanceID: "i-target"},
		ScannerHost: ScannerHost{HostID: "i-scan", Region: "us-east-1"},
	}); err == nil {
		t.Fatal("expected run vm scan to fail on mount error")
	}

	if got := workloadCounterValue(t, metrics.WorkloadScanRunsTotal, "aws", "failed", "false"); got != beforeRuns+1 {
		t.Fatalf("expected failed workload run counter to increase by 1, got before=%v after=%v", beforeRuns, got)
	}
	if got := workloadCounterValue(t, metrics.WorkloadScanMountFailuresTotal, "aws"); got != beforeMountFailures+1 {
		t.Fatalf("expected mount failure counter to increase by 1, got before=%v after=%v", beforeMountFailures, got)
	}
	if got := workloadHistogramCount(t, metrics.WorkloadScanStageDuration, "aws", "mount", "failed"); got != beforeMount+1 {
		t.Fatalf("expected failed mount histogram count to increase by 1, got before=%v after=%v", beforeMount, got)
	}
	if got := workloadGaugeVecValue(t, metrics.WorkloadScanActiveRuns, "aws"); got != 0 {
		t.Fatalf("expected active run gauge to return to 0 after failure, got %v", got)
	}
	if got := workloadGaugeVecValue(t, metrics.WorkloadScanActiveVolumeOps, "aws", "mount"); got != 0 {
		t.Fatalf("expected active volume ops gauge to return to 0 after failure, got %v", got)
	}
}

func TestRunnerRunVMScanRecordsFailedMetricWhenFinalSaveFails(t *testing.T) {
	metrics.Register()

	baseStore, err := NewSQLiteRunStore(filepath.Join(t.TempDir(), "workload-scan.db"))
	if err != nil {
		t.Fatalf("new sqlite run store: %v", err)
	}
	defer func() { _ = baseStore.Close() }()

	store := &failingRunStore{
		RunStore:             baseStore,
		failCompletedRunSave: true,
	}
	provider := &fakeProvider{
		volumes: []SourceVolume{{ID: "vol-a", SizeGiB: 10}},
	}
	runner := NewRunner(RunnerOptions{
		Store:     store,
		Providers: []Provider{provider},
		Mounter:   &fakeMounter{},
		Analyzer:  fakeAnalyzer{},
	})

	beforeFailed := workloadCounterValue(t, metrics.WorkloadScanRunsTotal, "aws", "failed", "false")
	beforeSucceeded := workloadCounterValue(t, metrics.WorkloadScanRunsTotal, "aws", "succeeded", "false")

	if _, err := runner.RunVMScan(context.Background(), ScanRequest{
		ID:          "workload_scan:metrics-final-save-failure",
		Target:      VMTarget{Provider: ProviderAWS, Region: "us-east-1", InstanceID: "i-target"},
		ScannerHost: ScannerHost{HostID: "i-scan", Region: "us-east-1"},
	}); err == nil {
		t.Fatal("expected run vm scan to fail when completed run persistence fails")
	}

	if got := workloadCounterValue(t, metrics.WorkloadScanRunsTotal, "aws", "failed", "false"); got != beforeFailed+1 {
		t.Fatalf("expected failed run counter to increase by 1, got before=%v after=%v", beforeFailed, got)
	}
	if got := workloadCounterValue(t, metrics.WorkloadScanRunsTotal, "aws", "succeeded", "false"); got != beforeSucceeded {
		t.Fatalf("expected succeeded run counter to remain unchanged, got before=%v after=%v", beforeSucceeded, got)
	}
}

func TestRunnerRunVMScanProvisionsAndReleasesEphemeralScannerHost(t *testing.T) {
	store, err := NewSQLiteRunStore(filepath.Join(t.TempDir(), "workload-scan.db"))
	if err != nil {
		t.Fatalf("new sqlite run store: %v", err)
	}
	defer func() { _ = store.Close() }()

	provider := &fakeProvider{
		volumes: []SourceVolume{{ID: "vol-a", SizeGiB: 10, Zone: "us-east-1a"}},
	}
	provisioner := &fakeScannerProvisioner{
		host: ScannerHost{HostID: "ephemeral-scan", Region: "us-east-1", Zone: "us-east-1a"},
	}
	runner := NewRunner(RunnerOptions{
		Store:       store,
		Providers:   []Provider{provider},
		Mounter:     &fakeMounter{},
		Analyzer:    fakeAnalyzer{},
		Provisioner: provisioner,
	})

	run, err := runner.RunVMScan(context.Background(), ScanRequest{
		ID:     "workload_scan:ephemeral-success",
		Target: VMTarget{Provider: ProviderAWS, Region: "us-east-1", InstanceID: "i-target"},
	})
	if err != nil {
		t.Fatalf("run vm scan: %v", err)
	}
	if run.ScannerHost.HostID != "ephemeral-scan" {
		t.Fatalf("expected provisioned scanner host on run, got %#v", run.ScannerHost)
	}
	if provisioner.provisionCalls != 1 {
		t.Fatalf("expected one provision call, got %d", provisioner.provisionCalls)
	}
	if provisioner.releaseCalls != 1 {
		t.Fatalf("expected one release call, got %d", provisioner.releaseCalls)
	}
	if len(provisioner.releasedHosts) != 1 || provisioner.releasedHosts[0].HostID != "ephemeral-scan" {
		t.Fatalf("expected release of provisioned host, got %#v", provisioner.releasedHosts)
	}
}

func TestRunnerRunVMScanReleasesEphemeralScannerHostOnFailure(t *testing.T) {
	store, err := NewSQLiteRunStore(filepath.Join(t.TempDir(), "workload-scan.db"))
	if err != nil {
		t.Fatalf("new sqlite run store: %v", err)
	}
	defer func() { _ = store.Close() }()

	provider := &fakeProvider{
		volumes: []SourceVolume{{ID: "vol-a", SizeGiB: 10, Zone: "us-east-1a"}},
	}
	provisioner := &fakeScannerProvisioner{
		host: ScannerHost{HostID: "ephemeral-scan", Region: "us-east-1", Zone: "us-east-1a"},
	}
	runner := NewRunner(RunnerOptions{
		Store:       store,
		Providers:   []Provider{provider},
		Mounter:     &fakeMounter{},
		Analyzer:    fakeAnalyzer{fail: true},
		Provisioner: provisioner,
	})

	run, err := runner.RunVMScan(context.Background(), ScanRequest{
		ID:     "workload_scan:ephemeral-failure",
		Target: VMTarget{Provider: ProviderAWS, Region: "us-east-1", InstanceID: "i-target"},
	})
	if err == nil {
		t.Fatal("expected run vm scan to fail")
	}
	if run == nil || run.Status != RunStatusFailed {
		t.Fatalf("expected failed run, got %#v", run)
	}
	if provisioner.provisionCalls != 1 {
		t.Fatalf("expected one provision call, got %d", provisioner.provisionCalls)
	}
	if provisioner.releaseCalls != 1 {
		t.Fatalf("expected one release call, got %d", provisioner.releaseCalls)
	}
}

func TestRunnerRunVMScanFailsWhenEphemeralScannerReleaseFails(t *testing.T) {
	store, err := NewSQLiteRunStore(filepath.Join(t.TempDir(), "workload-scan.db"))
	if err != nil {
		t.Fatalf("new sqlite run store: %v", err)
	}
	defer func() { _ = store.Close() }()

	provider := &fakeProvider{
		volumes: []SourceVolume{{ID: "vol-a", SizeGiB: 10, Zone: "us-east-1a"}},
	}
	provisioner := &fakeScannerProvisioner{
		host:       ScannerHost{HostID: "ephemeral-scan", Region: "us-east-1", Zone: "us-east-1a"},
		releaseErr: fmt.Errorf("terminate scanner failed"),
	}
	runner := NewRunner(RunnerOptions{
		Store:       store,
		Providers:   []Provider{provider},
		Mounter:     &fakeMounter{},
		Analyzer:    fakeAnalyzer{},
		Provisioner: provisioner,
	})

	run, err := runner.RunVMScan(context.Background(), ScanRequest{
		ID:     "workload_scan:ephemeral-release-failure",
		Target: VMTarget{Provider: ProviderAWS, Region: "us-east-1", InstanceID: "i-target"},
	})
	if err == nil {
		t.Fatal("expected run vm scan to fail when release fails")
	}
	if run == nil {
		t.Fatal("expected run record when release fails")
	}
	if run.Status != RunStatusFailed || run.Stage != RunStageCleanup {
		t.Fatalf("expected failed cleanup stage after release failure, got status=%s stage=%s", run.Status, run.Stage)
	}
	if !strings.Contains(run.Error, "release ephemeral scanner host") {
		t.Fatalf("expected release failure to be recorded on run, got %q", run.Error)
	}
}

func TestRunnerRunVMScanReleasesEphemeralScannerHostOnAnalyzerPanic(t *testing.T) {
	store, err := NewSQLiteRunStore(filepath.Join(t.TempDir(), "workload-scan.db"))
	if err != nil {
		t.Fatalf("new sqlite run store: %v", err)
	}
	defer func() { _ = store.Close() }()

	provider := &fakeProvider{
		volumes: []SourceVolume{{ID: "vol-a", SizeGiB: 10, Zone: "us-east-1a"}},
	}
	provisioner := &fakeScannerProvisioner{
		host: ScannerHost{HostID: "ephemeral-scan", Region: "us-east-1", Zone: "us-east-1a"},
	}
	runner := NewRunner(RunnerOptions{
		Store:       store,
		Providers:   []Provider{provider},
		Mounter:     &fakeMounter{},
		Analyzer:    fakeAnalyzer{panicMessage: "analyzer exploded"},
		Provisioner: provisioner,
	})

	run, err := runner.RunVMScan(context.Background(), ScanRequest{
		ID:     "workload_scan:ephemeral-panic",
		Target: VMTarget{Provider: ProviderAWS, Region: "us-east-1", InstanceID: "i-target"},
	})
	if err == nil {
		t.Fatal("expected run vm scan to fail on analyzer panic")
	}
	if !strings.Contains(err.Error(), "panic while scanning volume") {
		t.Fatalf("expected panic error context, got %v", err)
	}
	if run == nil || run.Status != RunStatusFailed {
		t.Fatalf("expected failed run after analyzer panic, got %#v", run)
	}
	if provisioner.releaseCalls != 1 {
		t.Fatalf("expected provisioned host release after panic, got %d", provisioner.releaseCalls)
	}
	if len(run.Volumes) != 1 {
		t.Fatalf("expected one volume record, got %#v", run.Volumes)
	}
	cleanup := run.Volumes[0].Cleanup
	if !cleanup.Unmounted || !cleanup.Detached || !cleanup.DeletedVolume || !cleanup.DeletedSnapshot {
		t.Fatalf("expected panic path cleanup to complete, got %#v", cleanup)
	}
	if !strings.Contains(run.Error, "panic while scanning volume") {
		t.Fatalf("expected panic recorded on run, got %q", run.Error)
	}
}

func TestRunnerRunVMScanAnalyzesWindowsMountedVolume(t *testing.T) {
	store, err := NewSQLiteRunStore(filepath.Join(t.TempDir(), "workload-scan.db"))
	if err != nil {
		t.Fatalf("new sqlite run store: %v", err)
	}
	defer func() { _ = store.Close() }()

	root := t.TempDir()
	mustWriteBinaryFile(t, filepath.Join(root, "Windows", "System32", "kernel32.dll"), buildMinimalPEBinary(peFixtureOptions{
		majorOSVersion:    10,
		minorOSVersion:    0,
		majorImageVersion: 20348,
		minorImageVersion: 3321,
	}))

	provider := &fakeProvider{
		volumes: []SourceVolume{{ID: "vol-win", SizeGiB: 40, Boot: true}},
	}
	runner := NewRunner(RunnerOptions{
		Store:     store,
		Providers: []Provider{provider},
		Mounter:   &fakeMounter{mountPath: root},
		Analyzer: workloadscanAnalyzerForTest(
			filesystemanalyzer.New(filesystemanalyzer.Options{}),
		),
	})

	run, err := runner.RunVMScan(context.Background(), ScanRequest{
		ID:          "workload_scan:windows",
		Target:      VMTarget{Provider: ProviderAWS, Region: "us-east-1", InstanceID: "i-win"},
		ScannerHost: ScannerHost{HostID: "i-scan", Region: "us-east-1"},
	})
	if err != nil {
		t.Fatalf("run vm scan: %v", err)
	}

	if len(run.Volumes) != 1 || run.Volumes[0].Analysis == nil || run.Volumes[0].Analysis.Catalog == nil {
		t.Fatalf("expected embedded workload analysis catalog, got %#v", run.Volumes)
	}
	catalog := run.Volumes[0].Analysis.Catalog
	if catalog.OS.ID != "windows" || catalog.OS.VersionID != "10.0.20348.3321" {
		t.Fatalf("expected windows os detection, got %#v", catalog.OS)
	}
	if len(catalog.Packages) != 1 || catalog.Packages[0].Ecosystem != "windows" || catalog.Packages[0].Name != "kernel32.dll" {
		t.Fatalf("expected windows package inventory, got %#v", catalog.Packages)
	}
	foundUnsigned := false
	for _, finding := range catalog.Misconfigurations {
		if finding.Type == "binary_signature" && finding.Path == "Windows/System32/kernel32.dll" {
			foundUnsigned = true
			break
		}
	}
	if !foundUnsigned {
		t.Fatalf("expected unsigned windows binary finding, got %#v", catalog.Misconfigurations)
	}
}

func workloadscanAnalyzerForTest(analyzer *filesystemanalyzer.Analyzer) Analyzer {
	return FilesystemAnalyzer{Analyzer: analyzer}
}

func mustWriteBinaryFile(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll(%s): %v", path, err)
	}
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("WriteFile(%s): %v", path, err)
	}
}

type peFixtureOptions struct {
	majorOSVersion    uint16
	minorOSVersion    uint16
	majorImageVersion uint16
	minorImageVersion uint16
}

func buildMinimalPEBinary(opts peFixtureOptions) []byte {
	const (
		peHeaderOffset     = 0x80
		fileHeaderOffset   = peHeaderOffset + 4
		optionalHeaderSize = 0xF0
		optionalHeaderOff  = fileHeaderOffset + 20
		sectionHeaderOff   = optionalHeaderOff + optionalHeaderSize
		fileAlignment      = 0x200
		sectionAlignment   = 0x1000
		textRawOffset      = 0x200
		textRawSize        = 0x200
	)

	data := make([]byte, textRawOffset+textRawSize)
	copy(data[:2], []byte("MZ"))
	binary.LittleEndian.PutUint32(data[0x3c:], peHeaderOffset)
	copy(data[peHeaderOffset:], []byte("PE\x00\x00"))

	binary.LittleEndian.PutUint16(data[fileHeaderOffset:], 0x8664)
	binary.LittleEndian.PutUint16(data[fileHeaderOffset+2:], 1)
	binary.LittleEndian.PutUint16(data[fileHeaderOffset+16:], optionalHeaderSize)
	binary.LittleEndian.PutUint16(data[fileHeaderOffset+18:], 0x0022)

	binary.LittleEndian.PutUint16(data[optionalHeaderOff:], 0x20b)
	data[optionalHeaderOff+2] = 1
	binary.LittleEndian.PutUint32(data[optionalHeaderOff+4:], textRawSize)
	binary.LittleEndian.PutUint32(data[optionalHeaderOff+16:], sectionAlignment)
	binary.LittleEndian.PutUint32(data[optionalHeaderOff+20:], sectionAlignment)
	binary.LittleEndian.PutUint64(data[optionalHeaderOff+24:], 0x140000000)
	binary.LittleEndian.PutUint32(data[optionalHeaderOff+32:], sectionAlignment)
	binary.LittleEndian.PutUint32(data[optionalHeaderOff+36:], fileAlignment)
	binary.LittleEndian.PutUint16(data[optionalHeaderOff+40:], opts.majorOSVersion)
	binary.LittleEndian.PutUint16(data[optionalHeaderOff+42:], opts.minorOSVersion)
	binary.LittleEndian.PutUint16(data[optionalHeaderOff+44:], opts.majorImageVersion)
	binary.LittleEndian.PutUint16(data[optionalHeaderOff+46:], opts.minorImageVersion)
	binary.LittleEndian.PutUint16(data[optionalHeaderOff+48:], 6)
	binary.LittleEndian.PutUint16(data[optionalHeaderOff+50:], 0)
	binary.LittleEndian.PutUint32(data[optionalHeaderOff+56:], sectionAlignment+textRawSize)
	binary.LittleEndian.PutUint32(data[optionalHeaderOff+60:], fileAlignment)
	binary.LittleEndian.PutUint16(data[optionalHeaderOff+68:], 3)
	binary.LittleEndian.PutUint64(data[optionalHeaderOff+72:], 0x100000)
	binary.LittleEndian.PutUint64(data[optionalHeaderOff+80:], 0x1000)
	binary.LittleEndian.PutUint64(data[optionalHeaderOff+88:], 0x100000)
	binary.LittleEndian.PutUint64(data[optionalHeaderOff+96:], 0x1000)
	binary.LittleEndian.PutUint32(data[optionalHeaderOff+108:], 16)

	copy(data[sectionHeaderOff:], []byte(".text\x00\x00\x00"))
	binary.LittleEndian.PutUint32(data[sectionHeaderOff+8:], 1)
	binary.LittleEndian.PutUint32(data[sectionHeaderOff+12:], sectionAlignment)
	binary.LittleEndian.PutUint32(data[sectionHeaderOff+16:], textRawSize)
	binary.LittleEndian.PutUint32(data[sectionHeaderOff+20:], textRawOffset)
	binary.LittleEndian.PutUint32(data[sectionHeaderOff+36:], 0x60000020)
	data[textRawOffset] = 0xc3

	return data
}

func workloadCounterValue(t *testing.T, vec *prometheus.CounterVec, labels ...string) float64 {
	t.Helper()
	counter, err := vec.GetMetricWithLabelValues(labels...)
	if err != nil {
		t.Fatalf("get counter metric with labels %v: %v", labels, err)
	}
	var metric dto.Metric
	if err := counter.Write(&metric); err != nil {
		t.Fatalf("write counter metric: %v", err)
	}
	return metric.GetCounter().GetValue()
}

func workloadGaugeVecValue(t *testing.T, gauge *prometheus.GaugeVec, labels ...string) float64 {
	t.Helper()
	metric, err := gauge.GetMetricWithLabelValues(labels...)
	if err != nil {
		t.Fatalf("get gauge metric with labels %v: %v", labels, err)
	}
	var dtoMetric dto.Metric
	if err := metric.Write(&dtoMetric); err != nil {
		t.Fatalf("write gauge metric: %v", err)
	}
	return dtoMetric.GetGauge().GetValue()
}

func workloadHistogramCount(t *testing.T, histogram *prometheus.HistogramVec, labels ...string) uint64 {
	t.Helper()
	metric, err := histogram.GetMetricWithLabelValues(labels...)
	if err != nil {
		t.Fatalf("get histogram metric with labels %v: %v", labels, err)
	}
	metricCollector, ok := metric.(prometheus.Metric)
	if !ok {
		t.Fatalf("histogram collector does not implement prometheus.Metric")
	}
	var dtoMetric dto.Metric
	if err := metricCollector.Write(&dtoMetric); err != nil {
		t.Fatalf("write histogram metric: %v", err)
	}
	return dtoMetric.GetHistogram().GetSampleCount()
}

func TestValidateRequestRequiresProviderSpecificScannerCoordinates(t *testing.T) {
	t.Run("gcp requires target and scanner zones", func(t *testing.T) {
		err := validateRequest(ScanRequest{
			Target: VMTarget{
				Provider:     ProviderGCP,
				ProjectID:    "project-a",
				Region:       "us-central1",
				InstanceName: "vm-a",
			},
			ScannerHost: ScannerHost{
				HostID:    "scanner-a",
				Region:    "us-central1",
				Zone:      "",
				ProjectID: "project-a",
			},
		})
		if err == nil {
			t.Fatal("expected gcp validation error")
		}
	})

	t.Run("azure requires scanner resource group", func(t *testing.T) {
		err := validateRequest(ScanRequest{
			Target: VMTarget{
				Provider:       ProviderAzure,
				SubscriptionID: "sub-a",
				ResourceGroup:  "rg-target",
				Region:         "eastus",
				InstanceName:   "vm-a",
			},
			ScannerHost: ScannerHost{
				HostID: "scanner-a",
				Region: "eastus",
			},
		})
		if err == nil {
			t.Fatal("expected azure validation error")
		}
	})
}

func TestRunnerRunVMScanRejectsPolicyViolationsBeforePersistence(t *testing.T) {
	store, err := NewSQLiteRunStore(filepath.Join(t.TempDir(), "workload-scan.db"))
	if err != nil {
		t.Fatalf("new sqlite run store: %v", err)
	}
	defer func() { _ = store.Close() }()

	policyEngine, err := scanpolicy.NewEngine([]scanpolicy.Policy{{
		ID:                     "platform-workload-policy",
		ScanKinds:              []scanpolicy.Kind{scanpolicy.KindWorkload},
		Teams:                  []string{"platform"},
		Providers:              []string{"aws"},
		MaxConcurrentSnapshots: 1,
	}})
	if err != nil {
		t.Fatalf("new policy engine: %v", err)
	}

	runner := NewRunner(RunnerOptions{
		Store:           store,
		PolicyEvaluator: policyEngine,
	})

	_, err = runner.RunVMScan(context.Background(), ScanRequest{
		RequestedBy: "user:alice",
		Target: VMTarget{
			Provider:   ProviderAWS,
			Region:     "us-east-1",
			InstanceID: "i-123",
		},
		ScannerHost: ScannerHost{
			HostID: "scanner-a",
			Region: "us-east-1",
		},
		MaxConcurrentSnapshots: 3,
		Metadata: map[string]string{
			"team": "platform",
		},
	})
	if err == nil {
		t.Fatal("expected policy validation error")
	}

	var validationErr *scanpolicy.ValidationError
	if !errors.As(err, &validationErr) {
		t.Fatalf("expected validation error, got %T", err)
	}

	runs, err := store.ListRuns(context.Background(), RunListOptions{Limit: 10})
	if err != nil {
		t.Fatalf("list runs: %v", err)
	}
	if len(runs) != 0 {
		t.Fatalf("expected no persisted runs, got %d", len(runs))
	}
}

func TestRunnerRunClaimedRunRejectsPolicyViolations(t *testing.T) {
	store, err := NewSQLiteRunStore(filepath.Join(t.TempDir(), "workload-scan.db"))
	if err != nil {
		t.Fatalf("new sqlite run store: %v", err)
	}
	defer func() { _ = store.Close() }()

	policyEngine, err := scanpolicy.NewEngine([]scanpolicy.Policy{{
		ID:                     "platform-workload-policy",
		ScanKinds:              []scanpolicy.Kind{scanpolicy.KindWorkload},
		Teams:                  []string{"platform"},
		Providers:              []string{"aws"},
		MaxConcurrentSnapshots: 1,
	}})
	if err != nil {
		t.Fatalf("new policy engine: %v", err)
	}

	now := time.Date(2026, 3, 21, 18, 0, 0, 0, time.UTC)
	run := newRunRecordFromRequest(ScanRequest{
		ID:          "workload_scan:claimed",
		RequestedBy: "user:alice",
		Target: VMTarget{
			Provider:   ProviderAWS,
			Region:     "us-east-1",
			InstanceID: "i-123",
		},
		ScannerHost: ScannerHost{
			HostID: "scanner-a",
			Region: "us-east-1",
		},
		MaxConcurrentSnapshots: 3,
		Metadata: map[string]string{
			"team": "platform",
		},
		SubmittedAt: now,
	})
	run.Status = RunStatusRunning
	run.Stage = RunStageInventory
	run.Distributed = &DistributedRunState{GroupID: "group-a"}
	if err := store.SaveRun(context.Background(), run); err != nil {
		t.Fatalf("save run: %v", err)
	}

	runner := NewRunner(RunnerOptions{
		Store:           store,
		PolicyEvaluator: policyEngine,
		Now: func() time.Time {
			return now
		},
	})

	_, err = runner.RunClaimedRun(context.Background(), run.ID)
	if err == nil {
		t.Fatal("expected policy validation error")
	}

	var validationErr *scanpolicy.ValidationError
	if !errors.As(err, &validationErr) {
		t.Fatalf("expected validation error, got %T", err)
	}

	stored, err := store.LoadRun(context.Background(), run.ID)
	if err != nil {
		t.Fatalf("load run: %v", err)
	}
	if stored == nil {
		t.Fatal("expected stored run")
	}
	if stored.Status != RunStatusFailed {
		t.Fatalf("expected failed run, got %s", stored.Status)
	}
	if stored.Error == "" {
		t.Fatal("expected persisted policy violation error")
	}
}
