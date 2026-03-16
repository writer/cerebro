package workloadscan

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

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

func (p *fakeProvider) ShareSnapshot(context.Context, VMTarget, ScannerHost, SnapshotArtifact) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.failShareSnapshot > 0 {
		p.failShareSnapshot--
		return fmt.Errorf("share snapshot failed")
	}
	return nil
}

func (p *fakeProvider) CreateInspectionVolume(_ context.Context, _ VMTarget, _ ScannerHost, snapshot SnapshotArtifact) (*InspectionVolume, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.failCreateVolume > 0 {
		p.failCreateVolume--
		return nil, fmt.Errorf("create inspection volume failed")
	}
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
}

func (m *fakeMounter) Mount(_ context.Context, attachment VolumeAttachment, _ SourceVolume) (*MountedVolume, error) {
	if m.failMount {
		return nil, fmt.Errorf("mount %s failed", attachment.VolumeID)
	}
	return &MountedVolume{
		VolumeID:   attachment.VolumeID,
		DevicePath: attachment.DeviceName,
		MountPath:  "/mnt/" + attachment.VolumeID,
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
	fail bool
}

func (a fakeAnalyzer) Analyze(_ context.Context, input AnalysisInput) (*AnalysisReport, error) {
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
