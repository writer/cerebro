package workloadscan

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestCoordinatorQueueDistributedRunsBalancesAcrossScannerHostsAndDeduplicatesTargets(t *testing.T) {
	store, err := NewSQLiteRunStore(filepath.Join(t.TempDir(), "workload-scan.db"))
	if err != nil {
		t.Fatalf("new sqlite run store: %v", err)
	}
	defer func() { _ = store.Close() }()

	submittedAt := time.Date(2026, 3, 21, 16, 0, 0, 0, time.UTC)
	coordinator := NewCoordinator(CoordinatorOptions{
		Store:    store,
		DedupTTL: 30 * time.Minute,
		Now: func() time.Time {
			return submittedAt
		},
	})

	report, err := coordinator.QueueDistributedRuns(context.Background(), DistributedDispatchRequest{
		GroupID:     "dist-group-1",
		RequestedBy: "scheduler",
		SubmittedAt: submittedAt,
		Targets: []TargetPriority{
			{
				Provider: ProviderAWS,
				Target:   VMTarget{Provider: ProviderAWS, Region: "us-east-1", InstanceID: "i-001"},
			},
			{
				Provider: ProviderAWS,
				Target:   VMTarget{Provider: ProviderAWS, Region: "us-east-1", InstanceID: "i-001"},
			},
			{
				Provider: ProviderAWS,
				Target:   VMTarget{Provider: ProviderAWS, Region: "us-east-1", InstanceID: "i-002"},
			},
			{
				Provider: ProviderAWS,
				Target:   VMTarget{Provider: ProviderAWS, Region: "us-east-1", InstanceID: "i-003"},
			},
		},
		ScannerHosts: []ScannerHost{
			{HostID: "scanner-a", Region: "us-east-1", Zone: "us-east-1a"},
			{HostID: "scanner-b", Region: "us-east-1", Zone: "us-east-1b"},
		},
		Metadata: map[string]string{"source": "scheduler"},
	})
	if err != nil {
		t.Fatalf("QueueDistributedRuns: %v", err)
	}
	if report.GroupID != "dist-group-1" {
		t.Fatalf("group id = %q, want dist-group-1", report.GroupID)
	}
	if report.QueuedRuns != 3 {
		t.Fatalf("queued runs = %d, want 3", report.QueuedRuns)
	}
	if report.Deduplicated != 1 {
		t.Fatalf("deduplicated = %d, want 1", report.Deduplicated)
	}
	if len(report.Dispatches) != 4 {
		t.Fatalf("dispatches = %d, want 4", len(report.Dispatches))
	}

	queuedDispatches := filterDistributedDispatches(report.Dispatches, DistributedDispatchStatusQueued)
	if len(queuedDispatches) != 3 {
		t.Fatalf("queued dispatches = %d, want 3", len(queuedDispatches))
	}
	if queuedDispatches[0].ScannerHost.HostID != "scanner-a" {
		t.Fatalf("first queued scanner host = %q, want scanner-a", queuedDispatches[0].ScannerHost.HostID)
	}
	if queuedDispatches[1].ScannerHost.HostID != "scanner-b" {
		t.Fatalf("second queued scanner host = %q, want scanner-b", queuedDispatches[1].ScannerHost.HostID)
	}
	if queuedDispatches[2].ScannerHost.HostID != "scanner-a" {
		t.Fatalf("third queued scanner host = %q, want scanner-a", queuedDispatches[2].ScannerHost.HostID)
	}

	dedupDispatches := filterDistributedDispatches(report.Dispatches, DistributedDispatchStatusDeduplicated)
	if len(dedupDispatches) != 1 {
		t.Fatalf("deduplicated dispatches = %d, want 1", len(dedupDispatches))
	}
	if dedupDispatches[0].ExistingRunID == "" {
		t.Fatalf("expected deduplicated dispatch to include existing run id, got %#v", dedupDispatches[0])
	}

	runs, err := store.ListRuns(context.Background(), RunListOptions{Limit: 10, OrderBySubmittedAt: true})
	if err != nil {
		t.Fatalf("ListRuns: %v", err)
	}
	if len(runs) != 3 {
		t.Fatalf("persisted runs = %d, want 3", len(runs))
	}
	for _, run := range runs {
		if run.Status != RunStatusQueued {
			t.Fatalf("run %s status = %s, want queued", run.ID, run.Status)
		}
		if run.Stage != RunStageQueued {
			t.Fatalf("run %s stage = %s, want queued", run.ID, run.Stage)
		}
		if run.Distributed == nil {
			t.Fatalf("run %s missing distributed metadata", run.ID)
		}
		if run.Distributed.GroupID != "dist-group-1" {
			t.Fatalf("run %s group id = %q, want dist-group-1", run.ID, run.Distributed.GroupID)
		}
		if run.Distributed.DedupKey == "" {
			t.Fatalf("run %s missing dedup key", run.ID)
		}
		if run.SubmittedAt != submittedAt {
			t.Fatalf("run %s submitted at = %s, want %s", run.ID, run.SubmittedAt, submittedAt)
		}
	}
}

func TestCoordinatorDistributedDedupBlocksActiveQueueAndReleasesAfterClaimedRunCompletes(t *testing.T) {
	store, err := NewSQLiteRunStore(filepath.Join(t.TempDir(), "workload-scan.db"))
	if err != nil {
		t.Fatalf("new sqlite run store: %v", err)
	}
	defer func() { _ = store.Close() }()

	now := time.Date(2026, 3, 21, 18, 0, 0, 0, time.UTC)
	coordinator := NewCoordinator(CoordinatorOptions{
		Store:    store,
		DedupTTL: time.Hour,
		Now: func() time.Time {
			return now
		},
	})
	host := ScannerHost{HostID: "scanner-a", Region: "us-east-1", Zone: "us-east-1a"}
	target := TargetPriority{
		Provider: ProviderAWS,
		Target:   VMTarget{Provider: ProviderAWS, Region: "us-east-1", InstanceID: "i-target"},
	}

	first, err := coordinator.QueueDistributedRuns(context.Background(), DistributedDispatchRequest{
		GroupID:      "dist-group-first",
		SubmittedAt:  now,
		Targets:      []TargetPriority{target},
		ScannerHosts: []ScannerHost{host},
	})
	if err != nil {
		t.Fatalf("QueueDistributedRuns first: %v", err)
	}
	if first.QueuedRuns != 1 || first.Deduplicated != 0 {
		t.Fatalf("first dispatch report = %#v, want 1 queued and 0 deduplicated", first)
	}

	second, err := coordinator.QueueDistributedRuns(context.Background(), DistributedDispatchRequest{
		GroupID:      "dist-group-second",
		SubmittedAt:  now.Add(time.Minute),
		Targets:      []TargetPriority{target},
		ScannerHosts: []ScannerHost{host},
	})
	if err != nil {
		t.Fatalf("QueueDistributedRuns second: %v", err)
	}
	if second.QueuedRuns != 0 || second.Deduplicated != 1 {
		t.Fatalf("second dispatch report = %#v, want 0 queued and 1 deduplicated", second)
	}

	claimed, ok, err := coordinator.ClaimNextRun(context.Background(), host)
	if err != nil {
		t.Fatalf("ClaimNextRun: %v", err)
	}
	if !ok || claimed == nil {
		t.Fatal("expected queued distributed run to be claimed")
	}
	if claimed.Distributed == nil || claimed.Distributed.ClaimedBy != "scanner-a" {
		t.Fatalf("claimed run distributed metadata = %#v, want claimed_by scanner-a", claimed.Distributed)
	}

	runner := NewRunner(RunnerOptions{
		Store:     store,
		Providers: []Provider{&fakeProvider{volumes: []SourceVolume{{ID: "vol-a", SizeGiB: 5}}}},
		Mounter:   &fakeMounter{},
		Analyzer:  fakeAnalyzer{},
	})
	run, err := runner.RunClaimedRun(context.Background(), claimed.ID)
	if err != nil {
		t.Fatalf("RunClaimedRun: %v", err)
	}
	if run.Status != RunStatusSucceeded {
		t.Fatalf("run status = %s, want succeeded", run.Status)
	}

	third, err := coordinator.QueueDistributedRuns(context.Background(), DistributedDispatchRequest{
		GroupID:      "dist-group-third",
		SubmittedAt:  now.Add(2 * time.Minute),
		Targets:      []TargetPriority{target},
		ScannerHosts: []ScannerHost{host},
	})
	if err != nil {
		t.Fatalf("QueueDistributedRuns third: %v", err)
	}
	if third.QueuedRuns != 1 || third.Deduplicated != 0 {
		t.Fatalf("third dispatch report = %#v, want 1 queued and 0 deduplicated", third)
	}
}

func TestCoordinatorClaimNextRunAllowsOnlyOneConcurrentClaimPerQueuedRun(t *testing.T) {
	store, err := NewSQLiteRunStore(filepath.Join(t.TempDir(), "workload-scan.db"))
	if err != nil {
		t.Fatalf("new sqlite run store: %v", err)
	}
	defer func() { _ = store.Close() }()

	host := ScannerHost{HostID: "scanner-a", Region: "us-east-1", Zone: "us-east-1a"}
	coordinatorA := NewCoordinator(CoordinatorOptions{Store: store, DedupTTL: time.Hour})
	coordinatorB := NewCoordinator(CoordinatorOptions{Store: store, DedupTTL: time.Hour})

	if _, err := coordinatorA.QueueDistributedRuns(context.Background(), DistributedDispatchRequest{
		GroupID:      "dist-group-claim",
		Targets:      []TargetPriority{{Provider: ProviderAWS, Target: VMTarget{Provider: ProviderAWS, Region: "us-east-1", InstanceID: "i-claim"}}},
		ScannerHosts: []ScannerHost{host},
	}); err != nil {
		t.Fatalf("QueueDistributedRuns: %v", err)
	}

	results := make(chan *RunRecord, 2)
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for _, coordinator := range []*Coordinator{coordinatorA, coordinatorB} {
		wg.Add(1)
		go func(c *Coordinator) {
			defer wg.Done()
			run, ok, err := c.ClaimNextRun(context.Background(), host)
			if err != nil {
				errs <- err
				return
			}
			if ok {
				results <- run
				return
			}
			results <- nil
		}(coordinator)
	}
	wg.Wait()
	close(results)
	close(errs)

	for err := range errs {
		if err != nil {
			t.Fatalf("ClaimNextRun concurrent error: %v", err)
		}
	}

	claimedCount := 0
	for run := range results {
		if run != nil {
			claimedCount++
		}
	}
	if claimedCount != 1 {
		t.Fatalf("claimed count = %d, want 1", claimedCount)
	}

	runs, err := store.ListRuns(context.Background(), RunListOptions{Limit: 10})
	if err != nil {
		t.Fatalf("ListRuns: %v", err)
	}
	if len(runs) != 1 {
		t.Fatalf("persisted runs = %d, want 1", len(runs))
	}
	if runs[0].Status != RunStatusRunning || runs[0].Stage != RunStageInventory {
		t.Fatalf("persisted claimed run status/stage = %s/%s, want running/inventory", runs[0].Status, runs[0].Stage)
	}
}

func TestCoordinatorClaimNextRunStealsEligibleQueuedWorkFromAnotherScannerHost(t *testing.T) {
	store, err := NewSQLiteRunStore(filepath.Join(t.TempDir(), "workload-scan.db"))
	if err != nil {
		t.Fatalf("new sqlite run store: %v", err)
	}
	defer func() { _ = store.Close() }()

	scannerA := ScannerHost{HostID: "scanner-a", Region: "us-east-1", Zone: "us-east-1a"}
	scannerB := ScannerHost{HostID: "scanner-b", Region: "us-east-1", Zone: "us-east-1b"}
	coordinator := NewCoordinator(CoordinatorOptions{Store: store, DedupTTL: time.Hour})

	report, err := coordinator.QueueDistributedRuns(context.Background(), DistributedDispatchRequest{
		GroupID: "dist-group-steal",
		Targets: []TargetPriority{{
			Provider: ProviderAWS,
			Target:   VMTarget{Provider: ProviderAWS, Region: "us-east-1", InstanceID: "i-steal"},
		}},
		ScannerHosts: []ScannerHost{scannerA, scannerB},
	})
	if err != nil {
		t.Fatalf("QueueDistributedRuns: %v", err)
	}
	if len(report.Dispatches) != 1 {
		t.Fatalf("dispatches = %d, want 1", len(report.Dispatches))
	}
	if report.Dispatches[0].ScannerHost.HostID != "scanner-a" {
		t.Fatalf("initial assignment = %q, want scanner-a", report.Dispatches[0].ScannerHost.HostID)
	}

	claimed, ok, err := coordinator.ClaimNextRun(context.Background(), scannerB)
	if err != nil {
		t.Fatalf("ClaimNextRun steal: %v", err)
	}
	if !ok || claimed == nil {
		t.Fatal("expected scanner-b to steal eligible queued run")
	}
	if claimed.ScannerHost.HostID != "scanner-b" {
		t.Fatalf("claimed scanner host = %q, want scanner-b", claimed.ScannerHost.HostID)
	}
	if claimed.Distributed == nil || claimed.Distributed.ClaimedBy != "scanner-b" {
		t.Fatalf("claimed distributed state = %#v, want claimed_by scanner-b", claimed.Distributed)
	}
}

func TestCoordinatorAggregateGroupSummarizesDistributedRunResults(t *testing.T) {
	store, err := NewSQLiteRunStore(filepath.Join(t.TempDir(), "workload-scan.db"))
	if err != nil {
		t.Fatalf("new sqlite run store: %v", err)
	}
	defer func() { _ = store.Close() }()

	base := time.Date(2026, 3, 21, 20, 0, 0, 0, time.UTC)
	records := []*RunRecord{
		{
			ID:          "workload_scan:agg-1",
			Provider:    ProviderAWS,
			Status:      RunStatusSucceeded,
			Stage:       RunStageCompleted,
			Target:      VMTarget{Provider: ProviderAWS, Region: "us-east-1", InstanceID: "i-001"},
			ScannerHost: ScannerHost{HostID: "scanner-a", Region: "us-east-1", Zone: "us-east-1a"},
			SubmittedAt: base,
			UpdatedAt:   base,
			Distributed: &DistributedRunState{GroupID: "dist-group-agg", DedupKey: "aws:us-east-1:i-001"},
			Summary: RunSummary{
				VolumeCount:      1,
				SucceededVolumes: 1,
				Findings:         3,
			},
		},
		{
			ID:          "workload_scan:agg-2",
			Provider:    ProviderAWS,
			Status:      RunStatusFailed,
			Stage:       RunStageFailed,
			Target:      VMTarget{Provider: ProviderAWS, Region: "us-east-1", InstanceID: "i-002"},
			ScannerHost: ScannerHost{HostID: "scanner-b", Region: "us-east-1", Zone: "us-east-1b"},
			SubmittedAt: base.Add(time.Minute),
			UpdatedAt:   base.Add(time.Minute),
			Distributed: &DistributedRunState{GroupID: "dist-group-agg", DedupKey: "aws:us-east-1:i-002"},
			Summary: RunSummary{
				VolumeCount:      2,
				FailedVolumes:    2,
				SnapshotGiBHours: 4,
			},
		},
		{
			ID:          "workload_scan:agg-3",
			Provider:    ProviderAWS,
			Status:      RunStatusRunning,
			Stage:       RunStageAnalyze,
			Target:      VMTarget{Provider: ProviderAWS, Region: "us-east-1", InstanceID: "i-003"},
			ScannerHost: ScannerHost{HostID: "scanner-a", Region: "us-east-1", Zone: "us-east-1a"},
			SubmittedAt: base.Add(2 * time.Minute),
			UpdatedAt:   base.Add(2 * time.Minute),
			Distributed: &DistributedRunState{GroupID: "dist-group-agg", DedupKey: "aws:us-east-1:i-003"},
			Summary: RunSummary{
				VolumeCount: 1,
			},
		},
	}
	for _, record := range records {
		if err := store.SaveRun(context.Background(), record); err != nil {
			t.Fatalf("SaveRun %s: %v", record.ID, err)
		}
	}

	coordinator := NewCoordinator(CoordinatorOptions{Store: store})
	summary, err := coordinator.AggregateGroup(context.Background(), "dist-group-agg")
	if err != nil {
		t.Fatalf("AggregateGroup: %v", err)
	}
	if summary == nil {
		t.Fatal("expected aggregate summary")
	}
	if summary.GroupID != "dist-group-agg" {
		t.Fatalf("group id = %q, want dist-group-agg", summary.GroupID)
	}
	if summary.TotalRuns != 3 {
		t.Fatalf("total runs = %d, want 3", summary.TotalRuns)
	}
	if summary.Succeeded != 1 || summary.Failed != 1 || summary.Running != 1 || summary.Queued != 0 {
		t.Fatalf("unexpected aggregate counts: %#v", summary)
	}
	if summary.TotalFindings != 3 {
		t.Fatalf("total findings = %d, want 3", summary.TotalFindings)
	}
	if summary.TotalVolumes != 4 {
		t.Fatalf("total volumes = %d, want 4", summary.TotalVolumes)
	}
	if summary.ScannerHostRuns["scanner-a"] != 2 {
		t.Fatalf("scanner-a runs = %d, want 2", summary.ScannerHostRuns["scanner-a"])
	}
	if summary.ScannerHostRuns["scanner-b"] != 1 {
		t.Fatalf("scanner-b runs = %d, want 1", summary.ScannerHostRuns["scanner-b"])
	}
	if summary.Complete {
		t.Fatalf("complete = true, want false while one run is still running")
	}
}

func filterDistributedDispatches(dispatches []DistributedDispatch, status DistributedDispatchStatus) []DistributedDispatch {
	filtered := make([]DistributedDispatch, 0, len(dispatches))
	for _, dispatch := range dispatches {
		if dispatch.Status == status {
			filtered = append(filtered, dispatch)
		}
	}
	return filtered
}
