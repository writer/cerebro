package complianceassessment

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestFindingEvaluationCollectorProducesPointInTimeResults(t *testing.T) {
	t.Parallel()
	cutoff := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name             string
		evaluation       *cerebrov1.FindingEvaluationRun
		wantOutcome      AutomatedOutcome
		wantEvidence     EvidenceState
		wantCompleteness CollectionCompleteness
		wantReason       ReasonCode
		wantFindings     int
		mutateRuntime    func(*cerebrov1.SourceRuntime)
	}{
		{
			name:        "satisfied event evaluation",
			evaluation:  eventEvaluationRun("evaluation-1", cutoff.Add(-30*time.Minute), 100, 12),
			wantOutcome: OutcomeSatisfied, wantEvidence: EvidenceSufficient,
			wantCompleteness: CollectionComplete, wantReason: ReasonSatisfied,
		},
		{
			name: "active finding",
			evaluation: func() *cerebrov1.FindingEvaluationRun {
				run := eventEvaluationRun("evaluation-2", cutoff.Add(-30*time.Minute), 100, 12)
				run.FindingIds = []string{"finding-1"}
				run.FindingsUpserted = 1
				run.FindingsEmitted = 1
				return run
			}(),
			wantOutcome: OutcomeNotSatisfied, wantEvidence: EvidenceSufficient,
			wantCompleteness: CollectionComplete, wantReason: ReasonActiveFinding, wantFindings: 1,
		},
		{
			name:        "truncated event evaluation",
			evaluation:  eventEvaluationRun("evaluation-3", cutoff.Add(-30*time.Minute), 10, 10),
			wantOutcome: OutcomeIndeterminate, wantEvidence: EvidenceIncomplete,
			wantCompleteness: CollectionTruncated, wantReason: ReasonCoverageIncomplete,
		},
		{
			name:        "stale event evaluation",
			evaluation:  eventEvaluationRun("evaluation-4", cutoff.Add(-3*time.Hour), 100, 12),
			wantOutcome: OutcomeIndeterminate, wantEvidence: EvidenceStale,
			wantCompleteness: CollectionUnknown, wantReason: ReasonEvidenceStale,
		},
		{
			name:        "missing event evaluation",
			wantOutcome: OutcomeIndeterminate, wantEvidence: EvidenceMissing,
			wantCompleteness: CollectionUnknown, wantReason: ReasonEvidenceMissing,
		},
		{
			name:        "satisfied graph evaluation",
			evaluation:  graphEvaluationRun("evaluation-5", cutoff.Add(-30*time.Minute), 14),
			wantOutcome: OutcomeSatisfied, wantEvidence: EvidenceSufficient,
			wantCompleteness: CollectionComplete, wantReason: ReasonSatisfied,
		},
		{
			name: "internally truncated graph evaluation",
			evaluation: func() *cerebrov1.FindingEvaluationRun {
				run := graphEvaluationRun("evaluation-6", cutoff.Add(-30*time.Minute), 2)
				run.GraphTruncated = boolPointer(true)
				return run
			}(),
			wantOutcome: OutcomeIndeterminate, wantEvidence: EvidenceIncomplete,
			wantCompleteness: CollectionTruncated, wantReason: ReasonCoverageIncomplete,
		},
		{
			name: "incomplete source snapshot",
			evaluation: func() *cerebrov1.FindingEvaluationRun {
				run := eventEvaluationRun("evaluation-7", cutoff.Add(-30*time.Minute), 100, 12)
				run.SourceSnapshots[0].LastSyncedAt = nil
				run.SourceSnapshots[0].CheckpointWatermark = nil
				run.SourceSnapshots[0].Complete = boolPointer(false)
				return run
			}(),
			wantOutcome: OutcomeIndeterminate, wantEvidence: EvidenceUntrusted,
			wantCompleteness: CollectionUnknown, wantReason: ReasonSourceUntrusted,
		},
		{
			name: "rejected source records",
			evaluation: func() *cerebrov1.FindingEvaluationRun {
				run := eventEvaluationRun("evaluation-8", cutoff.Add(-30*time.Minute), 100, 12)
				run.SourceSnapshots[0].RecordsRejected = 1
				run.SourceSnapshots[0].Complete = boolPointer(false)
				return run
			}(),
			wantOutcome: OutcomeIndeterminate, wantEvidence: EvidenceUntrusted,
			wantCompleteness: CollectionUnknown, wantReason: ReasonSourceUntrusted,
		},
		{
			name:       "failed current runtime",
			evaluation: eventEvaluationRun("evaluation-9", cutoff.Add(-30*time.Minute), 100, 12),
			mutateRuntime: func(runtime *cerebrov1.SourceRuntime) {
				runtime.Config["__cerebro_runtime_status"] = "failed"
				runtime.Config["__cerebro_runtime_last_failure_category"] = "provider"
			},
			wantOutcome: OutcomeIndeterminate, wantEvidence: EvidenceUntrusted,
			wantCompleteness: CollectionUnknown, wantReason: ReasonSourceUntrusted,
		},
		{
			name:       "changed source scope",
			evaluation: eventEvaluationRun("evaluation-10", cutoff.Add(-30*time.Minute), 100, 12),
			mutateRuntime: func(runtime *cerebrov1.SourceRuntime) {
				runtime.Config["__cerebro_resolved_progress_config_hash"] = "sha256:changed"
			},
			wantOutcome: OutcomeIndeterminate, wantEvidence: EvidenceUntrusted,
			wantCompleteness: CollectionUnknown, wantReason: ReasonSourceUntrusted,
		},
		{
			name:       "advanced current runtime progress",
			evaluation: eventEvaluationRun("evaluation-advanced-runtime", cutoff.Add(-30*time.Minute), 100, 12),
			mutateRuntime: func(runtime *cerebrov1.SourceRuntime) {
				advanced := runtime.GetLastSyncedAt().AsTime().Add(time.Minute)
				runtime.LastSyncedAt = timestamppb.New(advanced)
				runtime.Checkpoint.Watermark = timestamppb.New(advanced)
			},
			wantOutcome: OutcomeIndeterminate, wantEvidence: EvidenceUntrusted,
			wantCompleteness: CollectionUnknown, wantReason: ReasonSourceUntrusted,
		},
		{
			name: "unsupported cleanup run",
			evaluation: func() *cerebrov1.FindingEvaluationRun {
				run := eventEvaluationRun("evaluation-11", cutoff.Add(-30*time.Minute), 100, 12)
				run.RuleApplicable = boolPointer(false)
				return run
			}(),
			wantOutcome: OutcomeIndeterminate, wantEvidence: EvidenceUntrusted,
			wantCompleteness: CollectionUnknown, wantReason: ReasonSourceUnsupported,
		},
		{
			name: "graph projection predates source",
			evaluation: func() *cerebrov1.FindingEvaluationRun {
				run := graphEvaluationRun("evaluation-12", cutoff.Add(-30*time.Minute), 14)
				run.SourceSnapshots[0].GraphIngestedAt = timestamppb.New(run.SourceSnapshots[0].GetLastSyncedAt().AsTime().Add(-time.Minute))
				return run
			}(),
			wantOutcome: OutcomeIndeterminate, wantEvidence: EvidenceUntrusted,
			wantCompleteness: CollectionUnknown, wantReason: ReasonSourceUntrusted,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			plan := collectorTestPlan(cutoff)
			plans := &collectorPlanReader{plan: plan}
			runtime := collectorTestRuntimeForEvaluation(test.evaluation, cutoff)
			if test.mutateRuntime != nil {
				test.mutateRuntime(runtime)
			}
			runtimes := &collectorRuntimeLister{values: []*cerebrov1.SourceRuntime{runtime}}
			evaluations := &collectorEvaluationLister{}
			if test.evaluation != nil {
				evaluations.values = []*cerebrov1.FindingEvaluationRun{test.evaluation}
			}
			collector := NewFindingEvaluationCollector(plans, runtimes, evaluations)
			collector.now = func() time.Time { return cutoff }

			manifest, results, err := collector.Collect(context.Background(), collectorTestRun(cutoff))
			if err != nil {
				t.Fatalf("Collect() error = %v", err)
			}
			if err := ValidateInputManifest(manifest); err != nil {
				t.Fatalf("ValidateInputManifest() error = %v", err)
			}
			if len(manifest.Receipts) != 1 || manifest.Receipts[0].Completeness != test.wantCompleteness {
				t.Fatalf("receipts = %#v, want one %q receipt", manifest.Receipts, test.wantCompleteness)
			}
			if len(results) != 1 {
				t.Fatalf("len(results) = %d, want 1", len(results))
			}
			result := results[0]
			if result.AutomatedOutcome != test.wantOutcome || result.EvidenceState != test.wantEvidence || result.OperatingEffectivenessState != OperatingNotTested {
				t.Fatalf("result states = (%q, %q, %q), want (%q, %q, %q)", result.AutomatedOutcome, result.EvidenceState, result.OperatingEffectivenessState, test.wantOutcome, test.wantEvidence, OperatingNotTested)
			}
			if !containsReason(result.ReasonCodes, test.wantReason) || len(result.FindingIDs) != test.wantFindings {
				t.Fatalf("result reasons/findings = (%#v, %#v)", result.ReasonCodes, result.FindingIDs)
			}
			if got := runtimes.filter.TenantID; got != "tenant-1" {
				t.Fatalf("runtime tenant filter = %q, want tenant-1", got)
			}
			if got := evaluations.request; got.RuntimeID != "runtime-1" || got.RuleID != "rule-1" || got.Status != "completed" || !got.FinishedAtOrBefore.Equal(cutoff) || got.Limit != 1 {
				t.Fatalf("evaluation request = %#v", got)
			}
		})
	}
}

func TestFindingEvaluationCollectorRejectsPostPeriodEvidence(t *testing.T) {
	t.Parallel()
	cutoff := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	run := collectorTestRun(cutoff)
	run.PeriodEnd = cutoff.Add(-time.Hour)
	evaluation := eventEvaluationRun("evaluation-after-period", cutoff.Add(-30*time.Minute), 100, 12)
	evaluations := &collectorEvaluationLister{values: []*cerebrov1.FindingEvaluationRun{evaluation}}
	collector := NewFindingEvaluationCollector(
		&collectorPlanReader{plan: collectorTestPlan(cutoff)},
		&collectorRuntimeLister{values: []*cerebrov1.SourceRuntime{collectorTestRuntimeForEvaluation(evaluation, cutoff)}},
		evaluations,
	)
	collector.now = func() time.Time { return cutoff }
	manifest, results, err := collector.Collect(context.Background(), run)
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if !evaluations.request.FinishedAtOrBefore.Equal(run.PeriodEnd) {
		t.Fatalf("FinishedAtOrBefore = %v, want %v", evaluations.request.FinishedAtOrBefore, run.PeriodEnd)
	}
	if manifest.Receipts[0].Completeness != CollectionUnknown || results[0].AutomatedOutcome != OutcomeIndeterminate || !containsReason(results[0].ReasonCodes, ReasonEvidenceInvalid) {
		t.Fatalf("post-period result = receipt:%#v result:%#v", manifest.Receipts[0], results[0])
	}
}

func TestFindingEvaluationCollectorRejectsRuntimeOutsideTenant(t *testing.T) {
	t.Parallel()
	cutoff := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	collector := NewFindingEvaluationCollector(
		&collectorPlanReader{plan: collectorTestPlan(cutoff)},
		&collectorRuntimeLister{values: []*cerebrov1.SourceRuntime{{Id: "runtime-1", TenantId: "tenant-2"}}},
		&collectorEvaluationLister{},
	)
	collector.now = func() time.Time { return cutoff }
	_, _, err := collector.Collect(context.Background(), collectorTestRun(cutoff))
	if !errors.Is(err, ErrIncompleteInput) {
		t.Fatalf("Collect() error = %v, want ErrIncompleteInput", err)
	}
}

func TestFindingEvaluationCollectorRejectsInconsistentFindingCounts(t *testing.T) {
	t.Parallel()
	cutoff := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	evaluation := eventEvaluationRun("evaluation-1", cutoff.Add(-time.Minute), 100, 12)
	evaluation.FindingIds = []string{"finding-1"}
	collector := NewFindingEvaluationCollector(
		&collectorPlanReader{plan: collectorTestPlan(cutoff)},
		&collectorRuntimeLister{values: []*cerebrov1.SourceRuntime{collectorTestRuntimeForEvaluation(evaluation, cutoff)}},
		&collectorEvaluationLister{values: []*cerebrov1.FindingEvaluationRun{evaluation}},
	)
	collector.now = func() time.Time { return cutoff }
	_, _, err := collector.Collect(context.Background(), collectorTestRun(cutoff))
	if !errors.Is(err, ErrIncompleteInput) {
		t.Fatalf("Collect() error = %v, want ErrIncompleteInput", err)
	}
}

func TestValidateEvaluationSourceSnapshotsRequiresEveryGraphSourceInPlan(t *testing.T) {
	t.Parallel()
	finishedAt := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	evaluation := graphEvaluationRun("evaluation-cross-source", finishedAt, 4)
	second := collectorTestSourceSnapshot(evaluation.GetSourceSnapshots()[0].GetLastSyncedAt().AsTime(), true)
	second.RuntimeId = "runtime-2"
	second.SourceId = "github"
	second.Family = "audit"
	second.GraphIngestRunId = "graph-run-2"
	second.GraphCheckpointId = "graph-checkpoint-2"
	evaluation.SourceSnapshots = append(evaluation.SourceSnapshots, second)
	runtimes := map[string]*cerebrov1.SourceRuntime{
		"runtime-1": collectorTestRuntimeFromSnapshot(evaluation.GetSourceSnapshots()[0]),
		"runtime-2": collectorTestRuntimeFromSnapshot(second),
	}
	startedAt := evaluation.GetStartedAt().AsTime()
	if err := validateEvaluationSourceSnapshots(evaluation, []string{"runtime-1"}, startedAt, finishedAt, 2*time.Hour, runtimes); !errors.Is(err, ErrIncompleteInput) {
		t.Fatalf("validateEvaluationSourceSnapshots() error = %v, want dependency outside plan", err)
	}
	if err := validateEvaluationSourceSnapshots(evaluation, []string{"runtime-1", "runtime-2"}, startedAt, finishedAt, 2*time.Hour, runtimes); err != nil {
		t.Fatalf("validateEvaluationSourceSnapshots() with complete plan error = %v", err)
	}
	runtimes["runtime-3"] = collectorTestRuntimeFromSnapshot(evaluation.GetSourceSnapshots()[0])
	runtimes["runtime-3"].Id = "runtime-3"
	if err := validateEvaluationSourceSnapshots(evaluation, []string{"runtime-1", "runtime-2", "runtime-3"}, startedAt, finishedAt, 2*time.Hour, runtimes); !errors.Is(err, ErrIncompleteInput) {
		t.Fatalf("validateEvaluationSourceSnapshots() error = %v, want missing planned dependency", err)
	}
}

func TestFindingEvaluationCollectorConsumesSingleMultiSourceGraphRun(t *testing.T) {
	t.Parallel()
	cutoff := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	evaluation := graphEvaluationRun("evaluation-cross-source", cutoff.Add(-30*time.Minute), 4)
	second := collectorTestSourceSnapshot(evaluation.GetSourceSnapshots()[0].GetLastSyncedAt().AsTime(), true)
	second.RuntimeId = "runtime-2"
	second.SourceId = "github"
	second.Family = "audit"
	second.GraphIngestRunId = "graph-run-2"
	second.GraphCheckpointId = "graph-checkpoint-2"
	evaluation.SourceSnapshots = append(evaluation.SourceSnapshots, second)

	plan := collectorTestPlan(cutoff)
	plan.Execution.Tasks[0].RuntimeIDs = []string{"runtime-1", "runtime-2"}
	plan = normalizePlan(plan)
	evaluations := &collectorEvaluationLister{valuesByRuntime: map[string][]*cerebrov1.FindingEvaluationRun{
		"runtime-1": {evaluation},
		"runtime-2": nil,
	}}
	collector := NewFindingEvaluationCollector(
		&collectorPlanReader{plan: plan},
		&collectorRuntimeLister{values: []*cerebrov1.SourceRuntime{
			collectorTestRuntimeFromSnapshot(evaluation.GetSourceSnapshots()[0]),
			collectorTestRuntimeFromSnapshot(second),
		}},
		evaluations,
	)
	collector.now = func() time.Time { return cutoff }

	manifest, results, err := collector.Collect(context.Background(), collectorTestRun(cutoff))
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if len(evaluations.requests) != 2 {
		t.Fatalf("evaluation queries = %d, want one lookup per planned runtime", len(evaluations.requests))
	}
	if len(manifest.Receipts) != 1 || manifest.Receipts[0].RuntimeID != "runtime-1" || manifest.Receipts[0].Completeness != CollectionComplete {
		t.Fatalf("graph receipts = %#v, want one complete trigger-runtime receipt", manifest.Receipts)
	}
	if len(manifest.EvaluationRunIDs) != 1 || manifest.EvaluationRunIDs[0] != evaluation.GetId() {
		t.Fatalf("evaluation run ids = %#v, want only %q", manifest.EvaluationRunIDs, evaluation.GetId())
	}
	if len(results) != 1 || results[0].AutomatedOutcome != OutcomeSatisfied || results[0].EvidenceState != EvidenceSufficient {
		t.Fatalf("graph result = %#v, want satisfied with sufficient evidence", results)
	}
}

func collectorTestPlan(now time.Time) AssessmentPlanRevision {
	plan := planForValidation(now, []PlanTask{findingTaskForValidation(1, 1)})
	plan.Status = PlanPublished
	plan.Execution.Tasks[0].RuntimeIDs = []string{"runtime-1"}
	plan.Execution.Tasks[0].MaxAge = "2h"
	plan.ContentDigest = digestBytes([]byte("collector-test-plan"))
	plan.PublishedAt = now.Add(-time.Hour)
	plan.PublishedBy = "approver-1"
	return normalizePlan(plan)
}

func collectorTestRun(cutoff time.Time) AssessmentRun {
	return AssessmentRun{
		ID: "assessment-run-1", TenantID: "tenant-1", ProgramID: "program-1",
		ScopeRevisionID: "scope-revision-1", PlanRevisionID: "plan-revision-1",
		PeriodStart: cutoff.Add(-24 * time.Hour), PeriodEnd: cutoff,
		RequestedAt: cutoff, RequestedBy: "assessor-1",
	}
}

func eventEvaluationRun(id string, finishedAt time.Time, eventLimit, eventsProcessed uint32) *cerebrov1.FindingEvaluationRun {
	graphRule := false
	startedAt := finishedAt.Add(-time.Minute)
	sourceAt := startedAt.Add(-time.Minute)
	return &cerebrov1.FindingEvaluationRun{
		Id: id, RuntimeId: "runtime-1", RuleId: "rule-1", Status: "completed",
		EventLimit: eventLimit, EventsEvaluated: eventsProcessed, EventsProcessed: eventsProcessed,
		GraphRule: &graphRule, StartedAt: timestamppb.New(startedAt), FinishedAt: timestamppb.New(finishedAt),
		RuleApplicable: boolPointer(true), SourceDependencyComplete: boolPointer(true),
		SourceSnapshots: []*cerebrov1.FindingEvaluationSourceSnapshot{collectorTestSourceSnapshot(sourceAt, false)},
	}
}

func graphEvaluationRun(id string, finishedAt time.Time, rows uint32) *cerebrov1.FindingEvaluationRun {
	graphRule := true
	startedAt := finishedAt.Add(-time.Minute)
	sourceAt := startedAt.Add(-time.Minute)
	rowLimit := uint32(100)
	return &cerebrov1.FindingEvaluationRun{
		Id: id, RuntimeId: "runtime-1", RuleId: "rule-1", Status: "completed",
		GraphRule: &graphRule, GraphRowsRead: &rows, GraphTruncated: boolPointer(false), GraphRowLimit: &rowLimit,
		StartedAt: timestamppb.New(startedAt), FinishedAt: timestamppb.New(finishedAt),
		RuleApplicable: boolPointer(true), SourceDependencyComplete: boolPointer(true),
		SourceSnapshots: []*cerebrov1.FindingEvaluationSourceSnapshot{collectorTestSourceSnapshot(sourceAt, true)},
	}
}

func collectorTestSourceSnapshot(sourceAt time.Time, graph bool) *cerebrov1.FindingEvaluationSourceSnapshot {
	snapshot := &cerebrov1.FindingEvaluationSourceSnapshot{
		RuntimeId: "runtime-1", SourceId: "okta", Family: "user",
		LastSyncedAt: timestamppb.New(sourceAt), CheckpointWatermark: timestamppb.New(sourceAt), Complete: boolPointer(true),
		RecordsScanned: 12, RecordsAccepted: 12, RecordsRejected: 0, SyncStatus: "completed", ContractProbeState: "passing",
		ProgressConfigHash: "sha256:collector-test-runtime",
	}
	if graph {
		snapshot.GraphIngestRunId = "graph-run-1"
		snapshot.GraphIngestStatus = "completed"
		snapshot.GraphCheckpointId = "graph-checkpoint-1"
		snapshot.GraphIngestedAt = timestamppb.New(sourceAt.Add(30 * time.Second))
		snapshot.GraphSnapshotComplete = boolPointer(true)
	}
	return snapshot
}

func collectorTestRuntimeForEvaluation(evaluation *cerebrov1.FindingEvaluationRun, now time.Time) *cerebrov1.SourceRuntime {
	snapshot := collectorTestSourceSnapshot(now.Add(-time.Hour), false)
	if evaluation != nil && len(evaluation.GetSourceSnapshots()) != 0 && evaluation.GetSourceSnapshots()[0] != nil {
		snapshot = evaluation.GetSourceSnapshots()[0]
	}
	return collectorTestRuntimeFromSnapshot(snapshot)
}

func collectorTestRuntimeFromSnapshot(snapshot *cerebrov1.FindingEvaluationSourceSnapshot) *cerebrov1.SourceRuntime {
	return &cerebrov1.SourceRuntime{
		Id: snapshot.GetRuntimeId(), TenantId: "tenant-1", SourceId: snapshot.GetSourceId(), LastSyncedAt: snapshot.GetLastSyncedAt(),
		Checkpoint: &cerebrov1.SourceCheckpoint{Watermark: snapshot.GetCheckpointWatermark()},
		Config: map[string]string{
			"family": snapshot.GetFamily(), "__cerebro_runtime_status": "completed", "__cerebro_runtime_last_failure_category": "",
			"__cerebro_runtime_contract_probe_state": snapshot.GetContractProbeState(), "__cerebro_resolved_progress_config_hash": snapshot.GetProgressConfigHash(),
			"__cerebro_runtime_records_scanned":  strconv.FormatUint(uint64(snapshot.GetRecordsScanned()), 10),
			"__cerebro_runtime_records_accepted": strconv.FormatUint(uint64(snapshot.GetRecordsAccepted()), 10),
			"__cerebro_runtime_records_rejected": strconv.FormatUint(uint64(snapshot.GetRecordsRejected()), 10),
		},
	}
}

func boolPointer(value bool) *bool { return &value }

func containsReason(values []ReasonCode, want ReasonCode) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

type collectorPlanReader struct {
	plan AssessmentPlanRevision
}

func (s *collectorPlanReader) GetPlan(context.Context, string, string) (AssessmentPlanRevision, error) {
	return s.plan, nil
}

type collectorRuntimeLister struct {
	filter ports.SourceRuntimeFilter
	values []*cerebrov1.SourceRuntime
}

func (s *collectorRuntimeLister) ListSourceRuntimes(_ context.Context, filter ports.SourceRuntimeFilter) ([]*cerebrov1.SourceRuntime, error) {
	s.filter = filter
	return s.values, nil
}

type collectorEvaluationLister struct {
	request         ports.ListFindingEvaluationRunsRequest
	requests        []ports.ListFindingEvaluationRunsRequest
	values          []*cerebrov1.FindingEvaluationRun
	valuesByRuntime map[string][]*cerebrov1.FindingEvaluationRun
}

func (s *collectorEvaluationLister) ListFindingEvaluationRuns(_ context.Context, request ports.ListFindingEvaluationRunsRequest) ([]*cerebrov1.FindingEvaluationRun, error) {
	s.request = request
	s.requests = append(s.requests, request)
	if s.valuesByRuntime != nil {
		return s.valuesByRuntime[request.RuntimeID], nil
	}
	return s.values, nil
}
