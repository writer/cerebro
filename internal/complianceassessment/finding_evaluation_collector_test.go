package complianceassessment

import (
	"context"
	"errors"
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
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			plan := collectorTestPlan(cutoff)
			plans := &collectorPlanReader{plan: plan}
			runtimes := &collectorRuntimeLister{values: []*cerebrov1.SourceRuntime{{Id: "runtime-1", TenantId: "tenant-1"}}}
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
			if got := evaluations.request; got.RuntimeID != "runtime-1" || got.RuleID != "rule-1" || got.Status != "completed" || got.Limit != 1 {
				t.Fatalf("evaluation request = %#v", got)
			}
		})
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
		&collectorRuntimeLister{values: []*cerebrov1.SourceRuntime{{Id: "runtime-1", TenantId: "tenant-1"}}},
		&collectorEvaluationLister{values: []*cerebrov1.FindingEvaluationRun{evaluation}},
	)
	collector.now = func() time.Time { return cutoff }
	_, _, err := collector.Collect(context.Background(), collectorTestRun(cutoff))
	if !errors.Is(err, ErrIncompleteInput) {
		t.Fatalf("Collect() error = %v, want ErrIncompleteInput", err)
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
		PeriodStart: cutoff.Add(-24 * time.Hour), PeriodEnd: cutoff.Add(-time.Hour),
		RequestedAt: cutoff, RequestedBy: "assessor-1",
	}
}

func eventEvaluationRun(id string, finishedAt time.Time, eventLimit, eventsProcessed uint32) *cerebrov1.FindingEvaluationRun {
	graphRule := false
	return &cerebrov1.FindingEvaluationRun{
		Id: id, RuntimeId: "runtime-1", RuleId: "rule-1", Status: "completed",
		EventLimit: eventLimit, EventsEvaluated: eventsProcessed, EventsProcessed: eventsProcessed,
		GraphRule: &graphRule, FinishedAt: timestamppb.New(finishedAt),
	}
}

func graphEvaluationRun(id string, finishedAt time.Time, rows uint32) *cerebrov1.FindingEvaluationRun {
	graphRule := true
	return &cerebrov1.FindingEvaluationRun{
		Id: id, RuntimeId: "runtime-1", RuleId: "rule-1", Status: "completed",
		GraphRule: &graphRule, GraphRowsRead: &rows, FinishedAt: timestamppb.New(finishedAt),
	}
}

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
	request ports.ListFindingEvaluationRunsRequest
	values  []*cerebrov1.FindingEvaluationRun
}

func (s *collectorEvaluationLister) ListFindingEvaluationRuns(_ context.Context, request ports.ListFindingEvaluationRunsRequest) ([]*cerebrov1.FindingEvaluationRun, error) {
	s.request = request
	return s.values, nil
}
