package complianceassessment

import (
	"context"
	"errors"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestCompileExecutableObligationsIsDeterministicAndVersioned(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 15, 10, 0, 0, 0, time.UTC)
	plan := collectorTestPlan(now)

	first, err := CompileExecutableObligations(plan)
	if err != nil {
		t.Fatalf("CompileExecutableObligations() error = %v", err)
	}
	second, err := CompileExecutableObligations(plan)
	if err != nil {
		t.Fatalf("CompileExecutableObligations() repeat error = %v", err)
	}
	if len(first) != 1 || len(second) != 1 {
		t.Fatalf("compiled obligation counts = (%d, %d), want (1, 1)", len(first), len(second))
	}
	got := first[0]
	if got.ModelVersion != ExecutableObligationVersion || got.Predicate != ObligationPredicateNoActiveFindings || got.Digest == "" || got.Digest != second[0].Digest {
		t.Fatalf("compiled obligation = %#v", got)
	}
	if got.PlanRevisionID != plan.RevisionID || got.TaskID != plan.Execution.Tasks[0].ID || got.RuleID != plan.Execution.Tasks[0].RuleID || got.EvaluatorRevision != findingEvaluationCollectorRevision {
		t.Fatalf("compiled obligation binding = %#v", got)
	}

	changed := plan
	changed.Execution.Tasks = append([]PlanTask(nil), plan.Execution.Tasks...)
	changed.Execution.Tasks[0].RuleID = "rule-2"
	changedObligations, err := CompileExecutableObligations(changed)
	if err != nil {
		t.Fatalf("CompileExecutableObligations() changed plan error = %v", err)
	}
	if changedObligations[0].Digest == got.Digest {
		t.Fatal("obligation digest did not change with the executable rule")
	}
}

func TestExecutableObligationRejectsDigestTampering(t *testing.T) {
	t.Parallel()
	obligations, err := CompileExecutableObligations(collectorTestPlan(time.Date(2026, 7, 15, 10, 0, 0, 0, time.UTC)))
	if err != nil {
		t.Fatal(err)
	}
	tampered := obligations[0]
	tampered.MaxAge = "24h"
	if _, err := normalizeExecutableObligation(tampered); !errors.Is(err, ErrInvalidResult) {
		t.Fatalf("normalizeExecutableObligation() error = %v, want ErrInvalidResult", err)
	}
}

func TestExecuteExecutableObligationRunsNoActiveFindingsPredicate(t *testing.T) {
	t.Parallel()
	cutoff := time.Date(2026, 7, 15, 10, 0, 0, 0, time.UTC)
	obligations, err := CompileExecutableObligations(collectorTestPlan(cutoff))
	if err != nil {
		t.Fatal(err)
	}

	satisfied, err := executeExecutableObligation(obligations[0], cutoff, taskCollectionState{
		evaluationRunIDs: []string{"evaluation-1"},
		evidenceState:    EvidenceSufficient,
	})
	if err != nil {
		t.Fatalf("executeExecutableObligation() satisfied error = %v", err)
	}
	if satisfied.AutomatedOutcome != OutcomeSatisfied || !containsReason(satisfied.ReasonCodes, ReasonSatisfied) {
		t.Fatalf("satisfied execution = %#v", satisfied)
	}

	notSatisfied, err := executeExecutableObligation(obligations[0], cutoff, taskCollectionState{
		evaluationRunIDs: []string{"evaluation-1"},
		findingIDs:       []string{"finding-1"},
		evidenceState:    EvidenceSufficient,
	})
	if err != nil {
		t.Fatalf("executeExecutableObligation() finding error = %v", err)
	}
	if notSatisfied.AutomatedOutcome != OutcomeNotSatisfied || !containsReason(notSatisfied.ReasonCodes, ReasonActiveFinding) {
		t.Fatalf("not-satisfied execution = %#v", notSatisfied)
	}
}

func TestFindingEvaluationCollectorPinsCompiledObligationSet(t *testing.T) {
	t.Parallel()
	cutoff := time.Date(2026, 7, 15, 10, 0, 0, 0, time.UTC)
	plan := collectorTestPlan(cutoff)
	evaluation := eventEvaluationRun("evaluation-1", cutoff.Add(-time.Minute), 100, 12)
	collector := NewFindingEvaluationCollector(
		&collectorPlanReader{plan: plan},
		&collectorRuntimeLister{values: []*cerebrov1.SourceRuntime{collectorTestRuntimeForEvaluation(evaluation, cutoff)}},
		&collectorEvaluationLister{values: []*cerebrov1.FindingEvaluationRun{evaluation}},
	)
	collector.now = func() time.Time { return cutoff }

	manifest, results, err := collector.Collect(context.Background(), collectorTestRun(cutoff))
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	obligations, err := CompileExecutableObligations(plan)
	if err != nil {
		t.Fatal(err)
	}
	wantDigest, err := executableObligationSetDigest(obligations)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.MappingSetDigest != wantDigest {
		t.Fatalf("mapping set digest = %q, want compiled obligation set %q", manifest.MappingSetDigest, wantDigest)
	}
	if len(results) != 1 || results[0].EvaluatorRevision != obligations[0].EvaluatorRevision {
		t.Fatalf("results = %#v, want execution by obligation revision %q", results, obligations[0].EvaluatorRevision)
	}
}
