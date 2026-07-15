package complianceimpact

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/complianceintegration"
	"github.com/writer/cerebro/internal/ports"
)

func TestSchedulerTargetsAffectedPlanAndIsIdempotent(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 7, 15, 11, 0, 0, 0, time.UTC)
	impact := schedulerImpact(t, at, true)
	sink := &schedulerMonitorSink{monitors: []*ports.ComplianceMonitor{
		{ID: "monitor-a", TenantID: "tenant", PlanRevisionID: "plan-rev", TriggerKind: ports.ComplianceTriggerChange, Enabled: true},
		{ID: "monitor-b", TenantID: "tenant", PlanRevisionID: "other-plan", TriggerKind: ports.ComplianceTriggerChange, Enabled: true},
		{ID: "monitor-c", TenantID: "tenant", PlanRevisionID: "plan-rev", TriggerKind: ports.ComplianceTriggerTime, Enabled: true},
	}}
	scheduler, err := NewScheduler(staticImpactAnalyzer{result: impact}, sink)
	if err != nil {
		t.Fatal(err)
	}

	first, err := scheduler.Schedule(context.Background(), "event-1", impact.Signal)
	if err != nil {
		t.Fatal(err)
	}
	second, err := scheduler.Schedule(context.Background(), "event-1", impact.Signal)
	if err != nil {
		t.Fatal(err)
	}
	if first.Directive.Mode != AssessmentModeTargeted || first.RecordedSignals != 1 || second.RecordedSignals != 0 ||
		len(first.SelectedMonitorIDs) != 1 || first.SelectedMonitorIDs[0] != "monitor-a" {
		t.Fatalf("schedule results = first:%#v second:%#v", first, second)
	}
	if len(sink.signals) != 2 || sink.signals[0].ScopeDigest != first.Directive.Digest || sink.signals[0].SignalKind != "compliance_impact:updated:targeted" {
		t.Fatalf("signals = %#v", sink.signals)
	}
}

func TestSchedulerFallsBackToAllEnabledChangeMonitorsForIncompleteImpact(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 7, 15, 11, 0, 0, 0, time.UTC)
	impact := schedulerImpact(t, at, false)
	sink := &schedulerMonitorSink{monitors: []*ports.ComplianceMonitor{
		{ID: "monitor-a", TenantID: "tenant", PlanRevisionID: "plan-rev", TriggerKind: ports.ComplianceTriggerChange, Enabled: true},
		{ID: "monitor-b", TenantID: "tenant", PlanRevisionID: "other-plan", TriggerKind: ports.ComplianceTriggerChange, Enabled: true},
		{ID: "monitor-c", TenantID: "tenant", PlanRevisionID: "disabled", TriggerKind: ports.ComplianceTriggerChange, Enabled: false},
	}}
	scheduler, err := NewScheduler(staticImpactAnalyzer{result: impact}, sink)
	if err != nil {
		t.Fatal(err)
	}
	result, err := scheduler.Schedule(context.Background(), "event-2", impact.Signal)
	if err != nil {
		t.Fatal(err)
	}
	if result.Directive.Mode != AssessmentModeFullReconciliation || result.RecordedSignals != 2 || len(result.SelectedMonitorIDs) != 2 {
		t.Fatalf("result = %#v", result)
	}
}

func TestSchedulerChecksMonitorBoundBeforeWrites(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 7, 15, 11, 0, 0, 0, time.UTC)
	impact := schedulerImpact(t, at, false)
	sink := &schedulerMonitorSink{monitors: []*ports.ComplianceMonitor{
		{ID: "monitor-a", TenantID: "tenant", TriggerKind: ports.ComplianceTriggerChange, Enabled: true},
		{ID: "monitor-b", TenantID: "tenant", TriggerKind: ports.ComplianceTriggerChange, Enabled: true},
	}}
	scheduler, err := NewScheduler(staticImpactAnalyzer{result: impact}, sink)
	if err != nil {
		t.Fatal(err)
	}
	scheduler.maxMonitors = 1
	_, err = scheduler.Schedule(context.Background(), "event-3", impact.Signal)
	if !errors.Is(err, ErrImpactMonitorLimit) || len(sink.signals) != 0 {
		t.Fatalf("Schedule() = error %v, signals %#v", err, sink.signals)
	}
}

func schedulerImpact(t *testing.T, at time.Time, complete bool) Result {
	t.Helper()
	root := mustImpactRevision("policy", complianceintegration.FactPolicy, "policy-1", "policy-rev", 1, "sha256:"+strings.Repeat("a", 64), at)
	replacement := mustImpactRevision("policy", complianceintegration.FactPolicy, "policy-1", "policy-rev-2", 2, "sha256:"+strings.Repeat("b", 64), at.Add(time.Second))
	signal, err := complianceintegration.NewChangeSignal(complianceintegration.ChangeUpdated, root, &replacement, at)
	if err != nil {
		t.Fatal(err)
	}
	plan := mustImpactRevision("compliance", complianceintegration.FactAssessmentPlan, "plan-1", "plan-rev", 1, "sha256:"+strings.Repeat("c", 64), at)
	result := Result{TenantID: "tenant", Signal: signal, Complete: complete, Plans: []AffectedFact{{Revision: plan, Reasons: []ReasonCode{ReasonDependencyChanged}, Distance: 1}}}
	if !complete {
		result.Issues = []Issue{{Code: ReasonDepthBudgetExceeded, Revision: root}}
	}
	return result
}

type staticImpactAnalyzer struct {
	result Result
	err    error
}

func (a staticImpactAnalyzer) Analyze(context.Context, complianceintegration.ChangeSignal) (Result, error) {
	return a.result, a.err
}

type schedulerMonitorSink struct {
	monitors []*ports.ComplianceMonitor
	signals  []ports.ComplianceChangeSignal
	seen     map[string]struct{}
}

func (s *schedulerMonitorSink) ListMonitors(_ context.Context, filter ports.ComplianceMonitorFilter) ([]*ports.ComplianceMonitor, error) {
	result := make([]*ports.ComplianceMonitor, 0)
	for _, monitor := range s.monitors {
		if monitor.TenantID == filter.TenantID && monitor.ID > filter.AfterID {
			result = append(result, monitor)
		}
	}
	return result, nil
}

func (s *schedulerMonitorSink) RecordChangeSignal(_ context.Context, signal ports.ComplianceChangeSignal) (bool, error) {
	s.signals = append(s.signals, signal)
	if s.seen == nil {
		s.seen = map[string]struct{}{}
	}
	key := fmt.Sprintf("%s\x00%s", signal.MonitorID, signal.EventID)
	if _, ok := s.seen[key]; ok {
		return false, nil
	}
	s.seen[key] = struct{}{}
	return true, nil
}
