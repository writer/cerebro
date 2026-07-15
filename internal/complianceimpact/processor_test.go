package complianceimpact

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/complianceintegration"
)

func TestProcessorProjectsCurrentFactBeforeSchedulingPredecessorChange(t *testing.T) {
	projector := &processorProjector{}
	scheduler := &processorScheduler{projector: projector}
	processor, err := NewProcessor(projector, scheduler)
	if err != nil {
		t.Fatal(err)
	}
	previous := impactRevision(t, "tenant", complianceintegration.FactAssessmentPlan, "plan-1", 1)
	current := impactRevision(t, "tenant", complianceintegration.FactAssessmentPlan, "plan-1", 2)
	fact := impactFact(t, current)

	result, err := processor.Process(context.Background(), FactChange{
		EventID: "event-2", Kind: complianceintegration.ChangeUpdated, Fact: fact,
		Predecessor: &previous, ChangedAt: time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !projector.projected || !scheduler.projectedWhenCalled {
		t.Fatal("current fact was not projected before scheduling")
	}
	if scheduler.eventID != "event-2" || !scheduler.signal.Revision().Equal(previous) {
		t.Fatalf("scheduled event/signal = %q/%#v", scheduler.eventID, scheduler.signal)
	}
	replacement, ok := scheduler.signal.Replacement()
	if !ok || !replacement.Equal(current) {
		t.Fatalf("replacement = %#v, %v", replacement, ok)
	}
	if result.RecordedSignals != 1 {
		t.Fatalf("recorded signals = %d", result.RecordedSignals)
	}
}

func TestProcessorRejectsUpdateWithoutExactPredecessorAfterProjection(t *testing.T) {
	projector := &processorProjector{}
	processor, err := NewProcessor(projector, &processorScheduler{projector: projector})
	if err != nil {
		t.Fatal(err)
	}
	current := impactRevision(t, "tenant", complianceintegration.FactAssessmentPlan, "plan-1", 2)
	_, err = processor.Process(context.Background(), FactChange{
		EventID: "event-2", Kind: complianceintegration.ChangeUpdated, Fact: impactFact(t, current), ChangedAt: time.Now(),
	})
	if !errors.Is(err, ErrImpactProcessorUnavailable) {
		t.Fatalf("Process() error = %v", err)
	}
	if !projector.projected {
		t.Fatal("current fact should be rebuildable even when change lineage is incomplete")
	}
}

type processorProjector struct {
	projected bool
	fact      complianceintegration.DomainFact
}

func (p *processorProjector) ProjectFact(_ context.Context, fact complianceintegration.DomainFact) error {
	p.projected = true
	p.fact = fact
	return nil
}

type processorScheduler struct {
	projector           *processorProjector
	projectedWhenCalled bool
	eventID             string
	signal              complianceintegration.ChangeSignal
}

func (s *processorScheduler) Schedule(_ context.Context, eventID string, signal complianceintegration.ChangeSignal) (ScheduleResult, error) {
	s.projectedWhenCalled = s.projector.projected
	s.eventID = eventID
	s.signal = signal
	return ScheduleResult{RecordedSignals: 1}, nil
}
