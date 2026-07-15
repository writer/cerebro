package complianceimpact

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/complianceintegration"
)

var ErrImpactProcessorUnavailable = errors.New("compliance impact processor unavailable")

type factProjector interface {
	ProjectFact(context.Context, complianceintegration.DomainFact) error
}

type changeScheduler interface {
	Schedule(context.Context, string, complianceintegration.ChangeSignal) (ScheduleResult, error)
}

// FactChange binds one already-durable event to the exact fact revision it
// created and, for an update, the exact predecessor revision it replaced.
// Deleted and revoked facts identify the affected revision in Fact.
type FactChange struct {
	EventID     string
	Kind        complianceintegration.ChangeKind
	Fact        complianceintegration.DomainFact
	Predecessor *complianceintegration.RevisionRef
	ChangedAt   time.Time
}

// Processor is the single ordering boundary between source-domain adapters,
// the rebuildable impact graph, and monitor scheduling. The current fact is
// projected before traversal. An update traverses the predecessor so existing
// reverse dependencies remain visible and carries the current fact as its
// replacement.
type Processor struct {
	projector factProjector
	scheduler changeScheduler
}

func NewProcessor(projector factProjector, scheduler changeScheduler) (*Processor, error) {
	if projector == nil || scheduler == nil {
		return nil, ErrImpactProcessorUnavailable
	}
	return &Processor{projector: projector, scheduler: scheduler}, nil
}

func (p *Processor) Process(ctx context.Context, change FactChange) (ScheduleResult, error) {
	if p == nil || p.projector == nil || p.scheduler == nil {
		return ScheduleResult{}, ErrImpactProcessorUnavailable
	}
	change.EventID = strings.TrimSpace(change.EventID)
	current := change.Fact.Revision()
	if change.EventID == "" || current.ExactKey() == "" || change.ChangedAt.IsZero() {
		return ScheduleResult{}, fmt.Errorf("%w: event, exact fact, and changed time are required", ErrImpactProcessorUnavailable)
	}
	if err := p.projector.ProjectFact(ctx, change.Fact); err != nil {
		return ScheduleResult{}, fmt.Errorf("project changed compliance fact: %w", err)
	}

	signalRevision := current
	var replacement *complianceintegration.RevisionRef
	if change.Kind == complianceintegration.ChangeUpdated {
		if change.Predecessor == nil || change.Predecessor.ExactKey() == "" {
			return ScheduleResult{}, fmt.Errorf("%w: updated fact requires an exact predecessor", ErrImpactProcessorUnavailable)
		}
		if !change.Predecessor.SameSubject(current) || change.Predecessor.Version() >= current.Version() {
			return ScheduleResult{}, fmt.Errorf("%w: predecessor must be an older revision of the changed fact", ErrImpactProcessorUnavailable)
		}
		signalRevision = *change.Predecessor
		value := current
		replacement = &value
	} else if change.Predecessor != nil {
		return ScheduleResult{}, fmt.Errorf("%w: predecessor is only valid for an update", ErrImpactProcessorUnavailable)
	}
	signal, err := complianceintegration.NewChangeSignal(change.Kind, signalRevision, replacement, change.ChangedAt)
	if err != nil {
		return ScheduleResult{}, err
	}
	result, err := p.scheduler.Schedule(ctx, change.EventID, signal)
	if err != nil {
		return ScheduleResult{}, fmt.Errorf("schedule changed compliance fact: %w", err)
	}
	return result, nil
}
