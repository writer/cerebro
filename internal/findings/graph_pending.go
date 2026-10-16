package findings

import (
	"context"
	"fmt"
	"strings"

	"github.com/writer/cerebro/internal/ports"
)

// pendingFindingGraphProjections defers graph writes for the findings emitted
// during one replay. A replay can emit the same finding once per matching
// event, and projecting each emission rewrites the finding's whole graph
// context; projecting once from the final stored record leaves the same graph
// state at a fraction of the writes.
type pendingFindingGraphProjections[S any] struct {
	order []string
	byKey map[string]*pendingFindingGraphProjection[S]
}

type pendingFindingGraphProjection[S any] struct {
	finding *ports.FindingRecord
	isNew   bool
	state   S
}

func newPendingFindingGraphProjections[S any]() *pendingFindingGraphProjections[S] {
	return &pendingFindingGraphProjections[S]{byKey: map[string]*pendingFindingGraphProjection[S]{}}
}

func (p *pendingFindingGraphProjections[S]) add(ruleID string, finding *ports.FindingRecord, isNew bool, state S) {
	if p == nil || finding == nil {
		return
	}
	key := strings.TrimSpace(ruleID) + "\x00" + strings.TrimSpace(finding.ID)
	if existing, ok := p.byKey[key]; ok {
		existing.finding = finding
		existing.isNew = existing.isNew || isNew
		return
	}
	p.order = append(p.order, key)
	p.byKey[key] = &pendingFindingGraphProjection[S]{finding: finding, isNew: isNew, state: state}
}

func (p *pendingFindingGraphProjections[S]) entries() []*pendingFindingGraphProjection[S] {
	if p == nil {
		return nil
	}
	entries := make([]*pendingFindingGraphProjection[S], 0, len(p.order))
	for _, key := range p.order {
		entries = append(entries, p.byKey[key])
	}
	return entries
}

func (s *Service) projectFindingGraph(ctx context.Context, finding *ports.FindingRecord, isNew bool) error {
	if err := s.projectFindingAnchor(ctx, finding); err != nil {
		return fmt.Errorf("project finding %q graph anchor: %w", finding.ID, err)
	}
	if err := s.projectFindingExternalRefs(ctx, finding); err != nil {
		return fmt.Errorf("project finding %q external refs: %w", finding.ID, err)
	}
	if isNew {
		if err := s.projectFindingNewActionRecommendations(ctx, finding); err != nil {
			return fmt.Errorf("project finding %q action recommendations: %w", finding.ID, err)
		}
	}
	return nil
}
