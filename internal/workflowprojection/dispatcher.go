package workflowprojection

import (
	"context"
	"fmt"
	"strings"

	"google.golang.org/protobuf/proto"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/securityevents"
	"github.com/writer/cerebro/internal/workflowevents"
)

// Project applies one workflow event to the configured graph store.
func (s *Service) Project(ctx context.Context, event *cerebrov1.EventEnvelope) (ports.ProjectionResult, error) {
	if event == nil {
		return ports.ProjectionResult{}, fmt.Errorf("workflow event is required")
	}
	if s == nil || s.graph == nil {
		return ports.ProjectionResult{}, fmt.Errorf("workflow graph projection store is required")
	}
	kind := workflowProjectionKind(event.GetKind())
	event = eventWithProjectionKind(event, kind)
	switch kind {
	case workflowevents.EventKindKnowledgeDecisionRecorded:
		return s.projectDecision(ctx, event)
	case workflowevents.EventKindKnowledgeActionRecorded:
		return s.projectAction(ctx, event)
	case workflowevents.EventKindKnowledgeOutcomeRecorded:
		return s.projectOutcome(ctx, event)
	case workflowevents.EventKindFindingRecorded:
		return s.projectFindingRecorded(ctx, event)
	case workflowevents.EventKindFindingNoteAdded:
		return s.projectFindingNote(ctx, event)
	case workflowevents.EventKindFindingTicketLinked:
		return s.projectFindingTicket(ctx, event)
	case workflowevents.EventKindFindingStatusChanged:
		return s.projectFindingStatus(ctx, event)
	case workflowevents.EventKindFindingTombstoned:
		return s.projectFindingTombstoned(ctx, event)
	default:
		return ports.ProjectionResult{}, nil
	}
}

func workflowProjectionKind(kind string) string {
	switch strings.TrimSpace(kind) {
	case securityevents.FindingRecorded:
		return workflowevents.EventKindFindingRecorded
	case securityevents.FindingNoteAdded:
		return workflowevents.EventKindFindingNoteAdded
	case securityevents.FindingTicketLinked:
		return workflowevents.EventKindFindingTicketLinked
	case securityevents.FindingStatusChanged:
		return workflowevents.EventKindFindingStatusChanged
	default:
		return strings.TrimSpace(kind)
	}
}

func eventWithProjectionKind(event *cerebrov1.EventEnvelope, kind string) *cerebrov1.EventEnvelope {
	if event == nil || strings.TrimSpace(event.GetKind()) == kind {
		return event
	}
	clone, ok := proto.Clone(event).(*cerebrov1.EventEnvelope)
	if !ok {
		return event
	}
	clone.Kind = kind
	return clone
}
