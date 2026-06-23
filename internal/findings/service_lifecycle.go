package findings

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/workflowevents"
)

// FindingStatusUpdateOptions carries optimistic lifecycle preconditions and
// attribution for an external coordinator.
type FindingStatusUpdateOptions struct {
	ExpectedStatus     string
	LastObservedBefore time.Time
	Source             string
}

// ResolveFinding marks one persisted finding as resolved.
func (s *Service) ResolveFinding(ctx context.Context, id string, reason string) (*ports.FindingRecord, error) {
	return s.updateFindingStatus(ctx, id, findingStatusResolved, reason)
}

// SuppressFinding marks one persisted finding as suppressed.
func (s *Service) SuppressFinding(ctx context.Context, id string, reason string) (*ports.FindingRecord, error) {
	return s.updateFindingStatus(ctx, id, findingStatusSuppressed, reason)
}

// ResolveFindingWithOptions marks one persisted finding as resolved when any
// supplied lifecycle preconditions still match the live row.
func (s *Service) ResolveFindingWithOptions(ctx context.Context, id string, reason string, options FindingStatusUpdateOptions) (*ports.FindingRecord, error) {
	return s.updateFindingStatusWithOptions(ctx, id, findingStatusResolved, reason, options)
}

// SuppressFindingWithOptions marks one persisted finding as suppressed when any
// supplied lifecycle preconditions still match the live row.
func (s *Service) SuppressFindingWithOptions(ctx context.Context, id string, reason string, options FindingStatusUpdateOptions) (*ports.FindingRecord, error) {
	return s.updateFindingStatusWithOptions(ctx, id, findingStatusSuppressed, reason, options)
}

// AssignFinding updates or clears one persisted finding assignee.
func (s *Service) AssignFinding(ctx context.Context, id string, assignee string) (*ports.FindingRecord, error) {
	if s == nil || s.store == nil {
		return nil, ErrRuntimeUnavailable
	}
	findingID := strings.TrimSpace(id)
	if findingID == "" {
		return nil, fmt.Errorf("%w: finding id is required", ErrInvalidRequest)
	}
	finding, err := s.store.UpdateFindingAssignee(ctx, ports.FindingAssigneeUpdate{
		FindingID: findingID,
		Assignee:  strings.TrimSpace(assignee),
	})
	if err != nil {
		return nil, fmt.Errorf("assign finding %q: %w", findingID, err)
	}
	return finding, nil
}

// SetFindingDueDate updates one persisted finding due date.
func (s *Service) SetFindingDueDate(ctx context.Context, id string, dueAt time.Time) (*ports.FindingRecord, error) {
	if s == nil || s.store == nil {
		return nil, ErrRuntimeUnavailable
	}
	findingID := strings.TrimSpace(id)
	if findingID == "" {
		return nil, fmt.Errorf("%w: finding id is required", ErrInvalidRequest)
	}
	normalizedDueAt := dueAt.UTC()
	if normalizedDueAt.IsZero() {
		return nil, fmt.Errorf("%w: finding due date is required", ErrInvalidRequest)
	}
	finding, err := s.store.UpdateFindingDueDate(ctx, ports.FindingDueDateUpdate{
		FindingID: findingID,
		DueAt:     normalizedDueAt,
	})
	if err != nil {
		return nil, fmt.Errorf("set finding %q due date: %w", findingID, err)
	}
	finding, err = s.persistFindingRisk(ctx, finding, time.Now().UTC())
	if err != nil {
		return nil, fmt.Errorf("refresh finding %q risk after due date update: %w", findingID, err)
	}
	if err := s.projectFindingAnchorRevision(ctx, finding, "due-risk-refresh|"+time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return nil, fmt.Errorf("project finding %q due date risk update: %w", findingID, err)
	}
	if err := s.markFindingRiskProjected(ctx, finding); err != nil {
		return nil, fmt.Errorf("mark finding %q due date risk projected: %w", findingID, err)
	}
	return finding, nil
}

// AddFindingNote appends one analyst note to one persisted finding.
func (s *Service) AddFindingNote(ctx context.Context, id string, note string) (*ports.FindingRecord, error) {
	if s == nil || s.store == nil {
		return nil, ErrRuntimeUnavailable
	}
	findingID := strings.TrimSpace(id)
	if findingID == "" {
		return nil, fmt.Errorf("%w: finding id is required", ErrInvalidRequest)
	}
	body := strings.TrimSpace(note)
	if body == "" {
		return nil, fmt.Errorf("%w: finding note is required", ErrInvalidRequest)
	}
	createdAt := time.Now().UTC()
	noteRecord := ports.FindingNote{
		ID:        findingNoteID(findingID, createdAt),
		Body:      body,
		CreatedAt: createdAt,
	}
	finding, err := s.store.AddFindingNote(ctx, ports.FindingNoteCreate{
		FindingID: findingID,
		Note:      noteRecord,
	})
	if err != nil {
		return nil, fmt.Errorf("add finding %q note: %w", findingID, err)
	}
	if err := s.projectFindingNote(ctx, finding, noteRecord); err != nil {
		return nil, fmt.Errorf("project finding %q note into graph: %w", findingID, err)
	}
	return finding, nil
}

// LinkFindingTicket appends one external ticket reference to one persisted finding.
func (s *Service) LinkFindingTicket(ctx context.Context, id string, ticketURL string, name string, externalID string) (*ports.FindingRecord, error) {
	if s == nil || s.store == nil {
		return nil, ErrRuntimeUnavailable
	}
	findingID := strings.TrimSpace(id)
	if findingID == "" {
		return nil, fmt.Errorf("%w: finding id is required", ErrInvalidRequest)
	}
	normalizedURL := strings.TrimSpace(ticketURL)
	if normalizedURL == "" {
		return nil, fmt.Errorf("%w: finding ticket url is required", ErrInvalidRequest)
	}
	if _, err := url.ParseRequestURI(normalizedURL); err != nil {
		return nil, fmt.Errorf("%w: finding ticket url is invalid: %w", ErrInvalidRequest, err)
	}
	linkedAt := time.Now().UTC()
	ticket := ports.FindingTicket{
		URL:        normalizedURL,
		Name:       strings.TrimSpace(name),
		ExternalID: strings.TrimSpace(externalID),
		LinkedAt:   linkedAt,
	}
	finding, err := s.store.LinkFindingTicket(ctx, ports.FindingTicketLink{
		FindingID: findingID,
		Ticket:    ticket,
	})
	if err != nil {
		return nil, fmt.Errorf("link ticket to finding %q: %w", findingID, err)
	}
	if err := s.projectFindingTicket(ctx, finding, ticket); err != nil {
		return nil, fmt.Errorf("project finding %q ticket into graph: %w", findingID, err)
	}
	return finding, nil
}

// LinkFindingExternalRef appends or refreshes one external lifecycle reference on
// one persisted finding.
func (s *Service) LinkFindingExternalRef(ctx context.Context, id string, ref ports.FindingExternalRef) (*ports.FindingRecord, error) {
	if s == nil || s.store == nil {
		return nil, ErrRuntimeUnavailable
	}
	findingID := strings.TrimSpace(id)
	if findingID == "" {
		return nil, fmt.Errorf("%w: finding id is required", ErrInvalidRequest)
	}
	ref.System = strings.TrimSpace(ref.System)
	ref.Kind = strings.TrimSpace(ref.Kind)
	ref.ExternalID = strings.TrimSpace(ref.ExternalID)
	if ref.System == "" {
		return nil, fmt.Errorf("%w: external ref system is required", ErrInvalidRequest)
	}
	if ref.Kind == "" {
		return nil, fmt.Errorf("%w: external ref kind is required", ErrInvalidRequest)
	}
	if ref.ExternalID == "" {
		return nil, fmt.Errorf("%w: external ref external id is required", ErrInvalidRequest)
	}
	if ref.URL = strings.TrimSpace(ref.URL); ref.URL != "" {
		if _, err := url.ParseRequestURI(ref.URL); err != nil {
			return nil, fmt.Errorf("%w: external ref url is invalid: %w", ErrInvalidRequest, err)
		}
	}
	ref.ExternalStatus = strings.TrimSpace(ref.ExternalStatus)
	ref.ExternalStatusReason = strings.TrimSpace(ref.ExternalStatusReason)
	ref.LifecycleOwner = strings.TrimSpace(ref.LifecycleOwner)
	ref.ObservedAt = ref.ObservedAt.UTC()
	if ref.ObservedAt.IsZero() {
		ref.ObservedAt = time.Now().UTC()
	}
	finding, err := s.store.LinkFindingExternalRef(ctx, ports.FindingExternalRefLink{
		FindingID:   findingID,
		ExternalRef: ref,
	})
	if err != nil {
		return nil, fmt.Errorf("link external ref to finding %q: %w", findingID, err)
	}
	if err := s.projectFindingExternalRef(ctx, finding, ref); err != nil {
		return nil, fmt.Errorf("project finding %q external ref: %w", findingID, err)
	}
	return finding, nil
}

func (s *Service) updateFindingStatus(ctx context.Context, id string, status string, reason string) (*ports.FindingRecord, error) {
	return s.updateFindingStatusWithOptions(ctx, id, status, reason, FindingStatusUpdateOptions{})
}

func (s *Service) updateFindingStatusWithOptions(ctx context.Context, id string, status string, reason string, options FindingStatusUpdateOptions) (*ports.FindingRecord, error) {
	if s == nil || s.store == nil {
		return nil, ErrRuntimeUnavailable
	}
	findingID := strings.TrimSpace(id)
	if findingID == "" {
		return nil, fmt.Errorf("%w: finding id is required", ErrInvalidRequest)
	}
	finding, err := s.updateFindingStatusAndRisk(ctx, ports.FindingStatusUpdate{
		FindingID:          findingID,
		Status:             strings.TrimSpace(status),
		Reason:             strings.TrimSpace(reason),
		UpdatedAt:          time.Now().UTC(),
		ExpectedStatus:     strings.TrimSpace(options.ExpectedStatus),
		LastObservedBefore: options.LastObservedBefore.UTC(),
	})
	if err != nil {
		return nil, fmt.Errorf("update finding %q status to %q: %w", findingID, status, err)
	}
	statusSource := strings.TrimSpace(options.Source)
	if statusSource == "" {
		statusSource = workflowevents.FindingStatusSourceManual
	}
	if err := s.recordFindingStatusWorkflow(ctx, finding, statusSource); err != nil {
		return nil, fmt.Errorf("record finding %q status workflow: %w", findingID, err)
	}
	return finding, nil
}

func (s *Service) updateFindingStatusAndRisk(ctx context.Context, request ports.FindingStatusUpdate) (*ports.FindingRecord, error) {
	finding, err := s.store.UpdateFindingStatus(ctx, request)
	if err != nil {
		return nil, err
	}
	return s.persistFindingRisk(ctx, finding, request.UpdatedAt)
}

func findingNoteID(findingID string, createdAt time.Time) string {
	replacer := strings.NewReplacer(" ", "-", "_", "-", "/", "-", ":", "-", ".", "-")
	return "finding-note-" + replacer.Replace(strings.TrimSpace(findingID)) + "-" + fmt.Sprintf("%d", createdAt.UnixNano())
}
