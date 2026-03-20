package api

import (
	"context"
	"errors"

	"github.com/writer/cerebro/internal/ticketing"
)

var errTicketingUnavailable = errors.New("no ticketing provider configured")

type ticketingService interface {
	PrimaryConfigured() bool
	ListTickets(ctx context.Context, filter ticketing.TicketFilter) ([]*ticketing.Ticket, error)
	CreateTicket(ctx context.Context, ticket *ticketing.Ticket) (*ticketing.Ticket, error)
	GetTicket(ctx context.Context, id string) (*ticketing.Ticket, error)
	UpdateTicket(ctx context.Context, id string, update *ticketing.TicketUpdate) (*ticketing.Ticket, error)
	AddComment(ctx context.Context, ticketID string, comment *ticketing.Comment) error
	CloseTicket(ctx context.Context, id, resolution string) error
}

type serverTicketingService struct {
	deps *serverDependencies
}

func newTicketingService(deps *serverDependencies) ticketingService {
	return serverTicketingService{deps: deps}
}

func (s serverTicketingService) PrimaryConfigured() bool {
	return s.primary() != nil
}

func (s serverTicketingService) ListTickets(ctx context.Context, filter ticketing.TicketFilter) ([]*ticketing.Ticket, error) {
	primary, err := s.requirePrimary()
	if err != nil {
		return nil, err
	}
	return primary.ListTickets(ctx, filter)
}

func (s serverTicketingService) CreateTicket(ctx context.Context, ticket *ticketing.Ticket) (*ticketing.Ticket, error) {
	if _, err := s.requirePrimary(); err != nil {
		return nil, err
	}
	return s.deps.Ticketing.CreateTicket(ctx, ticket)
}

func (s serverTicketingService) GetTicket(ctx context.Context, id string) (*ticketing.Ticket, error) {
	primary, err := s.requirePrimary()
	if err != nil {
		return nil, err
	}
	return primary.GetTicket(ctx, id)
}

func (s serverTicketingService) UpdateTicket(ctx context.Context, id string, update *ticketing.TicketUpdate) (*ticketing.Ticket, error) {
	primary, err := s.requirePrimary()
	if err != nil {
		return nil, err
	}
	return primary.UpdateTicket(ctx, id, update)
}

func (s serverTicketingService) AddComment(ctx context.Context, ticketID string, comment *ticketing.Comment) error {
	primary, err := s.requirePrimary()
	if err != nil {
		return err
	}
	return primary.AddComment(ctx, ticketID, comment)
}

func (s serverTicketingService) CloseTicket(ctx context.Context, id, resolution string) error {
	primary, err := s.requirePrimary()
	if err != nil {
		return err
	}
	return primary.Close(ctx, id, resolution)
}

func (s serverTicketingService) primary() ticketing.Provider {
	if s.deps == nil || s.deps.Ticketing == nil {
		return nil
	}
	return s.deps.Ticketing.Primary()
}

func (s serverTicketingService) requirePrimary() (ticketing.Provider, error) {
	primary := s.primary()
	if primary == nil {
		return nil, errTicketingUnavailable
	}
	return primary, nil
}

var _ ticketingService = serverTicketingService{}
