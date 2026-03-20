package api

import (
	"context"
	"log/slog"
	"net/http"
	"testing"

	"github.com/writer/cerebro/internal/app"
	"github.com/writer/cerebro/internal/ticketing"
)

type stubTicketingService struct {
	primaryConfigured bool
	listTicketsFunc   func(context.Context, ticketing.TicketFilter) ([]*ticketing.Ticket, error)
	createTicketFunc  func(context.Context, *ticketing.Ticket) (*ticketing.Ticket, error)
	getTicketFunc     func(context.Context, string) (*ticketing.Ticket, error)
	updateTicketFunc  func(context.Context, string, *ticketing.TicketUpdate) (*ticketing.Ticket, error)
	addCommentFunc    func(context.Context, string, *ticketing.Comment) error
	closeTicketFunc   func(context.Context, string, string) error
}

func (s stubTicketingService) PrimaryConfigured() bool {
	return s.primaryConfigured
}

func (s stubTicketingService) ListTickets(ctx context.Context, filter ticketing.TicketFilter) ([]*ticketing.Ticket, error) {
	if s.listTicketsFunc != nil {
		return s.listTicketsFunc(ctx, filter)
	}
	return nil, nil
}

func (s stubTicketingService) CreateTicket(ctx context.Context, ticket *ticketing.Ticket) (*ticketing.Ticket, error) {
	if s.createTicketFunc != nil {
		return s.createTicketFunc(ctx, ticket)
	}
	return nil, nil
}

func (s stubTicketingService) GetTicket(ctx context.Context, id string) (*ticketing.Ticket, error) {
	if s.getTicketFunc != nil {
		return s.getTicketFunc(ctx, id)
	}
	return nil, nil
}

func (s stubTicketingService) UpdateTicket(ctx context.Context, id string, update *ticketing.TicketUpdate) (*ticketing.Ticket, error) {
	if s.updateTicketFunc != nil {
		return s.updateTicketFunc(ctx, id, update)
	}
	return nil, nil
}

func (s stubTicketingService) AddComment(ctx context.Context, ticketID string, comment *ticketing.Comment) error {
	if s.addCommentFunc != nil {
		return s.addCommentFunc(ctx, ticketID, comment)
	}
	return nil
}

func (s stubTicketingService) CloseTicket(ctx context.Context, id, resolution string) error {
	if s.closeTicketFunc != nil {
		return s.closeTicketFunc(ctx, id, resolution)
	}
	return nil
}

func TestTicketingListHandlerUsesServiceInterface(t *testing.T) {
	var called bool
	s := NewServerWithDependencies(serverDependencies{
		Config: &app.Config{},
		Logger: slog.Default(),
		ticketingOps: stubTicketingService{
			primaryConfigured: true,
			listTicketsFunc: func(_ context.Context, filter ticketing.TicketFilter) ([]*ticketing.Ticket, error) {
				called = true
				if filter.Status != "open" || filter.Priority != "high" || filter.Limit != 50 {
					t.Fatalf("unexpected ticket filter: %#v", filter)
				}
				return []*ticketing.Ticket{{ID: "T-1", Title: "Investigate", Priority: "high"}}, nil
			},
		},
	})
	t.Cleanup(func() { s.Close() })

	resp := do(t, s, http.MethodGet, "/api/v1/tickets/?status=open&priority=high", nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	if !called {
		t.Fatal("expected list tickets handler to use ticketing service")
	}
	body := decodeJSON(t, resp)
	if body["count"] != float64(1) {
		t.Fatalf("expected one ticket from stub service, got %#v", body)
	}
}

func TestTicketingMutationHandlersUseServiceInterface(t *testing.T) {
	var (
		createCalled  bool
		getCalled     bool
		updateCalled  bool
		commentCalled bool
		closeCalled   bool
	)

	s := NewServerWithDependencies(serverDependencies{
		Config: &app.Config{},
		Logger: slog.Default(),
		ticketingOps: stubTicketingService{
			primaryConfigured: true,
			createTicketFunc: func(_ context.Context, ticket *ticketing.Ticket) (*ticketing.Ticket, error) {
				createCalled = true
				if ticket.Title != "Broken auth" || ticket.Priority != "high" || len(ticket.FindingIDs) != 1 || ticket.FindingIDs[0] != "finding-1" {
					t.Fatalf("unexpected create ticket payload: %#v", ticket)
				}
				return &ticketing.Ticket{ID: "T-100", Title: ticket.Title}, nil
			},
			getTicketFunc: func(_ context.Context, id string) (*ticketing.Ticket, error) {
				getCalled = true
				if id != "T-100" {
					t.Fatalf("unexpected ticket id: %q", id)
				}
				return &ticketing.Ticket{ID: id, Title: "Broken auth"}, nil
			},
			updateTicketFunc: func(_ context.Context, id string, update *ticketing.TicketUpdate) (*ticketing.Ticket, error) {
				updateCalled = true
				if id != "T-100" || update == nil || update.Status == nil || *update.Status != "in_progress" {
					t.Fatalf("unexpected update request: id=%q update=%#v", id, update)
				}
				return &ticketing.Ticket{ID: id, Status: *update.Status}, nil
			},
			addCommentFunc: func(_ context.Context, id string, comment *ticketing.Comment) error {
				commentCalled = true
				if id != "T-100" || comment == nil || comment.Body != "looking now" {
					t.Fatalf("unexpected comment request: id=%q comment=%#v", id, comment)
				}
				return nil
			},
			closeTicketFunc: func(_ context.Context, id, resolution string) error {
				closeCalled = true
				if id != "T-100" || resolution != "fixed" {
					t.Fatalf("unexpected close request: id=%q resolution=%q", id, resolution)
				}
				return nil
			},
		},
	})
	t.Cleanup(func() { s.Close() })

	createResp := do(t, s, http.MethodPost, "/api/v1/tickets/", map[string]any{
		"title":       "Broken auth",
		"description": "users cannot sign in",
		"priority":    "high",
		"finding_ids": []string{"finding-1"},
	})
	if createResp.Code != http.StatusCreated {
		t.Fatalf("expected 201 for create, got %d: %s", createResp.Code, createResp.Body.String())
	}
	getResp := do(t, s, http.MethodGet, "/api/v1/tickets/T-100", nil)
	if getResp.Code != http.StatusOK {
		t.Fatalf("expected 200 for get, got %d: %s", getResp.Code, getResp.Body.String())
	}
	updateResp := do(t, s, http.MethodPut, "/api/v1/tickets/T-100", map[string]any{"status": "in_progress"})
	if updateResp.Code != http.StatusOK {
		t.Fatalf("expected 200 for update, got %d: %s", updateResp.Code, updateResp.Body.String())
	}
	commentResp := do(t, s, http.MethodPost, "/api/v1/tickets/T-100/comments", map[string]any{"body": "looking now"})
	if commentResp.Code != http.StatusCreated {
		t.Fatalf("expected 201 for comment, got %d: %s", commentResp.Code, commentResp.Body.String())
	}
	closeResp := do(t, s, http.MethodPost, "/api/v1/tickets/T-100/close", map[string]any{"resolution": "fixed"})
	if closeResp.Code != http.StatusOK {
		t.Fatalf("expected 200 for close, got %d: %s", closeResp.Code, closeResp.Body.String())
	}

	if !createCalled || !getCalled || !updateCalled || !commentCalled || !closeCalled {
		t.Fatalf("expected all ticketing mutation handlers to use service: create=%v get=%v update=%v comment=%v close=%v", createCalled, getCalled, updateCalled, commentCalled, closeCalled)
	}
}

func TestTicketingHandlersRespectUnconfiguredServiceSemantics(t *testing.T) {
	s := NewServerWithDependencies(serverDependencies{
		Config:       &app.Config{},
		Logger:       slog.Default(),
		ticketingOps: stubTicketingService{primaryConfigured: false},
	})
	t.Cleanup(func() { s.Close() })

	listResp := do(t, s, http.MethodGet, "/api/v1/tickets/", nil)
	if listResp.Code != http.StatusOK {
		t.Fatalf("expected 200 for unconfigured ticket list, got %d: %s", listResp.Code, listResp.Body.String())
	}
	listBody := decodeJSON(t, listResp)
	if listBody["count"] != float64(0) {
		t.Fatalf("expected zero-count empty list response, got %#v", listBody)
	}

	createResp := do(t, s, http.MethodPost, "/api/v1/tickets/", map[string]any{"title": "x"})
	if createResp.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 for unconfigured ticket create, got %d: %s", createResp.Code, createResp.Body.String())
	}
}
