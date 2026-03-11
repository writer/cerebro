package ticketing

import (
	"context"
	"testing"
	"time"
)

// MockProvider implements Provider interface for testing
type MockProvider struct {
	name    string
	tickets map[string]*Ticket
}

var _ Provider = (*MockProvider)(nil)

func NewMockProvider(name string) *MockProvider {
	return &MockProvider{
		name:    name,
		tickets: make(map[string]*Ticket),
	}
}

func (m *MockProvider) Name() string { return m.name }

func (m *MockProvider) Validate(ctx context.Context) error { return nil }

func (m *MockProvider) CreateTicket(ctx context.Context, ticket *Ticket) (*Ticket, error) {
	ticket.ID = "MOCK-" + ticket.Title[:min(5, len(ticket.Title))]
	ticket.ExternalID = ticket.ID
	ticket.Status = "open"
	ticket.CreatedAt = time.Now()
	ticket.UpdatedAt = time.Now()
	m.tickets[ticket.ID] = ticket
	return ticket, nil
}

func (m *MockProvider) UpdateTicket(ctx context.Context, id string, update *TicketUpdate) (*Ticket, error) {
	ticket := m.tickets[id]
	if update.Status != nil {
		ticket.Status = *update.Status
	}
	ticket.UpdatedAt = time.Now()
	return ticket, nil
}

func (m *MockProvider) GetTicket(ctx context.Context, id string) (*Ticket, error) {
	return m.tickets[id], nil
}

func (m *MockProvider) ListTickets(ctx context.Context, filter TicketFilter) ([]*Ticket, error) {
	tickets := make([]*Ticket, 0, len(m.tickets))
	for _, t := range m.tickets {
		tickets = append(tickets, t)
	}
	return tickets, nil
}

func (m *MockProvider) AddComment(ctx context.Context, ticketID string, comment *Comment) error {
	return nil
}

func (m *MockProvider) Close(ctx context.Context, id string, resolution string) error {
	if t, ok := m.tickets[id]; ok {
		t.Status = "closed"
		now := time.Now()
		t.ResolvedAt = &now
	}
	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func TestService_NewService(t *testing.T) {
	s := NewService()
	if s == nil {
		t.Fatal("NewService returned nil")
	}

	if s.providers == nil {
		t.Error("providers map should be initialized")
	}
}

func TestService_RegisterProvider(t *testing.T) {
	s := NewService()

	jira := NewMockProvider("jira")
	s.RegisterProvider(jira)

	provider, ok := s.GetProvider("jira")
	if !ok {
		t.Fatal("expected to find jira provider")
	}

	if provider.Name() != "jira" {
		t.Errorf("got name %s, want jira", provider.Name())
	}
}

func TestService_SetPrimary(t *testing.T) {
	s := NewService()

	s.RegisterProvider(NewMockProvider("jira"))
	s.RegisterProvider(NewMockProvider("linear"))

	// First registered should be primary by default
	if s.Primary().Name() != "jira" {
		t.Error("first provider should be primary")
	}

	s.SetPrimary("linear")
	if s.Primary().Name() != "linear" {
		t.Error("primary should be linear")
	}
}

func TestService_Primary_NoProviders(t *testing.T) {
	var nilService *Service
	if nilService.Primary() != nil {
		t.Fatal("expected nil service to have nil primary provider")
	}

	s := NewService()
	if s.Primary() != nil {
		t.Fatal("expected empty service to have nil primary provider")
	}
}

func TestService_Primary_UnknownProvider(t *testing.T) {
	s := NewService()
	s.RegisterProvider(NewMockProvider("jira"))
	s.SetPrimary("linear")

	if s.Primary() != nil {
		t.Fatal("expected nil primary when configured primary provider is missing")
	}
}

func TestService_CreateTicket(t *testing.T) {
	s := NewService()
	s.RegisterProvider(NewMockProvider("jira"))

	ticket := &Ticket{
		Title:       "Test Ticket",
		Description: "Test description",
		Priority:    "high",
		Type:        "incident",
	}

	created, err := s.CreateTicket(context.Background(), ticket)
	if err != nil {
		t.Fatalf("CreateTicket failed: %v", err)
	}

	if created.ID == "" {
		t.Error("ticket ID should be generated")
	}

	if created.Status != "open" {
		t.Errorf("got status %s, want open", created.Status)
	}
}

func TestService_CreateTicket_NoPrimaryConfigured(t *testing.T) {
	s := NewService()

	_, err := s.CreateTicket(context.Background(), &Ticket{Title: "Test Ticket"})
	if err == nil {
		t.Fatal("expected CreateTicket to fail when no provider is configured")
	}

	s.RegisterProvider(NewMockProvider("jira"))
	s.SetPrimary("linear")
	_, err = s.CreateTicket(context.Background(), &Ticket{Title: "Test Ticket"})
	if err == nil {
		t.Fatal("expected CreateTicket to fail when primary provider is missing")
	}
}

func TestService_CreateTicketFromFinding(t *testing.T) {
	s := NewService()
	s.RegisterProvider(NewMockProvider("jira"))

	ticket, err := s.CreateTicketFromFinding(
		context.Background(),
		"finding-123",
		"Security Finding",
		"A critical security finding",
		"critical",
	)

	if err != nil {
		t.Fatalf("CreateTicketFromFinding failed: %v", err)
	}

	if ticket.Type != "finding" {
		t.Errorf("got type %s, want finding", ticket.Type)
	}

	if len(ticket.FindingIDs) != 1 || ticket.FindingIDs[0] != "finding-123" {
		t.Error("finding ID should be set")
	}

	if ticket.Priority != "critical" {
		t.Errorf("got priority %s, want critical", ticket.Priority)
	}
}

func TestTicket_Fields(t *testing.T) {
	now := time.Now()
	ticket := &Ticket{
		ID:          "TICKET-1",
		ExternalID:  "JIRA-123",
		Title:       "Test",
		Description: "Test description",
		Priority:    "high",
		Status:      "open",
		Type:        "incident",
		Assignee:    "user@example.com",
		Reporter:    "reporter@example.com",
		Labels:      []string{"security", "critical"},
		FindingIDs:  []string{"f1", "f2"},
		AssetIDs:    []string{"a1"},
		ExternalURL: "https://jira.example.com/JIRA-123",
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if ticket.ID != "TICKET-1" {
		t.Error("ID field incorrect")
	}

	if ticket.ExternalID != "JIRA-123" {
		t.Error("external ID field incorrect")
	}

	if ticket.Title != "Test" {
		t.Error("title field incorrect")
	}

	if ticket.Description != "Test description" {
		t.Error("description field incorrect")
	}

	if ticket.Priority != "high" {
		t.Error("priority field incorrect")
	}

	if ticket.Status != "open" {
		t.Error("status field incorrect")
	}

	if ticket.Type != "incident" {
		t.Error("type field incorrect")
	}

	if ticket.Assignee != "user@example.com" {
		t.Error("assignee field incorrect")
	}

	if ticket.Reporter != "reporter@example.com" {
		t.Error("reporter field incorrect")
	}

	if len(ticket.Labels) != 2 {
		t.Error("labels field incorrect")
	}

	if len(ticket.FindingIDs) != 2 {
		t.Error("finding IDs field incorrect")
	}

	if len(ticket.AssetIDs) != 1 {
		t.Error("asset IDs field incorrect")
	}

	if ticket.ExternalURL != "https://jira.example.com/JIRA-123" {
		t.Error("external URL field incorrect")
	}

	if ticket.CreatedAt.IsZero() {
		t.Error("created at field incorrect")
	}

	if ticket.UpdatedAt.IsZero() {
		t.Error("updated at field incorrect")
	}
}

func TestTicketUpdate_Fields(t *testing.T) {
	status := "in_progress"
	priority := "critical"

	update := &TicketUpdate{
		Status:   &status,
		Priority: &priority,
		Labels:   []string{"urgent"},
	}

	if *update.Status != "in_progress" {
		t.Error("status field incorrect")
	}

	if *update.Priority != "critical" {
		t.Error("priority field incorrect")
	}

	if len(update.Labels) != 1 {
		t.Error("labels field incorrect")
	}
}

func TestTicketFilter_Fields(t *testing.T) {
	filter := TicketFilter{
		Status:    "open",
		Priority:  "high",
		Assignee:  "user@example.com",
		Label:     "security",
		FindingID: "f1",
		Limit:     10,
		Offset:    0,
	}

	if filter.Status != "open" {
		t.Error("status field incorrect")
	}

	if filter.Priority != "high" {
		t.Error("priority field incorrect")
	}

	if filter.Assignee != "user@example.com" {
		t.Error("assignee field incorrect")
	}

	if filter.Label != "security" {
		t.Error("label field incorrect")
	}

	if filter.FindingID != "f1" {
		t.Error("finding ID field incorrect")
	}

	if filter.Limit != 10 {
		t.Error("limit field incorrect")
	}

	if filter.Offset != 0 {
		t.Error("offset field incorrect")
	}
}

func TestComment_Fields(t *testing.T) {
	now := time.Now()
	comment := &Comment{
		ID:        "comment-1",
		Author:    "user@example.com",
		Body:      "This is a comment",
		CreatedAt: now,
	}

	if comment.ID != "comment-1" {
		t.Error("ID field incorrect")
	}

	if comment.Author != "user@example.com" {
		t.Error("author field incorrect")
	}

	if comment.Body != "This is a comment" {
		t.Error("body field incorrect")
	}

	if comment.CreatedAt.IsZero() {
		t.Error("created at field incorrect")
	}
}

func TestMockProvider_Operations(t *testing.T) {
	provider := NewMockProvider("test")

	// Create
	ticket, _ := provider.CreateTicket(context.Background(), &Ticket{
		Title:    "Test",
		Priority: "high",
	})

	// Get
	found, _ := provider.GetTicket(context.Background(), ticket.ID)
	if found.Title != "Test" {
		t.Error("GetTicket failed")
	}

	// Update
	status := "in_progress"
	if _, err := provider.UpdateTicket(context.Background(), ticket.ID, &TicketUpdate{
		Status: &status,
	}); err != nil {
		t.Fatalf("UpdateTicket failed: %v", err)
	}

	found, _ = provider.GetTicket(context.Background(), ticket.ID)
	if found.Status != "in_progress" {
		t.Error("UpdateTicket failed")
	}

	// List
	tickets, _ := provider.ListTickets(context.Background(), TicketFilter{})
	if len(tickets) != 1 {
		t.Error("ListTickets failed")
	}

	// Close
	if err := provider.Close(context.Background(), ticket.ID, "resolved"); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
	found, _ = provider.GetTicket(context.Background(), ticket.ID)
	if found.Status != "closed" {
		t.Error("Close failed")
	}
}
