package ticketing

import (
	"context"
	"time"
)

// Provider interface for ticketing systems
type Provider interface {
	Name() string
	CreateTicket(ctx context.Context, ticket *Ticket) (*Ticket, error)
	UpdateTicket(ctx context.Context, id string, update *TicketUpdate) (*Ticket, error)
	GetTicket(ctx context.Context, id string) (*Ticket, error)
	ListTickets(ctx context.Context, filter TicketFilter) ([]*Ticket, error)
	AddComment(ctx context.Context, ticketID string, comment *Comment) error
	Close(ctx context.Context, id string, resolution string) error
}

type Ticket struct {
	ID          string                 `json:"id"`
	ExternalID  string                 `json:"external_id"` // ID in external system
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Priority    string                 `json:"priority"` // critical, high, medium, low
	Status      string                 `json:"status"`   // open, in_progress, resolved, closed
	Type        string                 `json:"type"`     // incident, task, finding
	Assignee    string                 `json:"assignee,omitempty"`
	Reporter    string                 `json:"reporter"`
	Labels      []string               `json:"labels,omitempty"`
	FindingIDs  []string               `json:"finding_ids,omitempty"`
	AssetIDs    []string               `json:"asset_ids,omitempty"`
	ExternalURL string                 `json:"external_url,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	ResolvedAt  *time.Time             `json:"resolved_at,omitempty"`
}

type TicketUpdate struct {
	Title       *string  `json:"title,omitempty"`
	Description *string  `json:"description,omitempty"`
	Priority    *string  `json:"priority,omitempty"`
	Status      *string  `json:"status,omitempty"`
	Assignee    *string  `json:"assignee,omitempty"`
	Labels      []string `json:"labels,omitempty"`
}

type TicketFilter struct {
	Status    string
	Priority  string
	Assignee  string
	Label     string
	FindingID string
	Limit     int
	Offset    int
}

type Comment struct {
	ID        string    `json:"id"`
	Author    string    `json:"author"`
	Body      string    `json:"body"`
	CreatedAt time.Time `json:"created_at"`
}

// Service manages ticketing integrations
type Service struct {
	providers map[string]Provider
	primary   string
}

func NewService() *Service {
	return &Service{
		providers: make(map[string]Provider),
	}
}

func (s *Service) RegisterProvider(provider Provider) {
	s.providers[provider.Name()] = provider
	if s.primary == "" {
		s.primary = provider.Name()
	}
}

func (s *Service) SetPrimary(name string) {
	s.primary = name
}

func (s *Service) GetProvider(name string) (Provider, bool) {
	p, ok := s.providers[name]
	return p, ok
}

func (s *Service) Primary() Provider {
	return s.providers[s.primary]
}

func (s *Service) CreateTicket(ctx context.Context, ticket *Ticket) (*Ticket, error) {
	return s.Primary().CreateTicket(ctx, ticket)
}

func (s *Service) CreateTicketFromFinding(ctx context.Context, findingID, title, description, priority string) (*Ticket, error) {
	ticket := &Ticket{
		Title:       title,
		Description: description,
		Priority:    priority,
		Type:        "finding",
		FindingIDs:  []string{findingID},
		CreatedAt:   time.Now(),
	}
	return s.CreateTicket(ctx, ticket)
}
