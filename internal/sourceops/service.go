package sourceops

import (
	"context"
	"errors"
	"fmt"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
)

var (
	ErrInvalidSourceID     = errors.New("source id is required")
	ErrInvalidSourceConfig = errors.New("invalid source config")
	ErrSourceNotFound      = errors.New("source not found")
)

// Service exposes typed source preview operations over a registry.
type Service struct {
	registry *sourcecdk.Registry
}

// New constructs a source operations service.
func New(registry *sourcecdk.Registry) *Service {
	return &Service{registry: registry}
}

// List returns the registered source catalog.
func (s *Service) List() *cerebrov1.ListSourcesResponse {
	response := &cerebrov1.ListSourcesResponse{}
	if s == nil || s.registry == nil {
		return response
	}
	response.Sources = s.registry.List()
	return response
}

// Check validates configuration for a named source.
func (s *Service) Check(ctx context.Context, req *cerebrov1.CheckSourceRequest) (*cerebrov1.CheckSourceResponse, error) {
	source, err := s.lookup(req.GetSourceId())
	if err != nil {
		return nil, err
	}
	if err := source.Check(ctx, sourcecdk.NewConfig(req.GetConfig())); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidSourceConfig, err)
	}
	return &cerebrov1.CheckSourceResponse{
		Source: source.Spec(),
		Status: "ok",
	}, nil
}

// Discover returns the current URNs for a named source.
func (s *Service) Discover(ctx context.Context, req *cerebrov1.DiscoverSourceRequest) (*cerebrov1.DiscoverSourceResponse, error) {
	source, err := s.lookup(req.GetSourceId())
	if err != nil {
		return nil, err
	}
	urns, err := source.Discover(ctx, sourcecdk.NewConfig(req.GetConfig()))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidSourceConfig, err)
	}
	values := make([]string, 0, len(urns))
	for _, urn := range urns {
		values = append(values, urn.String())
	}
	return &cerebrov1.DiscoverSourceResponse{
		Source: source.Spec(),
		Urns:   values,
	}, nil
}

// Read returns one page of events for a named source.
func (s *Service) Read(ctx context.Context, req *cerebrov1.ReadSourceRequest) (*cerebrov1.ReadSourceResponse, error) {
	source, err := s.lookup(req.GetSourceId())
	if err != nil {
		return nil, err
	}
	pull, err := source.Read(ctx, sourcecdk.NewConfig(req.GetConfig()), req.GetCursor())
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidSourceConfig, err)
	}
	return &cerebrov1.ReadSourceResponse{
		Source:     source.Spec(),
		Events:     pull.Events,
		Checkpoint: pull.Checkpoint,
		NextCursor: pull.NextCursor,
	}, nil
}

func (s *Service) lookup(sourceID string) (sourcecdk.Source, error) {
	id := strings.TrimSpace(sourceID)
	if id == "" {
		return nil, ErrInvalidSourceID
	}
	if s == nil || s.registry == nil {
		return nil, fmt.Errorf("%w: %s", ErrSourceNotFound, id)
	}
	source, ok := s.registry.Get(id)
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrSourceNotFound, id)
	}
	return source, nil
}
