package sourceops

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"google.golang.org/protobuf/types/known/structpb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
)

var ErrSourceNotFound = errors.New("source not found")

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
		return nil, err
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
		return nil, err
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
		return nil, err
	}
	previews, err := previewEvents(pull.Events)
	if err != nil {
		return nil, err
	}
	return &cerebrov1.ReadSourceResponse{
		Source:        source.Spec(),
		Events:        pull.Events,
		Checkpoint:    pull.Checkpoint,
		NextCursor:    pull.NextCursor,
		PreviewEvents: previews,
	}, nil
}

func (s *Service) lookup(sourceID string) (sourcecdk.Source, error) {
	id := strings.TrimSpace(sourceID)
	if id == "" {
		return nil, fmt.Errorf("source id is required")
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

func previewEvents(events []*cerebrov1.EventEnvelope) ([]*cerebrov1.SourcePreviewEvent, error) {
	previews := make([]*cerebrov1.SourcePreviewEvent, 0, len(events))
	for _, event := range events {
		preview := &cerebrov1.SourcePreviewEvent{Event: event}
		if len(event.GetPayload()) == 0 {
			previews = append(previews, preview)
			continue
		}
		var payload any
		if err := json.Unmarshal(event.GetPayload(), &payload); err != nil {
			previews = append(previews, preview)
			continue
		}
		value, err := structpb.NewValue(payload)
		if err != nil {
			return nil, fmt.Errorf("build preview payload for event %q: %w", event.GetId(), err)
		}
		preview.Payload = value
		preview.PayloadDecoded = true
		previews = append(previews, preview)
	}
	return previews, nil
}
