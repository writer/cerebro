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
	"github.com/writer/cerebro/internal/sourceconfig"
	"github.com/writer/cerebro/internal/telemetry"
)

var (
	ErrSourceNotFound = errors.New("source not found")
	ErrInvalidRequest = errors.New("invalid source request")
)

// Service exposes typed source preview operations over a registry.
type Service struct {
	registry            *sourcecdk.Registry
	allowInternalConfig bool
}

// New constructs a source operations service.
func New(registry *sourcecdk.Registry) *Service {
	return &Service{registry: registry}
}

func (s *Service) WithInternalConfigAllowed() *Service {
	if s == nil {
		return nil
	}
	s.allowInternalConfig = true
	return s
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
func (s *Service) Check(ctx context.Context, req *cerebrov1.CheckSourceRequest) (_ *cerebrov1.CheckSourceResponse, err error) {
	ctx, span := telemetry.Start(ctx, "source.check", sourceOperationTelemetryAttrs(req.GetSourceId()))
	status := "completed"
	attrs := sourceOperationTelemetryAttrs(req.GetSourceId())
	defer func() {
		if err != nil {
			status = "failed"
			attrs = attrs.WithField(telemetry.Field{Key: "error_kind", Value: sourceOperationTelemetryErrorKind(err)})
		}
		annotateMainSourceOperation(ctx, "check", status, attrs)
		telemetry.End(span, status, attrs)
	}()
	source, err := s.lookup(req.GetSourceId())
	if err != nil {
		return nil, err
	}
	config, err := s.previewConfig(req.GetConfig())
	if err != nil {
		return nil, err
	}
	if err := source.Check(ctx, sourcecdk.NewConfig(config)); err != nil {
		return nil, sourceOperationError(err)
	}
	return &cerebrov1.CheckSourceResponse{
		Source: source.Spec(),
		Status: "ok",
	}, nil
}

// Discover returns the current URNs for a named source.
func (s *Service) Discover(ctx context.Context, req *cerebrov1.DiscoverSourceRequest) (_ *cerebrov1.DiscoverSourceResponse, err error) {
	ctx, span := telemetry.Start(ctx, "source.discover", sourceOperationTelemetryAttrs(req.GetSourceId()))
	status := "completed"
	attrs := sourceOperationTelemetryAttrs(req.GetSourceId())
	defer func() {
		if err != nil {
			status = "failed"
			attrs = attrs.WithField(telemetry.Field{Key: "error_kind", Value: sourceOperationTelemetryErrorKind(err)})
		}
		annotateMainSourceOperation(ctx, "discover", status, attrs)
		telemetry.End(span, status, attrs)
	}()
	source, err := s.lookup(req.GetSourceId())
	if err != nil {
		return nil, err
	}
	config, err := s.previewConfig(req.GetConfig())
	if err != nil {
		return nil, err
	}
	urns, err := source.Discover(ctx, sourcecdk.NewConfig(config))
	if err != nil {
		return nil, sourceOperationError(err)
	}
	values := make([]string, 0, len(urns))
	for _, urn := range urns {
		values = append(values, urn.String())
	}
	attrs = attrs.WithField(telemetry.Field{Key: "urn_count", Value: len(values)})
	return &cerebrov1.DiscoverSourceResponse{
		Source: source.Spec(),
		Urns:   values,
	}, nil
}

// Read returns one page of events for a named source.
func (s *Service) Read(ctx context.Context, req *cerebrov1.ReadSourceRequest) (_ *cerebrov1.ReadSourceResponse, err error) {
	ctx, span := telemetry.Start(ctx, "source.read", sourceOperationTelemetryAttrs(req.GetSourceId()))
	status := "completed"
	attrs := sourceOperationTelemetryAttrs(req.GetSourceId())
	defer func() {
		if err != nil {
			status = "failed"
			attrs = attrs.WithField(telemetry.Field{Key: "error_kind", Value: sourceOperationTelemetryErrorKind(err)})
		}
		annotateMainSourceOperation(ctx, "read", status, attrs)
		telemetry.End(span, status, attrs)
	}()
	source, err := s.lookup(req.GetSourceId())
	if err != nil {
		return nil, err
	}
	config, err := s.previewConfig(req.GetConfig())
	if err != nil {
		return nil, err
	}
	pull, err := source.Read(ctx, sourcecdk.NewConfig(config), req.GetCursor())
	if err != nil {
		return nil, sourceOperationError(err)
	}
	previews, err := previewEvents(pull.Events)
	if err != nil {
		return nil, err
	}
	attrs = attrs.
		WithField(telemetry.Field{Key: "event_count", Value: len(pull.Events)}).
		WithField(telemetry.Field{Key: "preview_event_count", Value: len(previews)}).
		WithField(telemetry.Field{Key: "has_next_cursor", Value: pull.NextCursor != nil})
	return &cerebrov1.ReadSourceResponse{
		Source:        source.Spec(),
		Events:        pull.Events,
		Checkpoint:    pull.Checkpoint,
		NextCursor:    pull.NextCursor,
		PreviewEvents: previews,
	}, nil
}

func sourceOperationError(err error) error {
	if errors.Is(err, sourcecdk.ErrInvalidConfig) {
		return fmt.Errorf("%w: %w", ErrInvalidRequest, err)
	}
	return err
}

func (s *Service) previewConfig(values map[string]string) (map[string]string, error) {
	config := make(map[string]string, len(values))
	for key, value := range values {
		if !s.allowInternalConfig && sourceconfig.InternalKey(key) {
			return nil, fmt.Errorf("%w: source config %q is reserved", ErrInvalidRequest, strings.TrimSpace(key))
		}
		config[key] = value
	}
	return config, nil
}

func (s *Service) lookup(sourceID string) (sourcecdk.Source, error) {
	id := strings.TrimSpace(sourceID)
	if id == "" {
		return nil, fmt.Errorf("%w: source id is required", ErrInvalidRequest)
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
		preview := &cerebrov1.SourcePreviewEvent{
			EventId: event.GetId(),
			Event:   event,
		}
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

func sourceOperationTelemetryAttrs(sourceID string) telemetry.Attributes {
	return telemetry.Attrs(telemetry.Field{Key: "source_id", Value: strings.TrimSpace(sourceID)})
}

func annotateMainSourceOperation(ctx context.Context, operation string, status string, attrs telemetry.Attributes) {
	telemetry.IncrementMain(ctx, "source.operation.count", 1)
	if status == "failed" {
		telemetry.IncrementMain(ctx, "source.operation.error.count", 1)
	}
	mainAttrs := attrs.With(telemetry.Attrs(
		telemetry.Field{Key: "source.operation", Value: operation},
		telemetry.Field{Key: "source.operation.status", Value: status},
	))
	telemetry.AnnotateMain(ctx, mainAttrs)
	telemetry.AnnotateMainPhase(ctx, "source."+strings.TrimSpace(operation), status, mainAttrs)
}

func sourceOperationTelemetryErrorKind(err error) string {
	switch {
	case errors.Is(err, ErrSourceNotFound):
		return "source_not_found"
	case errors.Is(err, ErrInvalidRequest):
		return "invalid_request"
	default:
		return "operation_failed"
	}
}
