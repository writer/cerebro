package github

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/primitives"
	"github.com/writer/cerebro/internal/sourcecdk"
)

//go:embed testdata/*.json
var fixtureFS embed.FS

type fixtureEvent struct {
	ID         string            `json:"id"`
	TenantID   string            `json:"tenant_id"`
	SourceID   string            `json:"source_id"`
	Kind       string            `json:"kind"`
	OccurredAt string            `json:"occurred_at"`
	SchemaRef  string            `json:"schema_ref"`
	Payload    json.RawMessage   `json:"payload"`
	Attributes map[string]string `json:"attributes"`
}

type fixtureSource struct {
	spec   *cerebrov1.SourceSpec
	urns   []sourcecdk.URN
	events []*primitives.Event
}

// NewFixture constructs the deterministic GitHub source used by tests.
func NewFixture() (sourcecdk.Source, error) {
	spec, err := loadSpec()
	if err != nil {
		return nil, err
	}
	urnBytes, err := fixtureFS.ReadFile("testdata/discover.json")
	if err != nil {
		return nil, fmt.Errorf("read discover fixture: %w", err)
	}
	var rawURNs []string
	if err := json.Unmarshal(urnBytes, &rawURNs); err != nil {
		return nil, fmt.Errorf("unmarshal discover fixture: %w", err)
	}
	urns := make([]sourcecdk.URN, 0, len(rawURNs))
	for _, rawURN := range rawURNs {
		urn, err := sourcecdk.ParseURN(rawURN)
		if err != nil {
			return nil, fmt.Errorf("parse discover urn: %w", err)
		}
		urns = append(urns, urn)
	}
	readBytes, err := fixtureFS.ReadFile("testdata/read.json")
	if err != nil {
		return nil, fmt.Errorf("read event fixture: %w", err)
	}
	var rawEvents []fixtureEvent
	if err := json.Unmarshal(readBytes, &rawEvents); err != nil {
		return nil, fmt.Errorf("unmarshal event fixture: %w", err)
	}
	events := make([]*primitives.Event, 0, len(rawEvents))
	for _, raw := range rawEvents {
		occurredAt, err := time.Parse(time.RFC3339, raw.OccurredAt)
		if err != nil {
			return nil, fmt.Errorf("parse event occurred_at: %w", err)
		}
		events = append(events, &primitives.Event{
			Id:         raw.ID,
			TenantId:   raw.TenantID,
			SourceId:   raw.SourceID,
			Kind:       raw.Kind,
			OccurredAt: timestamppb.New(occurredAt),
			SchemaRef:  raw.SchemaRef,
			Payload:    append([]byte(nil), raw.Payload...),
			Attributes: raw.Attributes,
		})
	}
	return &fixtureSource{spec: spec, urns: urns, events: events}, nil
}

func (s *fixtureSource) Spec() *cerebrov1.SourceSpec {
	return s.spec
}

func (s *fixtureSource) Check(_ context.Context, cfg sourcecdk.Config) error {
	token, ok := cfg.Lookup("token")
	if !ok || strings.TrimSpace(token) == "" {
		return fmt.Errorf("github token is required")
	}
	return nil
}

func (s *fixtureSource) Discover(ctx context.Context, cfg sourcecdk.Config) ([]sourcecdk.URN, error) {
	if err := s.Check(ctx, cfg); err != nil {
		return nil, err
	}
	urns := make([]sourcecdk.URN, len(s.urns))
	copy(urns, s.urns)
	return urns, nil
}

func (s *fixtureSource) Read(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	if err := s.Check(ctx, cfg); err != nil {
		return sourcecdk.Pull{}, err
	}
	index := 0
	if cursor != nil && strings.TrimSpace(cursor.Opaque) != "" {
		parsed, err := strconv.Atoi(cursor.Opaque)
		if err != nil {
			return sourcecdk.Pull{}, fmt.Errorf("parse cursor: %w", err)
		}
		index = parsed
	}
	if index >= len(s.events) {
		return sourcecdk.Pull{}, nil
	}
	event := proto.Clone(s.events[index]).(*cerebrov1.EventEnvelope)
	pull := sourcecdk.Pull{
		Events: []*primitives.Event{event},
		Checkpoint: &cerebrov1.SourceCheckpoint{
			Watermark:    event.OccurredAt,
			CursorOpaque: strconv.Itoa(index + 1),
		},
	}
	if index+1 < len(s.events) {
		pull.NextCursor = &cerebrov1.SourceCursor{Opaque: strconv.Itoa(index + 1)}
	}
	return pull, nil
}
