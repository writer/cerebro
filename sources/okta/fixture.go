package okta

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
	spec        *cerebrov1.SourceSpec
	auditURNs   []sourcecdk.URN
	userURNs    []sourcecdk.URN
	auditEvents []*primitives.Event
	userEvents  []*primitives.Event
}

// NewFixture constructs the deterministic Okta source used by tests.
func NewFixture() (sourcecdk.Source, error) {
	spec, err := loadSpec()
	if err != nil {
		return nil, err
	}
	auditURNs, err := loadFixtureURNs("testdata/discover_audit.json")
	if err != nil {
		return nil, err
	}
	userURNs, err := loadFixtureURNs("testdata/discover_user.json")
	if err != nil {
		return nil, err
	}
	auditEvents, err := loadFixtureEvents("testdata/read_audit.json")
	if err != nil {
		return nil, err
	}
	userEvents, err := loadFixtureEvents("testdata/read_user.json")
	if err != nil {
		return nil, err
	}
	return &fixtureSource{
		spec:        spec,
		auditURNs:   auditURNs,
		userURNs:    userURNs,
		auditEvents: auditEvents,
		userEvents:  userEvents,
	}, nil
}

func (s *fixtureSource) Spec() *cerebrov1.SourceSpec {
	return s.spec
}

func (s *fixtureSource) Check(_ context.Context, cfg sourcecdk.Config) error {
	_, err := parseSettings(cfg)
	return err
}

func (s *fixtureSource) Discover(ctx context.Context, cfg sourcecdk.Config) ([]sourcecdk.URN, error) {
	settings, err := parseSettings(cfg)
	if err != nil {
		return nil, err
	}
	if err := s.Check(ctx, cfg); err != nil {
		return nil, err
	}
	switch settings.family {
	case familyAudit:
		return cloneURNs(s.auditURNs), nil
	case familyUser:
		return cloneURNs(s.userURNs), nil
	default:
		return nil, fmt.Errorf("unsupported okta family %q", settings.family)
	}
}

func (s *fixtureSource) Read(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	settings, err := parseSettings(cfg)
	if err != nil {
		return sourcecdk.Pull{}, err
	}
	if err := s.Check(ctx, cfg); err != nil {
		return sourcecdk.Pull{}, err
	}
	index := 0
	if cursor != nil && strings.TrimSpace(cursor.Opaque) != "" {
		parsed, err := strconv.Atoi(strings.TrimSpace(cursor.Opaque))
		if err != nil {
			return sourcecdk.Pull{}, fmt.Errorf("parse cursor: %w", err)
		}
		if parsed < 0 {
			return sourcecdk.Pull{}, fmt.Errorf("cursor index must be non-negative")
		}
		index = parsed
	}
	events := s.eventsForFamily(settings.family)
	if index >= len(events) {
		return sourcecdk.Pull{}, nil
	}
	event := proto.Clone(events[index]).(*cerebrov1.EventEnvelope)
	pull := sourcecdk.Pull{
		Events: []*primitives.Event{event},
		Checkpoint: &cerebrov1.SourceCheckpoint{
			Watermark:    event.OccurredAt,
			CursorOpaque: strconv.Itoa(index + 1),
		},
	}
	if index+1 < len(events) {
		pull.NextCursor = &cerebrov1.SourceCursor{Opaque: strconv.Itoa(index + 1)}
	}
	return pull, nil
}

func (s *fixtureSource) eventsForFamily(family string) []*primitives.Event {
	switch family {
	case familyAudit:
		return s.auditEvents
	case familyUser:
		return s.userEvents
	default:
		return nil
	}
}

func loadFixtureURNs(path string) ([]sourcecdk.URN, error) {
	urnBytes, err := fixtureFS.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var rawURNs []string
	if err := json.Unmarshal(urnBytes, &rawURNs); err != nil {
		return nil, fmt.Errorf("unmarshal %s: %w", path, err)
	}
	urns := make([]sourcecdk.URN, 0, len(rawURNs))
	for _, rawURN := range rawURNs {
		urn, err := sourcecdk.ParseURN(rawURN)
		if err != nil {
			return nil, fmt.Errorf("parse urn %q from %s: %w", rawURN, path, err)
		}
		urns = append(urns, urn)
	}
	return urns, nil
}

func loadFixtureEvents(path string) ([]*primitives.Event, error) {
	eventBytes, err := fixtureFS.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var rawEvents []fixtureEvent
	if err := json.Unmarshal(eventBytes, &rawEvents); err != nil {
		return nil, fmt.Errorf("unmarshal %s: %w", path, err)
	}
	events := make([]*primitives.Event, 0, len(rawEvents))
	for _, raw := range rawEvents {
		occurredAt, err := time.Parse(time.RFC3339, raw.OccurredAt)
		if err != nil {
			return nil, fmt.Errorf("parse event occurred_at from %s: %w", path, err)
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
	return events, nil
}

func cloneURNs(values []sourcecdk.URN) []sourcecdk.URN {
	cloned := make([]sourcecdk.URN, len(values))
	copy(cloned, values)
	return cloned
}
