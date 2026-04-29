package sourcecdk

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/primitives"
)

// FixtureFamily contains deterministic source output for one event family.
type FixtureFamily struct {
	Name   string
	URNs   []URN
	Events []*primitives.Event
}

// FixtureSourceOptions configures a deterministic test source.
type FixtureSourceOptions struct {
	Spec          *cerebrov1.SourceSpec
	DefaultFamily string
	Check         func(context.Context, Config) error
	ResolveFamily func(Config) (string, error)
	Families      []FixtureFamily
}

type fixtureSource struct {
	spec          *cerebrov1.SourceSpec
	defaultFamily string
	check         func(context.Context, Config) error
	resolveFamily func(Config) (string, error)
	families      map[string]FixtureFamily
}

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

// NewFixtureSource constructs a deterministic Source implementation for tests.
func NewFixtureSource(options FixtureSourceOptions) (Source, error) {
	if options.Spec == nil {
		return nil, fmt.Errorf("fixture source spec is required")
	}
	source := &fixtureSource{
		spec:          options.Spec,
		defaultFamily: strings.TrimSpace(options.DefaultFamily),
		check:         options.Check,
		resolveFamily: options.ResolveFamily,
		families:      make(map[string]FixtureFamily, len(options.Families)),
	}
	for _, family := range options.Families {
		name := strings.TrimSpace(family.Name)
		if name == "" {
			return nil, fmt.Errorf("fixture family name is required")
		}
		if _, ok := source.families[name]; ok {
			return nil, fmt.Errorf("duplicate fixture family %q", name)
		}
		source.families[name] = FixtureFamily{
			Name:   name,
			URNs:   CloneURNs(family.URNs),
			Events: cloneEvents(family.Events),
		}
	}
	if source.defaultFamily == "" && len(options.Families) == 1 {
		source.defaultFamily = strings.TrimSpace(options.Families[0].Name)
	}
	return source, nil
}

func (s *fixtureSource) Spec() *cerebrov1.SourceSpec {
	return s.spec
}

func (s *fixtureSource) Check(ctx context.Context, cfg Config) error {
	if s.check != nil {
		if err := s.check(ctx, cfg); err != nil {
			return err
		}
	}
	_, err := s.family(cfg)
	return err
}

func (s *fixtureSource) Discover(ctx context.Context, cfg Config) ([]URN, error) {
	if err := s.Check(ctx, cfg); err != nil {
		return nil, err
	}
	family, err := s.family(cfg)
	if err != nil {
		return nil, err
	}
	return CloneURNs(family.URNs), nil
}

func (s *fixtureSource) Read(ctx context.Context, cfg Config, cursor *cerebrov1.SourceCursor) (Pull, error) {
	if err := s.Check(ctx, cfg); err != nil {
		return Pull{}, err
	}
	family, err := s.family(cfg)
	if err != nil {
		return Pull{}, err
	}
	index := 0
	if cursor != nil && strings.TrimSpace(cursor.Opaque) != "" {
		parsed, err := strconv.Atoi(cursor.Opaque)
		if err != nil {
			return Pull{}, fmt.Errorf("parse cursor: %w", err)
		}
		index = parsed
	}
	if index >= len(family.Events) {
		return Pull{}, nil
	}
	event := proto.Clone(family.Events[index]).(*cerebrov1.EventEnvelope)
	pull := Pull{
		Events: []*primitives.Event{event},
		Checkpoint: &cerebrov1.SourceCheckpoint{
			Watermark:    event.OccurredAt,
			CursorOpaque: strconv.Itoa(index + 1),
		},
	}
	if index+1 < len(family.Events) {
		pull.NextCursor = &cerebrov1.SourceCursor{Opaque: strconv.Itoa(index + 1)}
	}
	return pull, nil
}

func (s *fixtureSource) family(cfg Config) (FixtureFamily, error) {
	if s == nil {
		return FixtureFamily{}, fmt.Errorf("fixture source is required")
	}
	name := s.defaultFamily
	if s.resolveFamily != nil {
		resolved, err := s.resolveFamily(cfg)
		if err != nil {
			return FixtureFamily{}, err
		}
		name = strings.TrimSpace(resolved)
	} else if value, ok := cfg.Lookup("family"); ok && strings.TrimSpace(value) != "" {
		name = strings.TrimSpace(value)
	}
	family, ok := s.families[name]
	if !ok {
		return FixtureFamily{}, fmt.Errorf("unsupported fixture family %q", name)
	}
	return family, nil
}

// LoadFixtureURNs loads a JSON string array of URNs from a fixture filesystem.
func LoadFixtureURNs(fsys fs.FS, path string) ([]URN, error) {
	urnBytes, err := fs.ReadFile(fsys, path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var rawURNs []string
	if err := json.Unmarshal(urnBytes, &rawURNs); err != nil {
		return nil, fmt.Errorf("unmarshal %s: %w", path, err)
	}
	urns := make([]URN, 0, len(rawURNs))
	for _, rawURN := range rawURNs {
		urn, err := ParseURN(rawURN)
		if err != nil {
			return nil, fmt.Errorf("parse urn %q from %s: %w", rawURN, path, err)
		}
		urns = append(urns, urn)
	}
	return urns, nil
}

// LoadFixtureEvents loads normalized event fixtures.
func LoadFixtureEvents(fsys fs.FS, path string) ([]*primitives.Event, error) {
	eventBytes, err := fs.ReadFile(fsys, path)
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

// CloneURNs returns a shallow copy of URNs.
func CloneURNs(values []URN) []URN {
	cloned := make([]URN, len(values))
	copy(cloned, values)
	return cloned
}

func cloneEvents(values []*primitives.Event) []*primitives.Event {
	cloned := make([]*primitives.Event, 0, len(values))
	for _, value := range values {
		if value == nil {
			continue
		}
		cloned = append(cloned, proto.Clone(value).(*cerebrov1.EventEnvelope))
	}
	return cloned
}
