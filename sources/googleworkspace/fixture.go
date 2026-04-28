package googleworkspace

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"google.golang.org/protobuf/proto"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/primitives"
	"github.com/writer/cerebro/internal/sourcecdk"
)

//go:embed testdata/*.json
var fixtureFS embed.FS

type fixtureSource struct {
	spec   *cerebrov1.SourceSpec
	urns   map[string][]sourcecdk.URN
	events map[string][]*primitives.Event
}

// NewFixture constructs the deterministic Google Workspace source used by tests.
func NewFixture() (sourcecdk.Source, error) {
	spec, err := loadSpec()
	if err != nil {
		return nil, err
	}
	source := &fixtureSource{
		spec:   spec,
		urns:   map[string][]sourcecdk.URN{},
		events: map[string][]*primitives.Event{},
	}
	for _, family := range []string{familyAudit, familyGroup, familyGroupMember, familyRoleAssign, familyUser} {
		records, err := loadRawFixture("testdata/read_" + family + ".json")
		if err != nil {
			return nil, err
		}
		settings := settings{
			family:      family,
			domain:      "writer.com",
			customerID:  "C01",
			token:       "test-token",
			baseURL:     defaultBaseURL,
			groupKey:    "security@writer.com",
			application: "admin",
			perPage:     1,
		}
		for _, record := range records {
			event, err := sourceEvent(settings, record)
			if err != nil {
				return nil, err
			}
			source.events[family] = append(source.events[family], event)
			urn, err := discoverURN(settings, record)
			if err == nil && urn != "" {
				source.urns[family] = append(source.urns[family], urn)
			}
		}
	}
	return source, nil
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
	return cloneURNs(s.urns[settings.family]), nil
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
		parsed, err := strconv.Atoi(cursor.Opaque)
		if err != nil {
			return sourcecdk.Pull{}, fmt.Errorf("parse cursor: %w", err)
		}
		index = parsed
	}
	events := s.events[settings.family]
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

func loadRawFixture(path string) ([]json.RawMessage, error) {
	content, err := fixtureFS.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var records []json.RawMessage
	if err := json.Unmarshal(content, &records); err != nil {
		return nil, fmt.Errorf("unmarshal %s: %w", path, err)
	}
	return records, nil
}

func cloneURNs(values []sourcecdk.URN) []sourcecdk.URN {
	cloned := make([]sourcecdk.URN, len(values))
	copy(cloned, values)
	return cloned
}
