package jsonapi

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
)

type fanoutCursor struct {
	Index  int    `json:"index"`
	Cursor string `json:"cursor,omitempty"`
}

// ReadPathParamValues reads one configured family across a bounded list of path
// parameter values. The returned cursor preserves both the current value index
// and that value's provider cursor.
func (s *Source) ReadPathParamValues(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor, param string, values []string) (sourcecdk.Pull, error) {
	values = compactUniqueStrings(values)
	if len(values) == 0 {
		return sourcecdk.Pull{}, fmt.Errorf("%w: %s %s values are required", sourcecdk.ErrInvalidConfig, s.options.SourceID, param)
	}
	state := parseFanoutCursor(fanoutCursorToken(cursor))
	for state.Index < len(values) {
		pull, err := s.Read(ctx, configWithValue(cfg, param, values[state.Index]), sourceCursor(state.Cursor))
		if err != nil {
			return sourcecdk.Pull{}, err
		}
		if next := sourcecdk.CursorToken(pull.NextCursor); next != "" {
			pull.NextCursor = encodeFanoutCursor(s.options.SourceID, fanoutCursor{Index: state.Index, Cursor: next})
			return pull, nil
		}
		if len(pull.Events) > 0 {
			if state.Index+1 < len(values) {
				pull.NextCursor = encodeFanoutCursor(s.options.SourceID, fanoutCursor{Index: state.Index + 1})
			}
			return pull, nil
		}
		state.Index++
		state.Cursor = ""
	}
	return sourcecdk.Pull{}, nil
}

// CheckPathParamValues validates a path-parameter scoped family with the first
// configured value. Check calls should stay cheap while still proving the
// scoped endpoint can be reached with the provided credentials.
func (s *Source) CheckPathParamValues(ctx context.Context, cfg sourcecdk.Config, param string, values []string) error {
	values = compactUniqueStrings(values)
	if len(values) == 0 {
		return fmt.Errorf("%w: %s %s values are required", sourcecdk.ErrInvalidConfig, s.options.SourceID, param)
	}
	return s.Check(ctx, configWithValue(cfg, param, values[0]))
}

// DiscoverPathParamValues discovers URNs for a path-parameter scoped family
// across every configured value.
func (s *Source) DiscoverPathParamValues(ctx context.Context, cfg sourcecdk.Config, param string, values []string) ([]sourcecdk.URN, error) {
	values = compactUniqueStrings(values)
	if len(values) == 0 {
		return nil, fmt.Errorf("%w: %s %s values are required", sourcecdk.ErrInvalidConfig, s.options.SourceID, param)
	}
	seen := map[sourcecdk.URN]struct{}{}
	urns := []sourcecdk.URN{}
	for _, value := range values {
		discovered, err := s.Discover(ctx, configWithValue(cfg, param, value))
		if err != nil {
			return nil, err
		}
		for _, urn := range discovered {
			if _, ok := seen[urn]; ok {
				continue
			}
			seen[urn] = struct{}{}
			urns = append(urns, urn)
		}
	}
	return urns, nil
}

func parseFanoutCursor(raw string) fanoutCursor {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fanoutCursor{}
	}
	if state, ok := decodeFanoutCursor(raw); ok {
		return state
	}
	return fanoutCursor{Cursor: raw}
}

func fanoutCursorToken(cursor *cerebrov1.SourceCursor) string {
	if cursor == nil {
		return ""
	}
	opaque := strings.TrimSpace(cursor.GetOpaque())
	if _, ok := decodeFanoutCursor(opaque); ok {
		return opaque
	}
	return sourcecdk.CursorToken(cursor)
}

func decodeFanoutCursor(raw string) (fanoutCursor, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || !strings.HasPrefix(raw, "{") {
		return fanoutCursor{}, false
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &fields); err != nil {
		return fanoutCursor{}, false
	}
	if _, ok := fields["index"]; !ok {
		if _, ok := fields["cursor"]; !ok {
			return fanoutCursor{}, false
		}
	}
	var state fanoutCursor
	if err := json.Unmarshal([]byte(raw), &state); err == nil && state.Index >= 0 {
		return state, true
	}
	return fanoutCursor{}, false
}

func encodeFanoutCursor(sourceID string, state fanoutCursor) *cerebrov1.SourceCursor {
	token, err := json.Marshal(state)
	if err != nil {
		return nil
	}
	opaque, err := sourcecdk.EncodeCursorEnvelope(sourcecdk.CursorEnvelope{
		Version: 1,
		Source:  sourceID,
		Mode:    "fanout_path_param",
		Token:   string(token),
	})
	if err != nil {
		return nil
	}
	return &cerebrov1.SourceCursor{Opaque: opaque}
}

func sourceCursor(raw string) *cerebrov1.SourceCursor {
	if raw = strings.TrimSpace(raw); raw != "" {
		return &cerebrov1.SourceCursor{Opaque: raw}
	}
	return nil
}

func configWithValue(cfg sourcecdk.Config, key string, value string) sourcecdk.Config {
	values := cfg.Values()
	values[key] = value
	return sourcecdk.NewConfig(values)
}

func compactUniqueStrings(values []string) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}
