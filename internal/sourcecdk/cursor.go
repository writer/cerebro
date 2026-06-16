package sourcecdk

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

// CursorEnvelope is the common JSON shape for resumable source checkpoints.
// Opaque source cursors may still use provider-native tokens while a page is
// actively being fetched; durable checkpoint cursors should prefer this shape.
type CursorEnvelope struct {
	Version             int               `json:"version,omitempty"`
	Source              string            `json:"source,omitempty"`
	Family              string            `json:"family,omitempty"`
	Mode                string            `json:"mode,omitempty"`
	ResumableCheckpoint bool              `json:"resumable_checkpoint,omitempty"`
	Token               string            `json:"token,omitempty"`
	Watermark           string            `json:"watermark,omitempty"`
	BoundaryIDs         []string          `json:"boundary_ids,omitempty"`
	Extra               map[string]string `json:"extra,omitempty"`
}

// EncodeCursorEnvelope returns the canonical JSON representation of envelope.
func EncodeCursorEnvelope(envelope CursorEnvelope) (string, error) {
	envelope.Source = strings.TrimSpace(envelope.Source)
	envelope.Family = strings.TrimSpace(envelope.Family)
	envelope.Mode = strings.TrimSpace(envelope.Mode)
	envelope.Token = strings.TrimSpace(envelope.Token)
	envelope.Watermark = strings.TrimSpace(envelope.Watermark)
	envelope.BoundaryIDs = normalizedCursorValues(envelope.BoundaryIDs)
	envelope.Extra = normalizedCursorMap(envelope.Extra)
	payload, err := json.Marshal(envelope)
	if err != nil {
		return "", fmt.Errorf("marshal source cursor envelope: %w", err)
	}
	return string(payload), nil
}

// DecodeCursorEnvelope parses a CursorEnvelope from opaque JSON.
func DecodeCursorEnvelope(opaque string) (CursorEnvelope, bool) {
	raw := strings.TrimSpace(opaque)
	if raw == "" || !strings.HasPrefix(raw, "{") {
		return CursorEnvelope{}, false
	}
	var envelope CursorEnvelope
	if err := json.Unmarshal([]byte(raw), &envelope); err != nil {
		return CursorEnvelope{}, false
	}
	envelope.Source = strings.TrimSpace(envelope.Source)
	envelope.Family = strings.TrimSpace(envelope.Family)
	envelope.Mode = strings.TrimSpace(envelope.Mode)
	envelope.Token = strings.TrimSpace(envelope.Token)
	envelope.Watermark = strings.TrimSpace(envelope.Watermark)
	envelope.BoundaryIDs = normalizedCursorValues(envelope.BoundaryIDs)
	envelope.Extra = normalizedCursorMap(envelope.Extra)
	return envelope, true
}

// ResumableCursorOpaque reports whether opaque is a resumable checkpoint.
func ResumableCursorOpaque(opaque string) bool {
	envelope, ok := DecodeCursorEnvelope(opaque)
	return ok && envelope.ResumableCheckpoint
}

// CursorWatermark parses a cursor envelope watermark.
func CursorWatermark(envelope CursorEnvelope) time.Time {
	if strings.TrimSpace(envelope.Watermark) == "" {
		return time.Time{}
	}
	watermark, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(envelope.Watermark))
	if err != nil {
		return time.Time{}
	}
	return watermark.UTC()
}

// SetCursorWatermark writes a UTC RFC3339Nano watermark into envelope.
func SetCursorWatermark(envelope *CursorEnvelope, watermark time.Time) {
	if envelope == nil || watermark.IsZero() {
		return
	}
	envelope.Watermark = watermark.UTC().Format(time.RFC3339Nano)
}

// CursorToken returns the provider-native token carried directly by cursor or
// by a standard cursor envelope.
func CursorToken(cursor *cerebrov1.SourceCursor) string {
	if cursor == nil {
		return ""
	}
	opaque := strings.TrimSpace(cursor.GetOpaque())
	if envelope, ok := DecodeCursorEnvelope(opaque); ok {
		return strings.TrimSpace(envelope.Token)
	}
	return opaque
}

// CursorPage parses a one-based page number from CursorToken.
func CursorPage(cursor *cerebrov1.SourceCursor) (int, error) {
	token := CursorToken(cursor)
	if token == "" {
		return 1, nil
	}
	page, err := strconv.Atoi(token)
	if err != nil {
		return 0, fmt.Errorf("%w: parse cursor: %w", ErrInvalidConfig, err)
	}
	if page < 1 {
		return 0, fmt.Errorf("%w: cursor page must be greater than zero", ErrInvalidConfig)
	}
	return page, nil
}

func normalizedCursorValues(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	sort.Strings(out)
	return out
}

func normalizedCursorMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]string, len(values))
	for key, value := range values {
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" || value == "" {
			continue
		}
		out[key] = value
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
