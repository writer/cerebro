package sentinelone

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"
)

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func addAttribute(attributes map[string]string, key string, value string) {
	if strings.TrimSpace(value) == "" {
		return
	}
	attributes[key] = strings.TrimSpace(value)
}

func boolString(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

func sortedStrings(values []string) []string {
	cleaned := make([]string, 0, len(values))
	for _, value := range values {
		v := strings.TrimSpace(value)
		if v == "" {
			continue
		}
		cleaned = append(cleaned, v)
	}
	sort.Strings(cleaned)
	return cleaned
}

func intToString(value int) string {
	return strconv.Itoa(value)
}

func parseTimestamp(value string) time.Time {
	v := strings.TrimSpace(value)
	if v == "" {
		return time.Time{}
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05.000000Z"} {
		if parsed, err := time.Parse(layout, v); err == nil {
			return parsed.UTC()
		}
	}
	return time.Time{}
}

func decodeRaw(raw json.RawMessage, label string) (map[string]any, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return nil, fmt.Errorf("decode %s raw payload: %w", label, err)
	}
	return decoded, nil
}

func cloneRaw(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return nil
	}
	out := make(json.RawMessage, len(raw))
	copy(out, raw)
	return out
}

func eventID(prefix string, settings settings, parts ...string) string {
	values := make([]string, 0, len(parts)+2)
	values = append(values, prefix, settings.host)
	for _, part := range parts {
		values = append(values, strings.TrimSpace(part))
	}
	return strings.Join(values, "-")
}

func eventOccurredAt(values ...time.Time) time.Time {
	for _, t := range values {
		if !t.IsZero() {
			return t.UTC()
		}
	}
	return time.Now().UTC()
}

func toTimestamp(t time.Time) *timestamppb.Timestamp {
	return timestamppb.New(t)
}

func buildPagedQuery(cursor string, limit int) url.Values {
	query := url.Values{}
	if limit > 0 {
		query.Set("limit", strconv.Itoa(limit))
	}
	if strings.TrimSpace(cursor) != "" {
		query.Set("cursor", strings.TrimSpace(cursor))
	}
	return query
}

func isNotFound(err error) bool {
	var responseErr *responseError
	return errors.As(err, &responseErr) && responseErr.statusCode == http.StatusNotFound
}

func wrapLookupError(subject string, err error) error {
	if isNotFound(err) {
		return fmt.Errorf("%s not found", subject)
	}
	return fmt.Errorf("%s: %w", subject, err)
}
