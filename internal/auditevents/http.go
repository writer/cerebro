package auditevents

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/writer/cerebro/internal/ports"
)

const (
	auditEventCursorVersion = 1
	auditEventCursorMaxAge  = 15 * time.Minute
)

type HTTPActorV1 struct {
	ID    string `json:"id"`
	Kind  string `json:"kind"`
	Label string `json:"label"`
}

type HTTPResourceV1 struct {
	ID    string `json:"id"`
	Type  string `json:"type"`
	Label string `json:"label"`
}

type HTTPEventV1 struct {
	ID         string          `json:"id"`
	Action     string          `json:"action"`
	Actor      *HTTPActorV1    `json:"actor,omitempty"`
	Category   string          `json:"category"`
	DurationMS *int64          `json:"duration_ms,omitempty"`
	OccurredAt string          `json:"occurred_at"`
	Outcome    string          `json:"outcome"`
	RequestID  string          `json:"request_id"`
	Resource   *HTTPResourceV1 `json:"resource,omitempty"`
	Service    string          `json:"service"`
	Summary    string          `json:"summary"`
	TraceID    string          `json:"trace_id"`
}

type HTTPWindowV1 struct {
	StartTime string `json:"start_time"`
	EndTime   string `json:"end_time"`
}

type HTTPPageV1 struct {
	Events     []HTTPEventV1 `json:"events"`
	NextCursor string        `json:"next_cursor"`
	Status     string        `json:"status"`
	Window     HTTPWindowV1  `json:"window"`
}

type cursorV1 struct {
	Version        int    `json:"v"`
	After          string `json:"a"`
	Before         string `json:"b"`
	LastOccurredAt string `json:"t"`
	LastID         string `json:"i"`
	Checksum       string `json:"c"`
}

// ParseHTTPQuery converts bounded public query parameters into the stable
// reader contract. Cursor content is client-controlled resume state, so the
// authorized tenant is always supplied independently by the transport layer.
// The cursor checksum detects accidental corruption; it is not a MAC and no
// authorization or evidence decision relies on it.
func ParseHTTPQuery(values url.Values, tenantID string, now time.Time) (ports.AuditEventQueryV1, error) {
	limit, err := strictInteger(values.Get("limit"), DefaultLimit, 1, MaxLimit, "limit")
	if err != nil {
		return ports.AuditEventQueryV1{}, err
	}
	minutes, err := strictInteger(values.Get("minutes"), DefaultMinutes, MinMinutes, MaxMinutes, "minutes")
	if err != nil {
		return ports.AuditEventQueryV1{}, err
	}
	query := ports.AuditEventQueryV1{
		TenantID: strings.TrimSpace(tenantID),
		Limit:    uint32(limit), // #nosec G115 -- strictInteger bounds this value to MaxLimit.
		Before:   now.UTC(),
		After:    now.UTC().Add(-time.Duration(minutes) * time.Minute),
	}
	for field, target := range map[string]*string{
		"action": &query.Action, "actor": &query.Actor, "q": &query.Query,
		"resource_type": &query.ResourceType, "service": &query.Service, "trace_id": &query.TraceID,
	} {
		*target, err = filterText(field, values.Get(field))
		if err != nil {
			return ports.AuditEventQueryV1{}, err
		}
	}
	query.Outcome = strings.ToLower(strings.TrimSpace(values.Get("outcome")))
	if query.Outcome != "" && !ValidOutcome(query.Outcome) {
		return ports.AuditEventQueryV1{}, fmt.Errorf("%w: invalid outcome", ports.ErrAuditEventInvalid)
	}
	cursorValue, err := optionalText("cursor", values.Get("cursor"), MaxCursorCharacters)
	if err != nil {
		return ports.AuditEventQueryV1{}, err
	}
	if cursorValue != "" {
		cursor, err := decodeCursor(cursorValue)
		if err != nil {
			return ports.AuditEventQueryV1{}, err
		}
		query.After, err = time.Parse(time.RFC3339Nano, cursor.After)
		if err != nil {
			return ports.AuditEventQueryV1{}, fmt.Errorf("%w: invalid cursor window", ports.ErrAuditEventInvalid)
		}
		query.Before, err = time.Parse(time.RFC3339Nano, cursor.Before)
		if err != nil {
			return ports.AuditEventQueryV1{}, fmt.Errorf("%w: invalid cursor window", ports.ErrAuditEventInvalid)
		}
		query.PageBeforeOccurredAt, err = time.Parse(time.RFC3339Nano, cursor.LastOccurredAt)
		if err != nil {
			return ports.AuditEventQueryV1{}, fmt.Errorf("%w: invalid cursor boundary", ports.ErrAuditEventInvalid)
		}
		query.PageBeforeID = strings.TrimSpace(cursor.LastID)
		if query.Before.Sub(query.After) != time.Duration(minutes)*time.Minute ||
			query.Before.After(now.UTC().Add(time.Minute)) || query.Before.Before(now.UTC().Add(-auditEventCursorMaxAge)) {
			return ports.AuditEventQueryV1{}, fmt.Errorf("%w: cursor window is expired or invalid", ports.ErrAuditEventInvalid)
		}
		if cursor.Checksum != cursorCorruptionChecksum(query, minutes) {
			return ports.AuditEventQueryV1{}, fmt.Errorf("%w: cursor checksum does not match resume state", ports.ErrAuditEventInvalid)
		}
	}
	if err := ValidateQuery(query); err != nil {
		return ports.AuditEventQueryV1{}, err
	}
	return query, nil
}

// NewHTTPPage validates a reader result and converts it into the fixed public
// response allowlist. TenantID and source projection metadata are never copied.
func NewHTTPPage(query ports.AuditEventQueryV1, page ports.AuditEventPageV1) (HTTPPageV1, error) {
	if err := ValidateQuery(query); err != nil {
		return HTTPPageV1{}, err
	}
	if len(page.Events) > int(query.Limit) {
		return HTTPPageV1{}, errors.New("reader returned an oversized audit-event page")
	}
	response := HTTPPageV1{
		Events: make([]HTTPEventV1, 0, len(page.Events)),
		Status: "complete",
		Window: HTTPWindowV1{
			StartTime: query.After.UTC().Format(time.RFC3339Nano),
			EndTime:   query.Before.UTC().Format(time.RFC3339Nano),
		},
	}
	if page.Partial {
		response.Status = "partial"
	}
	var previous *ports.AuditEventV1
	for _, event := range page.Events {
		normalized, err := Normalize(event)
		if err != nil || normalized.TenantID != query.TenantID || normalized.OccurredAt.Before(query.After) || normalized.OccurredAt.After(query.Before) {
			return HTTPPageV1{}, errors.New("reader returned an invalid tenant-scoped audit event")
		}
		if !query.PageBeforeOccurredAt.IsZero() && !strictlyOlderThanBoundary(normalized, query.PageBeforeOccurredAt, query.PageBeforeID) {
			return HTTPPageV1{}, errors.New("reader returned an audit event that does not advance the page boundary")
		}
		if previous != nil && (previous.OccurredAt.Before(normalized.OccurredAt) ||
			(previous.OccurredAt.Equal(normalized.OccurredAt) && previous.ID <= normalized.ID)) {
			return HTTPPageV1{}, errors.New("reader returned audit events outside deterministic order")
		}
		response.Events = append(response.Events, newHTTPEvent(normalized))
		previous = normalized
	}
	if page.HasMore {
		if len(page.Events) == 0 {
			return HTTPPageV1{}, errors.New("reader returned an empty nonterminal audit-event page")
		}
		cursor, err := encodeCursor(query, previous)
		if err != nil {
			return HTTPPageV1{}, err
		}
		response.NextCursor = cursor
	}
	return response, nil
}

func strictInteger(raw string, fallback int, minimum int, maximum int, field string) (int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < minimum || value > maximum {
		return 0, fmt.Errorf("%w: %s must be between %d and %d", ports.ErrAuditEventInvalid, field, minimum, maximum)
	}
	return value, nil
}

func filterText(field string, raw string) (string, error) {
	return optionalText(field, raw, MaxQueryCharacters)
}

func encodeCursor(query ports.AuditEventQueryV1, last *ports.AuditEventV1) (string, error) {
	if last == nil || strings.TrimSpace(last.ID) == "" || last.OccurredAt.IsZero() {
		return "", errors.New("invalid audit-event page boundary")
	}
	minutes := int(query.Before.Sub(query.After) / time.Minute)
	resumeQuery := query
	resumeQuery.PageBeforeOccurredAt = last.OccurredAt.UTC()
	resumeQuery.PageBeforeID = strings.TrimSpace(last.ID)
	cursor := cursorV1{
		Version: auditEventCursorVersion, After: query.After.UTC().Format(time.RFC3339Nano),
		Before:         query.Before.UTC().Format(time.RFC3339Nano),
		LastOccurredAt: last.OccurredAt.UTC().Format(time.RFC3339Nano), LastID: strings.TrimSpace(last.ID),
		Checksum: cursorCorruptionChecksum(resumeQuery, minutes),
	}
	payload, err := json.Marshal(cursor)
	if err != nil {
		return "", fmt.Errorf("encode audit event cursor: %w", err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	if utf8.RuneCountInString(encoded) > MaxCursorCharacters {
		return "", errors.New("encoded audit-event cursor is too long")
	}
	return encoded, nil
}

func decodeCursor(value string) (cursorV1, error) {
	payload, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return cursorV1{}, fmt.Errorf("%w: invalid cursor", ports.ErrAuditEventInvalid)
	}
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	var cursor cursorV1
	if err := decoder.Decode(&cursor); err != nil {
		return cursorV1{}, fmt.Errorf("%w: invalid cursor", ports.ErrAuditEventInvalid)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return cursorV1{}, fmt.Errorf("%w: invalid cursor", ports.ErrAuditEventInvalid)
	}
	if cursor.Version != auditEventCursorVersion || len(cursor.Checksum) != sha256.Size*2 {
		return cursorV1{}, fmt.Errorf("%w: unsupported cursor", ports.ErrAuditEventInvalid)
	}
	return cursor, nil
}

// cursorCorruptionChecksum is an unkeyed checksum over the complete resume
// state, including the keyset boundary. It detects accidental corruption only;
// clients can recompute it and it must never be treated as authentication.
func cursorCorruptionChecksum(query ports.AuditEventQueryV1, minutes int) string {
	values := []string{
		strings.TrimSpace(query.TenantID), strings.ToLower(strings.TrimSpace(query.Action)),
		strings.ToLower(strings.TrimSpace(query.Actor)), strings.ToLower(strings.TrimSpace(query.Outcome)),
		strings.TrimSpace(query.Query), strings.ToLower(strings.TrimSpace(query.ResourceType)),
		strings.ToLower(strings.TrimSpace(query.Service)), strings.ToLower(strings.TrimSpace(query.TraceID)),
		query.After.UTC().Format(time.RFC3339Nano), query.Before.UTC().Format(time.RFC3339Nano),
		query.PageBeforeOccurredAt.UTC().Format(time.RFC3339Nano), strings.TrimSpace(query.PageBeforeID),
		strconv.Itoa(minutes), strconv.FormatUint(uint64(query.Limit), 10),
	}
	hash := sha256.New()
	for _, value := range values {
		_, _ = hash.Write([]byte(strconv.Itoa(len(value))))
		_, _ = hash.Write([]byte{':'})
		_, _ = hash.Write([]byte(value))
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func strictlyOlderThanBoundary(event *ports.AuditEventV1, occurredAt time.Time, eventID string) bool {
	if event.OccurredAt.Before(occurredAt) {
		return true
	}
	return event.OccurredAt.Equal(occurredAt) && event.ID < strings.TrimSpace(eventID)
}

func newHTTPEvent(event *ports.AuditEventV1) HTTPEventV1 {
	view := HTTPEventV1{
		ID: event.ID, Action: event.Action, Category: event.Category, DurationMS: event.DurationMS,
		OccurredAt: event.OccurredAt.UTC().Format(time.RFC3339Nano), Outcome: event.Outcome,
		RequestID: event.RequestID, Service: event.Service, Summary: event.Summary, TraceID: event.TraceID,
	}
	if event.Actor != nil {
		view.Actor = &HTTPActorV1{ID: event.Actor.ID, Kind: event.Actor.Kind, Label: event.Actor.Label}
	}
	if event.Resource != nil {
		view.Resource = &HTTPResourceV1{ID: event.Resource.ID, Type: event.Resource.Type, Label: event.Resource.Label}
	}
	return view
}
