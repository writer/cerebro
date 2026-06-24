package cosmo

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/primitives"
	"github.com/writer/cerebro/internal/sourcecdk"
)

type messageWindow struct {
	since          time.Time
	until          time.Time
	eventTypeIndex int
	offset         int
}

func (s *Source) memoryFamily(family string, path string, collection string) sourcecdk.Family[settings] {
	return sourcecdk.Family[settings]{
		Name: family,
		Check: func(ctx context.Context, settings settings) error {
			_, _, err := s.listMemory(ctx, settings, path, collection, 0, 1)
			if err != nil {
				return fmt.Errorf("cosmo %s: %w", family, err)
			}
			return nil
		},
		Discover: func(ctx context.Context, settings settings) ([]sourcecdk.URN, error) {
			records, _, err := s.listMemory(ctx, settings, path, collection, 0, familyPageSize(settings, family))
			if err != nil {
				return nil, fmt.Errorf("cosmo %s: %w", family, err)
			}
			return urnsFor(settings, family, records)
		},
		Read: func(ctx context.Context, settings settings, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
			offset, err := readOffset(cursor)
			if err != nil {
				return sourcecdk.Pull{}, err
			}
			limit := familyPageSize(settings, family)
			records, next, err := s.listMemory(ctx, settings, path, collection, offset, limit)
			if err != nil {
				return sourcecdk.Pull{}, fmt.Errorf("cosmo %s: %w", family, err)
			}
			return pullFromRecords(settings, family, records, next)
		},
	}
}

func (s *Source) messageFamily() sourcecdk.Family[settings] {
	return sourcecdk.Family[settings]{
		Name: familyMessage,
		Check: func(ctx context.Context, settings settings) error {
			window, ok, err := readMessageCursor(settings, nil, time.Now())
			if err != nil {
				return err
			}
			if !ok {
				return nil
			}
			_, err = s.listMessages(ctx, settings, window, 1)
			if err != nil {
				return fmt.Errorf("cosmo message: %w", err)
			}
			return nil
		},
		Discover: func(ctx context.Context, settings settings) ([]sourcecdk.URN, error) {
			window, ok, err := readMessageCursor(settings, nil, time.Now())
			if err != nil {
				return nil, err
			}
			if !ok {
				return nil, nil
			}
			records := make([]record, 0, settings.perPage)
			for eventTypeIndex := range settings.eventTypes {
				if len(records) >= settings.perPage {
					break
				}
				eventWindow := window
				eventWindow.eventTypeIndex = eventTypeIndex
				eventWindow.offset = 0
				remaining := settings.perPage - len(records)
				page, err := s.listMessages(ctx, settings, eventWindow, remaining)
				if err != nil {
					return nil, fmt.Errorf("cosmo message: %w", err)
				}
				records = append(records, page...)
			}
			return urnsFor(settings, familyMessage, records)
		},
		Read: func(ctx context.Context, settings settings, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
			window, ok, err := readMessageCursor(settings, cursor, time.Now())
			if err != nil {
				return sourcecdk.Pull{}, err
			}
			if !ok {
				checkpoint := messageCheckpointCursor(window.since)
				return messagePullFromRecords(settings, nil, "", checkpoint, window.since)
			}
			records, err := s.listMessages(ctx, settings, window, settings.perPage)
			if err != nil {
				return sourcecdk.Pull{}, fmt.Errorf("cosmo message: %w", err)
			}
			next, checkpoint := nextMessageCursor(settings, window, len(records), settings.perPage)
			return messagePullFromRecords(settings, records, next, checkpoint, window.until)
		},
	}
}

func (s *Source) surveyFeedbackFamily() sourcecdk.Family[settings] {
	return sourcecdk.Family[settings]{
		Name: familySurveyFeedback,
		Check: func(ctx context.Context, settings settings) error {
			_, err := s.listSurveyFeedback(ctx, settings)
			if err != nil {
				return fmt.Errorf("cosmo survey_feedback: %w", err)
			}
			return nil
		},
		Discover: func(ctx context.Context, settings settings) ([]sourcecdk.URN, error) {
			records, err := s.listSurveyFeedback(ctx, settings)
			if err != nil {
				return nil, fmt.Errorf("cosmo survey_feedback: %w", err)
			}
			page, _ := pageRecords(records, 0, settings.perPage)
			return urnsFor(settings, familySurveyFeedback, page)
		},
		Read: func(ctx context.Context, settings settings, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
			offset, err := readOffset(cursor)
			if err != nil {
				return sourcecdk.Pull{}, err
			}
			records, err := s.listSurveyFeedback(ctx, settings)
			if err != nil {
				return sourcecdk.Pull{}, fmt.Errorf("cosmo survey_feedback: %w", err)
			}
			page, next := pageRecords(records, offset, settings.perPage)
			return pullFromRecords(settings, familySurveyFeedback, page, next)
		},
	}
}

func readMessageCursor(settings settings, cursor *cerebrov1.SourceCursor, now time.Time) (messageWindow, bool, error) {
	now = now.UTC()
	if cursor == nil || strings.TrimSpace(cursor.Opaque) == "" {
		since := settings.initialSince
		until := minTime(since.Add(settings.maxWindow), now)
		window := messageWindow{since: since, until: until}
		return window, until.After(since), nil
	}
	var payload messageCursor
	if err := json.Unmarshal([]byte(strings.TrimSpace(cursor.Opaque)), &payload); err != nil {
		return messageWindow{}, false, fmt.Errorf("parse cosmo message cursor: %w", err)
	}
	if payload.Source != messageExportCursorSource {
		return messageWindow{}, false, fmt.Errorf("cosmo message cursor source = %q, want %q", payload.Source, messageExportCursorSource)
	}
	if payload.EventTypeIndex < 0 || payload.EventTypeIndex >= len(settings.eventTypes) {
		return messageWindow{}, false, fmt.Errorf("cosmo message cursor event_type_index is out of range")
	}
	if payload.Offset < 0 {
		return messageWindow{}, false, fmt.Errorf("cosmo message cursor offset must be non-negative")
	}
	since, ok := parseMessageCursorTime(payload.Since)
	if !ok {
		return messageWindow{}, false, fmt.Errorf("cosmo message cursor since must be an ISO timestamp")
	}
	eventTypeIndex := payload.EventTypeIndex
	offset := payload.Offset
	var until time.Time
	if strings.TrimSpace(payload.Until) == "" {
		until = minTime(since.Add(settings.maxWindow), now)
		eventTypeIndex = 0
		offset = 0
	} else {
		var parsed bool
		until, parsed = parseMessageCursorTime(payload.Until)
		if !parsed {
			return messageWindow{}, false, fmt.Errorf("cosmo message cursor until must be an ISO timestamp")
		}
		if until.Sub(since) > settings.maxWindow {
			return messageWindow{}, false, fmt.Errorf("cosmo message cursor window exceeds max_window_hours")
		}
	}
	window := messageWindow{since: since, until: until, eventTypeIndex: eventTypeIndex, offset: offset}
	if !until.After(since) {
		return window, false, nil
	}
	return window, true, nil
}

func parseMessageCursorTime(value string) (time.Time, bool) {
	parsed, ok := parseTime(value)
	if !ok {
		return time.Time{}, false
	}
	return parsed.UTC(), true
}

func nextMessageCursor(settings settings, window messageWindow, records int, limit int) (string, string) {
	if records == limit && window.offset+limit < messageExportMaxOffset {
		next := encodeMessageCursor(window.since, window.until, window.eventTypeIndex, window.offset+limit)
		return next, next
	}
	if window.eventTypeIndex+1 < len(settings.eventTypes) {
		next := encodeMessageCursor(window.since, window.until, window.eventTypeIndex+1, 0)
		return next, next
	}
	checkpoint := messageCheckpointCursor(window.until)
	return "", checkpoint
}

func messageCheckpointCursor(since time.Time) string {
	return encodeMessageCursor(since, time.Time{}, 0, 0)
}

func encodeMessageCursor(since time.Time, until time.Time, eventTypeIndex int, offset int) string {
	payload := messageCursor{
		Source:              messageExportCursorSource,
		ResumableCheckpoint: true,
		Since:               since.UTC().Format(time.RFC3339Nano),
		EventTypeIndex:      eventTypeIndex,
		Offset:              offset,
	}
	if !until.IsZero() {
		payload.Until = until.UTC().Format(time.RFC3339Nano)
	}
	encoded, _ := json.Marshal(payload)
	return string(encoded)
}

func messagePullFromRecords(settings settings, records []record, next string, checkpoint string, watermark time.Time) (sourcecdk.Pull, error) {
	pull := sourcecdk.Pull{
		Checkpoint: &cerebrov1.SourceCheckpoint{
			Watermark:    timestamppb.New(watermark.UTC()),
			CursorOpaque: strings.TrimSpace(checkpointCursor(next, checkpoint)),
		},
	}
	if strings.TrimSpace(next) != "" {
		pull.NextCursor = &cerebrov1.SourceCursor{Opaque: strings.TrimSpace(next)}
	}
	if len(records) == 0 {
		return pull, nil
	}
	events := make([]*primitives.Event, 0, len(records))
	for _, record := range records {
		events = append(events, eventFromRecord(settings, familyMessage, record))
	}
	pull.Events = events
	pull.Checkpoint.Watermark = events[len(events)-1].OccurredAt
	return pull, nil
}

func urnsFor(settings settings, family string, records []record) ([]sourcecdk.URN, error) {
	urns := make([]sourcecdk.URN, 0, len(records))
	for _, record := range records {
		urn, err := recordURN(settings, family, record.ID)
		if err != nil {
			return nil, err
		}
		urns = append(urns, urn)
	}
	return urns, nil
}

func recordURN(settings settings, family string, id string) (sourcecdk.URN, error) {
	return sourcecdk.URNFor(normalizeID(settings.tenantID), family, sourcecdk.StableExternalID(id, "unknown"))
}

func pullFromRecords(settings settings, family string, records []record, next string) (sourcecdk.Pull, error) {
	if len(records) == 0 {
		pull := sourcecdk.Pull{}
		if strings.TrimSpace(next) != "" {
			pull.NextCursor = &cerebrov1.SourceCursor{Opaque: strings.TrimSpace(next)}
		}
		return pull, nil
	}
	events := make([]*primitives.Event, 0, len(records))
	for _, record := range records {
		events = append(events, eventFromRecord(settings, family, record))
	}
	pull := sourcecdk.Pull{
		Events: events,
		Checkpoint: &cerebrov1.SourceCheckpoint{
			Watermark:    events[len(events)-1].OccurredAt,
			CursorOpaque: checkpointCursor(next, events[len(events)-1].Id),
		},
	}
	if strings.TrimSpace(next) != "" {
		pull.NextCursor = &cerebrov1.SourceCursor{Opaque: strings.TrimSpace(next)}
	}
	return pull, nil
}

func eventFromRecord(settings settings, family string, record record) *primitives.Event {
	occurredAt := occurredAtFor(record.Values)
	attrs := attributesFor(family, record.Values)
	attrs["record_id"] = record.ID
	trimEmptyAttributes(attrs)
	return &primitives.Event{
		Id:         eventID(settings, family, record.ID),
		TenantId:   settings.tenantID,
		SourceId:   sourceID,
		Kind:       "cosmo." + family,
		OccurredAt: timestamppb.New(occurredAt),
		SchemaRef:  "cosmo/" + family + "/v1",
		Payload:    cloneRaw(record.Raw),
		Attributes: attrs,
	}
}

func eventID(settings settings, family string, recordID string) string {
	return strings.Join([]string{sourceID, normalizeID(settings.tenantID), family, sourcecdk.StableExternalID(recordID, "unknown")}, "-")
}

func attributesFor(family string, values map[string]any) map[string]string {
	attrs := map[string]string{}
	switch family {
	case familySession:
		attrs["ticket_id"] = firstValueString(values, "ticket_id")
		attrs["thread_key"] = firstValueString(values, "thread_key")
		attrs["user"] = firstValueString(values, "user")
		attrs["agent_type"] = firstValueString(values, "agent_type")
		attrs["status"] = firstValueString(values, "status")
		attrs["source"] = firstValueString(values, "source")
	case familyFact:
		attrs["key"], attrs["category"] = firstValueString(values, "key"), firstValueString(values, "category")
		attrs["source"], attrs["confidence"] = firstValueString(values, "source"), firstValueString(values, "confidence")
		attrs["risk_reason"] = firstValueString(values, "risk_reason")
		attrs["risk_severity"] = firstValueString(values, "risk_severity", "severity")
	case familyMessage:
		attrs["ticket_id"] = firstValueString(values, "ticket_id")
		attrs["event_type"] = firstValueString(values, "event_type")
		attrs["role"] = firstValueString(values, "role")
		attrs["user"] = firstValueString(values, "user", "username")
		attrs["user_id"] = firstValueString(values, "user_id", "userId", "user.id")
		attrs["email"] = firstValueString(values, "email", "user_email", "userEmail", "user.email")
		attrs["tool_name"] = firstValueString(values, "tool_name")
		attrs["agent_type"] = firstValueString(values, "agent_type")
		attrs["run_url"] = firstValueString(values, "run_url")
	case familySurveyFeedback:
		attrs["ticket_id"] = firstValueString(values, "ticketId")
		attrs["channel"] = firstValueString(values, "channel")
		attrs["user_id"] = firstValueString(values, "userId")
		attrs["reaction"] = firstValueString(values, "reaction")
		attrs["sentiment"] = firstValueString(values, "sentiment")
		attrs["workflow_run_url"] = firstValueString(values, "workflowRunUrl")
	}
	return attrs
}

func familyPageSize(settings settings, family string) int {
	limit := settings.perPage
	switch family {
	case familySession:
		if limit > 100 {
			return 100
		}
	case familyFact:
		if limit > 200 {
			return 200
		}
	}
	return limit
}

func pageRecords(records []record, offset int, limit int) ([]record, string) {
	if offset >= len(records) {
		return nil, ""
	}
	end := offset + limit
	if end > len(records) {
		end = len(records)
	}
	next := ""
	if end < len(records) {
		next = strconv.Itoa(end)
	}
	return records[offset:end], next
}

func readOffset(cursor *cerebrov1.SourceCursor) (int, error) {
	if cursor == nil || strings.TrimSpace(cursor.Opaque) == "" {
		return 0, nil
	}
	offset, err := strconv.Atoi(strings.TrimSpace(cursor.Opaque))
	if err != nil {
		return 0, fmt.Errorf("parse cosmo cursor: %w", err)
	}
	if offset < 0 {
		return 0, fmt.Errorf("cosmo cursor must be non-negative")
	}
	return offset, nil
}

func occurredAtFor(values map[string]any) time.Time {
	for _, key := range []string{"updated_at", "created_at", "feedbackAt", "surveyCreatedAt", "date"} {
		if parsed, ok := parseTime(valueString(valueAt(values, key))); ok {
			return parsed.UTC()
		}
	}
	return time.Unix(0, 0).UTC()
}

func parseTime(value string) (time.Time, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05", "2006-01-02"} {
		parsed, err := time.Parse(layout, value)
		if err == nil {
			return parsed, true
		}
	}
	return time.Time{}, false
}

func minTime(left time.Time, right time.Time) time.Time {
	if left.Before(right) {
		return left
	}
	return right
}

func checkpointCursor(next string, fallback string) string {
	if strings.TrimSpace(next) != "" {
		return strings.TrimSpace(next)
	}
	return strings.TrimSpace(fallback)
}

func normalizeID(value string) string {
	if value = strings.TrimSpace(value); value == "" {
		return "unknown"
	}
	replacer := strings.NewReplacer(" ", "-", "/", "-", ":", "-", "\n", "-", "\t", "-")
	return replacer.Replace(value)
}

func trimEmptyAttributes(attrs map[string]string) {
	for key, value := range attrs {
		if strings.TrimSpace(value) == "" {
			delete(attrs, key)
			continue
		}
		attrs[key] = strings.TrimSpace(value)
	}
}
