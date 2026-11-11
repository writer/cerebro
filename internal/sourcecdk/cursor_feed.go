package sourcecdk

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/primitives"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// CursorFeedPage is the decoded shape of a paginated JSON feed that reports
// an opaque resume cursor and an explicit "more data available" flag
// alongside its items, rather than treating an empty Items slice as the only
// end-of-feed signal. A source decodes a page response directly into this
// type (it is a valid json.Unmarshal target) instead of declaring its own
// {items, nextCursor, hasMore} envelope.
type CursorFeedPage struct {
	Items      []json.RawMessage `json:"items"`
	NextCursor string            `json:"nextCursor"`
	HasMore    bool              `json:"hasMore"`
}

// NextOpaqueCursor applies the authoritative continuation signal for a
// CursorFeedPage: HasMore, not an empty Items slice, decides whether paging
// continues. An empty filtered page with HasMore true still returns its
// cursor, so a resumed read continues instead of stopping early.
func (p CursorFeedPage) NextOpaqueCursor() string {
	if !p.HasMore {
		return ""
	}
	return strings.TrimSpace(p.NextCursor)
}

// CursorFeedQuery builds the query parameters for one page of a cursor-paged
// feed: a bounded page size, an optional resume cursor, and any fixed
// provider-required parameters (e.g. a filter scoping the feed to one
// upstream source). Parameters with blank values are omitted.
func CursorFeedQuery(params map[string]string, pageSize int, cursor string) url.Values {
	query := url.Values{}
	for key, value := range params {
		AddQueryParam(query, key, value)
	}
	query.Set("limit", strconv.Itoa(pageSize))
	AddQueryParam(query, "cursor", cursor)
	return query
}

// ClampPageSize bounds pageSize to [1, max], defaulting to max when pageSize
// is zero, negative, or exceeds max.
func ClampPageSize(pageSize int, max int) int {
	if pageSize <= 0 || pageSize > max {
		return max
	}
	return pageSize
}

// CursorFeedCheckpointPull builds a Pull for a cursor-feed family whose every
// page -- including an empty or terminal one -- returns a resumable
// checkpoint (CursorEnvelope, ResumableCheckpoint:true) carrying the page's
// raw nextCursor as Token, so a later sync resumes from exactly that
// provider cursor instead of re-traversing the whole feed. Pull.NextCursor
// (the in-sync continuation cursor) is set only when the page reports
// HasMore, carrying the same raw cursor unwrapped. The checkpoint watermark
// is the max of the prior checkpoint's watermark and the newest emitted
// event's OccurredAt, so it never moves backwards.
func CursorFeedCheckpointPull[T any](source string, family string, records []T, page CursorFeedPage, checkpoint *cerebrov1.SourceCheckpoint, build func(T) (*primitives.Event, error)) (Pull, error) {
	events := make([]*primitives.Event, 0, len(records))
	watermark := CursorFeedPriorWatermark(checkpoint)
	for _, rec := range records {
		event, err := build(rec)
		if err != nil {
			return Pull{}, err
		}
		events = append(events, event)
		if occurredAt := event.GetOccurredAt().AsTime(); occurredAt.After(watermark) {
			watermark = occurredAt
		}
	}
	envelope := CursorEnvelope{
		Source:              source,
		Family:              family,
		Mode:                "cursor_feed",
		ResumableCheckpoint: true,
		Token:               strings.TrimSpace(page.NextCursor),
	}
	SetCursorWatermark(&envelope, watermark)
	cursorOpaque, err := EncodeCursorEnvelope(envelope)
	if err != nil {
		return Pull{}, fmt.Errorf("encode %s %s cursor checkpoint: %w", source, family, err)
	}
	pull := Pull{
		Events:     events,
		Checkpoint: &cerebrov1.SourceCheckpoint{CursorOpaque: cursorOpaque},
	}
	if !watermark.IsZero() {
		pull.Checkpoint.Watermark = timestamppb.New(watermark)
	}
	if next := page.NextOpaqueCursor(); next != "" {
		pull.NextCursor = &cerebrov1.SourceCursor{Opaque: next}
	}
	return pull, nil
}

// CursorFeedPriorWatermark reads the later of the prior checkpoint's durable
// watermark and the watermark carried in its cursor envelope (the envelope
// this family itself wrote on the previous page), so a page that emits no
// newer events never regresses the stored watermark.
func CursorFeedPriorWatermark(checkpoint *cerebrov1.SourceCheckpoint) time.Time {
	var watermark time.Time
	if ts := checkpoint.GetWatermark(); ts != nil {
		watermark = ts.AsTime()
	}
	if envelope, ok := DecodeCursorEnvelope(checkpoint.GetCursorOpaque()); ok {
		if w := CursorWatermark(envelope); w.After(watermark) {
			watermark = w
		}
	}
	return watermark
}

// CursorFeedPageToList adapts a cursor-feed page-fetch function -- one that
// returns the decoded records alongside the raw CursorFeedPage -- to the
// legacy (records, nextOpaqueCursor, error) list shape that simpler
// Check/Discover/Read implementations still expect, applying
// CursorFeedPage.NextOpaqueCursor's HasMore-driven continuation rule.
func CursorFeedPageToList[S any, T any](page func(context.Context, S, string, int) ([]T, CursorFeedPage, error)) func(context.Context, S, string, int) ([]T, string, error) {
	return func(ctx context.Context, settings S, cursor string, pageSize int) ([]T, string, error) {
		records, p, err := page(ctx, settings, cursor, pageSize)
		if err != nil {
			return nil, "", err
		}
		return records, p.NextOpaqueCursor(), nil
	}
}
