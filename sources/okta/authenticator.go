package okta

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/writer/cerebro/internal/primitives"
)

const familyAuthenticator = "authenticator"

type authenticatorRecord struct {
	ID      string     `json:"id"`
	Key     string     `json:"key"`
	Name    string     `json:"name"`
	Status  string     `json:"status"`
	Type    string     `json:"type"`
	Created *time.Time `json:"created"`
	raw     json.RawMessage
}

func (s *Source) listAuthenticators(ctx context.Context, settings settings, after string, limit int) ([]authenticatorRecord, string, error) {
	query := url.Values{}
	query.Set("limit", strconv.Itoa(limit))
	addQuery(query, "after", after)
	return listJSONRecords(ctx, s, settings, "/api/v1/authenticators", query, "okta authenticator", func(record *authenticatorRecord, raw json.RawMessage) {
		record.raw = append(json.RawMessage(nil), raw...)
	})
}

func authenticatorEvent(settings settings, record authenticatorRecord) (*primitives.Event, error) {
	occurredAt := firstRecordTime(record.Created)
	raw, err := decodeRawPayload(record.raw, "okta authenticator")
	if err != nil {
		return nil, err
	}
	payload, err := json.Marshal(map[string]any{
		"domain": settings.domain,
		"id":     record.ID,
		"key":    record.Key,
		"name":   record.Name,
		"status": record.Status,
		"type":   record.Type,
		"raw":    raw,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal okta authenticator payload: %w", err)
	}
	return &primitives.Event{
		Id:         fmt.Sprintf("okta-authenticator-%s-%d", record.ID, occurredAt.UnixMilli()),
		TenantId:   settings.domain,
		SourceId:   "okta",
		Kind:       "okta.authenticator",
		OccurredAt: timestamppb.New(occurredAt),
		SchemaRef:  "okta/authenticator/v1",
		Payload:    payload,
		Attributes: map[string]string{
			"authenticator_id": record.ID,
			"domain":           settings.domain,
			"family":           familyAuthenticator,
			"key":              record.Key,
			"name":             record.Name,
			"resource_id":      record.ID,
			"resource_type":    "Authenticator",
			"status":           record.Status,
			"type":             record.Type,
		},
	}, nil
}
