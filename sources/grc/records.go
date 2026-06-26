package grc

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/primitives"
	"github.com/writer/cerebro/internal/sourcecdk"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type grcRecord struct {
	Raw    json.RawMessage
	Values map[string]any
	ID     string
}

func parseRecord(family grcFamily, raw json.RawMessage) (grcRecord, error) {
	values := map[string]any{}
	if err := json.Unmarshal(raw, &values); err != nil {
		return grcRecord{}, fmt.Errorf("decode grc %s record: %w", string(family), err)
	}
	id := recordID(family, values, raw)
	return grcRecord{
		Raw:    append(json.RawMessage(nil), raw...),
		Values: values,
		ID:     id,
	}, nil
}

func urnsFor(settings settings, family grcFamily, records []grcRecord) ([]sourcecdk.URN, error) {
	urns := make([]sourcecdk.URN, 0, len(records))
	for _, record := range records {
		urn, err := sourcecdk.ParseURN(fmt.Sprintf("urn:cerebro:%s:grc_%s:%s:%s", settings.tenantID, string(family), settings.provider, record.ID))
		if err != nil {
			return nil, err
		}
		urns = append(urns, urn)
	}
	return urns, nil
}

func pullFromRecords(settings settings, family grcFamily, records []grcRecord, next string) (sourcecdk.Pull, error) {
	return sourcecdk.PullFromRecords(records, next,
		func(rec grcRecord) (*primitives.Event, error) {
			return eventFromRecord(settings, family, rec), nil
		},
		func(rec grcRecord) string { return strings.TrimSpace(rec.ID) },
	)
}

func eventFromRecord(settings settings, family grcFamily, record grcRecord) *primitives.Event {
	occurredAt := occurredAtFor(family, record.Values)
	payload := append([]byte(nil), record.Raw...)
	return &primitives.Event{
		Id:         grcEventID(settings, family, record.ID),
		TenantId:   settings.tenantID,
		SourceId:   sourceID,
		Kind:       "grc." + string(family),
		OccurredAt: timestamppb.New(occurredAt),
		SchemaRef:  "grc/" + string(family) + "/v1",
		Payload:    payload,
		Attributes: attributesFor(settings, family, record),
	}
}

func grcEventID(settings settings, family grcFamily, recordID string) string {
	return strings.Join([]string{
		"grc",
		normalizeID(settings.provider),
		normalizeID(settings.tenantID),
		grcRuntimeScope(settings),
		normalizeID(string(family)),
		normalizeID(recordID),
	}, "-")
}

func grcRuntimeScope(settings settings) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		settings.baseURL,
		settings.clientID,
		settings.scope,
	}, "\x00")))
	return hex.EncodeToString(sum[:])[:12]
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func recordID(family grcFamily, values map[string]any, raw json.RawMessage) string {
	for _, key := range grcDescriptorFor(family).IDKeys {
		if value := fieldString(values, key); value != "" {
			return normalizeID(value)
		}
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])[:16]
}

func normalizeID(value string) string {
	value = strings.TrimSpace(value)
	value = strings.ReplaceAll(value, "/", "_")
	return strings.ReplaceAll(value, " ", "_")
}

func occurredAtFor(family grcFamily, values map[string]any) time.Time {
	for _, key := range grcDescriptorFor(family).TimestampKeys {
		if value := fieldString(values, key); value != "" {
			if parsed, err := time.Parse(time.RFC3339Nano, value); err == nil {
				return parsed.UTC()
			}
			if parsed, err := time.Parse(time.RFC3339, value); err == nil {
				return parsed.UTC()
			}
		}
	}
	return time.Now().UTC()
}

func fieldString(values map[string]any, path string) string {
	return sourcecdk.JSONObject(values).FieldString(path)
}

func valueString(value any) string {
	return (sourcecdk.JSONScalar{Value: value}).SourceString()
}

func arrayValue(values map[string]any, key string) []any {
	return []any(sourcecdk.JSONObject(values).Array(key))
}
