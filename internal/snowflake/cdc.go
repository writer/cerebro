package snowflake

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/warehouse"
)

// CDCEvent is an alias for warehouse.CDCEvent for backward compatibility.
type CDCEvent = warehouse.CDCEvent

// EnsureCDCEventsTable creates the CDC_EVENTS table if it does not exist.
// Uses mutex + flag so transient failures don't permanently poison the cache.
func (c *Client) EnsureCDCEventsTable(ctx context.Context) error {
	c.cdcSchemaMu.Lock()
	defer c.cdcSchemaMu.Unlock()
	if c.cdcSchemaReady {
		return nil
	}
	query := `CREATE TABLE IF NOT EXISTS CDC_EVENTS (
        event_id VARCHAR PRIMARY KEY,
        table_name VARCHAR,
        resource_id VARCHAR,
        change_type VARCHAR,
        provider VARCHAR,
        region VARCHAR,
        account_id VARCHAR,
        payload VARIANT,
        payload_hash VARCHAR,
        event_time TIMESTAMP_TZ,
        ingested_at TIMESTAMP_TZ DEFAULT CURRENT_TIMESTAMP()
    )`
	if _, err := c.Exec(ctx, query); err != nil {
		return err
	}
	c.cdcSchemaReady = true
	return nil
}

// InsertCDCEvents writes CDC events idempotently to CDC_EVENTS.
func (c *Client) InsertCDCEvents(ctx context.Context, events []CDCEvent) error {
	if len(events) == 0 {
		return nil
	}
	if err := c.EnsureCDCEventsTable(ctx); err != nil {
		return err
	}

	const batchSize = 500
	for i := 0; i < len(events); i += batchSize {
		end := i + batchSize
		if end > len(events) {
			end = len(events)
		}
		if err := c.insertCDCEventBatch(ctx, events[i:end]); err != nil {
			return err
		}
	}

	return nil
}

func (c *Client) insertCDCEventBatch(ctx context.Context, events []CDCEvent) error {
	rows := make([]string, 0, len(events))

	for _, event := range events {
		eventTime := event.EventTime
		if eventTime.IsZero() {
			eventTime = time.Now().UTC()
		}
		eventID := event.EventID
		if eventID == "" {
			eventID = BuildCDCEventID(event.TableName, event.ResourceID, event.ChangeType, event.PayloadHash, eventTime)
		}

		payloadValue := "NULL"
		if event.Payload != nil {
			jsonVal, _ := json.Marshal(event.Payload)
			escaped := escapeSnowflakeString(string(jsonVal))
			payloadValue = fmt.Sprintf("PARSE_JSON('%s')", escaped)
		}

		row := fmt.Sprintf(
			"SELECT %s AS event_id, %s AS table_name, %s AS resource_id, %s AS change_type, %s AS provider, %s AS region, %s AS account_id, %s AS payload, %s AS payload_hash, TO_TIMESTAMP_TZ('%s') AS event_time",
			sqlStringOrNull(eventID),
			sqlStringOrNull(event.TableName),
			sqlStringOrNull(event.ResourceID),
			sqlStringOrNull(event.ChangeType),
			sqlStringOrNull(event.Provider),
			sqlStringOrNull(event.Region),
			sqlStringOrNull(event.AccountID),
			payloadValue,
			sqlStringOrNull(event.PayloadHash),
			escapeSnowflakeString(eventTime.UTC().Format(time.RFC3339Nano)),
		)
		rows = append(rows, row)
	}

	source := strings.Join(rows, " UNION ALL ")
	query := fmt.Sprintf(`
        MERGE INTO CDC_EVENTS t
        USING (%s) s
        ON t.event_id = s.event_id
        WHEN NOT MATCHED THEN INSERT (
            event_id, table_name, resource_id, change_type, provider, region, account_id, payload, payload_hash, event_time
        ) VALUES (
            s.event_id, s.table_name, s.resource_id, s.change_type, s.provider, s.region, s.account_id, s.payload, s.payload_hash, s.event_time
        )`, source)

	_, err := c.Exec(ctx, query)
	return err
}

// GetCDCEvents returns CDC events for a table since the provided time.
func (c *Client) GetCDCEvents(ctx context.Context, table string, since time.Time, limit int) ([]CDCEvent, error) {
	if limit <= 0 {
		limit = 1000
	}

	if err := c.EnsureCDCEventsTable(ctx); err != nil {
		return nil, err
	}

	query := `SELECT event_id, table_name, resource_id, change_type, provider, region, account_id, payload_hash, event_time
        FROM CDC_EVENTS`
	var conditions []string
	var args []interface{}

	if table != "" {
		conditions = append(conditions, "table_name = ?")
		args = append(args, table)
	}
	if !since.IsZero() {
		conditions = append(conditions, "event_time > ?")
		args = append(args, since)
	}

	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}

	query += " ORDER BY event_time ASC LIMIT ?"
	args = append(args, limit)

	result, err := c.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}

	events := make([]CDCEvent, 0, result.Count)
	for _, row := range result.Rows {
		events = append(events, cdcEventFromRow(row))
	}

	return events, nil
}

func cdcEventFromRow(row map[string]interface{}) CDCEvent {
	return CDCEvent{
		EventID:     queryRowString(row, "event_id"),
		TableName:   queryRowString(row, "table_name"),
		ResourceID:  queryRowString(row, "resource_id"),
		ChangeType:  queryRowString(row, "change_type"),
		Provider:    queryRowString(row, "provider"),
		Region:      queryRowString(row, "region"),
		AccountID:   queryRowString(row, "account_id"),
		PayloadHash: queryRowString(row, "payload_hash"),
		EventTime:   queryRowTime(row, "event_time"),
	}
}

// BuildCDCEventID builds a deterministic CDC event identifier.
// Deprecated: Use warehouse.BuildCDCEventID directly.
func BuildCDCEventID(table, resourceID, changeType, payloadHash string, eventTime time.Time) string {
	return warehouse.BuildCDCEventID(table, resourceID, changeType, payloadHash, eventTime)
}

func sqlStringOrNull(value string) string {
	if value == "" {
		return "NULL"
	}
	return fmt.Sprintf("'%s'", escapeSnowflakeString(value))
}

func escapeSnowflakeString(value string) string {
	escaped := strings.ReplaceAll(value, "\\", "\\\\")
	return strings.ReplaceAll(escaped, "'", "''")
}

func toString(value interface{}) string {
	switch typed := value.(type) {
	case string:
		return typed
	case []byte:
		return string(typed)
	default:
		if value == nil {
			return ""
		}
		return fmt.Sprintf("%v", value)
	}
}

func toTime(value interface{}) time.Time {
	switch typed := value.(type) {
	case time.Time:
		return typed
	case string:
		parsed, err := time.Parse(time.RFC3339Nano, typed)
		if err == nil {
			return parsed
		}
		parsed, err = time.Parse(time.RFC3339, typed)
		if err == nil {
			return parsed
		}
	case []byte:
		parsed, err := time.Parse(time.RFC3339Nano, string(typed))
		if err == nil {
			return parsed
		}
	}
	return time.Time{}
}
