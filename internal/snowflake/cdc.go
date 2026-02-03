package snowflake

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// CDCEvent represents a change data capture event for an asset table.
type CDCEvent struct {
	EventID     string
	TableName   string
	ResourceID  string
	ChangeType  string
	Provider    string
	Region      string
	AccountID   string
	Payload     interface{}
	PayloadHash string
	EventTime   time.Time
}

// EnsureCDCEventsTable creates the CDC_EVENTS table if it does not exist.
func (c *Client) EnsureCDCEventsTable(ctx context.Context) error {
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
	_, err := c.Exec(ctx, query)
	return err
}

// InsertCDCEvents writes CDC events idempotently to CDC_EVENTS.
func (c *Client) InsertCDCEvents(ctx context.Context, events []CDCEvent) error {
	if len(events) == 0 {
		return nil
	}
	if err := c.EnsureCDCEventsTable(ctx); err != nil {
		return err
	}

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

		query := fmt.Sprintf(`
            MERGE INTO CDC_EVENTS t
            USING (
                SELECT %s AS event_id,
                    %s AS table_name,
                    %s AS resource_id,
                    %s AS change_type,
                    %s AS provider,
                    %s AS region,
                    %s AS account_id,
                    %s AS payload,
                    %s AS payload_hash,
                    TO_TIMESTAMP_TZ('%s') AS event_time
            ) s
            ON t.event_id = s.event_id
            WHEN NOT MATCHED THEN INSERT (
                event_id,
                table_name,
                resource_id,
                change_type,
                provider,
                region,
                account_id,
                payload,
                payload_hash,
                event_time
            ) VALUES (
                s.event_id,
                s.table_name,
                s.resource_id,
                s.change_type,
                s.provider,
                s.region,
                s.account_id,
                s.payload,
                s.payload_hash,
                s.event_time
            )`,
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

		if _, err := c.Exec(ctx, query); err != nil {
			return err
		}
	}

	return nil
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
		events = append(events, CDCEvent{
			EventID:     toString(row["EVENT_ID"]),
			TableName:   toString(row["TABLE_NAME"]),
			ResourceID:  toString(row["RESOURCE_ID"]),
			ChangeType:  toString(row["CHANGE_TYPE"]),
			Provider:    toString(row["PROVIDER"]),
			Region:      toString(row["REGION"]),
			AccountID:   toString(row["ACCOUNT_ID"]),
			PayloadHash: toString(row["PAYLOAD_HASH"]),
			EventTime:   toTime(row["EVENT_TIME"]),
		})
	}

	return events, nil
}

// BuildCDCEventID builds a deterministic CDC event identifier.
func BuildCDCEventID(table, resourceID, changeType, payloadHash string, eventTime time.Time) string {
	seed := fmt.Sprintf("%s|%s|%s|%s|%s", table, resourceID, changeType, payloadHash, eventTime.UTC().Format(time.RFC3339Nano))
	sum := sha256.Sum256([]byte(seed))
	return hex.EncodeToString(sum[:])
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
