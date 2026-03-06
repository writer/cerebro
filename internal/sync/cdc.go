package sync

import (
	"time"

	"github.com/evalops/cerebro/internal/snowflake"
)

const (
	cdcChangeAdded    = "added"
	cdcChangeModified = "modified"
	cdcChangeRemoved  = "removed"
)

func buildRowLookup(rows []map[string]interface{}) map[string]map[string]interface{} {
	lookup := make(map[string]map[string]interface{}, len(rows))
	for _, row := range rows {
		if id, ok := row["_cq_id"].(string); ok && id != "" {
			lookup[id] = row
		}
	}
	return lookup
}

func buildCDCEventsFromChanges(table, provider, region, account string, changes *ChangeSet, rows map[string]map[string]interface{}, syncTime time.Time, hashFunc func(map[string]interface{}) string) []snowflake.CDCEvent {
	if changes == nil {
		return nil
	}

	eventTime := syncTime
	if eventTime.IsZero() {
		eventTime = time.Now().UTC()
	}

	events := make([]snowflake.CDCEvent, 0, len(changes.Added)+len(changes.Modified)+len(changes.Removed))
	appendEvent := func(changeType, id string, row map[string]interface{}) {
		payload := interface{}(nil)
		payloadHash := ""
		accountID := account
		regionValue := region

		if row != nil && changeType != cdcChangeRemoved {
			payload = copyPayload(row)
			if hashFunc != nil {
				payloadHash = hashFunc(row)
			}
			if accountID == "" {
				accountID = extractString(row, "account_id", "account", "project")
			}
			if regionValue == "" {
				regionValue = extractString(row, "region", "location")
			}
		}

		events = append(events, snowflake.CDCEvent{
			EventID:     snowflake.BuildCDCEventID(table, id, changeType, payloadHash, eventTime),
			TableName:   table,
			ResourceID:  id,
			ChangeType:  changeType,
			Provider:    provider,
			Region:      regionValue,
			AccountID:   accountID,
			Payload:     payload,
			PayloadHash: payloadHash,
			EventTime:   eventTime,
		})
	}

	for _, id := range changes.Added {
		appendEvent(cdcChangeAdded, id, rows[id])
	}
	for _, id := range changes.Modified {
		appendEvent(cdcChangeModified, id, rows[id])
	}
	for _, id := range changes.Removed {
		appendEvent(cdcChangeRemoved, id, nil)
	}

	return events
}

func copyPayload(row map[string]interface{}) map[string]interface{} {
	payload := make(map[string]interface{}, len(row))
	for key, value := range row {
		if key == "_cq_id" || key == "_cq_hash" {
			continue
		}
		payload[key] = value
	}
	return payload
}

func extractString(row map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		if value, ok := row[key]; ok {
			switch typed := value.(type) {
			case string:
				if typed != "" {
					return typed
				}
			case []byte:
				if len(typed) > 0 {
					return string(typed)
				}
			}
		}
	}
	return ""
}
