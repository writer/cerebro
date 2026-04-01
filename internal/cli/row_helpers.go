package cli

import (
	"strings"
	"time"
)

func scheduleRowValue(row map[string]interface{}, key string) interface{} {
	for candidate, value := range row {
		if strings.EqualFold(candidate, key) {
			return value
		}
	}
	return nil
}

func getTime(row map[string]interface{}, key string) time.Time {
	switch value := scheduleRowValue(row, key).(type) {
	case time.Time:
		return value.UTC()
	case *time.Time:
		if value != nil {
			return value.UTC()
		}
	case string:
		if value == "" {
			return time.Time{}
		}
		if ts, err := time.Parse(time.RFC3339Nano, value); err == nil {
			return ts.UTC()
		}
		if ts, err := time.Parse(time.RFC3339, value); err == nil {
			return ts.UTC()
		}
		if ts, err := time.Parse("2006-01-02 15:04:05.999999999-07:00", value); err == nil {
			return ts.UTC()
		}
		if ts, err := time.Parse("2006-01-02 15:04:05.999999999", value); err == nil {
			return ts.UTC()
		}
		if ts, err := time.Parse("2006-01-02 15:04:05", value); err == nil {
			return ts.UTC()
		}
	case []byte:
		text := string(value)
		if text == "" {
			return time.Time{}
		}
		if ts, err := time.Parse(time.RFC3339Nano, text); err == nil {
			return ts.UTC()
		}
		if ts, err := time.Parse(time.RFC3339, text); err == nil {
			return ts.UTC()
		}
		if ts, err := time.Parse("2006-01-02 15:04:05.999999999-07:00", text); err == nil {
			return ts.UTC()
		}
		if ts, err := time.Parse("2006-01-02 15:04:05.999999999", text); err == nil {
			return ts.UTC()
		}
		if ts, err := time.Parse("2006-01-02 15:04:05", text); err == nil {
			return ts.UTC()
		}
	}
	return time.Time{}
}
