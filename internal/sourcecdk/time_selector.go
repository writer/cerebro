package sourcecdk

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ParseTimeSelector resolves a time-window selector that is either a relative
// simplified ISO-8601 duration (interpreted as that span before now) or an
// absolute RFC3339 timestamp. Values beginning with "P" (case-insensitive) are
// treated as durations; all other values are parsed as RFC3339 timestamps.
func ParseTimeSelector(value string, now time.Time) (time.Time, error) {
	trimmed := strings.TrimSpace(value)
	if strings.HasPrefix(strings.ToUpper(trimmed), "P") {
		duration, err := parseSimpleISODuration(trimmed)
		if err != nil {
			return time.Time{}, err
		}
		return now.Add(-duration), nil
	}
	return time.Parse(time.RFC3339, trimmed)
}

func parseSimpleISODuration(value string) (time.Duration, error) {
	normalized := strings.ToUpper(strings.TrimSpace(value))
	if normalized == "" || normalized[0] != 'P' {
		return 0, fmt.Errorf("duration must start with P")
	}
	remaining := strings.TrimPrefix(normalized, "P")
	days := 0
	if index := strings.Index(remaining, "D"); index >= 0 {
		parsed, err := strconv.Atoi(remaining[:index])
		if err != nil {
			return 0, err
		}
		days = parsed
		remaining = remaining[index+1:]
	}
	hours := 0
	minutes := 0
	if strings.HasPrefix(remaining, "T") {
		remaining = strings.TrimPrefix(remaining, "T")
		if index := strings.Index(remaining, "H"); index >= 0 {
			parsed, err := strconv.Atoi(remaining[:index])
			if err != nil {
				return 0, err
			}
			hours = parsed
			remaining = remaining[index+1:]
		}
		if index := strings.Index(remaining, "M"); index >= 0 {
			parsed, err := strconv.Atoi(remaining[:index])
			if err != nil {
				return 0, err
			}
			minutes = parsed
		}
	}
	if days == 0 && hours == 0 && minutes == 0 {
		return 0, fmt.Errorf("duration must include days, hours, or minutes")
	}
	return time.Duration(days)*24*time.Hour + time.Duration(hours)*time.Hour + time.Duration(minutes)*time.Minute, nil
}
