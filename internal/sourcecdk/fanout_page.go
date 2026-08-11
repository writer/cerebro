package sourcecdk

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

type fanoutPageCursor struct {
	ParentID         string `json:"parent_id"`
	NextParentCursor string `json:"next_parent_cursor,omitempty"`
	AfterRecordID    string `json:"after_record_id,omitempty"`
}

// PageFanoutRecords bounds a child collection while preserving the provider's
// parent cursor. It is intended for APIs that list parents first and expose all
// children for one parent without child pagination.
func PageFanoutRecords[T any](
	rawCursor string,
	cursorPrefix string,
	limit int,
	configuredParentID string,
	resolveParent func(string) (string, string, error),
	readRecords func(string) ([]T, error),
	recordID func(T) string,
) ([]T, string, error) {
	if limit <= 0 {
		return nil, "", fmt.Errorf("fanout page limit must be positive")
	}
	state, providerCursor, encoded, err := decodeFanoutPageCursor(rawCursor, cursorPrefix)
	if err != nil {
		return nil, "", err
	}
	configuredParentID = strings.TrimSpace(configuredParentID)
	if configuredParentID != "" {
		if !encoded && strings.TrimSpace(rawCursor) != "" {
			return nil, "", nil
		}
		if state.ParentID != "" && state.ParentID != configuredParentID {
			return nil, "", fmt.Errorf("fanout cursor parent does not match configured parent")
		}
		state.ParentID, state.NextParentCursor = configuredParentID, ""
	} else if state.ParentID == "" {
		state.ParentID, state.NextParentCursor, err = resolveParent(providerCursor)
		if err != nil {
			return nil, "", err
		}
	}
	if state.ParentID == "" {
		return nil, state.NextParentCursor, nil
	}
	records, err := readRecords(state.ParentID)
	if err != nil {
		return nil, "", err
	}
	sort.Slice(records, func(i, j int) bool { return recordID(records[i]) < recordID(records[j]) })
	for index, record := range records {
		id := strings.TrimSpace(recordID(record))
		if id == "" || (index > 0 && id == strings.TrimSpace(recordID(records[index-1]))) {
			return nil, "", fmt.Errorf("fanout record identity must be non-empty and unique")
		}
	}
	start := sort.Search(len(records), func(index int) bool { return recordID(records[index]) > state.AfterRecordID })
	end := start + limit
	if end > len(records) {
		end = len(records)
	}
	page := records[start:end]
	if end == len(records) {
		return page, state.NextParentCursor, nil
	}
	state.AfterRecordID = recordID(records[end-1])
	next, err := encodeFanoutPageCursor(state, cursorPrefix)
	if err != nil {
		return nil, "", err
	}
	return page, next, nil
}

func decodeFanoutPageCursor(raw string, prefix string) (fanoutPageCursor, string, bool, error) {
	trimmed := strings.TrimSpace(raw)
	if !strings.HasPrefix(trimmed, prefix) {
		return fanoutPageCursor{}, trimmed, false, nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(trimmed, prefix))
	if err != nil {
		return fanoutPageCursor{}, "", true, fmt.Errorf("decode fanout cursor: %w", err)
	}
	var state fanoutPageCursor
	if err := json.Unmarshal(payload, &state); err != nil {
		return fanoutPageCursor{}, "", true, fmt.Errorf("decode fanout cursor payload: %w", err)
	}
	state.ParentID = strings.TrimSpace(state.ParentID)
	state.NextParentCursor = strings.TrimSpace(state.NextParentCursor)
	state.AfterRecordID = strings.TrimSpace(state.AfterRecordID)
	if state.ParentID == "" {
		return fanoutPageCursor{}, "", true, fmt.Errorf("fanout cursor parent is required")
	}
	return state, "", true, nil
}

func encodeFanoutPageCursor(state fanoutPageCursor, prefix string) (string, error) {
	payload, err := json.Marshal(state)
	if err != nil {
		return "", fmt.Errorf("encode fanout cursor: %w", err)
	}
	return prefix + base64.RawURLEncoding.EncodeToString(payload), nil
}
