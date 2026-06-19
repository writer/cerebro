package sourcecdk

import (
	"encoding/json"
	"fmt"
	"strings"
)

type ListResponsePagination struct {
	NextCursor string
	TotalItems int
}

func DecodeListResponseData(raw json.RawMessage, label string, arrayKeys ...string) ([]json.RawMessage, ListResponsePagination, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return nil, ListResponsePagination{}, nil
	}
	if strings.HasPrefix(trimmed, "[") {
		var records []json.RawMessage
		if err := json.Unmarshal(raw, &records); err != nil {
			return nil, ListResponsePagination{}, fmt.Errorf("decode %s data array: %w", label, err)
		}
		return records, ListResponsePagination{}, nil
	}
	if !strings.HasPrefix(trimmed, "{") {
		return nil, ListResponsePagination{}, fmt.Errorf("decode %s data: expected array or object", label)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		return nil, ListResponsePagination{}, fmt.Errorf("decode %s data object: %w", label, err)
	}
	pagination := listPaginationFromObject(object)
	for _, key := range append(arrayKeys, "items", "records", "data") {
		value := object[key]
		if len(value) == 0 || strings.TrimSpace(string(value)) == "null" || !strings.HasPrefix(strings.TrimSpace(string(value)), "[") {
			continue
		}
		var records []json.RawMessage
		if err := json.Unmarshal(value, &records); err != nil {
			return nil, ListResponsePagination{}, fmt.Errorf("decode %s data.%s array: %w", label, key, err)
		}
		return records, pagination, nil
	}
	return nil, ListResponsePagination{}, fmt.Errorf("decode %s data object: missing records array", label)
}

func listPaginationFromObject(object map[string]json.RawMessage) ListResponsePagination {
	var pagination ListResponsePagination
	if raw := object["pagination"]; len(raw) > 0 && strings.TrimSpace(string(raw)) != "null" {
		_ = json.Unmarshal(raw, &pagination)
	}
	if pagination.NextCursor == "" {
		_ = json.Unmarshal(object["nextCursor"], &pagination.NextCursor)
	}
	if pagination.TotalItems == 0 {
		_ = json.Unmarshal(object["totalItems"], &pagination.TotalItems)
	}
	return pagination
}
