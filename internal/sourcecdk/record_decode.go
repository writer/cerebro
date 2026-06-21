package sourcecdk

import (
	"encoding/json"
	"fmt"
)

// DecodeRecords unmarshals raw JSON list items into typed records. The optional
// setRaw hook receives the verbatim bytes for each item so callers can retain
// the original payload alongside the decoded value. The label is used only for
// error context.
func DecodeRecords[T any](rawRecords []json.RawMessage, label string, setRaw func(*T, json.RawMessage)) ([]T, error) {
	records := make([]T, 0, len(rawRecords))
	for _, raw := range rawRecords {
		var record T
		if err := json.Unmarshal(raw, &record); err != nil {
			return nil, fmt.Errorf("decode %s: %w", label, err)
		}
		if setRaw != nil {
			setRaw(&record, raw)
		}
		records = append(records, record)
	}
	return records, nil
}
