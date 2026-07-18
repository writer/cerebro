package githubaudit

import (
	"encoding/json"
	"fmt"
	"time"

	gogithub "github.com/google/go-github/v66/github"
)

// RawFields contains the provider fields retained in an audit event payload.
type RawFields map[string]any

// RawEntry returns the provider fields with typed timestamps normalized so
// audit payloads remain identical across hosts with different local zones.
func RawEntry(entry *gogithub.AuditEntry) (RawFields, error) {
	payload, err := json.Marshal(entry)
	if err != nil {
		return nil, fmt.Errorf("marshal github audit raw payload: %w", err)
	}
	var raw RawFields
	if err := json.Unmarshal(payload, &raw); err != nil {
		return nil, fmt.Errorf("unmarshal github audit raw payload: %w", err)
	}
	// go-github converts numeric audit timestamps through time.Local when it
	// marshals AuditEntry. Restore one canonical representation explicitly.
	if entry.Timestamp != nil && !entry.Timestamp.IsZero() {
		raw["@timestamp"] = entry.Timestamp.UTC().Format(time.RFC3339Nano)
	}
	if entry.CreatedAt != nil && !entry.CreatedAt.IsZero() {
		raw["created_at"] = entry.CreatedAt.UTC().Format(time.RFC3339Nano)
	}
	return raw, nil
}
