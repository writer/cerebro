package graphingest

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/evalops/cerebro/internal/events"
	"github.com/evalops/cerebro/internal/graph"
)

// DeadLetterRecord captures one mapper write rejected by ontology validation.
type DeadLetterRecord struct {
	RecordedAt  time.Time                     `json:"recorded_at"`
	EventID     string                        `json:"event_id"`
	EventType   string                        `json:"event_type"`
	EventSource string                        `json:"event_source,omitempty"`
	MappingName string                        `json:"mapping_name"`
	EntityType  string                        `json:"entity_type"`
	EntityID    string                        `json:"entity_id"`
	EntityKind  string                        `json:"entity_kind,omitempty"`
	Payload     map[string]any                `json:"payload,omitempty"`
	Issues      []graph.SchemaValidationIssue `json:"issues"`
}

// DeadLetterSink persists mapper dead-letter records.
type DeadLetterSink interface {
	WriteDeadLetter(record DeadLetterRecord) error
}

// FileDeadLetterSink appends dead-letter records as JSONL.
type FileDeadLetterSink struct {
	path string
	mu   sync.Mutex
}

func NewFileDeadLetterSink(path string) (*FileDeadLetterSink, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("dead-letter path is required")
	}
	return &FileDeadLetterSink{path: path}, nil
}

func (s *FileDeadLetterSink) WriteDeadLetter(record DeadLetterRecord) error {
	if s == nil {
		return fmt.Errorf("dead-letter sink is nil")
	}

	record.RecordedAt = record.RecordedAt.UTC()
	if record.RecordedAt.IsZero() {
		record.RecordedAt = time.Now().UTC()
	}

	if err := os.MkdirAll(filepath.Dir(s.path), 0o750); err != nil {
		return fmt.Errorf("create dead-letter directory: %w", err)
	}

	payload, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("marshal dead-letter record: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	file, err := os.OpenFile(s.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open dead-letter file: %w", err)
	}
	defer func() {
		_ = file.Close()
	}()

	if _, err := file.Write(append(payload, '\n')); err != nil {
		return fmt.Errorf("append dead-letter record: %w", err)
	}
	return nil
}

func buildDeadLetterRecord(evt events.CloudEvent, mappingName, entityType, entityID, entityKind string, payload map[string]any, issues []graph.SchemaValidationIssue) DeadLetterRecord {
	return DeadLetterRecord{
		RecordedAt:  time.Now().UTC(),
		EventID:     strings.TrimSpace(evt.ID),
		EventType:   strings.TrimSpace(evt.Type),
		EventSource: strings.TrimSpace(evt.Source),
		MappingName: strings.TrimSpace(mappingName),
		EntityType:  strings.TrimSpace(entityType),
		EntityID:    strings.TrimSpace(entityID),
		EntityKind:  strings.TrimSpace(entityKind),
		Payload:     payload,
		Issues:      append([]graph.SchemaValidationIssue(nil), issues...),
	}
}
