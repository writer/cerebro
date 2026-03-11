package graphingest

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/events"
	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/jsonl"
)

// DeadLetterRecord captures one mapper write rejected by ontology validation.
type DeadLetterRecord struct {
	RecordedAt  time.Time                     `json:"recorded_at"`
	EventID     string                        `json:"event_id"`
	EventType   string                        `json:"event_type"`
	EventSource string                        `json:"event_source,omitempty"`
	EventTime   time.Time                     `json:"event_time,omitempty"`
	EventData   map[string]any                `json:"event_data,omitempty"`
	EventTenant string                        `json:"event_tenant,omitempty"`
	EventSpec   string                        `json:"event_specversion,omitempty"`
	EventSchema string                        `json:"event_schema,omitempty"`
	EventVer    string                        `json:"event_schema_version,omitempty"`
	EventCT     string                        `json:"event_datacontenttype,omitempty"`
	EventSubj   string                        `json:"event_subject,omitempty"`
	EventTrace  string                        `json:"event_traceparent,omitempty"`
	MappingName string                        `json:"mapping_name"`
	EntityType  string                        `json:"entity_type"`
	EntityID    string                        `json:"entity_id"`
	EntityKind  string                        `json:"entity_kind,omitempty"`
	Payload     map[string]any                `json:"payload,omitempty"`
	Issues      []graph.SchemaValidationIssue `json:"issues"`
}

// ReplayEvent reconstructs a CloudEvent from dead-letter metadata.
// Returns false when no raw event payload was captured.
func (r DeadLetterRecord) ReplayEvent() (events.CloudEvent, bool) {
	at := r.EventTime.UTC()
	if at.IsZero() {
		at = r.RecordedAt.UTC()
	}
	if at.IsZero() {
		at = time.Now().UTC()
	}
	data := cloneAnyMap(r.EventData)
	return events.CloudEvent{
		SpecVersion:     firstNonEmptyString(r.EventSpec, "1.0"),
		ID:              strings.TrimSpace(r.EventID),
		Source:          strings.TrimSpace(r.EventSource),
		Type:            strings.TrimSpace(r.EventType),
		Subject:         strings.TrimSpace(r.EventSubj),
		Time:            at,
		DataSchema:      strings.TrimSpace(r.EventSchema),
		SchemaVersion:   strings.TrimSpace(r.EventVer),
		TenantID:        strings.TrimSpace(r.EventTenant),
		TraceParent:     strings.TrimSpace(r.EventTrace),
		DataContentType: strings.TrimSpace(r.EventCT),
		Data:            data,
	}, len(data) > 0
}

// DeadLetterTailMetrics summarizes a bounded tail window of DLQ records.
type DeadLetterTailMetrics struct {
	Path              string         `json:"path"`
	Exists            bool           `json:"exists"`
	SizeBytes         int64          `json:"size_bytes,omitempty"`
	ModifiedAt        time.Time      `json:"modified_at,omitempty"`
	TailLimit         int            `json:"tail_limit"`
	TailLines         int            `json:"tail_lines"`
	RecordsParsed     int            `json:"records_parsed"`
	ParseErrors       int            `json:"parse_errors,omitempty"`
	LastRecordedAt    time.Time      `json:"last_recorded_at,omitempty"`
	IssueCodeCounts   map[string]int `json:"issue_code_counts,omitempty"`
	EntityTypeCounts  map[string]int `json:"entity_type_counts,omitempty"`
	EntityKindCounts  map[string]int `json:"entity_kind_counts,omitempty"`
	MappingNameCounts map[string]int `json:"mapping_name_counts,omitempty"`
	EventTypeCounts   map[string]int `json:"event_type_counts,omitempty"`
}

// DeadLetterScanStats describes full-file DLQ scan counters.
type DeadLetterScanStats struct {
	LinesRead     int `json:"lines_read"`
	RecordsParsed int `json:"records_parsed"`
	ParseErrors   int `json:"parse_errors"`
}

// DeadLetterSink persists mapper dead-letter records.
type DeadLetterSink interface {
	WriteDeadLetter(record DeadLetterRecord) error
}

// FileDeadLetterSink appends dead-letter records as JSONL.
type FileDeadLetterSink struct {
	sink *jsonl.FileSink
}

func NewFileDeadLetterSink(path string) (*FileDeadLetterSink, error) {
	sink, err := jsonl.NewFileSink(path)
	if err != nil {
		return nil, fmt.Errorf("dead-letter path is required: %w", err)
	}
	return &FileDeadLetterSink{sink: sink}, nil
}

func (s *FileDeadLetterSink) WriteDeadLetter(record DeadLetterRecord) error {
	if s == nil {
		return fmt.Errorf("dead-letter sink is nil")
	}

	record.RecordedAt = record.RecordedAt.UTC()
	if record.RecordedAt.IsZero() {
		record.RecordedAt = time.Now().UTC()
	}
	return s.sink.Write(record)
}

// InspectDeadLetterFile returns bounded tail summary metrics for one DLQ file.
func InspectDeadLetterFile(path string, tailLimit int) (DeadLetterTailMetrics, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return DeadLetterTailMetrics{}, fmt.Errorf("dead-letter path is required")
	}

	if tailLimit <= 0 {
		tailLimit = 25
	}
	if tailLimit > 500 {
		tailLimit = 500
	}

	metrics := DeadLetterTailMetrics{
		Path:      path,
		TailLimit: tailLimit,
	}

	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return metrics, nil
		}
		return DeadLetterTailMetrics{}, fmt.Errorf("stat dead-letter file: %w", err)
	}
	if info.IsDir() {
		return DeadLetterTailMetrics{}, fmt.Errorf("dead-letter path %q is a directory", path)
	}

	metrics.Exists = true
	metrics.SizeBytes = info.Size()
	metrics.ModifiedAt = info.ModTime().UTC()

	file, err := os.Open(path) // #nosec G304 -- operator-configured path
	if err != nil {
		return DeadLetterTailMetrics{}, fmt.Errorf("open dead-letter file: %w", err)
	}
	defer func() {
		_ = file.Close()
	}()

	lines, err := readTailLines(file, tailLimit)
	if err != nil {
		return DeadLetterTailMetrics{}, err
	}
	metrics.TailLines = len(lines)

	issueCounts := make(map[string]int)
	entityTypeCounts := make(map[string]int)
	entityKindCounts := make(map[string]int)
	mappingCounts := make(map[string]int)
	eventTypeCounts := make(map[string]int)

	for _, line := range lines {
		var record DeadLetterRecord
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			metrics.ParseErrors++
			continue
		}
		metrics.RecordsParsed++
		if record.RecordedAt.After(metrics.LastRecordedAt) {
			metrics.LastRecordedAt = record.RecordedAt.UTC()
		}
		if key := strings.TrimSpace(record.EntityType); key != "" {
			entityTypeCounts[key]++
		}
		if key := strings.TrimSpace(record.EntityKind); key != "" {
			entityKindCounts[key]++
		}
		if key := strings.TrimSpace(record.MappingName); key != "" {
			mappingCounts[key]++
		}
		if key := strings.TrimSpace(record.EventType); key != "" {
			eventTypeCounts[key]++
		}
		for _, issue := range record.Issues {
			if key := strings.TrimSpace(string(issue.Code)); key != "" {
				issueCounts[key]++
			}
		}
	}

	metrics.IssueCodeCounts = nonEmptyIntMap(issueCounts)
	metrics.EntityTypeCounts = nonEmptyIntMap(entityTypeCounts)
	metrics.EntityKindCounts = nonEmptyIntMap(entityKindCounts)
	metrics.MappingNameCounts = nonEmptyIntMap(mappingCounts)
	metrics.EventTypeCounts = nonEmptyIntMap(eventTypeCounts)
	return metrics, nil
}

// StreamDeadLetter iterates records in a dead-letter JSONL file.
// Invalid JSON lines are counted and skipped.
func StreamDeadLetter(path string, handle func(record DeadLetterRecord) error) (DeadLetterScanStats, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return DeadLetterScanStats{}, fmt.Errorf("dead-letter path is required")
	}
	file, err := os.Open(path) // #nosec G304 -- operator-configured path
	if err != nil {
		return DeadLetterScanStats{}, fmt.Errorf("open dead-letter file: %w", err)
	}
	defer func() {
		_ = file.Close()
	}()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)

	stats := DeadLetterScanStats{}
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		stats.LinesRead++

		var record DeadLetterRecord
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			stats.ParseErrors++
			continue
		}
		stats.RecordsParsed++
		if handle != nil {
			if err := handle(record); err != nil {
				return stats, err
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return stats, fmt.Errorf("scan dead-letter file: %w", err)
	}
	return stats, nil
}

func buildDeadLetterRecord(evt events.CloudEvent, mappingName, entityType, entityID, entityKind string, payload map[string]any, issues []graph.SchemaValidationIssue) DeadLetterRecord {
	return DeadLetterRecord{
		RecordedAt:  time.Now().UTC(),
		EventID:     strings.TrimSpace(evt.ID),
		EventType:   strings.TrimSpace(evt.Type),
		EventSource: strings.TrimSpace(evt.Source),
		EventTime:   evt.Time.UTC(),
		EventData:   cloneAnyMap(evt.Data),
		EventTenant: strings.TrimSpace(evt.TenantID),
		EventSpec:   strings.TrimSpace(evt.SpecVersion),
		EventSchema: strings.TrimSpace(evt.DataSchema),
		EventVer:    strings.TrimSpace(evt.SchemaVersion),
		EventCT:     strings.TrimSpace(evt.DataContentType),
		EventSubj:   strings.TrimSpace(evt.Subject),
		EventTrace:  strings.TrimSpace(evt.TraceParent),
		MappingName: strings.TrimSpace(mappingName),
		EntityType:  strings.TrimSpace(entityType),
		EntityID:    strings.TrimSpace(entityID),
		EntityKind:  strings.TrimSpace(entityKind),
		Payload:     payload,
		Issues:      append([]graph.SchemaValidationIssue(nil), issues...),
	}
}

func readTailLines(file *os.File, limit int) ([]string, error) {
	if file == nil {
		return nil, fmt.Errorf("dead-letter file handle is nil")
	}
	if limit <= 0 {
		return nil, nil
	}

	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat dead-letter file: %w", err)
	}
	size := info.Size()
	if size <= 0 {
		return nil, nil
	}

	const chunkSize int64 = 4096
	offset := size
	buffer := make([]byte, 0, int(minInt64(size, 64*1024)))
	newlines := 0

	for offset > 0 && newlines <= limit {
		start := offset - chunkSize
		if start < 0 {
			start = 0
		}
		length := offset - start
		chunk := make([]byte, int(length))
		n, err := file.ReadAt(chunk, start)
		if err != nil && err != io.EOF {
			return nil, fmt.Errorf("read dead-letter file tail: %w", err)
		}
		chunk = chunk[:n]
		buffer = append(chunk, buffer...)
		newlines += bytes.Count(chunk, []byte{'\n'})
		offset = start
	}

	lines := strings.Split(string(buffer), "\n")
	if offset > 0 && len(lines) > 0 {
		// Drop the first partial line when we did not scan from byte zero.
		lines = lines[1:]
	}
	for len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "" {
		lines = lines[:len(lines)-1]
	}
	if len(lines) > limit {
		lines = lines[len(lines)-limit:]
	}

	out := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out, nil
}

func cloneAnyMap(values map[string]any) map[string]any {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]any, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}

func nonEmptyIntMap(values map[string]int) map[string]int {
	if len(values) == 0 {
		return nil
	}
	return values
}

func minInt64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}
