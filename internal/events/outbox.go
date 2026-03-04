package events

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type outboxRecord struct {
	Subject   string          `json:"subject"`
	Payload   json.RawMessage `json:"payload"`
	MessageID string          `json:"message_id,omitempty"`
	CreatedAt time.Time       `json:"created_at"`
	Attempts  int             `json:"attempts,omitempty"`
}

type outboxDLQRecord struct {
	Subject       string          `json:"subject,omitempty"`
	Payload       json.RawMessage `json:"payload,omitempty"`
	MessageID     string          `json:"message_id,omitempty"`
	CreatedAt     time.Time       `json:"created_at,omitempty"`
	Attempts      int             `json:"attempts,omitempty"`
	Reason        string          `json:"reason"`
	Raw           string          `json:"raw,omitempty"`
	QuarantinedAt time.Time       `json:"quarantined_at"`
}

type outboxConfig struct {
	MaxRecords  int
	MaxAge      time.Duration
	MaxAttempts int
	DLQPath     string
}

type outboxStats struct {
	Depth     int
	OldestAge time.Duration
}

type outboxFlushResult struct {
	Published   int
	Quarantined int
	Remaining   int
}

type fileOutbox struct {
	path   string
	config outboxConfig
	mu     sync.Mutex
}

func newFileOutbox(path string, cfg outboxConfig) *fileOutbox {
	config := cfg
	if strings.TrimSpace(config.DLQPath) == "" {
		config.DLQPath = path + ".dlq.jsonl"
	}

	return &fileOutbox{
		path:   path,
		config: config,
	}
}

func (o *fileOutbox) enqueue(record outboxRecord) error {
	normalized, err := normalizeOutboxRecord(record)
	if err != nil {
		return err
	}

	o.mu.Lock()
	defer o.mu.Unlock()

	records, quarantined, err := o.loadRecordsLocked()
	if err != nil {
		return err
	}
	if quarantined > 0 || len(records) > 0 {
		if rewriteErr := o.writeRecordsLocked(records); rewriteErr != nil {
			return rewriteErr
		}
	}

	records = append(records, normalized)
	records, expiredOrDropped, err := o.applyRetentionLocked(records)
	if err != nil {
		return err
	}
	if expiredOrDropped > 0 {
		if writeErr := o.writeRecordsLocked(records); writeErr != nil {
			return writeErr
		}
		return nil
	}

	if err := o.writeRecordsLocked(records); err != nil {
		return err
	}

	return nil
}

func (o *fileOutbox) flush(send func(record outboxRecord) error) (outboxFlushResult, error) {
	result := outboxFlushResult{}
	if send == nil {
		return result, errors.New("outbox send callback is required")
	}

	o.mu.Lock()
	defer o.mu.Unlock()

	records, quarantined, err := o.loadRecordsLocked()
	if err != nil {
		return result, err
	}
	result.Quarantined += quarantined

	records, expiredOrDropped, err := o.applyRetentionLocked(records)
	if err != nil {
		return result, err
	}
	result.Quarantined += expiredOrDropped

	remaining := make([]outboxRecord, 0)

	for i := 0; i < len(records); i++ {
		record := records[i]

		if err := send(record); err != nil {
			record.Attempts++
			if o.config.MaxAttempts > 0 && record.Attempts >= o.config.MaxAttempts {
				if quarantineErr := o.quarantineLocked(outboxDLQRecord{
					Subject:       record.Subject,
					Payload:       record.Payload,
					MessageID:     record.MessageID,
					CreatedAt:     record.CreatedAt,
					Attempts:      record.Attempts,
					Reason:        fmt.Sprintf("max delivery attempts reached: %v", err),
					QuarantinedAt: time.Now().UTC(),
				}); quarantineErr != nil {
					return result, quarantineErr
				}
				result.Quarantined++
				continue
			}

			remaining = append(remaining, record)
			remaining = append(remaining, records[i+1:]...)
			result.Remaining = len(remaining)
			if rewriteErr := o.writeRecordsLocked(remaining); rewriteErr != nil {
				return result, errors.Join(err, rewriteErr)
			}
			return result, err
		}

		result.Published++
	}

	if err := o.writeRecordsLocked(remaining); err != nil {
		return result, err
	}
	result.Remaining = len(remaining)

	return result, nil
}

func (o *fileOutbox) stats() (outboxStats, error) {
	stats := outboxStats{}

	o.mu.Lock()
	defer o.mu.Unlock()

	records, quarantined, err := o.loadRecordsLocked()
	if err != nil {
		return stats, err
	}

	records, expiredOrDropped, err := o.applyRetentionLocked(records)
	if err != nil {
		return stats, err
	}

	if quarantined > 0 || expiredOrDropped > 0 {
		if err := o.writeRecordsLocked(records); err != nil {
			return stats, err
		}
	}

	stats.Depth = len(records)
	if len(records) == 0 {
		return stats, nil
	}

	oldest := records[0].CreatedAt
	for i := 1; i < len(records); i++ {
		if records[i].CreatedAt.Before(oldest) {
			oldest = records[i].CreatedAt
		}
	}

	stats.OldestAge = time.Since(oldest)
	if stats.OldestAge < 0 {
		stats.OldestAge = 0
	}

	return stats, nil
}

func (o *fileOutbox) loadRecordsLocked() ([]outboxRecord, int, error) {
	data, err := os.ReadFile(o.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, 0, nil
		}
		return nil, 0, fmt.Errorf("read outbox file: %w", err)
	}

	lines := bytes.Split(data, []byte("\n"))
	records := make([]outboxRecord, 0, len(lines))
	quarantined := 0

	for _, line := range lines {
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) == 0 {
			continue
		}

		var record outboxRecord
		if err := json.Unmarshal(trimmed, &record); err != nil {
			if quarantineErr := o.quarantineLocked(outboxDLQRecord{
				Reason:        fmt.Sprintf("malformed outbox record: %v", err),
				Raw:           string(trimmed),
				QuarantinedAt: time.Now().UTC(),
			}); quarantineErr != nil {
				return nil, quarantined, quarantineErr
			}
			quarantined++
			continue
		}

		normalized, normErr := normalizeOutboxRecord(record)
		if normErr != nil {
			if quarantineErr := o.quarantineLocked(outboxDLQRecord{
				Subject:       record.Subject,
				Payload:       record.Payload,
				MessageID:     record.MessageID,
				CreatedAt:     record.CreatedAt,
				Attempts:      record.Attempts,
				Reason:        fmt.Sprintf("invalid outbox record: %v", normErr),
				Raw:           string(trimmed),
				QuarantinedAt: time.Now().UTC(),
			}); quarantineErr != nil {
				return nil, quarantined, quarantineErr
			}
			quarantined++
			continue
		}

		records = append(records, normalized)
	}

	return records, quarantined, nil
}

func (o *fileOutbox) applyRetentionLocked(records []outboxRecord) ([]outboxRecord, int, error) {
	if len(records) == 0 {
		return nil, 0, nil
	}

	now := time.Now().UTC()
	kept := make([]outboxRecord, 0, len(records))
	quarantined := 0

	for _, record := range records {
		if o.config.MaxAge > 0 && now.Sub(record.CreatedAt) > o.config.MaxAge {
			if err := o.quarantineLocked(outboxDLQRecord{
				Subject:       record.Subject,
				Payload:       record.Payload,
				MessageID:     record.MessageID,
				CreatedAt:     record.CreatedAt,
				Attempts:      record.Attempts,
				Reason:        fmt.Sprintf("record expired after %s", o.config.MaxAge),
				QuarantinedAt: now,
			}); err != nil {
				return nil, quarantined, err
			}
			quarantined++
			continue
		}
		kept = append(kept, record)
	}

	if o.config.MaxRecords > 0 && len(kept) > o.config.MaxRecords {
		overflow := len(kept) - o.config.MaxRecords
		for _, record := range kept[:overflow] {
			if err := o.quarantineLocked(outboxDLQRecord{
				Subject:       record.Subject,
				Payload:       record.Payload,
				MessageID:     record.MessageID,
				CreatedAt:     record.CreatedAt,
				Attempts:      record.Attempts,
				Reason:        fmt.Sprintf("record dropped to enforce max_records=%d", o.config.MaxRecords),
				QuarantinedAt: now,
			}); err != nil {
				return nil, quarantined, err
			}
			quarantined++
		}
		kept = kept[overflow:]
	}

	return kept, quarantined, nil
}

func (o *fileOutbox) writeRecordsLocked(records []outboxRecord) error {
	if len(records) == 0 {
		if err := os.Remove(o.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove empty outbox: %w", err)
		}
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(o.path), 0o750); err != nil {
		return fmt.Errorf("create outbox dir: %w", err)
	}

	lines := make([][]byte, 0, len(records))
	for _, record := range records {
		data, err := json.Marshal(record)
		if err != nil {
			return fmt.Errorf("marshal outbox record: %w", err)
		}
		lines = append(lines, data)
	}

	buf := bytes.Join(lines, []byte("\n"))
	buf = append(buf, '\n')

	tmpPath := o.path + ".tmp"
	if err := os.WriteFile(tmpPath, buf, 0o600); err != nil { // #nosec G703 -- path derived from o.path set at construction, not user input
		return fmt.Errorf("write outbox temp file: %w", err)
	}
	if err := os.Rename(tmpPath, o.path); err != nil {
		return fmt.Errorf("replace outbox file: %w", err)
	}

	return nil
}

func (o *fileOutbox) quarantineLocked(record outboxDLQRecord) error {
	record.Reason = strings.TrimSpace(record.Reason)
	if record.Reason == "" {
		record.Reason = "unknown"
	}
	if record.QuarantinedAt.IsZero() {
		record.QuarantinedAt = time.Now().UTC()
	}

	if err := os.MkdirAll(filepath.Dir(o.config.DLQPath), 0o750); err != nil {
		return fmt.Errorf("create outbox dlq dir: %w", err)
	}

	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("marshal outbox dlq record: %w", err)
	}

	f, err := os.OpenFile(o.config.DLQPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("open outbox dlq file: %w", err)
	}
	defer func() { _ = f.Close() }()

	if _, err := f.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("append outbox dlq record: %w", err)
	}

	return nil
}

func normalizeOutboxRecord(record outboxRecord) (outboxRecord, error) {
	record.Subject = strings.TrimSpace(record.Subject)
	if record.Subject == "" {
		return outboxRecord{}, errors.New("outbox record subject is required")
	}
	if len(record.Payload) == 0 {
		return outboxRecord{}, errors.New("outbox record payload is required")
	}
	if record.CreatedAt.IsZero() {
		record.CreatedAt = time.Now().UTC()
	}
	record.MessageID = strings.TrimSpace(record.MessageID)
	if record.Attempts < 0 {
		record.Attempts = 0
	}

	return record, nil
}
