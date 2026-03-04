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
	CreatedAt time.Time       `json:"created_at"`
}

type fileOutbox struct {
	path string
	mu   sync.Mutex
}

func newFileOutbox(path string) *fileOutbox {
	return &fileOutbox{path: path}
}

func (o *fileOutbox) enqueue(record outboxRecord) error {
	if strings.TrimSpace(record.Subject) == "" {
		return errors.New("outbox record subject is required")
	}
	if len(record.Payload) == 0 {
		return errors.New("outbox record payload is required")
	}
	if record.CreatedAt.IsZero() {
		record.CreatedAt = time.Now().UTC()
	}

	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("marshal outbox record: %w", err)
	}

	o.mu.Lock()
	defer o.mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(o.path), 0o755); err != nil {
		return fmt.Errorf("create outbox dir: %w", err)
	}

	f, err := os.OpenFile(o.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("open outbox file: %w", err)
	}
	defer func() { _ = f.Close() }()

	if _, err := f.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("append outbox record: %w", err)
	}

	return nil
}

func (o *fileOutbox) flush(send func(record outboxRecord) error) (int, error) {
	if send == nil {
		return 0, errors.New("outbox send callback is required")
	}

	o.mu.Lock()
	defer o.mu.Unlock()

	data, err := os.ReadFile(o.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, fmt.Errorf("read outbox file: %w", err)
	}

	lines := bytes.Split(data, []byte("\n"))
	remaining := make([][]byte, 0, len(lines))
	published := 0

	for i := 0; i < len(lines); i++ {
		line := bytes.TrimSpace(lines[i])
		if len(line) == 0 {
			continue
		}

		var record outboxRecord
		if err := json.Unmarshal(line, &record); err != nil {
			return published, fmt.Errorf("decode outbox record: %w", err)
		}

		if err := send(record); err != nil {
			remaining = append(remaining, line)
			for j := i + 1; j < len(lines); j++ {
				rest := bytes.TrimSpace(lines[j])
				if len(rest) > 0 {
					remaining = append(remaining, rest)
				}
			}

			if rewriteErr := o.rewrite(remaining); rewriteErr != nil {
				return published, errors.Join(err, fmt.Errorf("rewrite outbox after failure: %w", rewriteErr))
			}
			return published, err
		}

		published++
	}

	if err := o.rewrite(remaining); err != nil {
		return published, err
	}

	return published, nil
}

func (o *fileOutbox) rewrite(records [][]byte) error {
	if len(records) == 0 {
		if err := os.Remove(o.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove empty outbox: %w", err)
		}
		return nil
	}

	buf := bytes.Join(records, []byte("\n"))
	buf = append(buf, '\n')

	tmpPath := o.path + ".tmp"
	if err := os.WriteFile(tmpPath, buf, 0o600); err != nil {
		return fmt.Errorf("write outbox temp file: %w", err)
	}
	if err := os.Rename(tmpPath, o.path); err != nil {
		return fmt.Errorf("replace outbox file: %w", err)
	}

	return nil
}
