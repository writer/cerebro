package jsonl

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// FileSink appends newline-delimited JSON records to one file.
type FileSink struct {
	path string
	mu   sync.Mutex
}

func NewFileSink(path string) (*FileSink, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("jsonl path is required")
	}
	return &FileSink{path: path}, nil
}

func (s *FileSink) Write(record any) error {
	if s == nil {
		return fmt.Errorf("jsonl sink is nil")
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o750); err != nil {
		return fmt.Errorf("create jsonl directory: %w", err)
	}
	payload, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("marshal jsonl record: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	file, err := os.OpenFile(s.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open jsonl file: %w", err)
	}
	defer func() {
		_ = file.Close()
	}()
	if _, err := file.Write(append(payload, '\n')); err != nil {
		return fmt.Errorf("append jsonl record: %w", err)
	}
	return nil
}
