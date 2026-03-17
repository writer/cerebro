package graph

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// GraphMutationLog persists graph mutation records to an append-only local file.
type GraphMutationLog struct {
	path string
}

func NewGraphMutationLog(path string) *GraphMutationLog {
	return &GraphMutationLog{path: path}
}

func (l *GraphMutationLog) Path() string {
	if l == nil {
		return ""
	}
	return l.path
}

func (l *GraphMutationLog) Append(record GraphMutationRecord) error {
	if l == nil || l.path == "" {
		return fmt.Errorf("graph mutation log path required")
	}
	if err := os.MkdirAll(filepath.Dir(l.path), 0o750); err != nil {
		return fmt.Errorf("create graph mutation log dir: %w", err)
	}
	file, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600) // #nosec G304 -- graph mutation log path is controlled by the local operator.
	if err != nil {
		return fmt.Errorf("open graph mutation log: %w", err)
	}

	if err := AppendGraphMutationRecord(file, record); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close graph mutation log: %w", err)
	}
	return nil
}

func (l *GraphMutationLog) LoadAll() ([]GraphMutationRecord, error) {
	if l == nil || l.path == "" {
		return nil, fmt.Errorf("graph mutation log path required")
	}
	file, err := os.Open(l.path) // #nosec G304 -- graph mutation log path is controlled by the local operator.
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("open graph mutation log: %w", err)
	}
	return loadGraphMutationRecordsFromReadCloser(file)
}

func (l *GraphMutationLog) LoadAfterSequence(sequence uint64) ([]GraphMutationRecord, error) {
	records, err := l.LoadAll()
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, nil
	}
	filtered := make([]GraphMutationRecord, 0, len(records))
	for _, record := range records {
		if record.Sequence > sequence {
			filtered = append(filtered, record)
		}
	}
	return filtered, nil
}

func (l *GraphMutationLog) CompactThroughSequence(sequence uint64) error {
	if l == nil || l.path == "" {
		return fmt.Errorf("graph mutation log path required")
	}
	records, err := l.LoadAfterSequence(sequence)
	if err != nil {
		return err
	}
	if len(records) == 0 {
		if err := os.Remove(l.path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove compacted graph mutation log: %w", err)
		}
		return nil
	}
	dir := filepath.Dir(l.path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create graph mutation log dir: %w", err)
	}
	tmpPath := l.path + ".tmp"
	file, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600) // #nosec G304 -- compacted WAL temp path is derived from the operator-controlled log path.
	if err != nil {
		return fmt.Errorf("open compacted graph mutation log: %w", err)
	}
	for _, record := range records {
		if err := AppendGraphMutationRecord(file, record); err != nil {
			_ = file.Close()
			_ = os.Remove(tmpPath)
			return err
		}
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("close compacted graph mutation log: %w", err)
	}
	if err := os.Rename(tmpPath, l.path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("rename compacted graph mutation log: %w", err)
	}
	return nil
}

func loadGraphMutationRecordsFromReadCloser(reader io.ReadCloser) ([]GraphMutationRecord, error) {
	if reader == nil {
		return nil, fmt.Errorf("graph mutation log reader required")
	}
	records, loadErr := LoadGraphMutationRecords(reader)
	if err := reader.Close(); err != nil {
		closeErr := fmt.Errorf("close graph mutation log: %w", err)
		if loadErr != nil {
			return records, errors.Join(loadErr, closeErr)
		}
		return records, closeErr
	}
	return records, loadErr
}
