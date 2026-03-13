package graph

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	reportRunStoreVersion        = "1"
	reportSnapshotPayloadVersion = "1"
)

// ReportRunStore persists report-run metadata separately from materialized result payloads.
type ReportRunStore struct {
	stateFile   string
	snapshotDir string
}

type persistedReportRunStore struct {
	Version string                     `json:"version"`
	SavedAt time.Time                  `json:"saved_at"`
	Runs    []persistedReportRunRecord `json:"runs"`
}

type persistedReportRunRecord struct {
	Run          *ReportRun         `json:"run"`
	SnapshotFile string             `json:"snapshot_file,omitempty"`
	Attempts     []ReportRunAttempt `json:"attempts,omitempty"`
	Events       []ReportRunEvent   `json:"events,omitempty"`
}

type persistedReportSnapshotPayload struct {
	Version      string         `json:"version"`
	RunID        string         `json:"run_id"`
	ReportID     string         `json:"report_id"`
	ResultSchema string         `json:"result_schema"`
	GeneratedAt  time.Time      `json:"generated_at"`
	Result       map[string]any `json:"result"`
}

// NewReportRunStore creates a new report-run persistence store.
func NewReportRunStore(stateFile, snapshotDir string) *ReportRunStore {
	return &ReportRunStore{
		stateFile:   strings.TrimSpace(stateFile),
		snapshotDir: strings.TrimSpace(snapshotDir),
	}
}

// StateFile returns the configured report-run state path.
func (s *ReportRunStore) StateFile() string {
	if s == nil {
		return ""
	}
	return s.stateFile
}

// SnapshotDir returns the configured report-snapshot directory.
func (s *ReportRunStore) SnapshotDir() string {
	if s == nil {
		return ""
	}
	return s.snapshotDir
}

// Load restores persisted report runs and any materialized snapshots.
func (s *ReportRunStore) Load() (map[string]*ReportRun, error) {
	runs := make(map[string]*ReportRun)
	if s == nil || strings.TrimSpace(s.stateFile) == "" {
		return runs, nil
	}
	data, err := os.ReadFile(s.stateFile)
	if err != nil {
		if os.IsNotExist(err) {
			return runs, nil
		}
		return nil, fmt.Errorf("read report run state: %w", err)
	}
	var state persistedReportRunStore
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("decode report run state: %w", err)
	}
	if version := strings.TrimSpace(state.Version); version != "" && version != reportRunStoreVersion {
		return nil, fmt.Errorf("unsupported report run state version %q", version)
	}
	for _, record := range state.Runs {
		if record.Run == nil || strings.TrimSpace(record.Run.ID) == "" {
			continue
		}
		run := CloneReportRun(record.Run)
		run.Attempts = CloneReportRunAttempts(record.Attempts)
		run.Events = CloneReportRunEvents(record.Events)
		run.AttemptCount = len(run.Attempts)
		run.EventCount = len(run.Events)
		if run.Snapshot != nil && strings.TrimSpace(record.SnapshotFile) != "" {
			run.Snapshot.StoragePath = filepath.Join(s.snapshotDir, strings.TrimSpace(record.SnapshotFile))
			payload, err := loadReportSnapshotPayload(run.Snapshot.StoragePath)
			if err == nil {
				run.Result = cloneReportResult(payload.Result)
			}
		}
		runs[run.ID] = run
	}
	return runs, nil
}

// SaveAll persists the full report-run index and any retained snapshot payloads.
func (s *ReportRunStore) SaveAll(runs map[string]*ReportRun) error {
	if s == nil || strings.TrimSpace(s.stateFile) == "" {
		return nil
	}
	state := persistedReportRunStore{
		Version: reportRunStoreVersion,
		SavedAt: time.Now().UTC(),
		Runs:    make([]persistedReportRunRecord, 0, len(runs)),
	}
	ids := make([]string, 0, len(runs))
	for id := range runs {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	retainedSnapshots := make(map[string]struct{})
	for _, id := range ids {
		run := CloneReportRun(runs[id])
		if run == nil {
			continue
		}
		record := persistedReportRunRecord{Run: run}
		record.Attempts = CloneReportRunAttempts(run.Attempts)
		record.Events = CloneReportRunEvents(run.Events)
		if run.Snapshot != nil {
			snapshotPath := strings.TrimSpace(run.Snapshot.StoragePath)
			if snapshotPath == "" {
				snapshotPath = s.snapshotPathForRun(run.ReportID, run.ID)
				run.Snapshot.StoragePath = snapshotPath
			}
			record.SnapshotFile = filepath.Base(snapshotPath)
			retainedSnapshots[record.SnapshotFile] = struct{}{}
			if run.Result != nil {
				payload := persistedReportSnapshotPayload{
					Version:      reportSnapshotPayloadVersion,
					RunID:        run.ID,
					ReportID:     run.ReportID,
					ResultSchema: run.Snapshot.ResultSchema,
					GeneratedAt:  run.Snapshot.GeneratedAt,
					Result:       cloneReportResult(run.Result),
				}
				if err := saveReportSnapshotPayload(snapshotPath, payload); err != nil {
					return err
				}
			}
		}
		run.Result = nil
		state.Runs = append(state.Runs, record)
	}
	if err := s.cleanupSnapshotFiles(retainedSnapshots); err != nil {
		return err
	}
	return writeJSONAtomic(s.stateFile, state)
}

func (s *ReportRunStore) snapshotPathForRun(reportID, runID string) string {
	dir := strings.TrimSpace(s.snapshotDir)
	if dir == "" {
		dir = filepath.Join(filepath.Dir(s.stateFile), "snapshots")
	}
	filename := sanitizeReportFileName(reportID) + "-" + sanitizeReportFileName(runID) + ".json.gz"
	return filepath.Join(dir, filename)
}

func (s *ReportRunStore) cleanupSnapshotFiles(retained map[string]struct{}) error {
	dir := strings.TrimSpace(s.snapshotDir)
	if dir == "" {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read report snapshot dir: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if _, ok := retained[entry.Name()]; ok {
			continue
		}
		if err := os.Remove(filepath.Join(dir, entry.Name())); err != nil {
			return fmt.Errorf("remove stale report snapshot %s: %w", entry.Name(), err)
		}
	}
	return nil
}

func saveReportSnapshotPayload(path string, payload persistedReportSnapshotPayload) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create report snapshot dir: %w", err)
	}
	tmpFile := path + ".tmp"
	file, err := os.Create(tmpFile) // #nosec G304 -- report snapshot path is configured by the local platform operator and intentionally file-system based.
	if err != nil {
		return fmt.Errorf("create report snapshot file: %w", err)
	}
	gzipWriter := gzip.NewWriter(file)
	if err := json.NewEncoder(gzipWriter).Encode(payload); err != nil {
		_ = gzipWriter.Close()
		_ = file.Close()
		_ = os.Remove(tmpFile)
		return fmt.Errorf("encode report snapshot payload: %w", err)
	}
	if err := gzipWriter.Close(); err != nil {
		_ = file.Close()
		_ = os.Remove(tmpFile)
		return fmt.Errorf("finalize report snapshot payload: %w", err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(tmpFile)
		return fmt.Errorf("close report snapshot file: %w", err)
	}
	if err := os.Rename(tmpFile, path); err != nil {
		_ = os.Remove(tmpFile)
		return fmt.Errorf("commit report snapshot payload: %w", err)
	}
	return nil
}

func loadReportSnapshotPayload(path string) (*persistedReportSnapshotPayload, error) {
	file, err := os.Open(path) // #nosec G304 -- report snapshot path is configured by the local platform operator and intentionally file-system based.
	if err != nil {
		return nil, fmt.Errorf("open report snapshot payload: %w", err)
	}
	defer func() { _ = file.Close() }()
	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		return nil, fmt.Errorf("create report snapshot reader: %w", err)
	}
	defer func() { _ = gzipReader.Close() }()
	var payload persistedReportSnapshotPayload
	if err := json.NewDecoder(gzipReader).Decode(&payload); err != nil {
		return nil, fmt.Errorf("decode report snapshot payload: %w", err)
	}
	if version := strings.TrimSpace(payload.Version); version != "" && version != reportSnapshotPayloadVersion {
		return nil, fmt.Errorf("unsupported report snapshot payload version %q", version)
	}
	return &payload, nil
}
