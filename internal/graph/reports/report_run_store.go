package reports

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/executionstore"
)

const (
	reportRunStoreVersion        = "2"
	reportSnapshotPayloadVersion = "1"
)

// ReportRunStore persists report-run metadata in the shared execution store
// while keeping materialized result payloads as separate filesystem artifacts.
type ReportRunStore struct {
	executionFile string
	legacyState   string
	snapshotDir   string
	execution     *executionstore.SQLiteStore
}

type persistedReportRunRecord struct {
	Version      string             `json:"version,omitempty"`
	Run          *ReportRun         `json:"run"`
	SnapshotFile string             `json:"snapshot_file,omitempty"`
	Attempts     []ReportRunAttempt `json:"attempts,omitempty"`
	Events       []ReportRunEvent   `json:"events,omitempty"`
}

type persistedReportRunStore struct {
	Version string                     `json:"version"`
	SavedAt time.Time                  `json:"saved_at"`
	Runs    []persistedReportRunRecord `json:"runs"`
}

type persistedReportSnapshotPayload struct {
	Version      string         `json:"version"`
	RunID        string         `json:"run_id"`
	ReportID     string         `json:"report_id"`
	ResultSchema string         `json:"result_schema"`
	GeneratedAt  time.Time      `json:"generated_at"`
	Result       map[string]any `json:"result"`
}

func NewReportRunStore(executionFile, snapshotDir, legacyStateFile string) (*ReportRunStore, error) {
	store, err := executionstore.NewSQLiteStore(strings.TrimSpace(executionFile))
	if err != nil {
		return nil, err
	}
	return &ReportRunStore{
		executionFile: strings.TrimSpace(executionFile),
		legacyState:   strings.TrimSpace(legacyStateFile),
		snapshotDir:   strings.TrimSpace(snapshotDir),
		execution:     store,
	}, nil
}

func (s *ReportRunStore) Close() error {
	if s == nil || s.execution == nil {
		return nil
	}
	return s.execution.Close()
}

// StateFile returns the shared execution store path backing report metadata.
func (s *ReportRunStore) StateFile() string {
	if s == nil {
		return ""
	}
	return s.executionFile
}

func (s *ReportRunStore) LegacyStateFile() string {
	if s == nil {
		return ""
	}
	return s.legacyState
}

func (s *ReportRunStore) SnapshotDir() string {
	if s == nil {
		return ""
	}
	return s.snapshotDir
}

func (s *ReportRunStore) Load() (map[string]*ReportRun, error) {
	runs := make(map[string]*ReportRun)
	if s == nil || s.execution == nil {
		return runs, nil
	}
	storedRuns, err := s.ListRuns("")
	if err != nil {
		return nil, err
	}
	for _, run := range storedRuns {
		if run == nil || strings.TrimSpace(run.ID) == "" {
			continue
		}
		runs[run.ID] = run
	}
	if len(runs) > 0 || strings.TrimSpace(s.legacyState) == "" {
		return runs, nil
	}
	legacyRuns, err := s.loadLegacyState()
	if err != nil {
		return nil, err
	}
	if len(legacyRuns) == 0 {
		return runs, nil
	}
	if err := s.SaveAll(legacyRuns); err != nil {
		return nil, fmt.Errorf("import legacy report run state: %w", err)
	}
	return legacyRuns, nil
}

func (s *ReportRunStore) LoadRun(runID string) (*ReportRun, error) {
	if s == nil || s.execution == nil {
		return nil, nil
	}
	env, err := s.execution.LoadRun(context.Background(), executionstore.NamespacePlatformReportRun, strings.TrimSpace(runID))
	if err != nil || env == nil {
		return nil, err
	}
	return s.decodeRunEnvelope(*env)
}

func (s *ReportRunStore) ListRuns(reportID string) ([]*ReportRun, error) {
	if s == nil || s.execution == nil {
		return nil, nil
	}
	envs, err := s.execution.ListRuns(context.Background(), executionstore.NamespacePlatformReportRun, executionstore.RunListOptions{
		OrderBySubmittedAt: true,
	})
	if err != nil {
		return nil, err
	}
	runs := make([]*ReportRun, 0, len(envs))
	reportID = strings.TrimSpace(reportID)
	for _, env := range envs {
		run, err := s.decodeRunEnvelope(env)
		if err != nil {
			return nil, err
		}
		if run == nil {
			continue
		}
		if reportID != "" && strings.TrimSpace(run.ReportID) != reportID {
			continue
		}
		runs = append(runs, run)
	}
	return runs, nil
}

func (s *ReportRunStore) SaveRun(run *ReportRun) error {
	if s == nil || s.execution == nil || run == nil {
		return nil
	}
	previous, err := s.LoadRun(run.ID)
	if err != nil {
		return err
	}
	retainedSnapshots := make(map[string]struct{})
	if err := s.persistRun(context.Background(), run, retainedSnapshots); err != nil {
		return err
	}
	if previous != nil && previous.Snapshot != nil {
		if name := filepath.Base(strings.TrimSpace(previous.Snapshot.StoragePath)); name != "" {
			if run.Snapshot == nil || filepath.Base(strings.TrimSpace(run.Snapshot.StoragePath)) != name {
				if err := os.Remove(filepath.Join(s.snapshotRoot(), name)); err != nil && !os.IsNotExist(err) {
					return fmt.Errorf("remove superseded report snapshot %s: %w", name, err)
				}
			}
		}
	}
	return nil
}

// SaveAll persists the current report-run set into the shared execution store.
func (s *ReportRunStore) SaveAll(runs map[string]*ReportRun) error {
	if s == nil || s.execution == nil {
		return nil
	}
	ctx := context.Background()
	existing, err := s.execution.ListRuns(ctx, executionstore.NamespacePlatformReportRun, executionstore.RunListOptions{})
	if err != nil {
		return fmt.Errorf("list report runs: %w", err)
	}
	retainedRuns := make(map[string]struct{}, len(runs))
	retainedSnapshots := make(map[string]struct{}, len(runs))
	ids := make([]string, 0, len(runs))
	for id := range runs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		run := runs[id]
		if run == nil {
			continue
		}
		retainedRuns[strings.TrimSpace(run.ID)] = struct{}{}
		if err := s.persistRun(ctx, run, retainedSnapshots); err != nil {
			return err
		}
	}
	for _, env := range existing {
		if _, ok := retainedRuns[strings.TrimSpace(env.RunID)]; ok {
			continue
		}
		if err := s.execution.DeleteEvents(ctx, executionstore.NamespacePlatformReportRun, env.RunID); err != nil {
			return fmt.Errorf("delete report run events %q: %w", env.RunID, err)
		}
		if err := s.execution.DeleteRun(ctx, executionstore.NamespacePlatformReportRun, env.RunID); err != nil {
			return fmt.Errorf("delete report run %q: %w", env.RunID, err)
		}
	}
	if err := s.cleanupSnapshotFiles(retainedSnapshots); err != nil {
		return err
	}
	return nil
}

func (s *ReportRunStore) persistRun(ctx context.Context, input *ReportRun, retainedSnapshots map[string]struct{}) error {
	run := CloneReportRun(input)
	if run == nil {
		return nil
	}
	record := persistedReportRunRecord{
		Version:  reportRunStoreVersion,
		Run:      run,
		Attempts: CloneReportRunAttempts(run.Attempts),
	}
	if run.Snapshot != nil {
		snapshotPath := strings.TrimSpace(run.Snapshot.StoragePath)
		if snapshotPath == "" {
			snapshotPath = s.snapshotPathForRun(run.ReportID, run.ID)
			run.Snapshot.StoragePath = snapshotPath
		}
		record.SnapshotFile = filepath.Base(snapshotPath)
		if retainedSnapshots != nil {
			retainedSnapshots[record.SnapshotFile] = struct{}{}
		}
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
	record.Run.Result = nil

	payload, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("encode report run %q: %w", run.ID, err)
	}
	runEnv := executionstore.RunEnvelope{
		Namespace:   executionstore.NamespacePlatformReportRun,
		RunID:       strings.TrimSpace(run.ID),
		Kind:        strings.TrimSpace(run.ReportID),
		Status:      strings.TrimSpace(run.Status),
		Stage:       reportRunStage(run),
		SubmittedAt: run.SubmittedAt.UTC(),
		StartedAt:   run.StartedAt,
		CompletedAt: run.CompletedAt,
		UpdatedAt:   reportRunUpdatedAt(run),
		Payload:     payload,
	}
	eventEnvs := make([]executionstore.EventEnvelope, 0, len(run.Events))
	for _, event := range run.Events {
		eventPayload, err := json.Marshal(event)
		if err != nil {
			return fmt.Errorf("encode report run event %q/%d: %w", run.ID, event.Sequence, err)
		}
		eventEnvs = append(eventEnvs, executionstore.EventEnvelope{
			Namespace:  executionstore.NamespacePlatformReportRun,
			RunID:      run.ID,
			Sequence:   int64(event.Sequence),
			RecordedAt: event.Timestamp.UTC(),
			Payload:    eventPayload,
		})
	}
	if err := s.execution.ReplaceRunWithEvents(ctx, runEnv, eventEnvs); err != nil {
		return fmt.Errorf("persist report run %q: %w", run.ID, err)
	}
	return nil
}

func (s *ReportRunStore) decodeRunEnvelope(env executionstore.RunEnvelope) (*ReportRun, error) {
	var record persistedReportRunRecord
	if err := json.Unmarshal(env.Payload, &record); err != nil {
		return nil, fmt.Errorf("decode report run payload %q: %w", env.RunID, err)
	}
	if record.Run == nil || strings.TrimSpace(record.Run.ID) == "" {
		return nil, nil
	}
	run := CloneReportRun(record.Run)
	run.Attempts = CloneReportRunAttempts(record.Attempts)
	run.AttemptCount = len(run.Attempts)
	events, err := s.execution.LoadEvents(context.Background(), executionstore.NamespacePlatformReportRun, run.ID)
	if err != nil {
		return nil, fmt.Errorf("load report run events %q: %w", run.ID, err)
	}
	run.Events = decodeReportRunEvents(events)
	if len(run.Events) == 0 {
		run.Events = CloneReportRunEvents(record.Events)
	}
	run.EventCount = len(run.Events)
	if run.Snapshot != nil && strings.TrimSpace(record.SnapshotFile) != "" {
		run.Snapshot.StoragePath = filepath.Join(s.snapshotRoot(), strings.TrimSpace(record.SnapshotFile))
		payload, err := loadReportSnapshotPayload(run.Snapshot.StoragePath)
		if err == nil {
			run.Result = cloneReportResult(payload.Result)
		}
	}
	return run, nil
}

func decodeReportRunEvents(envs []executionstore.EventEnvelope) []ReportRunEvent {
	events := make([]ReportRunEvent, 0, len(envs))
	for _, env := range envs {
		var event ReportRunEvent
		if err := json.Unmarshal(env.Payload, &event); err != nil {
			continue
		}
		event.Sequence = int(env.Sequence)
		if event.Timestamp.IsZero() {
			event.Timestamp = env.RecordedAt.UTC()
		}
		events = append(events, event)
	}
	return events
}

func (s *ReportRunStore) loadLegacyState() (map[string]*ReportRun, error) {
	runs := make(map[string]*ReportRun)
	path := strings.TrimSpace(s.legacyState)
	if path == "" {
		return runs, nil
	}
	data, err := os.ReadFile(path) // #nosec G304 -- legacy state path is platform-controlled local storage configuration.
	if err != nil {
		if os.IsNotExist(err) {
			return runs, nil
		}
		return nil, fmt.Errorf("read legacy report run state: %w", err)
	}
	var state persistedReportRunStore
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("decode legacy report run state: %w", err)
	}
	for _, record := range state.Runs {
		if record.Run == nil || strings.TrimSpace(record.Run.ID) == "" {
			continue
		}
		run := CloneReportRun(record.Run)
		run.Attempts = CloneReportRunAttempts(record.Attempts)
		run.AttemptCount = len(run.Attempts)
		run.Events = CloneReportRunEvents(record.Events)
		run.EventCount = len(run.Events)
		if run.Snapshot != nil && strings.TrimSpace(record.SnapshotFile) != "" {
			run.Snapshot.StoragePath = filepath.Join(s.snapshotRoot(), strings.TrimSpace(record.SnapshotFile))
			payload, err := loadReportSnapshotPayload(run.Snapshot.StoragePath)
			if err == nil {
				run.Result = cloneReportResult(payload.Result)
			}
		}
		runs[run.ID] = run
	}
	return runs, nil
}

func reportRunStage(run *ReportRun) string {
	if run == nil {
		return ""
	}
	if attempt := LatestReportRunAttempt(run); attempt != nil && strings.TrimSpace(attempt.Status) != "" {
		return strings.TrimSpace(attempt.Status)
	}
	return strings.TrimSpace(run.Status)
}

func reportRunUpdatedAt(run *ReportRun) time.Time {
	if run == nil {
		return time.Now().UTC()
	}
	if run.CompletedAt != nil && !run.CompletedAt.IsZero() {
		return run.CompletedAt.UTC()
	}
	if len(run.Events) > 0 {
		return run.Events[len(run.Events)-1].Timestamp.UTC()
	}
	if run.StartedAt != nil && !run.StartedAt.IsZero() {
		return run.StartedAt.UTC()
	}
	return run.SubmittedAt.UTC()
}

func (s *ReportRunStore) snapshotRoot() string {
	dir := strings.TrimSpace(s.snapshotDir)
	if dir == "" {
		dir = filepath.Join(filepath.Dir(s.executionFile), "report-snapshots")
	}
	return dir
}

func (s *ReportRunStore) snapshotPathForRun(reportID, runID string) string {
	filename := sanitizeReportFileName(reportID) + "-" + sanitizeReportFileName(runID) + ".json.gz"
	return filepath.Join(s.snapshotRoot(), filename)
}

func (s *ReportRunStore) cleanupSnapshotFiles(retained map[string]struct{}) error {
	dir := s.snapshotRoot()
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
	file, err := os.Create(tmpFile) // #nosec G304 -- report snapshot path is platform-controlled local storage.
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
	file, err := os.Open(path) // #nosec G304 -- report snapshot path is platform-controlled local storage.
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
