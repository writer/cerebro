package vulndb

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// FileStore persists advisory data as a local JSON state file.
type FileStore struct {
	path string
	mem  *MemoryStore
	mu   sync.Mutex
}

type fileState struct {
	Vulnerabilities  []Vulnerability   `json:"vulnerabilities,omitempty"`
	AffectedPackages []AffectedPackage `json:"affected_packages,omitempty"`
	SyncStates       []SyncState       `json:"sync_states,omitempty"`
	SyncJobs         []SyncJob         `json:"sync_jobs,omitempty"`
}

// NewFileStore opens or initializes a file-backed vulnerability store.
func NewFileStore(ctx context.Context, path string) (*FileStore, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if path == "" {
		return nil, fmt.Errorf("vulndb state path is required")
	}
	store := &FileStore{path: path, mem: NewMemoryStore()}
	if err := store.load(ctx); err != nil {
		return nil, err
	}
	return store, nil
}

// UpsertVulnerability inserts or replaces a normalized advisory and persists the state file.
func (s *FileStore) UpsertVulnerability(ctx context.Context, v Vulnerability) error {
	if err := s.mem.UpsertVulnerability(ctx, v); err != nil {
		return err
	}
	return s.save(ctx)
}

// FindVulnerability returns an advisory by canonical ID or alias.
func (s *FileStore) FindVulnerability(ctx context.Context, idOrAlias string) (Vulnerability, bool, error) {
	return s.mem.FindVulnerability(ctx, idOrAlias)
}

// UpsertAffectedPackage inserts or replaces an affected package row and persists the state file.
func (s *FileStore) UpsertAffectedPackage(ctx context.Context, pkg AffectedPackage) error {
	if err := s.mem.UpsertAffectedPackage(ctx, pkg); err != nil {
		return err
	}
	return s.save(ctx)
}

// ReplaceAffectedPackages replaces affected package rows for one vulnerability/source and persists the state file.
func (s *FileStore) ReplaceAffectedPackages(ctx context.Context, vulnerabilityID string, source string, packages []AffectedPackage) error {
	if err := s.mem.ReplaceAffectedPackages(ctx, vulnerabilityID, source, packages); err != nil {
		return err
	}
	return s.save(ctx)
}

// CandidateAffectedPackages returns all advisory package rows for an ecosystem/name pair.
func (s *FileStore) CandidateAffectedPackages(ctx context.Context, query PackageQuery) ([]AffectedPackage, error) {
	return s.mem.CandidateAffectedPackages(ctx, query)
}

// GetSyncState returns feed synchronization progress by logical source label.
func (s *FileStore) GetSyncState(ctx context.Context, source string) (SyncState, bool, error) {
	return s.mem.GetSyncState(ctx, source)
}

// PutSyncState records feed synchronization progress and persists the state file.
func (s *FileStore) PutSyncState(ctx context.Context, state SyncState) error {
	if err := s.mem.PutSyncState(ctx, state); err != nil {
		return err
	}
	return s.save(ctx)
}

// Stats returns counts for persisted advisory data.
func (s *FileStore) Stats(ctx context.Context) (Stats, error) {
	return s.mem.Stats(ctx)
}

// PutSyncJob upserts a durable advisory feed synchronization job and persists the state file.
func (s *FileStore) PutSyncJob(ctx context.Context, job SyncJob) error {
	if err := s.mem.PutSyncJob(ctx, job); err != nil {
		return err
	}
	return s.save(ctx)
}

// GetSyncJob returns a durable advisory feed synchronization job.
func (s *FileStore) GetSyncJob(ctx context.Context, id string) (SyncJob, bool, error) {
	return s.mem.GetSyncJob(ctx, id)
}

// ListDueSyncJobs returns sync jobs whose next run is due and whose lease is free or expired.
func (s *FileStore) ListDueSyncJobs(ctx context.Context, now time.Time, limit int) ([]SyncJob, error) {
	return s.mem.ListDueSyncJobs(ctx, now, limit)
}

// AcquireSyncJobLease leases a sync job for a worker and persists the state file.
func (s *FileStore) AcquireSyncJobLease(ctx context.Context, id string, owner string, ttl time.Duration) (bool, error) {
	acquired, err := s.mem.AcquireSyncJobLease(ctx, id, owner, ttl)
	if err != nil || !acquired {
		return acquired, err
	}
	return acquired, s.save(ctx)
}

// ReleaseSyncJobLease releases a sync job lease held by owner and persists the state file.
func (s *FileStore) ReleaseSyncJobLease(ctx context.Context, id string, owner string) error {
	if err := s.mem.ReleaseSyncJobLease(ctx, id, owner); err != nil {
		return err
	}
	return s.save(ctx)
}

// CompleteSyncJob records a successful sync job run and persists the state file.
func (s *FileStore) CompleteSyncJob(ctx context.Context, id string, owner string, nextRunAt time.Time) error {
	if err := s.mem.CompleteSyncJob(ctx, id, owner, nextRunAt); err != nil {
		return err
	}
	return s.save(ctx)
}

// FailSyncJob records a failed sync job run and persists the state file.
func (s *FileStore) FailSyncJob(ctx context.Context, id string, owner string, nextRunAt time.Time, syncErr error) error {
	if err := s.mem.FailSyncJob(ctx, id, owner, nextRunAt, syncErr); err != nil {
		return err
	}
	return s.save(ctx)
}

func (s *FileStore) load(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if len(data) == 0 {
		return nil
	}
	var state fileState
	if err := json.Unmarshal(data, &state); err != nil {
		return fmt.Errorf("decode vulndb state: %w", err)
	}
	for _, vulnerability := range state.Vulnerabilities {
		if err := s.mem.UpsertVulnerability(ctx, vulnerability); err != nil {
			return err
		}
	}
	for _, affected := range state.AffectedPackages {
		if err := s.mem.UpsertAffectedPackage(ctx, affected); err != nil {
			return err
		}
	}
	for _, syncState := range state.SyncStates {
		if err := s.mem.PutSyncState(ctx, syncState); err != nil {
			return err
		}
	}
	for _, syncJob := range state.SyncJobs {
		if err := s.mem.PutSyncJob(ctx, syncJob); err != nil {
			return err
		}
	}
	return nil
}

func (s *FileStore) save(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.snapshot()
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	file, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(append(data, '\n')); err != nil {
		_ = file.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	syncDir(dir)
	return nil
}

func syncDir(path string) {
	dir, err := os.Open(path)
	if err != nil {
		return
	}
	defer func() {
		_ = dir.Close()
	}()
	_ = dir.Sync()
}

func (s *FileStore) snapshot() fileState {
	s.mem.mu.RLock()
	defer s.mem.mu.RUnlock()
	state := fileState{
		Vulnerabilities:  make([]Vulnerability, 0, len(s.mem.vulnerabilities)),
		AffectedPackages: make([]AffectedPackage, 0),
		SyncStates:       make([]SyncState, 0, len(s.mem.syncStates)),
		SyncJobs:         make([]SyncJob, 0, len(s.mem.syncJobs)),
	}
	for _, vulnerability := range s.mem.vulnerabilities {
		state.Vulnerabilities = append(state.Vulnerabilities, cloneVulnerability(vulnerability))
	}
	for _, rows := range s.mem.affected {
		for _, affected := range rows {
			state.AffectedPackages = append(state.AffectedPackages, affected)
		}
	}
	for _, syncState := range s.mem.syncStates {
		state.SyncStates = append(state.SyncStates, syncState)
	}
	for _, syncJob := range s.mem.syncJobs {
		state.SyncJobs = append(state.SyncJobs, syncJob)
	}
	sort.Slice(state.Vulnerabilities, func(i, j int) bool {
		return state.Vulnerabilities[i].ID < state.Vulnerabilities[j].ID
	})
	sort.Slice(state.AffectedPackages, func(i, j int) bool {
		return affectedPackageKey(state.AffectedPackages[i]) < affectedPackageKey(state.AffectedPackages[j])
	})
	sort.Slice(state.SyncStates, func(i, j int) bool {
		return state.SyncStates[i].Source < state.SyncStates[j].Source
	})
	sort.Slice(state.SyncJobs, func(i, j int) bool {
		return state.SyncJobs[i].ID < state.SyncJobs[j].ID
	})
	return state
}
