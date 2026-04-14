package graph

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

const graphRecoverySourceLocal = "local"

type GraphPersistenceOptions struct {
	LocalPath    string
	MaxSnapshots int
}

type GraphPersistenceStatus struct {
	Configured            bool       `json:"configured"`
	LocalPath             string     `json:"local_path,omitempty"`
	LastPersistedSnapshot string     `json:"last_persisted_snapshot_id,omitempty"`
	LastPersistedAt       *time.Time `json:"last_persisted_at,omitempty"`
	LastRecoverySource    string     `json:"last_recovery_source,omitempty"`
	LastRecoveredSnapshot string     `json:"last_recovered_snapshot_id,omitempty"`
	LastRecoveredAt       *time.Time `json:"last_recovered_at,omitempty"`
	LastRecoveryError     string     `json:"last_recovery_error,omitempty"`
}

type GraphPersistenceStore struct {
	local *SnapshotStore

	statusMu sync.RWMutex
	status   GraphPersistenceStatus
}

func NewGraphPersistenceStore(opts GraphPersistenceOptions) (*GraphPersistenceStore, error) {
	localPath := strings.TrimSpace(opts.LocalPath)
	if localPath == "" {
		return nil, fmt.Errorf("graph persistence local path required")
	}
	local := NewSnapshotStore(localPath, opts.MaxSnapshots)
	return &GraphPersistenceStore{
		local: local,
		status: GraphPersistenceStatus{
			Configured: true,
			LocalPath:  local.BasePath(),
		},
	}, nil
}

func (s *GraphPersistenceStore) LocalStore() *SnapshotStore {
	if s == nil {
		return nil
	}
	return s.local
}

func (s *GraphPersistenceStore) Status() GraphPersistenceStatus {
	if s == nil {
		return GraphPersistenceStatus{}
	}
	s.statusMu.RLock()
	defer s.statusMu.RUnlock()
	status := s.status
	status.LastPersistedAt = cloneTimePtr(status.LastPersistedAt)
	status.LastRecoveredAt = cloneTimePtr(status.LastRecoveredAt)
	return status
}

func (s *GraphPersistenceStore) Save(g *Graph) error {
	_, err := s.SaveGraph(g)
	return err
}

func (s *GraphPersistenceStore) SaveGraph(g *Graph) (*GraphSnapshotRecord, error) {
	if s == nil || s.local == nil {
		return nil, fmt.Errorf("graph persistence store not configured")
	}
	record, _, err := s.local.SaveGraph(g)
	if err != nil {
		return nil, err
	}
	s.recordPersisted(record)
	return record, nil
}

func (s *GraphPersistenceStore) LoadLatest() (*Graph, error) {
	snapshot, _, _, err := s.LoadLatestSnapshot()
	if err != nil {
		return nil, err
	}
	return RestoreFromSnapshot(snapshot), nil
}

func (s *GraphPersistenceStore) PeekLatestSnapshot() (*Snapshot, *GraphSnapshotRecord, string, error) {
	if s == nil || s.local == nil {
		return nil, nil, "", fmt.Errorf("graph persistence store not configured")
	}
	snapshot, record, err := s.local.LoadLatestSnapshot()
	if err != nil {
		return nil, nil, "", err
	}
	return snapshot, record, graphRecoverySourceLocal, nil
}

func (s *GraphPersistenceStore) LoadLatestSnapshot() (*Snapshot, *GraphSnapshotRecord, string, error) {
	if s == nil || s.local == nil {
		return nil, nil, "", fmt.Errorf("graph persistence store not configured")
	}
	snapshot, record, err := s.local.LoadLatestSnapshot()
	s.recordRecovered(record, graphRecoverySourceLocal, err)
	if err != nil {
		return nil, nil, "", err
	}
	return snapshot, record, graphRecoverySourceLocal, nil
}

func (s *GraphPersistenceStore) ListGraphSnapshotRecords() ([]GraphSnapshotRecord, error) {
	if s == nil || s.local == nil {
		return nil, fmt.Errorf("graph persistence store not configured")
	}
	return s.local.ListGraphSnapshotRecords()
}

func (s *GraphPersistenceStore) LoadSnapshotsByRecordIDs(snapshotIDs ...string) (map[string]*Snapshot, map[string]*GraphSnapshotRecord, error) {
	if s == nil || s.local == nil {
		return nil, nil, fmt.Errorf("graph persistence store not configured")
	}
	return s.local.LoadSnapshotsByRecordIDs(snapshotIDs...)
}

func (s *GraphPersistenceStore) DiffByTime(t1, t2 time.Time) (*GraphDiff, error) {
	if s == nil || s.local == nil {
		return nil, fmt.Errorf("graph persistence store not configured")
	}
	return s.local.DiffByTime(t1, t2)
}

func (s *GraphPersistenceStore) recordPersisted(record *GraphSnapshotRecord) {
	s.statusMu.Lock()
	defer s.statusMu.Unlock()
	s.status.Configured = true
	if record != nil {
		now := time.Now().UTC()
		s.status.LastPersistedSnapshot = strings.TrimSpace(record.ID)
		s.status.LastPersistedAt = &now
	}
}

func (s *GraphPersistenceStore) recordRecovered(record *GraphSnapshotRecord, source string, err error) {
	s.statusMu.Lock()
	defer s.statusMu.Unlock()
	s.status.LastRecoverySource = strings.TrimSpace(source)
	if err != nil {
		s.status.LastRecoveryError = strings.TrimSpace(err.Error())
		return
	}
	now := time.Now().UTC()
	s.status.LastRecoveryError = ""
	s.status.LastRecoveredAt = &now
	if record != nil {
		s.status.LastRecoveredSnapshot = strings.TrimSpace(record.ID)
	}
}
