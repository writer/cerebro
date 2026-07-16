package complianceimprovement

import (
	"context"
	"fmt"
	"sync"
)

// MemoryStore is a concurrency-safe implementation for local evaluation and
// focused tests. Production runtimes provide the same expected-version port
// with durable storage.
type MemoryStore struct {
	mu      sync.RWMutex
	records map[string]ImprovementRecord
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{records: map[string]ImprovementRecord{}}
}

func (s *MemoryStore) CreateComplianceImprovement(_ context.Context, request CreateRecordRequest) (ImprovementRecord, bool, error) {
	if s == nil {
		return ImprovementRecord{}, false, ErrUnavailable
	}
	key := recordKey(request.Run.TenantID, request.Run.ID)
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.records[key]; ok {
		if existing.Run.IdempotencyKey != request.Run.IdempotencyKey || existing.Run.ProgramID != request.Run.ProgramID {
			return ImprovementRecord{}, false, fmt.Errorf("%w: run id already exists with different input", ErrConflict)
		}
		return cloneRecord(existing), false, nil
	}
	record := ImprovementRecord{Run: request.Run, Revision: request.Revision}
	s.records[key] = cloneRecord(record)
	return cloneRecord(record), true, nil
}

func (s *MemoryStore) GetComplianceImprovement(_ context.Context, tenantID, runID string) (ImprovementRecord, error) {
	if s == nil {
		return ImprovementRecord{}, ErrUnavailable
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	record, ok := s.records[recordKey(tenantID, runID)]
	if !ok {
		return ImprovementRecord{}, ErrNotFound
	}
	return cloneRecord(record), nil
}

func (s *MemoryStore) AppendComplianceImprovementRevision(_ context.Context, request AppendRevisionRequest) (ImprovementRecord, error) {
	if s == nil {
		return ImprovementRecord{}, ErrUnavailable
	}
	key := recordKey(request.TenantID, request.RunID)
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.records[key]
	if !ok {
		return ImprovementRecord{}, ErrNotFound
	}
	if current.Run.AggregateVersion != request.ExpectedVersion {
		return ImprovementRecord{}, fmt.Errorf("%w: expected version %d, current version %d", ErrConflict, request.ExpectedVersion, current.Run.AggregateVersion)
	}
	if request.Run.AggregateVersion != request.ExpectedVersion+1 || request.Revision.Version.Version != request.Run.AggregateVersion {
		return ImprovementRecord{}, fmt.Errorf("%w: next version must advance exactly once", ErrConflict)
	}
	record := ImprovementRecord{Run: request.Run, Revision: request.Revision}
	s.records[key] = cloneRecord(record)
	return cloneRecord(record), nil
}

func recordKey(tenantID, runID string) string { return tenantID + "\x00" + runID }

func cloneRecord(value ImprovementRecord) ImprovementRecord {
	value.Revision.Proposal = normalizeProposal(value.Revision.Proposal)
	return value
}
