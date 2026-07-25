package verifiedaccessaction

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
)

// Store persists the current record and its immutable transition chain.
// The applied result is true only for the caller that advances the record.
// Executors must not call a provider when AppendAccessAction returns false.
type Store interface {
	CreateAccessAction(context.Context, Outcome) (bool, error)
	GetAccessAction(context.Context, string, string) (Record, error)
	AppendAccessAction(context.Context, Outcome) (bool, error)
	ListAccessActionTransitions(context.Context, string, string) ([]TransitionReceipt, error)
}

// MemoryStore provides the same compare-and-swap behavior as the durable store
// for focused tests and local evaluation.
type MemoryStore struct {
	mu          sync.RWMutex
	records     map[string]Record
	transitions map[string][]TransitionReceipt
	idempotency map[string]string
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		records:     map[string]Record{},
		transitions: map[string][]TransitionReceipt{},
		idempotency: map[string]string{},
	}
}

func (s *MemoryStore) CreateAccessAction(_ context.Context, outcome Outcome) (bool, error) {
	if s == nil {
		return false, ErrState
	}
	if err := VerifyCreateOutcome(outcome); err != nil {
		return false, err
	}
	key := accessActionKey(outcome.Record.TenantID, outcome.Record.ID)
	idempotencyKey := accessActionKey(outcome.Record.TenantID, outcome.Record.IdempotencyKey)
	s.mu.Lock()
	defer s.mu.Unlock()
	if existingActionID, ok := s.idempotency[idempotencyKey]; ok &&
		existingActionID != outcome.Record.ID {
		return false, ErrConflict
	}
	if existing, ok := s.records[key]; ok {
		if existing.Digest == outcome.Record.Digest &&
			existing.LastTransitionDigest == outcome.Transition.Digest {
			return false, nil
		}
		return false, ErrConflict
	}
	s.records[key] = cloneRecord(outcome.Record)
	s.transitions[key] = []TransitionReceipt{cloneTransition(outcome.Transition)}
	s.idempotency[idempotencyKey] = outcome.Record.ID
	return true, nil
}

func (s *MemoryStore) GetAccessAction(_ context.Context, tenantID, actionID string) (Record, error) {
	if s == nil {
		return Record{}, ErrState
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	record, ok := s.records[accessActionKey(clean(tenantID), clean(actionID))]
	if !ok {
		return Record{}, ErrNotFound
	}
	return cloneRecord(record), nil
}

func (s *MemoryStore) AppendAccessAction(_ context.Context, outcome Outcome) (bool, error) {
	if s == nil {
		return false, ErrState
	}
	if err := VerifyAppendOutcome(outcome); err != nil {
		return false, err
	}
	key := accessActionKey(outcome.Record.TenantID, outcome.Record.ID)
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.records[key]
	if !ok {
		return false, ErrNotFound
	}
	if current.Digest == outcome.Record.Digest &&
		current.LastTransitionDigest == outcome.Transition.Digest {
		return false, nil
	}
	if current.Status != outcome.Transition.FromStatus ||
		current.LastTransitionDigest != outcome.Transition.PreviousTransitionDigest {
		return false, ErrConflict
	}
	s.records[key] = cloneRecord(outcome.Record)
	s.transitions[key] = append(s.transitions[key], cloneTransition(outcome.Transition))
	return true, nil
}

func (s *MemoryStore) ListAccessActionTransitions(_ context.Context, tenantID, actionID string) ([]TransitionReceipt, error) {
	if s == nil {
		return nil, ErrState
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	values, ok := s.transitions[accessActionKey(clean(tenantID), clean(actionID))]
	if !ok {
		return nil, ErrNotFound
	}
	result := make([]TransitionReceipt, len(values))
	for index := range values {
		result[index] = cloneTransition(values[index])
	}
	return result, nil
}

// VerifyCreateOutcome checks the proposal record and first transition before
// persistence.
func VerifyCreateOutcome(outcome Outcome) error {
	if err := VerifyTransition(outcome.Record, outcome.Transition); err != nil {
		return err
	}
	if outcome.Record.Status != StatusProposed ||
		outcome.Transition.FromStatus != "" ||
		outcome.Transition.PreviousTransitionDigest != "" {
		return fmt.Errorf("%w: create requires the proposal transition", ErrState)
	}
	return nil
}

// VerifyAppendOutcome checks a non-initial transition before persistence.
func VerifyAppendOutcome(outcome Outcome) error {
	if err := VerifyTransition(outcome.Record, outcome.Transition); err != nil {
		return err
	}
	if outcome.Transition.FromStatus == "" ||
		outcome.Transition.PreviousTransitionDigest == "" {
		return fmt.Errorf("%w: append requires a predecessor transition", ErrState)
	}
	return nil
}

func accessActionKey(tenantID, actionID string) string {
	return tenantID + "\x00" + actionID
}

func cloneTransition(value TransitionReceipt) TransitionReceipt {
	payload, _ := json.Marshal(value)
	var result TransitionReceipt
	_ = json.Unmarshal(payload, &result)
	return result
}
