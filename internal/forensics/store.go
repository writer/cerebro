package forensics

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/executionstore"
)

type Store interface {
	SaveCapture(context.Context, *CaptureRecord) error
	LoadCapture(context.Context, string) (*CaptureRecord, error)
	ListCaptures(context.Context, CaptureListOptions) ([]CaptureRecord, error)
	SaveEvidence(context.Context, *RemediationEvidenceRecord) error
	LoadEvidence(context.Context, string) (*RemediationEvidenceRecord, error)
	ListEvidence(context.Context, EvidenceListOptions) ([]RemediationEvidenceRecord, error)
	Close() error
}

type SQLiteStore struct {
	store     executionstore.Store
	ownsStore bool
}

func NewSQLiteStore(path string) (*SQLiteStore, error) {
	store, err := executionstore.NewSQLiteStore(path)
	if err != nil {
		return nil, err
	}
	forensicsStore := NewSQLiteStoreWithExecutionStore(store)
	forensicsStore.ownsStore = true
	return forensicsStore, nil
}

func NewSQLiteStoreWithExecutionStore(store executionstore.Store) *SQLiteStore {
	return &SQLiteStore{store: store}
}

func (s *SQLiteStore) SaveCapture(ctx context.Context, record *CaptureRecord) error {
	if s == nil || s.store == nil || record == nil {
		return nil
	}
	payload, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("encode forensic capture: %w", err)
	}
	return s.store.UpsertRun(ctx, executionstore.RunEnvelope{
		Namespace:   executionstore.NamespaceForensicCapture,
		RunID:       strings.TrimSpace(record.ID),
		Kind:        string(record.Target.Provider),
		Status:      string(record.Status),
		Stage:       "capture",
		SubmittedAt: record.SubmittedAt,
		CompletedAt: record.CompletedAt,
		UpdatedAt:   captureUpdatedAt(record),
		Payload:     payload,
	})
}

func (s *SQLiteStore) LoadCapture(ctx context.Context, captureID string) (*CaptureRecord, error) {
	if s == nil || s.store == nil {
		return nil, nil
	}
	env, err := s.store.LoadRun(ctx, executionstore.NamespaceForensicCapture, strings.TrimSpace(captureID))
	if err != nil {
		return nil, err
	}
	if env == nil {
		return nil, nil
	}
	var record CaptureRecord
	if err := json.Unmarshal(env.Payload, &record); err != nil {
		return nil, fmt.Errorf("decode forensic capture: %w", err)
	}
	return &record, nil
}

func (s *SQLiteStore) ListCaptures(ctx context.Context, opts CaptureListOptions) ([]CaptureRecord, error) {
	if s == nil || s.store == nil {
		return nil, nil
	}
	envs, err := s.store.ListRuns(ctx, executionstore.NamespaceForensicCapture, executionstore.RunListOptions{
		Statuses:           captureStatusesToStrings(opts.Statuses),
		Limit:              opts.Limit,
		Offset:             opts.Offset,
		OrderBySubmittedAt: true,
	})
	if err != nil {
		return nil, err
	}
	records := make([]CaptureRecord, 0, len(envs))
	for _, env := range envs {
		var record CaptureRecord
		if err := json.Unmarshal(env.Payload, &record); err != nil {
			return nil, fmt.Errorf("decode forensic capture payload: %w", err)
		}
		if opts.IncidentID != "" && strings.TrimSpace(record.IncidentID) != strings.TrimSpace(opts.IncidentID) {
			continue
		}
		if opts.WorkloadID != "" && strings.TrimSpace(record.WorkloadID) != strings.TrimSpace(opts.WorkloadID) {
			continue
		}
		records = append(records, record)
	}
	return records, nil
}

func (s *SQLiteStore) SaveEvidence(ctx context.Context, record *RemediationEvidenceRecord) error {
	if s == nil || s.store == nil || record == nil {
		return nil
	}
	payload, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("encode remediation evidence: %w", err)
	}
	updatedAt := record.CreatedAt
	if updatedAt.IsZero() {
		updatedAt = recordUpdatedAt(record.ChainOfCustody, record.CreatedAt)
	}
	return s.store.UpsertRun(ctx, executionstore.RunEnvelope{
		Namespace:   executionstore.NamespaceForensicEvidence,
		RunID:       strings.TrimSpace(record.ID),
		Kind:        "remediation_evidence",
		Status:      string(record.Status),
		Stage:       "record",
		SubmittedAt: record.CreatedAt,
		CompletedAt: timePtr(record.CreatedAt),
		UpdatedAt:   updatedAt,
		Payload:     payload,
	})
}

func (s *SQLiteStore) LoadEvidence(ctx context.Context, evidenceID string) (*RemediationEvidenceRecord, error) {
	if s == nil || s.store == nil {
		return nil, nil
	}
	env, err := s.store.LoadRun(ctx, executionstore.NamespaceForensicEvidence, strings.TrimSpace(evidenceID))
	if err != nil {
		return nil, err
	}
	if env == nil {
		return nil, nil
	}
	var record RemediationEvidenceRecord
	if err := json.Unmarshal(env.Payload, &record); err != nil {
		return nil, fmt.Errorf("decode remediation evidence: %w", err)
	}
	return &record, nil
}

func (s *SQLiteStore) ListEvidence(ctx context.Context, opts EvidenceListOptions) ([]RemediationEvidenceRecord, error) {
	if s == nil || s.store == nil {
		return nil, nil
	}
	envs, err := s.store.ListRuns(ctx, executionstore.NamespaceForensicEvidence, executionstore.RunListOptions{
		Limit:              opts.Limit,
		Offset:             opts.Offset,
		OrderBySubmittedAt: true,
	})
	if err != nil {
		return nil, err
	}
	records := make([]RemediationEvidenceRecord, 0, len(envs))
	for _, env := range envs {
		var record RemediationEvidenceRecord
		if err := json.Unmarshal(env.Payload, &record); err != nil {
			return nil, fmt.Errorf("decode remediation evidence payload: %w", err)
		}
		if opts.IncidentID != "" && strings.TrimSpace(record.IncidentID) != strings.TrimSpace(opts.IncidentID) {
			continue
		}
		if opts.WorkloadID != "" && strings.TrimSpace(record.WorkloadID) != strings.TrimSpace(opts.WorkloadID) {
			continue
		}
		records = append(records, record)
	}
	return records, nil
}

func (s *SQLiteStore) Close() error {
	if s == nil || s.store == nil || !s.ownsStore {
		return nil
	}
	return s.store.Close()
}

func captureStatusesToStrings(statuses []CaptureStatus) []string {
	if len(statuses) == 0 {
		return nil
	}
	out := make([]string, 0, len(statuses))
	for _, status := range statuses {
		out = append(out, string(status))
	}
	return out
}

func captureUpdatedAt(record *CaptureRecord) time.Time {
	if record == nil {
		return time.Time{}
	}
	return recordUpdatedAt(record.ChainOfCustody, record.SubmittedAt)
}

func recordUpdatedAt(events []CustodyEvent, fallback time.Time) time.Time {
	updatedAt := fallback
	for _, event := range events {
		if event.RecordedAt.After(updatedAt) {
			updatedAt = event.RecordedAt
		}
	}
	return updatedAt
}

func timePtr(value time.Time) *time.Time {
	if value.IsZero() {
		return nil
	}
	copy := value.UTC()
	return &copy
}
