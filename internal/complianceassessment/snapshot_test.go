package complianceassessment

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/workflowevents"
)

func TestAssessmentSnapshotBindsResultsDecisionsAndEvidenceAtCutoff(t *testing.T) {
	now := time.Date(2026, 7, 15, 10, 0, 0, 0, time.UTC)
	decisionStore, run, result := completedDecisionRun(t, now)
	store := newSnapshotRunStore(decisionStore)
	log := &runLog{}
	service := NewAssessmentService(store, log, nil, nil)
	service.now = func() time.Time { return now.Add(2 * time.Minute) }
	first, _, err := service.RecordAssuranceDecision(context.Background(), validAssuranceDecisionRequest(run, result, now.Add(time.Minute)))
	if err != nil {
		t.Fatal(err)
	}

	service.now = func() time.Time { return now.Add(3 * time.Minute) }
	snapshot, created, err := service.CreateAssessmentSnapshot(context.Background(), AssessmentSnapshotRequest{
		TenantID: run.TenantID, RunID: run.ID, IdempotencyKey: "snapshot-request-1", CreatedBy: "assessor-1",
	})
	if err != nil {
		t.Fatalf("CreateAssessmentSnapshot() error = %v", err)
	}
	if !created || snapshot.DecisionCount != 1 || snapshot.QualifiedDecisionCount != 1 || snapshot.MissingDecisionCount != 0 || snapshot.EvidenceCount != 1 {
		t.Fatalf("CreateAssessmentSnapshot() = (%+v, %v)", snapshot, created)
	}
	if len(log.events) != 2 || log.events[1].GetKind() != workflowevents.EventKindComplianceAssessmentSnapshotRecorded {
		t.Fatalf("events = %+v", log.events)
	}
	rebuildDecisionStore, _, _ := completedDecisionRun(t, now)
	rebuildStore := newSnapshotRunStore(rebuildDecisionStore)
	projected, err := NewAssessmentService(rebuildStore, &runLog{}, nil, nil).ProjectEvent(context.Background(), log.events[1])
	if err != nil || !projected {
		t.Fatalf("ProjectEvent(snapshot) = (%v, %v)", projected, err)
	}
	rebuilt, err := rebuildStore.GetAssessmentSnapshot(context.Background(), run.TenantID, snapshot.ID)
	if err != nil || rebuilt.RecordDigest != snapshot.RecordDigest {
		t.Fatalf("rebuilt snapshot = (%+v, %v)", rebuilt, err)
	}

	secondRequest := validAssuranceDecisionRequest(run, result, now.Add(4*time.Minute))
	secondRequest.IdempotencyKey = "decision-request-2"
	service.now = func() time.Time { return now.Add(5 * time.Minute) }
	second, _, err := service.RecordAssuranceDecision(context.Background(), secondRequest)
	if err != nil {
		t.Fatal(err)
	}
	if second.ID == first.ID {
		t.Fatal("second decision reused the first decision ID")
	}

	audit, err := service.GetAssessmentSnapshotLens(context.Background(), run.TenantID, snapshot.ID, LensAudienceAudit, "", 10)
	if err != nil {
		t.Fatalf("GetAssessmentSnapshotLens() error = %v", err)
	}
	if len(audit.Items) != 1 || audit.Items[0].DecisionID != first.ID || len(audit.Items[0].EvidenceIDs) != 1 || len(audit.Items[0].FindingIDs) != 0 {
		t.Fatalf("audit lens = %+v, want cutoff-bound first decision and governed fields", audit)
	}
	leadership, err := service.GetAssessmentSnapshotLens(context.Background(), run.TenantID, snapshot.ID, LensAudienceLeadership, "", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(leadership.Items) != 1 || leadership.Items[0].DecisionID != "" || len(leadership.Items[0].EvidenceIDs) != 0 || len(leadership.Items[0].ReasonCodes) != 0 {
		t.Fatalf("leadership lens exposed suppressed fields: %+v", leadership.Items)
	}

	replayed, created, err := service.CreateAssessmentSnapshot(context.Background(), AssessmentSnapshotRequest{
		TenantID: run.TenantID, RunID: run.ID, IdempotencyKey: "snapshot-request-1", CreatedBy: "assessor-1",
	})
	if err != nil || created || replayed.ID != snapshot.ID {
		t.Fatalf("idempotent snapshot = (%+v, %v, %v)", replayed, created, err)
	}
}

func TestAssessmentSnapshotRejectsIdempotencyReuseAndTamperedResults(t *testing.T) {
	now := time.Date(2026, 7, 15, 10, 0, 0, 0, time.UTC)
	decisionStore, run, _ := completedDecisionRun(t, now)
	store := newSnapshotRunStore(decisionStore)
	service := NewAssessmentService(store, &runLog{}, nil, nil)
	service.now = func() time.Time { return now.Add(time.Minute) }
	_, _, err := service.CreateAssessmentSnapshot(context.Background(), AssessmentSnapshotRequest{
		TenantID: run.TenantID, RunID: run.ID, IdempotencyKey: "snapshot-request-1", CreatedBy: "assessor-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = service.CreateAssessmentSnapshot(context.Background(), AssessmentSnapshotRequest{
		TenantID: run.TenantID, RunID: "another-run", IdempotencyKey: "snapshot-request-1", CreatedBy: "assessor-1",
	})
	if !errors.Is(err, ports.ErrJobIdempotencyConflict) {
		t.Fatalf("idempotency reuse error = %v", err)
	}

	chunk := store.chunks[runKey(run.TenantID, run.ID)][1]
	chunk.Results[0].EvaluatorRevision = "tampered"
	payload, err := canonicalBytes(chunk.Results)
	if err != nil {
		t.Fatal(err)
	}
	chunk.Digest = digestResultChunkPayload("", payload)
	store.chunks[runKey(run.TenantID, run.ID)][1] = chunk
	_, err = service.GetAssessmentSnapshotLens(context.Background(), run.TenantID, store.snapshotIDs[runKey(run.TenantID, "snapshot-request-1")], LensAudienceSecurity, "", 10)
	if !errors.Is(err, ErrAssessmentConflict) {
		t.Fatalf("tampered lens error = %v, want conflict", err)
	}
}

type snapshotRunStore struct {
	*decisionRunStore
	snapshotMu  sync.Mutex
	snapshots   map[string]AssessmentSnapshot
	snapshotIDs map[string]string
}

func newSnapshotRunStore(store *decisionRunStore) *snapshotRunStore {
	return &snapshotRunStore{decisionRunStore: store, snapshots: map[string]AssessmentSnapshot{}, snapshotIDs: map[string]string{}}
}

func (s *snapshotRunStore) ApplyAssessmentSnapshot(_ context.Context, _ string, snapshot AssessmentSnapshot) error {
	s.snapshotMu.Lock()
	defer s.snapshotMu.Unlock()
	key := runKey(snapshot.TenantID, snapshot.ID)
	if existing, ok := s.snapshots[key]; ok && existing.RecordDigest != snapshot.RecordDigest {
		return ErrAssessmentConflict
	}
	s.snapshots[key] = snapshot
	s.snapshotIDs[runKey(snapshot.TenantID, snapshot.IdempotencyKey)] = snapshot.ID
	return nil
}

func (s *snapshotRunStore) GetAssessmentSnapshot(_ context.Context, tenantID, snapshotID string) (AssessmentSnapshot, error) {
	s.snapshotMu.Lock()
	defer s.snapshotMu.Unlock()
	snapshot, ok := s.snapshots[runKey(tenantID, snapshotID)]
	if !ok {
		return AssessmentSnapshot{}, ErrAssessmentSnapshotNotFound
	}
	return snapshot, nil
}

func (s *snapshotRunStore) FindAssessmentSnapshotByIdempotency(_ context.Context, tenantID, key string) (AssessmentSnapshot, error) {
	s.snapshotMu.Lock()
	defer s.snapshotMu.Unlock()
	id := s.snapshotIDs[runKey(tenantID, key)]
	if id == "" {
		return AssessmentSnapshot{}, ErrAssessmentSnapshotNotFound
	}
	return s.snapshots[runKey(tenantID, id)], nil
}

func (s *snapshotRunStore) ListAssuranceDecisionsByRun(_ context.Context, tenantID, runID string) ([]AssuranceDecision, error) {
	s.decisionMu.Lock()
	defer s.decisionMu.Unlock()
	result := []AssuranceDecision{}
	for _, decision := range s.decisions {
		if decision.TenantID == tenantID && decision.RunID == runID {
			result = append(result, decision)
		}
	}
	return result, nil
}
