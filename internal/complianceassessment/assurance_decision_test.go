package complianceassessment

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/workflowevents"
)

func TestRecordAssuranceDecisionBindsCompletedRunArtifacts(t *testing.T) {
	now := time.Date(2026, 7, 15, 8, 0, 0, 0, time.UTC)
	store, run, result := completedDecisionRun(t, now)
	log := &runLog{}
	service := NewAssessmentService(store, log, nil, nil)
	service.now = func() time.Time { return now.Add(2 * time.Minute) }
	request := validAssuranceDecisionRequest(run, result, now.Add(time.Minute))

	recorded, created, err := service.RecordAssuranceDecision(context.Background(), request)
	if err != nil {
		t.Fatalf("RecordAssuranceDecision() error = %v", err)
	}
	if !created || recorded.RunID != run.ID || recorded.ResultID != result.ID || recorded.ObjectiveID != result.ObjectiveID {
		t.Fatalf("RecordAssuranceDecision() = (%+v, %v), want bound decision", recorded, created)
	}
	if !recorded.Decision.Qualified || recorded.Decision.DecisionDigest == "" || recorded.RecordDigest == "" {
		t.Fatalf("recorded decision is not qualified and content addressed: reasons=%v record=%+v", recorded.Decision.Reasons, recorded)
	}
	if err := recorded.Decision.AuthorizeProductionUse(); err != nil {
		t.Fatalf("AuthorizeProductionUse() error = %v", err)
	}
	read, err := service.GetAssuranceDecision(context.Background(), run.TenantID, recorded.ID)
	if err != nil || read.RecordDigest != recorded.RecordDigest {
		t.Fatalf("GetAssuranceDecision() = (%+v, %v)", read, err)
	}
	if len(log.events) != 1 || log.events[0].GetKind() != workflowevents.EventKindComplianceAssuranceDecisionRecorded {
		t.Fatalf("appended events = %+v", log.events)
	}

	replayed, created, err := service.RecordAssuranceDecision(context.Background(), request)
	if err != nil || created || replayed.ID != recorded.ID || len(log.events) != 1 {
		t.Fatalf("idempotent RecordAssuranceDecision() = (%+v, %v, %v), events=%d", replayed, created, err, len(log.events))
	}
}

func TestRecordAssuranceDecisionRejectsChangedArtifactsAndIdempotencyReuse(t *testing.T) {
	now := time.Date(2026, 7, 15, 8, 0, 0, 0, time.UTC)
	store, run, result := completedDecisionRun(t, now)
	service := NewAssessmentService(store, &runLog{}, nil, nil)
	service.now = func() time.Time { return now.Add(2 * time.Minute) }
	request := validAssuranceDecisionRequest(run, result, now.Add(time.Minute))
	if _, _, err := service.RecordAssuranceDecision(context.Background(), request); err != nil {
		t.Fatalf("RecordAssuranceDecision() error = %v", err)
	}

	request.Input.Result.EvaluatorRevision = "changed-evaluator"
	if _, _, err := service.RecordAssuranceDecision(context.Background(), request); !errors.Is(err, ports.ErrJobIdempotencyConflict) {
		t.Fatalf("idempotency reuse error = %v, want conflict", err)
	}
	request.IdempotencyKey = "decision-request-2"
	if _, _, err := service.RecordAssuranceDecision(context.Background(), request); !errors.Is(err, ErrAssessmentConflict) {
		t.Fatalf("changed result error = %v, want assessment conflict", err)
	}
}

func TestRecordAssuranceDecisionRejectsResultProjectionThatDoesNotMatchRun(t *testing.T) {
	now := time.Date(2026, 7, 15, 8, 0, 0, 0, time.UTC)
	store, run, result := completedDecisionRun(t, now)
	result.EvaluatorRevision = "altered-projection"
	chunk := store.chunks[runKey(run.TenantID, run.ID)][1]
	chunk.Results = []ObjectiveResult{result}
	payload, err := canonicalBytes(chunk.Results)
	if err != nil {
		t.Fatal(err)
	}
	chunk.Digest = digestResultChunkPayload("", payload)
	store.chunks[runKey(run.TenantID, run.ID)][1] = chunk
	service := NewAssessmentService(store, &runLog{}, nil, nil)
	service.now = func() time.Time { return now.Add(2 * time.Minute) }
	_, _, err = service.RecordAssuranceDecision(context.Background(), validAssuranceDecisionRequest(run, result, now.Add(time.Minute)))
	if !errors.Is(err, ErrAssessmentConflict) {
		t.Fatalf("RecordAssuranceDecision() error = %v, want run result hash conflict", err)
	}
}

func TestProjectEventRebuildsAssuranceDecisionProjection(t *testing.T) {
	now := time.Date(2026, 7, 15, 8, 0, 0, 0, time.UTC)
	store, run, result := completedDecisionRun(t, now)
	log := &runLog{}
	service := NewAssessmentService(store, log, nil, nil)
	service.now = func() time.Time { return now.Add(2 * time.Minute) }
	recorded, _, err := service.RecordAssuranceDecision(context.Background(), validAssuranceDecisionRequest(run, result, now.Add(time.Minute)))
	if err != nil {
		t.Fatal(err)
	}

	rebuildStore, _, _ := completedDecisionRun(t, now)
	rebuildService := NewAssessmentService(rebuildStore, &runLog{}, nil, nil)
	projected, err := rebuildService.ProjectEvent(context.Background(), log.events[0])
	if err != nil || !projected {
		t.Fatalf("ProjectEvent() = (%v, %v)", projected, err)
	}
	read, err := rebuildService.GetAssuranceDecision(context.Background(), run.TenantID, recorded.ID)
	if err != nil || read.RecordDigest != recorded.RecordDigest {
		t.Fatalf("rebuilt decision = (%+v, %v)", read, err)
	}
}

func TestProjectEventRejectsAssuranceVerdictChangedAfterQualification(t *testing.T) {
	now := time.Date(2026, 7, 15, 8, 0, 0, 0, time.UTC)
	store, run, result := completedDecisionRun(t, now)
	log := &runLog{}
	service := NewAssessmentService(store, log, nil, nil)
	service.now = func() time.Time { return now.Add(2 * time.Minute) }
	recorded, _, err := service.RecordAssuranceDecision(context.Background(), validAssuranceDecisionRequest(run, result, now.Add(time.Minute)))
	if err != nil {
		t.Fatal(err)
	}
	recorded.Decision.Qualified = false
	recorded.RecordDigest, err = assuranceDecisionDigest(recorded)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(recorded)
	if err != nil {
		t.Fatal(err)
	}
	event, err := workflowevents.NewComplianceAggregateEvent(workflowevents.ComplianceAggregateRecorded{
		Kind: workflowevents.EventKindComplianceAssuranceDecisionRecorded, TenantID: recorded.TenantID,
		AggregateType: "assurance_decision", AggregateID: recorded.ID, AggregateVersion: 1,
		Operation: "assurance_decision_recorded", ContentDigest: recorded.RecordDigest,
		PayloadJSON: string(payload), ActorID: recorded.RecordedBy, RecordedAt: recorded.RecordedAt.Format(time.RFC3339Nano),
	})
	if err != nil {
		t.Fatal(err)
	}
	rebuildStore, _, _ := completedDecisionRun(t, now)
	projected, err := NewAssessmentService(rebuildStore, &runLog{}, nil, nil).ProjectEvent(context.Background(), event)
	if err == nil || projected {
		t.Fatalf("ProjectEvent() = (%v, %v), want verdict mismatch", projected, err)
	}
}

func validAssuranceDecisionRequest(run AssessmentRun, result ObjectiveResult, asOf time.Time) AssuranceDecisionRequest {
	return AssuranceDecisionRequest{
		TenantID: run.TenantID, RunID: run.ID, ResultID: result.ID,
		IdempotencyKey: "decision-request-1", RecordedBy: "assessor-1",
		Input: QualificationInput{
			Manifest: *run.InputManifest, Result: result, AsOf: asOf,
			EvidenceProofs: []EvidenceProof{{
				EvidenceID: result.EvidenceIDs[0], State: EvidenceSufficient,
				CollectedAt: asOf.Add(-time.Minute), ValidUntil: asOf.Add(time.Hour),
			}},
			Limitations: []Limitation{}, RequiredReviews: []ReviewRequirement{},
			Verification: VerificationProof{State: VerificationNotRequired},
		},
	}
}

func completedDecisionRun(t *testing.T, now time.Time) (*decisionRunStore, AssessmentRun, ObjectiveResult) {
	t.Helper()
	manifest := NormalizeManifest(completeManifest(now))
	inputHash, err := CanonicalManifestDigest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	result := NormalizeResult(validResults(now, 1)[0])
	result.EvidenceIDs = []string{"evidence-1"}
	resultSetHash, err := CanonicalResultSetDigest([]ObjectiveResult{result})
	if err != nil {
		t.Fatal(err)
	}
	run := AssessmentRun{
		ID: "assessment-run-00000000000000000000000000000001", TenantID: "tenant-1",
		ProgramID: manifest.ProgramID, ScopeRevisionID: manifest.ScopeRevisionID, PlanRevisionID: manifest.PlanRevisionID,
		State: RunComplete, Version: 4, RequestedAt: now.Add(-time.Hour), RequestedBy: "assessor-1",
		RequestHash: "sha256:request", IdempotencyKey: "run-request-1", InputManifest: &manifest,
		InputHash: inputHash, AutomatedResultHash: resultSetHash, ResultCount: 1,
		CollectionBarrierAt: now.Add(-time.Minute), CompletedAt: now,
	}
	base := newRunStore()
	base.runs[runKey(run.TenantID, run.ID)] = run
	base.byKey[runKey(run.TenantID, run.IdempotencyKey)] = run.ID
	base.chunks[runKey(run.TenantID, run.ID)] = map[uint32]ResultChunk{1: {
		RunID: run.ID, Sequence: 1, FirstResultID: result.ID, LastResultID: result.ID,
		Count: 1, Digest: decisionTestChunkDigest(t, result), Results: []ObjectiveResult{result},
	}}
	return &decisionRunStore{runStore: base, decisions: map[string]AssuranceDecision{}, decisionByKey: map[string]string{}}, run, result
}

func decisionTestChunkDigest(t *testing.T, result ObjectiveResult) string {
	t.Helper()
	payload, err := canonicalBytes([]ObjectiveResult{result})
	if err != nil {
		t.Fatal(err)
	}
	return digestResultChunkPayload("", payload)
}

type decisionRunStore struct {
	*runStore
	decisionMu    sync.Mutex
	decisions     map[string]AssuranceDecision
	decisionByKey map[string]string
}

func (s *decisionRunStore) ApplyAssuranceDecision(_ context.Context, eventID string, decision AssuranceDecision) error {
	s.decisionMu.Lock()
	defer s.decisionMu.Unlock()
	key := runKey(decision.TenantID, decision.ID)
	if existing, ok := s.decisions[key]; ok {
		if existing.RecordDigest != decision.RecordDigest {
			return ErrAssessmentConflict
		}
		return nil
	}
	s.decisions[key] = decision
	s.decisionByKey[runKey(decision.TenantID, decision.IdempotencyKey)] = decision.ID
	_ = eventID
	return nil
}

func (s *decisionRunStore) GetAssuranceDecision(_ context.Context, tenantID, decisionID string) (AssuranceDecision, error) {
	s.decisionMu.Lock()
	defer s.decisionMu.Unlock()
	decision, ok := s.decisions[runKey(tenantID, decisionID)]
	if !ok {
		return AssuranceDecision{}, ErrAssuranceDecisionNotFound
	}
	return decision, nil
}

func (s *decisionRunStore) FindAssuranceDecisionByIdempotency(_ context.Context, tenantID, key string) (AssuranceDecision, error) {
	s.decisionMu.Lock()
	defer s.decisionMu.Unlock()
	id := s.decisionByKey[runKey(tenantID, key)]
	if id == "" {
		return AssuranceDecision{}, ErrAssuranceDecisionNotFound
	}
	return s.decisions[runKey(tenantID, id)], nil
}
