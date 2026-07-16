package policycandidate

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/graphstore"
	"github.com/writer/cerebro/internal/ports"
)

type memoryExperimentStore struct {
	experiments  map[string]*PolicyExperiment
	observations map[string][]*PolicyExperimentObservation
}

func (s *memoryExperimentStore) CreatePolicyExperiment(_ context.Context, experiment *PolicyExperiment) error {
	if s.experiments == nil {
		s.experiments = map[string]*PolicyExperiment{}
	}
	s.experiments[experiment.ID] = cloneExperiment(experiment)
	return nil
}

func (s *memoryExperimentStore) GetPolicyExperiment(_ context.Context, id string) (*PolicyExperiment, error) {
	experiment := s.experiments[id]
	if experiment == nil {
		return nil, ErrNotFound
	}
	result := cloneExperiment(experiment)
	result.ObservationCount = int64(len(s.observations[id]))
	return result, nil
}

func (s *memoryExperimentStore) ListPolicyExperiments(_ context.Context, request ListExperimentsRequest) ([]*PolicyExperiment, error) {
	var result []*PolicyExperiment
	for _, experiment := range s.experiments {
		if experiment.TenantID == request.TenantID && (request.CandidateID == "" || experiment.CandidateID == request.CandidateID) && (request.Status == "" || experiment.Status == request.Status) {
			result = append(result, cloneExperiment(experiment))
		}
	}
	return result, nil
}

func (s *memoryExperimentStore) SavePolicyExperiment(_ context.Context, experiment *PolicyExperiment, expectedRevision int64) error {
	stored := s.experiments[experiment.ID]
	if stored == nil || stored.Revision != expectedRevision {
		return ErrConflict
	}
	s.experiments[experiment.ID] = cloneExperiment(experiment)
	return nil
}

func (s *memoryExperimentStore) AppendPolicyExperimentObservation(_ context.Context, observation *PolicyExperimentObservation) (*PolicyExperimentObservation, error) {
	stored := s.experiments[observation.ExperimentID]
	if stored == nil || stored.Status != ExperimentStatusRunning {
		return nil, ErrConflict
	}
	for _, existing := range s.observations[observation.ExperimentID] {
		if existing.IdempotencyKey == observation.IdempotencyKey {
			copy := *existing
			return &copy, nil
		}
	}
	copy := *observation
	copy.Sequence = int64(len(s.observations[observation.ExperimentID]) + 1)
	s.observations[observation.ExperimentID] = append(s.observations[observation.ExperimentID], &copy)
	return &copy, nil
}

func (s *memoryExperimentStore) ListPolicyExperimentObservations(_ context.Context, request ListExperimentObservationsRequest) ([]*PolicyExperimentObservation, error) {
	return append([]*PolicyExperimentObservation(nil), s.observations[request.ExperimentID]...), nil
}

func TestExperimentLifecyclePinsArtifactsAndRequiresObservation(t *testing.T) {
	now := time.Unix(200, 0).UTC()
	candidates := &memoryStore{}
	experiments := &memoryExperimentStore{observations: map[string][]*PolicyExperimentObservation{}}
	candidate := provedExperimentCandidate(now)
	if err := candidates.CreatePolicyCandidate(context.Background(), candidate); err != nil {
		t.Fatal(err)
	}
	service := Service{Store: candidates, Experiments: experiments, Now: func() time.Time { return now }}
	experiment, err := service.CreateExperiment(context.Background(), CreateExperimentRequest{
		CandidateID: candidate.ID, IdempotencyKey: "test.experiment.1", DatasetDigest: strings.Repeat("d", 64),
		Checkpoints: []PolicyExperimentCheckpoint{{RuntimeID: "runtime-1", ID: "checkpoint-1", Digest: strings.Repeat("e", 64), Complete: true, Current: true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if experiment.Status != ExperimentStatusQueued || experiment.Pins.CandidateRevision != candidate.Revision || experiment.Pins.PolicyDigest != candidate.Artifacts.PolicyDigest {
		t.Fatalf("experiment = %#v", experiment)
	}
	running, err := service.TransitionExperiment(context.Background(), TransitionExperimentRequest{ExperimentID: experiment.ID, ExpectedRevision: 1, Status: ExperimentStatusRunning})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.TransitionExperiment(context.Background(), TransitionExperimentRequest{ExperimentID: experiment.ID, ExpectedRevision: running.Revision, Status: ExperimentStatusCompleted}); !errors.Is(err, ErrConflict) {
		t.Fatalf("complete without observations error = %v, want conflict", err)
	}
	observation, err := service.AppendExperimentObservation(context.Background(), AppendExperimentObservationRequest{
		ExperimentID: experiment.ID, Kind: "current_shadow", CheckpointID: "checkpoint-1",
		ReceiptDigest: strings.Repeat("f", 64), IdempotencyKey: "test.observation.1", Metrics: map[string]float64{"match_count": 2},
	})
	if err != nil {
		t.Fatal(err)
	}
	if observation.Sequence != 1 {
		t.Fatalf("observation sequence = %d, want 1", observation.Sequence)
	}
	stored, err := service.GetExperiment(context.Background(), experiment.ID)
	if err != nil {
		t.Fatal(err)
	}
	completed, err := service.TransitionExperiment(context.Background(), TransitionExperimentRequest{ExperimentID: experiment.ID, ExpectedRevision: stored.Revision, Status: ExperimentStatusCompleted})
	if err != nil {
		t.Fatal(err)
	}
	if completed.Status != ExperimentStatusCompleted || completed.FinishedAt.IsZero() {
		t.Fatalf("completed experiment = %#v", completed)
	}
}

func TestEvaluateCurrentExperimentReadsGraphWithoutMutatingCandidate(t *testing.T) {
	now := time.Unix(300, 0).UTC()
	candidates := &memoryStore{}
	candidate := provedExperimentCandidate(now)
	if err := candidates.CreatePolicyCandidate(context.Background(), candidate); err != nil {
		t.Fatal(err)
	}
	graph := newGraphStore()
	graph.useShadowRows = true
	graph.shadowRows = []ports.CypherRow{{Values: map[string]any{"primary_urn": "private"}}}
	service := Service{Store: candidates, Graph: graph, Now: func() time.Time { return now }}
	experiment := &PolicyExperiment{ID: "pex_test", CandidateID: candidate.ID, TenantID: candidate.TenantID, Pins: PolicyExperimentPins{
		CandidateRevision: candidate.Revision, PolicyDigest: candidate.Artifacts.PolicyDigest, TestDigest: candidate.Artifacts.TestDigest,
		CatalogDigest: candidate.CoverageGap.CatalogDigest, DatasetDigest: strings.Repeat("d", 64),
		Checkpoints: []PolicyExperimentCheckpoint{{RuntimeID: "runtime-current", ID: "checkpoint-current", Digest: strings.Repeat("e", 64), Complete: true, Current: true}},
	}}
	observations, err := service.EvaluateCurrentExperiment(context.Background(), experiment)
	if err != nil {
		t.Fatal(err)
	}
	if len(observations) != 1 || observations[0].Kind != "current_shadow" || observations[0].Metrics["match_count"] != 1 || len(observations[0].ReceiptDigest) != 64 {
		t.Fatalf("observations = %#v", observations)
	}
	stored, err := candidates.GetPolicyCandidate(context.Background(), candidate.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Revision != candidate.Revision || stored.Shadow != nil || stored.PRReady != candidate.PRReady {
		t.Fatalf("candidate was mutated: %#v", stored)
	}
}

func TestExperimentRunnerCancellationTerminatesRunningExperiment(t *testing.T) {
	now := time.Unix(350, 0).UTC()
	candidates := &memoryStore{}
	experiments := &memoryExperimentStore{observations: map[string][]*PolicyExperimentObservation{}}
	candidate := provedExperimentCandidate(now)
	_ = candidates.CreatePolicyCandidate(context.Background(), candidate)
	checkpoint := graphstore.IngestCheckpoint{ID: "checkpoint-cancel", SourceID: "aws", TenantID: "tenant-a", Completed: true}
	checkpointDigest, err := DigestPolicyExperimentCheckpoint(checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	experiment := &PolicyExperiment{
		ID: "pex_cancel", CandidateID: candidate.ID, TenantID: candidate.TenantID, Status: ExperimentStatusQueued, Revision: 1,
		Pins: PolicyExperimentPins{CandidateRevision: candidate.Revision, PolicyDigest: candidate.Artifacts.PolicyDigest,
			TestDigest: candidate.Artifacts.TestDigest, CatalogDigest: candidate.CoverageGap.CatalogDigest, DatasetDigest: strings.Repeat("d", 64),
			Checkpoints: []PolicyExperimentCheckpoint{{RuntimeID: "runtime-cancel", ID: checkpoint.ID, Digest: checkpointDigest, Complete: true, Current: true}}},
		CreatedAt: now, UpdatedAt: now,
	}
	_ = experiments.CreatePolicyExperiment(context.Background(), experiment)
	service := Service{Store: candidates, Experiments: experiments, Now: func() time.Time { return now }}
	runner := ExperimentRunner{
		Service: service, Checkpoints: experimentCheckpointStore{checkpoint: checkpoint},
		Statuses: experimentStatusReader{status: ExperimentCheckpointStatus{RuntimeID: "runtime-cancel", TenantID: "tenant-a", CheckpointID: checkpoint.ID, Found: true, Completed: true, CheckpointCurrent: true}},
		Handler: ExperimentJobHandlerFunc(func(ctx context.Context, _ ExperimentJobInput) (ExperimentJobOutput, error) {
			return ExperimentJobOutput{}, ctx.Err()
		}),
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := runner.Run(ctx, &ports.Job{ID: "job-cancel", TenantID: "tenant-a", SubjectID: experiment.ID}); !errors.Is(err, context.Canceled) {
		t.Fatalf("runner error = %v, want canceled", err)
	}
	stored, err := experiments.GetPolicyExperiment(context.Background(), experiment.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != ExperimentStatusFailed || stored.StatusReason != "job_cancelled" || stored.FinishedAt.IsZero() {
		t.Fatalf("canceled experiment = %#v", stored)
	}
}

type experimentCheckpointStore struct{ checkpoint graphstore.IngestCheckpoint }

func (s experimentCheckpointStore) GetIngestCheckpoint(context.Context, string) (graphstore.IngestCheckpoint, bool, error) {
	return s.checkpoint, true, nil
}

type experimentStatusReader struct{ status ExperimentCheckpointStatus }

func (r experimentStatusReader) PolicyExperimentCheckpointStatus(context.Context, string) (ExperimentCheckpointStatus, error) {
	return r.status, nil
}

func provedExperimentCandidate(now time.Time) *Candidate {
	return &Candidate{
		ID: "pc_experiment", TenantID: "tenant-a", Status: StatusProved, Revision: 3,
		Artifacts:   &Artifacts{Rule: graphRule(), PolicyDigest: strings.Repeat("a", 64), TestDigest: strings.Repeat("b", 64)},
		CoverageGap: &CoverageGapReceipt{CatalogDigest: strings.Repeat("c", 64)},
		CreatedAt:   now, UpdatedAt: now,
	}
}

func cloneExperiment(experiment *PolicyExperiment) *PolicyExperiment {
	payload, _ := json.Marshal(experiment)
	var cloned PolicyExperiment
	_ = json.Unmarshal(payload, &cloned)
	return &cloned
}
