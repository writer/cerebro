package bootstrap

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/findingdsl"
	"github.com/writer/cerebro/internal/graphstore"
	"github.com/writer/cerebro/internal/policycandidate"
	"github.com/writer/cerebro/internal/ports"
)

type policyExperimentRuntimeStore struct {
	*stubRuntimeStore
	candidates   map[string]*policycandidate.Candidate
	experiments  map[string]*policycandidate.PolicyExperiment
	observations map[string][]*policycandidate.PolicyExperimentObservation
}

func (s *policyExperimentRuntimeStore) CreatePolicyCandidate(_ context.Context, candidate *policycandidate.Candidate) error {
	s.candidates[candidate.ID] = cloneJSON(candidate)
	return nil
}

func (s *policyExperimentRuntimeStore) GetPolicyCandidate(_ context.Context, id string) (*policycandidate.Candidate, error) {
	candidate := s.candidates[id]
	if candidate == nil {
		return nil, policycandidate.ErrNotFound
	}
	return cloneJSON(candidate), nil
}

func (s *policyExperimentRuntimeStore) ListPolicyCandidates(context.Context, policycandidate.ListRequest) ([]*policycandidate.Candidate, error) {
	return nil, nil
}

func (s *policyExperimentRuntimeStore) SavePolicyCandidate(_ context.Context, candidate *policycandidate.Candidate, expected int64) error {
	stored := s.candidates[candidate.ID]
	if stored == nil || stored.Revision != expected {
		return policycandidate.ErrConflict
	}
	s.candidates[candidate.ID] = cloneJSON(candidate)
	return nil
}

func (s *policyExperimentRuntimeStore) CreatePolicyExperiment(_ context.Context, experiment *policycandidate.PolicyExperiment) error {
	s.experiments[experiment.ID] = cloneJSON(experiment)
	return nil
}

func (s *policyExperimentRuntimeStore) GetPolicyExperiment(_ context.Context, id string) (*policycandidate.PolicyExperiment, error) {
	experiment := s.experiments[id]
	if experiment == nil {
		return nil, policycandidate.ErrNotFound
	}
	result := cloneJSON(experiment)
	result.ObservationCount = int64(len(s.observations[id]))
	return result, nil
}

func (s *policyExperimentRuntimeStore) ListPolicyExperiments(context.Context, policycandidate.ListExperimentsRequest) ([]*policycandidate.PolicyExperiment, error) {
	return nil, nil
}

func (s *policyExperimentRuntimeStore) SavePolicyExperiment(_ context.Context, experiment *policycandidate.PolicyExperiment, expected int64) error {
	stored := s.experiments[experiment.ID]
	if stored == nil || stored.Revision != expected {
		return policycandidate.ErrConflict
	}
	s.experiments[experiment.ID] = cloneJSON(experiment)
	return nil
}

func (s *policyExperimentRuntimeStore) AppendPolicyExperimentObservation(_ context.Context, observation *policycandidate.PolicyExperimentObservation) (*policycandidate.PolicyExperimentObservation, error) {
	for _, existing := range s.observations[observation.ExperimentID] {
		if existing.IdempotencyKey == observation.IdempotencyKey {
			return cloneJSON(existing), nil
		}
	}
	copy := cloneJSON(observation)
	copy.Sequence = int64(len(s.observations[observation.ExperimentID]) + 1)
	s.observations[observation.ExperimentID] = append(s.observations[observation.ExperimentID], copy)
	return cloneJSON(copy), nil
}

func (s *policyExperimentRuntimeStore) ListPolicyExperimentObservations(_ context.Context, request policycandidate.ListExperimentObservationsRequest) ([]*policycandidate.PolicyExperimentObservation, error) {
	return append([]*policycandidate.PolicyExperimentObservation(nil), s.observations[request.ExperimentID]...), nil
}

func TestPolicyExperimentJobRunsCurrentGraphCanaryAndPersistsReceipt(t *testing.T) {
	now := time.Unix(400, 0).UTC()
	rule := findingdsl.NewPolicyRule(findingdsl.NewPolicyRuleInput{
		ID: "candidate-current-canary", Name: "Candidate current canary", Description: "Finds one current tenant-scoped graph path.", Severity: "high",
		Graph: findingdsl.PolicyRuleGraphFinding{
			Query:    `MATCH (actor:Entity {tenant_id: $tenant_id})-[:RELATION {relation: 'acted_on'}]->(task:Entity {tenant_id: $tenant_id})-[:RELATION {relation: 'depends_on'}]->(definition:Entity {tenant_id: $tenant_id}) RETURN definition.urn AS primary_urn, definition.urn AS fingerprint_key, 'path' AS summary, [actor.urn, task.urn, definition.urn] AS resource_urns, [{urn: actor.urn}, {urn: definition.urn}] AS evidence LIMIT $row_limit`,
			RowLimit: 100, RequiredColumns: []string{"primary_urn", "fingerprint_key", "summary", "resource_urns"},
		},
		Frameworks: []findingdsl.PolicyFramework{{Name: "SOC 2", Controls: []string{"CC6.1"}}},
	})
	candidate := &policycandidate.Candidate{
		ID: "pc_canary", TenantID: "tenant-a", Status: policycandidate.StatusProved, Revision: 2,
		Artifacts:   &policycandidate.Artifacts{Rule: rule, PolicyDigest: strings.Repeat("a", 64), TestDigest: strings.Repeat("b", 64)},
		CoverageGap: &policycandidate.CoverageGapReceipt{CatalogDigest: strings.Repeat("c", 64)}, CreatedAt: now, UpdatedAt: now,
	}
	checkpoint := graphstore.IngestCheckpoint{ID: "checkpoint-current", SourceID: "aws", TenantID: "tenant-a", ConfigHash: "config", Completed: true, PagesRead: 1, EventsRead: 3, UpdatedAt: now.Format(time.RFC3339)}
	checkpointDigest, err := policycandidate.DigestPolicyExperimentCheckpoint(checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	experiment := &policycandidate.PolicyExperiment{
		ID: "pex_canary", CandidateID: candidate.ID, TenantID: candidate.TenantID, Status: policycandidate.ExperimentStatusQueued, Revision: 1,
		Pins: policycandidate.PolicyExperimentPins{
			CandidateRevision: candidate.Revision, PolicyDigest: candidate.Artifacts.PolicyDigest, TestDigest: candidate.Artifacts.TestDigest,
			CatalogDigest: candidate.CoverageGap.CatalogDigest, DatasetDigest: strings.Repeat("d", 64),
			Checkpoints: []policycandidate.PolicyExperimentCheckpoint{{RuntimeID: "runtime-canary", ID: checkpoint.ID, Digest: checkpointDigest, Complete: true, Current: true}},
		}, CreatedAt: now, UpdatedAt: now,
	}
	store := &policyExperimentRuntimeStore{
		stubRuntimeStore: &stubRuntimeStore{}, candidates: map[string]*policycandidate.Candidate{candidate.ID: candidate},
		experiments: map[string]*policycandidate.PolicyExperiment{experiment.ID: experiment}, observations: map[string][]*policycandidate.PolicyExperimentObservation{},
	}
	graph := &stubGraphStore{
		checkpoints: map[string]graphstore.IngestCheckpoint{checkpoint.ID: checkpoint},
		cypherRows:  [][]ports.CypherRow{{{Values: map[string]any{"primary_urn": "private"}}}},
	}
	statusReader := policyExperimentStatusReader{status: policycandidate.ExperimentCheckpointStatus{
		RuntimeID: "runtime-canary", TenantID: "tenant-a", CheckpointID: checkpoint.ID, Found: true, Completed: true, CheckpointCurrent: true,
	}}
	app := New(config.Config{HTTPAddr: "127.0.0.1:0"}, Dependencies{StateStore: store, GraphStore: graph, PolicyExperimentCheckpoints: statusReader}, nil)
	result, _, err := app.runPolicyCandidateExperimentJob(context.Background(), &ports.Job{
		ID: "job-canary", TenantID: "tenant-a", SubjectID: experiment.ID, Payload: map[string]any{"experiment_id": experiment.ID},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result["status"] != policycandidate.ExperimentStatusCompleted || result["observation_count"] != int64(1) {
		t.Fatalf("job result = %#v", result)
	}
	observations := store.observations[experiment.ID]
	if len(observations) != 1 || observations[0].Kind != "current_shadow" || observations[0].Metrics["match_count"] != 1 || len(observations[0].ReceiptDigest) != 64 {
		t.Fatalf("observations = %#v", observations)
	}
	if len(graph.cypherRequests) != 1 || graph.cypherRequests[0].Params["tenant_id"] != "tenant-a" || graph.cypherRequests[0].RowLimit != policycandidate.MaxShadowRows+1 {
		t.Fatalf("graph requests = %#v", graph.cypherRequests)
	}
}

type policyExperimentStatusReader struct {
	status policycandidate.ExperimentCheckpointStatus
}

func (r policyExperimentStatusReader) PolicyExperimentCheckpointStatus(context.Context, string) (policycandidate.ExperimentCheckpointStatus, error) {
	return r.status, nil
}

func cloneJSON[T any](value *T) *T {
	payload, _ := json.Marshal(value)
	var result T
	_ = json.Unmarshal(payload, &result)
	return &result
}
