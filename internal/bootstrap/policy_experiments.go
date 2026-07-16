package bootstrap

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/graphingest"
	"github.com/writer/cerebro/internal/graphstore"
	platformjobs "github.com/writer/cerebro/internal/jobs"
	"github.com/writer/cerebro/internal/policycandidate"
	"github.com/writer/cerebro/internal/ports"
)

type createPolicyExperimentRequest struct {
	RuntimeID string `json:"runtime_id"`
}

func (a *App) handleCreatePolicyExperiment(w http.ResponseWriter, r *http.Request) {
	candidate, err := a.authorizedPolicyCandidate(r, r.PathValue("candidateID"))
	if err != nil {
		writePolicyCandidateError(w, err)
		return
	}

	var request createPolicyExperimentRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxProtoJSONBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writePolicyCandidateError(w, fmt.Errorf("%w: decode request: %v", policycandidate.ErrInvalidRequest, err))
		return
	}
	status, err := a.graphIngestService().RuntimeCheckpointStatus(r.Context(), graphingest.RuntimeRequest{RuntimeID: strings.TrimSpace(request.RuntimeID)})
	if err != nil {
		writePolicyCandidateError(w, fmt.Errorf("%w: current graph checkpoint is unavailable", policycandidate.ErrGraphUnavailable))
		return
	}
	if !status.Found || !status.Completed || !status.CheckpointCurrent || status.TenantID != candidate.TenantID {
		writePolicyCandidateError(w, fmt.Errorf("%w: runtime has no complete current tenant checkpoint", policycandidate.ErrConflict))
		return
	}
	checkpointStore, ok := a.deps.GraphStore.(interface {
		GetIngestCheckpoint(context.Context, string) (graphstore.IngestCheckpoint, bool, error)
	})
	if !ok {
		writePolicyCandidateError(w, policycandidate.ErrGraphUnavailable)
		return
	}
	checkpoint, found, err := checkpointStore.GetIngestCheckpoint(r.Context(), status.CheckpointID)
	if err != nil || !found || checkpoint.TenantID != candidate.TenantID {
		writePolicyCandidateError(w, policycandidate.ErrGraphUnavailable)
		return
	}
	checkpointDigest, err := policycandidate.DigestPolicyExperimentCheckpoint(checkpoint)
	if err != nil {
		writePolicyCandidateError(w, err)
		return
	}

	experiment, err := a.policyCandidateService().CreateExperiment(r.Context(), policycandidate.CreateExperimentRequest{
		CandidateID:    candidate.ID,
		IdempotencyKey: r.Header.Get("Idempotency-Key"),
		DatasetDigest:  policycandidate.CurrentCanaryDatasetDigest(),
		Checkpoints: []policycandidate.PolicyExperimentCheckpoint{{
			RuntimeID: status.RuntimeID, ID: status.CheckpointID, Digest: checkpointDigest, Complete: true, Current: true,
		}},
	})
	if err != nil {
		writePolicyCandidateError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, experiment)
}

func (a *App) handleListPolicyExperiments(w http.ResponseWriter, r *http.Request) {
	candidate, err := a.authorizedPolicyCandidate(r, r.PathValue("candidateID"))
	if err != nil {
		writePolicyCandidateError(w, err)
		return
	}
	limit, err := policyExperimentLimit(r, "limit")
	if err != nil {
		writePolicyCandidateError(w, err)
		return
	}
	experiments, err := a.policyCandidateService().ListExperiments(r.Context(), policycandidate.ListExperimentsRequest{
		TenantID:    candidate.TenantID,
		CandidateID: candidate.ID,
		Status:      r.URL.Query().Get("status"),
		Limit:       limit,
	})
	if err != nil {
		writePolicyCandidateError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"experiments": experiments})
}

func (a *App) handleGetPolicyExperiment(w http.ResponseWriter, r *http.Request) {
	experiment, err := a.authorizedPolicyExperiment(r, r.PathValue("experimentID"))
	if err != nil {
		writePolicyCandidateError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, experiment)
}

func (a *App) handleRunPolicyExperiment(w http.ResponseWriter, r *http.Request) {
	experiment, err := a.authorizedPolicyExperiment(r, r.PathValue("experimentID"))
	if err != nil {
		writePolicyCandidateError(w, err)
		return
	}
	runKey := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if runKey == "" || len(runKey) > policycandidate.MaxExperimentLabelBytes {
		writePolicyCandidateError(w, fmt.Errorf("%w: Idempotency-Key is required", policycandidate.ErrInvalidRequest))
		return
	}
	runDigest := sha256.Sum256([]byte(runKey))
	job, created, err := a.jobService().Create(r.Context(), ports.CreateJobRequest{
		Kind: platformjobs.KindPolicyCandidateExperiment, TenantID: experiment.TenantID,
		SubjectType: "policy_experiment", SubjectID: experiment.ID,
		IdempotencyKey: "policy-experiment:" + experiment.ID + ":" + hex.EncodeToString(runDigest[:8]),
		Payload:        map[string]any{"experiment_id": experiment.ID, "tenant_id": experiment.TenantID},
	})
	if err != nil {
		writeJobError(w, err)
		return
	}
	if created {
		a.jobService().StartAsync(r.Context(), job)
	}
	status := http.StatusAccepted
	if !created {
		status = http.StatusOK
	}
	writeJSON(w, status, map[string]any{"experiment": experiment, "job": job})
}

func (a *App) handleListPolicyExperimentObservations(w http.ResponseWriter, r *http.Request) {
	experiment, err := a.authorizedPolicyExperiment(r, r.PathValue("experimentID"))
	if err != nil {
		writePolicyCandidateError(w, err)
		return
	}
	limit, err := policyExperimentLimit(r, "limit")
	if err != nil {
		writePolicyCandidateError(w, err)
		return
	}
	observations, err := a.policyCandidateService().ListExperimentObservations(r.Context(), policycandidate.ListExperimentObservationsRequest{
		ExperimentID: experiment.ID,
		Limit:        limit,
	})
	if err != nil {
		writePolicyCandidateError(w, err)
		return
	}
	views := make([]policyExperimentObservationView, 0, len(observations))
	for _, observation := range observations {
		views = append(views, newPolicyExperimentObservationView(observation))
	}
	writeJSON(w, http.StatusOK, map[string]any{"observations": views})
}

type policyExperimentObservationView struct {
	ID            string             `json:"id"`
	ExperimentID  string             `json:"experiment_id"`
	Sequence      int64              `json:"sequence"`
	Kind          string             `json:"kind"`
	CheckpointID  string             `json:"checkpoint_id,omitempty"`
	ReceiptDigest string             `json:"receipt_digest"`
	Metrics       map[string]float64 `json:"metrics,omitempty"`
	ObservedAt    time.Time          `json:"observed_at"`
	CreatedAt     time.Time          `json:"created_at"`
}

func newPolicyExperimentObservationView(observation *policycandidate.PolicyExperimentObservation) policyExperimentObservationView {
	if observation == nil {
		return policyExperimentObservationView{}
	}
	return policyExperimentObservationView{
		ID: observation.ID, ExperimentID: observation.ExperimentID, Sequence: observation.Sequence,
		Kind: observation.Kind, CheckpointID: observation.CheckpointID, ReceiptDigest: observation.ReceiptDigest,
		Metrics: observation.Metrics, ObservedAt: observation.ObservedAt, CreatedAt: observation.CreatedAt,
	}
}

func (a *App) authorizedPolicyExperiment(r *http.Request, id string) (*policycandidate.PolicyExperiment, error) {
	experiment, err := a.policyCandidateService().GetExperiment(r.Context(), id)
	if err != nil {
		return nil, err
	}
	if err := authorizeTenantID(r.Context(), experiment.TenantID); err != nil {
		return nil, err
	}
	return experiment, nil
}

func policyExperimentLimit(r *http.Request, name string) (int, error) {
	raw := strings.TrimSpace(r.URL.Query().Get(name))
	if raw == "" {
		return 0, nil
	}
	limit, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("%w: %s must be an integer", policycandidate.ErrInvalidRequest, name)
	}
	return limit, nil
}
