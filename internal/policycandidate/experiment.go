package policycandidate

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"strings"

	"github.com/writer/cerebro/internal/findingdsl"
	"github.com/writer/cerebro/internal/graphagent"
	"github.com/writer/cerebro/internal/graphstore"
	"github.com/writer/cerebro/internal/ports"
)

var experimentDigestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
var experimentObservationKindPattern = regexp.MustCompile(`^[a-z][a-z0-9_.-]*$`)
var experimentIdempotencyKeyPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]*$`)

func CurrentCanaryDatasetDigest() string {
	return digest([]byte("policy-experiment/current-shadow/v1"))
}

func (s Service) CreateExperiment(ctx context.Context, request CreateExperimentRequest) (*PolicyExperiment, error) {
	if s.Experiments == nil {
		return nil, ErrStoreUnavailable
	}
	candidate, err := s.Get(ctx, strings.TrimSpace(request.CandidateID))
	if err != nil {
		return nil, err
	}
	if candidate.Status != StatusProved && candidate.Status != StatusReadyForReview {
		return nil, fmt.Errorf("%w: candidate status %q cannot start an experiment", ErrConflict, candidate.Status)
	}
	if candidate.Artifacts == nil || candidate.CoverageGap == nil {
		return nil, fmt.Errorf("%w: candidate has no proved artifacts or coverage receipt", ErrConflict)
	}
	request.IdempotencyKey = strings.TrimSpace(request.IdempotencyKey)
	if len(request.IdempotencyKey) > MaxExperimentLabelBytes || !experimentIdempotencyKeyPattern.MatchString(request.IdempotencyKey) {
		return nil, fmt.Errorf("%w: idempotency key is required", ErrInvalidRequest)
	}
	pins := PolicyExperimentPins{
		CandidateRevision: candidate.Revision,
		PolicyDigest:      strings.TrimSpace(candidate.Artifacts.PolicyDigest),
		TestDigest:        strings.TrimSpace(candidate.Artifacts.TestDigest),
		CatalogDigest:     strings.TrimSpace(candidate.CoverageGap.CatalogDigest),
		DatasetDigest:     strings.TrimSpace(request.DatasetDigest),
		Checkpoints:       cloneExperimentCheckpoints(request.Checkpoints),
	}
	blockedReason, err := validateExperimentPins(pins)
	if err != nil {
		return nil, err
	}
	now := s.now()
	id := deterministicExperimentID(candidate.TenantID, candidate.ID, request.IdempotencyKey)
	experiment := &PolicyExperiment{
		ID: id, CandidateID: candidate.ID, TenantID: candidate.TenantID, Status: ExperimentStatusQueued,
		Revision: 1, Pins: pins, CreatedAt: now, UpdatedAt: now,
	}
	if blockedReason != "" {
		experiment.Status = ExperimentStatusBlocked
		experiment.StatusReason = blockedReason
	}
	if err := s.Experiments.CreatePolicyExperiment(ctx, experiment); err != nil {
		return nil, err
	}
	return s.Experiments.GetPolicyExperiment(ctx, experiment.ID)
}

func (s Service) GetExperiment(ctx context.Context, id string) (*PolicyExperiment, error) {
	if s.Experiments == nil {
		return nil, ErrStoreUnavailable
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, fmt.Errorf("%w: experiment id is required", ErrInvalidRequest)
	}
	return s.Experiments.GetPolicyExperiment(ctx, id)
}

func (s Service) ListExperiments(ctx context.Context, request ListExperimentsRequest) ([]*PolicyExperiment, error) {
	if s.Experiments == nil {
		return nil, ErrStoreUnavailable
	}
	request.TenantID = strings.TrimSpace(request.TenantID)
	request.CandidateID = strings.TrimSpace(request.CandidateID)
	request.Status = strings.TrimSpace(request.Status)
	if request.TenantID == "" {
		return nil, fmt.Errorf("%w: tenant id is required", ErrInvalidRequest)
	}
	if request.Status != "" && !validExperimentStatus(request.Status) {
		return nil, fmt.Errorf("%w: unknown experiment status %q", ErrInvalidRequest, request.Status)
	}
	if request.Limit == 0 {
		request.Limit = DefaultExperimentListLimit
	}
	if request.Limit < 1 || request.Limit > MaxExperimentListLimit {
		return nil, fmt.Errorf("%w: experiment limit must be between 1 and %d", ErrInvalidRequest, MaxExperimentListLimit)
	}
	return s.Experiments.ListPolicyExperiments(ctx, request)
}

func (s Service) TransitionExperiment(ctx context.Context, request TransitionExperimentRequest) (*PolicyExperiment, error) {
	experiment, err := s.GetExperiment(ctx, request.ExperimentID)
	if err != nil {
		return nil, err
	}
	request.Status = strings.TrimSpace(request.Status)
	request.Reason = strings.TrimSpace(request.Reason)
	if request.ExpectedRevision < 1 || request.ExpectedRevision != experiment.Revision {
		return nil, ErrConflict
	}
	if !validExperimentTransition(experiment.Status, request.Status) {
		return nil, fmt.Errorf("%w: experiment cannot transition from %q to %q", ErrConflict, experiment.Status, request.Status)
	}
	if (request.Status == ExperimentStatusFailed || request.Status == ExperimentStatusBlocked) && request.Reason == "" {
		return nil, fmt.Errorf("%w: failed and blocked experiments require a reason", ErrInvalidRequest)
	}
	if len(request.Reason) > MaxExperimentStatusReasonBytes {
		return nil, fmt.Errorf("%w: experiment status reason exceeds %d bytes", ErrInvalidRequest, MaxExperimentStatusReasonBytes)
	}
	if request.Status == ExperimentStatusCompleted {
		observations, err := s.Experiments.ListPolicyExperimentObservations(ctx, ListExperimentObservationsRequest{ExperimentID: experiment.ID, Limit: MaxExperimentObservations})
		if err != nil {
			return nil, err
		}
		covered := make(map[string]struct{}, len(observations))
		for _, observation := range observations {
			if observation != nil && strings.TrimSpace(observation.CheckpointID) != "" {
				covered[strings.TrimSpace(observation.CheckpointID)] = struct{}{}
			}
		}
		for _, checkpoint := range experiment.Pins.Checkpoints {
			if _, ok := covered[strings.TrimSpace(checkpoint.ID)]; !ok {
				return nil, fmt.Errorf("%w: completed experiment requires an observation for every pinned checkpoint", ErrConflict)
			}
		}
	}
	experiment.Status = request.Status
	experiment.StatusReason = request.Reason
	now := s.now()
	if request.Status == ExperimentStatusRunning && experiment.StartedAt.IsZero() {
		experiment.StartedAt = now
	}
	if request.Status == ExperimentStatusCompleted || request.Status == ExperimentStatusFailed || request.Status == ExperimentStatusBlocked {
		experiment.FinishedAt = now
	}
	experiment.Revision++
	experiment.UpdatedAt = now
	if err := s.Experiments.SavePolicyExperiment(ctx, experiment, request.ExpectedRevision); err != nil {
		experiment.Revision--
		return nil, err
	}
	return experiment, nil
}

func (s Service) AppendExperimentObservation(ctx context.Context, request AppendExperimentObservationRequest) (*PolicyExperimentObservation, error) {
	experiment, err := s.GetExperiment(ctx, request.ExperimentID)
	if err != nil {
		return nil, err
	}
	if experiment.Status != ExperimentStatusRunning {
		return nil, fmt.Errorf("%w: observations require a running experiment", ErrConflict)
	}
	if experiment.ObservationCount >= MaxExperimentObservations {
		return nil, fmt.Errorf("%w: experiment observation limit reached", ErrConflict)
	}
	request.Kind = strings.TrimSpace(request.Kind)
	request.CheckpointID = strings.TrimSpace(request.CheckpointID)
	request.DatasetCaseID = strings.TrimSpace(request.DatasetCaseID)
	request.ReceiptDigest = strings.TrimSpace(request.ReceiptDigest)
	request.IdempotencyKey = strings.TrimSpace(request.IdempotencyKey)
	if len(request.Kind) > MaxExperimentLabelBytes || len(request.CheckpointID) > MaxExperimentLabelBytes || len(request.DatasetCaseID) > MaxExperimentLabelBytes ||
		len(request.IdempotencyKey) > MaxExperimentLabelBytes || !experimentObservationKindPattern.MatchString(request.Kind) ||
		!experimentIdempotencyKeyPattern.MatchString(request.IdempotencyKey) || !experimentDigestPattern.MatchString(request.ReceiptDigest) {
		return nil, fmt.Errorf("%w: observation kind and receipt digest are required", ErrInvalidRequest)
	}
	if request.CheckpointID != "" && !experimentHasCheckpoint(experiment, request.CheckpointID) {
		return nil, fmt.Errorf("%w: observation checkpoint is not pinned by the experiment", ErrInvalidRequest)
	}
	if len(request.Metrics) > MaxExperimentMetrics {
		return nil, fmt.Errorf("%w: observation metrics exceed %d entries", ErrInvalidRequest, MaxExperimentMetrics)
	}
	metrics := make(map[string]float64, len(request.Metrics))
	for key, value := range request.Metrics {
		key = strings.TrimSpace(key)
		if len(key) > MaxExperimentLabelBytes || !experimentObservationKindPattern.MatchString(key) || math.IsNaN(value) || math.IsInf(value, 0) {
			return nil, fmt.Errorf("%w: observation metrics require safe names and finite values", ErrInvalidRequest)
		}
		metrics[key] = value
	}
	now := s.now()
	observedAt := request.ObservedAt.UTC()
	if observedAt.IsZero() {
		observedAt = now
	}
	id, err := newExperimentResourceID("peo_")
	if err != nil {
		return nil, fmt.Errorf("create policy experiment observation id: %w", err)
	}
	return s.Experiments.AppendPolicyExperimentObservation(ctx, &PolicyExperimentObservation{
		ID: id, ExperimentID: experiment.ID, TenantID: experiment.TenantID, Kind: request.Kind,
		CheckpointID: request.CheckpointID, DatasetCaseID: request.DatasetCaseID,
		ReceiptDigest: request.ReceiptDigest, IdempotencyKey: request.IdempotencyKey, Metrics: metrics, ObservedAt: observedAt, CreatedAt: now,
	})
}

func (s Service) ListExperimentObservations(ctx context.Context, request ListExperimentObservationsRequest) ([]*PolicyExperimentObservation, error) {
	if _, err := s.GetExperiment(ctx, request.ExperimentID); err != nil {
		return nil, err
	}
	request.ExperimentID = strings.TrimSpace(request.ExperimentID)
	if request.Limit == 0 {
		request.Limit = DefaultExperimentObservationListLimit
	}
	if request.Limit < 1 || request.Limit > MaxExperimentObservationListLimit {
		return nil, fmt.Errorf("%w: observation limit must be between 1 and %d", ErrInvalidRequest, MaxExperimentObservationListLimit)
	}
	return s.Experiments.ListPolicyExperimentObservations(ctx, request)
}

// EvaluateCurrentExperiment executes one pinned current-graph canary without
// mutating the candidate or writing production findings. Historical pins need
// a point-in-time graph reader and are intentionally refused by this evaluator.
func (s Service) EvaluateCurrentExperiment(ctx context.Context, experiment *PolicyExperiment) ([]AppendExperimentObservationRequest, error) {
	if experiment == nil {
		return nil, fmt.Errorf("%w: experiment is required", ErrInvalidRequest)
	}
	if s.Graph == nil {
		return nil, ErrGraphUnavailable
	}
	candidate, err := s.Get(ctx, experiment.CandidateID)
	if err != nil {
		return nil, err
	}
	if candidate.Revision != experiment.Pins.CandidateRevision || candidate.Artifacts == nil ||
		candidate.Artifacts.PolicyDigest != experiment.Pins.PolicyDigest || candidate.Artifacts.TestDigest != experiment.Pins.TestDigest ||
		candidate.CoverageGap == nil || candidate.CoverageGap.CatalogDigest != experiment.Pins.CatalogDigest {
		return nil, fmt.Errorf("%w: candidate revision or artifact pins changed", ErrConflict)
	}
	var current *PolicyExperimentCheckpoint
	for index := range experiment.Pins.Checkpoints {
		pin := &experiment.Pins.Checkpoints[index]
		if !pin.Current {
			continue
		}
		if current != nil {
			return nil, fmt.Errorf("%w: current-graph evaluation requires exactly one current checkpoint", ErrInvalidRequest)
		}
		current = pin
	}
	if current == nil {
		return nil, fmt.Errorf("%w: historical replay requires a point-in-time graph evaluator", ErrGraphUnavailable)
	}
	rule := candidate.Artifacts.Rule
	if issues := findingdsl.ValidatePolicyRule(rule); len(issues) != 0 {
		return nil, fmt.Errorf("%w: stored rule is invalid", ErrConflict)
	}
	params := cloneMap(rule.Spec.Graph.Params)
	if params == nil {
		params = map[string]any{}
	}
	params["tenant_id"] = candidate.TenantID
	evaluationLimit := rule.Spec.Graph.RowLimit
	if evaluationLimit <= 0 || evaluationLimit > MaxShadowRows {
		evaluationLimit = MaxShadowRows
	}
	fetchLimit := evaluationLimit + 1
	params["row_limit"] = fetchLimit
	validation, _, err := graphagent.ValidateRuntimeBoundReadCypher(ctx, rule.Spec.Graph.Query, fetchLimit)
	if err != nil {
		return nil, fmt.Errorf("%w: validate stored graph query: %w", ErrConflict, err)
	}
	if !validation.OK {
		return nil, fmt.Errorf("%w: stored graph query refused (%s): %s", ErrConflict, validation.Code, validation.Reason)
	}
	rows, err := s.Graph.ExecuteReadCypher(ctx, ports.CypherQueryRequest{Query: rule.Spec.Graph.Query, Params: params, RowLimit: fetchLimit})
	if err != nil {
		return nil, err
	}
	matchCount := len(rows)
	truncated := matchCount > evaluationLimit
	if truncated {
		matchCount = evaluationLimit
	}
	receiptPayload, err := json.Marshal(struct {
		ExperimentID  string `json:"experiment_id"`
		CheckpointID  string `json:"checkpoint_id"`
		PolicyDigest  string `json:"policy_digest"`
		DatasetDigest string `json:"dataset_digest"`
		MatchCount    int    `json:"match_count"`
		Truncated     bool   `json:"truncated"`
	}{experiment.ID, current.ID, experiment.Pins.PolicyDigest, experiment.Pins.DatasetDigest, matchCount, truncated})
	if err != nil {
		return nil, fmt.Errorf("encode current experiment receipt: %w", err)
	}
	truncatedMetric := float64(0)
	if truncated {
		truncatedMetric = 1
	}
	return []AppendExperimentObservationRequest{{
		Kind: "current_shadow", CheckpointID: current.ID, ReceiptDigest: digest(receiptPayload),
		Metrics:    map[string]float64{"match_count": float64(matchCount), "truncated": truncatedMetric, "row_limit": float64(evaluationLimit)},
		ObservedAt: s.now(),
	}}, nil
}

func validateExperimentPins(pins PolicyExperimentPins) (string, error) {
	if pins.CandidateRevision < 1 || !experimentDigestPattern.MatchString(pins.PolicyDigest) || !experimentDigestPattern.MatchString(pins.TestDigest) || !experimentDigestPattern.MatchString(pins.CatalogDigest) || !experimentDigestPattern.MatchString(pins.DatasetDigest) {
		return "", fmt.Errorf("%w: experiment revision and policy, test, catalog, and dataset digests are required", ErrInvalidRequest)
	}
	if len(pins.Checkpoints) == 0 || len(pins.Checkpoints) > MaxExperimentCheckpoints {
		return "", fmt.Errorf("%w: experiment requires 1-%d checkpoint pins", ErrInvalidRequest, MaxExperimentCheckpoints)
	}
	seen := map[string]struct{}{}
	blocked := ""
	for _, checkpoint := range pins.Checkpoints {
		runtimeID := strings.TrimSpace(checkpoint.RuntimeID)
		id := strings.TrimSpace(checkpoint.ID)
		if runtimeID == "" || id == "" || !experimentDigestPattern.MatchString(strings.TrimSpace(checkpoint.Digest)) {
			return "", fmt.Errorf("%w: checkpoint runtime id, id, and digest are required", ErrInvalidRequest)
		}
		if _, exists := seen[id]; exists {
			return "", fmt.Errorf("%w: checkpoint %q is pinned more than once", ErrInvalidRequest, id)
		}
		seen[id] = struct{}{}
		if !checkpoint.Complete {
			blocked = "checkpoint_incomplete"
		}
	}
	return blocked, nil
}

// DigestPolicyExperimentCheckpoint returns the canonical checkpoint snapshot
// digest used by experiment pins. ConfigHash alone is insufficient because it
// does not identify replay progress or terminal state.
func DigestPolicyExperimentCheckpoint(checkpoint graphstore.IngestCheckpoint) (string, error) {
	payload, err := json.Marshal(struct {
		ID               string `json:"id"`
		SourceID         string `json:"source_id"`
		TenantID         string `json:"tenant_id"`
		ConfigHash       string `json:"config_hash"`
		CursorOpaque     string `json:"cursor_opaque"`
		CheckpointOpaque string `json:"checkpoint_opaque"`
		Completed        bool   `json:"completed"`
		PagesRead        int64  `json:"pages_read"`
		EventsRead       int64  `json:"events_read"`
		UpdatedAt        string `json:"updated_at"`
	}{
		ID: checkpoint.ID, SourceID: checkpoint.SourceID, TenantID: checkpoint.TenantID,
		ConfigHash: checkpoint.ConfigHash, CursorOpaque: checkpoint.CursorOpaque,
		CheckpointOpaque: checkpoint.CheckpointOpaque, Completed: checkpoint.Completed,
		PagesRead: checkpoint.PagesRead, EventsRead: checkpoint.EventsRead, UpdatedAt: checkpoint.UpdatedAt,
	})
	if err != nil {
		return "", fmt.Errorf("encode policy experiment checkpoint: %w", err)
	}
	return digest(payload), nil
}

func validExperimentStatus(status string) bool {
	switch status {
	case ExperimentStatusQueued, ExperimentStatusRunning, ExperimentStatusCompleted, ExperimentStatusFailed, ExperimentStatusBlocked:
		return true
	default:
		return false
	}
}

func validExperimentTransition(from string, to string) bool {
	switch from {
	case ExperimentStatusQueued:
		return to == ExperimentStatusRunning || to == ExperimentStatusBlocked
	case ExperimentStatusRunning:
		return to == ExperimentStatusCompleted || to == ExperimentStatusFailed || to == ExperimentStatusBlocked
	default:
		return false
	}
}

func experimentHasCheckpoint(experiment *PolicyExperiment, checkpointID string) bool {
	for _, checkpoint := range experiment.Pins.Checkpoints {
		if strings.TrimSpace(checkpoint.ID) == checkpointID {
			return true
		}
	}
	return false
}

func cloneExperimentCheckpoints(input []PolicyExperimentCheckpoint) []PolicyExperimentCheckpoint {
	return append([]PolicyExperimentCheckpoint(nil), input...)
}

func newExperimentResourceID(prefix string) (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(value[:]), nil
}

func deterministicExperimentID(tenantID string, candidateID string, idempotencyKey string) string {
	sum := digest([]byte(strings.TrimSpace(tenantID) + "\x00" + strings.TrimSpace(candidateID) + "\x00" + strings.TrimSpace(idempotencyKey)))
	return "pex_" + sum[:32]
}
