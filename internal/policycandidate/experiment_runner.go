package policycandidate

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/writer/cerebro/internal/graphstore"
	platformjobs "github.com/writer/cerebro/internal/jobs"
	"github.com/writer/cerebro/internal/ports"
)

type ExperimentJobInput struct {
	Experiment PolicyExperiment
}

type ExperimentJobOutput struct {
	Observations []AppendExperimentObservationRequest
}

type ExperimentJobHandler interface {
	RunPolicyExperiment(context.Context, ExperimentJobInput) (ExperimentJobOutput, error)
}

type ExperimentJobHandlerFunc func(context.Context, ExperimentJobInput) (ExperimentJobOutput, error)

func (f ExperimentJobHandlerFunc) RunPolicyExperiment(ctx context.Context, input ExperimentJobInput) (ExperimentJobOutput, error) {
	return f(ctx, input)
}

type ExperimentCheckpointStore interface {
	GetIngestCheckpoint(context.Context, string) (graphstore.IngestCheckpoint, bool, error)
}

// ExperimentRunner executes immutable evaluation runs through the generic
// leased-job substrate. Its only write surface is append-only experiment state.
type ExperimentRunner struct {
	Service     Service
	Checkpoints ExperimentCheckpointStore
	Statuses    ExperimentCheckpointStatusReader
	Handler     ExperimentJobHandler
}

func (r ExperimentRunner) Run(ctx context.Context, job *ports.Job) (map[string]any, map[string]string, error) {
	if job == nil || strings.TrimSpace(job.ID) == "" {
		return nil, nil, fmt.Errorf("%w: policy experiment job is required", platformjobs.ErrInvalidRequest)
	}
	experimentID := strings.TrimSpace(job.SubjectID)
	if value, ok := job.Payload["experiment_id"].(string); ok && strings.TrimSpace(value) != "" {
		experimentID = strings.TrimSpace(value)
	}
	if experimentID == "" {
		return nil, nil, fmt.Errorf("%w: experiment_id is required", platformjobs.ErrInvalidRequest)
	}
	experiment, err := r.Service.GetExperiment(ctx, experimentID)
	if err != nil {
		return nil, nil, err
	}
	if strings.TrimSpace(job.TenantID) == "" || experiment.TenantID != job.TenantID {
		return nil, nil, ErrNotFound
	}
	refs := map[string]string{"policy_experiment_id": experiment.ID}
	if experiment.Status == ExperimentStatusCompleted {
		return experimentJobResult(experiment), refs, nil
	}
	if experiment.Status != ExperimentStatusQueued && experiment.Status != ExperimentStatusRunning {
		return nil, refs, fmt.Errorf("%w: policy experiment status %q cannot run", platformjobs.ErrInvalidRequest, experiment.Status)
	}
	if reason, validationErr := r.validateCheckpoints(ctx, experiment); validationErr != nil {
		return nil, refs, validationErr
	} else if reason != "" {
		blocked, transitionErr := r.Service.TransitionExperiment(ctx, TransitionExperimentRequest{
			ExperimentID: experiment.ID, ExpectedRevision: experiment.Revision, Status: ExperimentStatusBlocked, Reason: reason,
		})
		if transitionErr != nil {
			return nil, refs, transitionErr
		}
		return experimentJobResult(blocked), refs, fmt.Errorf("%w: policy experiment blocked: %s", platformjobs.ErrInvalidRequest, reason)
	}
	if experiment.Status == ExperimentStatusQueued {
		experiment, err = r.Service.TransitionExperiment(ctx, TransitionExperimentRequest{
			ExperimentID: experiment.ID, ExpectedRevision: experiment.Revision, Status: ExperimentStatusRunning,
		})
		if err != nil {
			return nil, refs, err
		}
	}
	input := ExperimentJobInput{Experiment: cloneRunnerExperiment(*experiment)}
	var output ExperimentJobOutput
	var runErr error
	if r.Handler != nil {
		output, runErr = r.Handler.RunPolicyExperiment(ctx, input)
	} else {
		output.Observations, runErr = r.Service.EvaluateCurrentExperiment(ctx, &input.Experiment)
	}
	if runErr != nil {
		reason := "handler_failed"
		if errors.Is(runErr, context.Canceled) || errors.Is(ctx.Err(), context.Canceled) {
			reason = "job_cancelled"
		}
		return nil, refs, r.fail(context.WithoutCancel(ctx), experiment.ID, reason, runErr)
	}
	if len(output.Observations) == 0 {
		return nil, refs, r.fail(ctx, experiment.ID, "observations_required", errors.New("policy experiment handler returned no observations"))
	}
	if len(output.Observations) > MaxExperimentObservations {
		return nil, refs, r.fail(ctx, experiment.ID, "observation_limit_exceeded", fmt.Errorf("policy experiment handler returned more than %d observations", MaxExperimentObservations))
	}
	for index, observation := range output.Observations {
		observation.ExperimentID = experiment.ID
		observation.IdempotencyKey = fmt.Sprintf("job.%s.%d", job.ID, index)
		if _, err := r.Service.AppendExperimentObservation(ctx, observation); err != nil {
			return nil, refs, r.fail(context.WithoutCancel(ctx), experiment.ID, "observation_append_failed", err)
		}
	}
	experiment, err = r.Service.GetExperiment(ctx, experiment.ID)
	if err != nil {
		return nil, refs, err
	}
	experiment, err = r.Service.TransitionExperiment(ctx, TransitionExperimentRequest{
		ExperimentID: experiment.ID, ExpectedRevision: experiment.Revision, Status: ExperimentStatusCompleted,
	})
	if err != nil {
		return nil, refs, err
	}
	return experimentJobResult(experiment), refs, nil
}

func (r ExperimentRunner) validateCheckpoints(ctx context.Context, experiment *PolicyExperiment) (string, error) {
	if experiment == nil || len(experiment.Pins.Checkpoints) == 0 {
		return "checkpoint_missing", nil
	}
	if r.Checkpoints == nil {
		return "", fmt.Errorf("%w: policy experiment checkpoint store is unavailable", platformjobs.ErrRuntimeUnavailable)
	}
	for _, pin := range experiment.Pins.Checkpoints {
		if strings.TrimSpace(pin.ID) == "" {
			return "checkpoint_missing", nil
		}
		if !pin.Complete {
			return "checkpoint_incomplete", nil
		}
		checkpoint, found, err := r.Checkpoints.GetIngestCheckpoint(ctx, pin.ID)
		if err != nil {
			return "", platformjobs.Retryable(fmt.Errorf("read policy experiment checkpoint %q: %w", pin.ID, err))
		}
		if !found {
			return "checkpoint_missing", nil
		}
		if strings.TrimSpace(checkpoint.TenantID) == "" || checkpoint.TenantID != experiment.TenantID {
			return "checkpoint_tenant_mismatch", nil
		}
		if !checkpoint.Completed {
			return "checkpoint_incomplete", nil
		}
		digest, err := DigestPolicyExperimentCheckpoint(checkpoint)
		if err != nil {
			return "", err
		}
		if digest != pin.Digest {
			return "checkpoint_changed", nil
		}
		if pin.Current && strings.TrimSpace(checkpoint.CursorOpaque) != "" {
			return "checkpoint_not_current", nil
		}
		if pin.Current {
			if r.Statuses == nil {
				return "", fmt.Errorf("%w: policy experiment checkpoint status is unavailable", platformjobs.ErrRuntimeUnavailable)
			}
			status, err := r.Statuses.PolicyExperimentCheckpointStatus(ctx, pin.RuntimeID)
			if err != nil {
				return "", platformjobs.Retryable(fmt.Errorf("read current policy experiment checkpoint status: %w", err))
			}
			if !status.Found || !status.Completed || !status.CheckpointCurrent || status.RuntimeID != pin.RuntimeID || status.TenantID != experiment.TenantID || status.CheckpointID != pin.ID {
				return "checkpoint_not_current", nil
			}
		}
	}
	return "", nil
}

func (r ExperimentRunner) fail(ctx context.Context, experimentID string, reason string, cause error) error {
	experiment, err := r.Service.GetExperiment(ctx, experimentID)
	if err != nil {
		return errors.Join(cause, err)
	}
	if experiment.Status != ExperimentStatusRunning {
		return cause
	}
	_, transitionErr := r.Service.TransitionExperiment(ctx, TransitionExperimentRequest{
		ExperimentID: experiment.ID, ExpectedRevision: experiment.Revision, Status: ExperimentStatusFailed, Reason: reason,
	})
	return errors.Join(cause, transitionErr)
}

func experimentJobResult(experiment *PolicyExperiment) map[string]any {
	if experiment == nil {
		return nil
	}
	return map[string]any{"experiment_id": experiment.ID, "status": experiment.Status, "observation_count": experiment.ObservationCount}
}

func cloneRunnerExperiment(experiment PolicyExperiment) PolicyExperiment {
	experiment.Pins.Checkpoints = append([]PolicyExperimentCheckpoint(nil), experiment.Pins.Checkpoints...)
	return experiment
}
