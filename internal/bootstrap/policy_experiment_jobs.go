package bootstrap

import (
	"context"

	"github.com/writer/cerebro/internal/graphingest"
	platformjobs "github.com/writer/cerebro/internal/jobs"
	"github.com/writer/cerebro/internal/policycandidate"
	"github.com/writer/cerebro/internal/ports"
)

type PolicyExperimentJobHandler = policycandidate.ExperimentJobHandler

func (a *App) runPolicyCandidateExperimentJob(ctx context.Context, job *ports.Job, _ *platformjobs.Service) (map[string]any, map[string]string, error) {
	checkpoints, _ := a.deps.GraphStore.(policycandidate.ExperimentCheckpointStore)
	statuses := a.deps.PolicyExperimentCheckpoints
	if statuses == nil {
		statuses = policyExperimentCheckpointStatusAdapter{service: a.graphIngestService()}
	}
	runner := policycandidate.ExperimentRunner{
		Service: a.policyCandidateService(), Checkpoints: checkpoints, Statuses: statuses, Handler: a.deps.PolicyExperiments,
	}
	return runner.JobRunner()(ctx, job, nil)
}

type policyExperimentCheckpointStatusAdapter struct{ service *graphingest.Service }

func (a policyExperimentCheckpointStatusAdapter) PolicyExperimentCheckpointStatus(ctx context.Context, runtimeID string) (policycandidate.ExperimentCheckpointStatus, error) {
	status, err := a.service.RuntimeCheckpointStatus(ctx, graphingest.RuntimeRequest{RuntimeID: runtimeID})
	if err != nil {
		return policycandidate.ExperimentCheckpointStatus{}, err
	}
	return policycandidate.ExperimentCheckpointStatus{
		RuntimeID: status.RuntimeID, TenantID: status.TenantID, CheckpointID: status.CheckpointID,
		Found: status.Found, Completed: status.Completed, CheckpointCurrent: status.CheckpointCurrent,
	}, nil
}
