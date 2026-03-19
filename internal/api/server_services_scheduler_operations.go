package api

import (
	"context"
	"errors"

	"github.com/evalops/cerebro/internal/scheduler"
	"github.com/evalops/cerebro/internal/webhooks"
)

var errSchedulerUnavailable = errors.New("scheduler not initialized")

type schedulerOperationsService interface {
	Status() (scheduler.Status, error)
	ListJobs() ([]scheduler.Job, error)
	RunJob(ctx context.Context, name, triggeredBy string) error
	EnableJob(name string) error
	DisableJob(name string) error
}

type serverSchedulerOperationsService struct {
	deps *serverDependencies
}

func newSchedulerOperationsService(deps *serverDependencies) schedulerOperationsService {
	return serverSchedulerOperationsService{deps: deps}
}

func (s serverSchedulerOperationsService) Status() (scheduler.Status, error) {
	if s.deps == nil || s.deps.Scheduler == nil {
		return scheduler.Status{}, errSchedulerUnavailable
	}
	return s.deps.Scheduler.Status(), nil
}

func (s serverSchedulerOperationsService) ListJobs() ([]scheduler.Job, error) {
	if s.deps == nil || s.deps.Scheduler == nil {
		return nil, errSchedulerUnavailable
	}
	return s.deps.Scheduler.ListJobs(), nil
}

func (s serverSchedulerOperationsService) RunJob(ctx context.Context, name, triggeredBy string) error {
	if s.deps == nil || s.deps.Scheduler == nil {
		return errSchedulerUnavailable
	}
	if err := s.deps.Scheduler.RunNow(name); err != nil {
		return err
	}
	if s.deps.Webhooks != nil {
		if err := s.deps.Webhooks.EmitWithErrors(ctx, webhooks.EventSchedulerJobRun, map[string]interface{}{
			"job_name":     name,
			"triggered_by": triggeredBy,
		}); err != nil && s.deps.Logger != nil {
			s.deps.Logger.Warn("failed to emit scheduler job event", "job", name, "error", err)
		}
	}
	return nil
}

func (s serverSchedulerOperationsService) EnableJob(name string) error {
	if s.deps == nil || s.deps.Scheduler == nil {
		return errSchedulerUnavailable
	}
	s.deps.Scheduler.EnableJob(name)
	return nil
}

func (s serverSchedulerOperationsService) DisableJob(name string) error {
	if s.deps == nil || s.deps.Scheduler == nil {
		return errSchedulerUnavailable
	}
	s.deps.Scheduler.DisableJob(name)
	return nil
}

var _ schedulerOperationsService = serverSchedulerOperationsService{}
