package api

import (
	"context"
	"errors"

	"github.com/writer/cerebro/internal/remediation"
	"github.com/writer/cerebro/internal/webhooks"
)

var (
	errRemediationUnavailable         = errors.New("remediation not initialized")
	errRemediationExecutorUnavailable = errors.New("remediation executor not initialized")
)

type remediationOperationsService interface {
	ListRules() ([]remediation.Rule, error)
	CreateRule(ctx context.Context, rule remediation.Rule, createdBy string) (remediation.Rule, error)
	UpdateRule(id string, rule remediation.Rule) (*remediation.Rule, error)
	DeleteRule(id string) error
	GetRule(id string) (*remediation.Rule, bool, error)
	EnableRule(id string) error
	DisableRule(id string) error
	ListExecutions(limit int) ([]*remediation.Execution, error)
	GetExecution(id string) (*remediation.Execution, bool, error)
	ApproveExecution(ctx context.Context, id, approverID string) error
	RejectExecution(ctx context.Context, id, rejecterID, reason string) error
}

type serverRemediationOperationsService struct {
	deps *serverDependencies
}

func newRemediationOperationsService(deps *serverDependencies) remediationOperationsService {
	return serverRemediationOperationsService{deps: deps}
}

func (s serverRemediationOperationsService) ListRules() ([]remediation.Rule, error) {
	if s.deps == nil || s.deps.Remediation == nil {
		return nil, errRemediationUnavailable
	}
	return s.deps.Remediation.ListRules(), nil
}

func (s serverRemediationOperationsService) CreateRule(ctx context.Context, rule remediation.Rule, createdBy string) (remediation.Rule, error) {
	if s.deps == nil || s.deps.Remediation == nil {
		return remediation.Rule{}, errRemediationUnavailable
	}
	if err := s.deps.Remediation.AddRule(rule); err != nil {
		return remediation.Rule{}, err
	}
	if s.deps.Webhooks != nil {
		if err := s.deps.Webhooks.EmitWithErrors(ctx, webhooks.EventRemediationRule, map[string]interface{}{
			"rule_id":    rule.ID,
			"rule_name":  rule.Name,
			"created_by": createdBy,
		}); err != nil && s.deps.Logger != nil {
			s.deps.Logger.Warn("failed to emit remediation rule event", "rule_id", rule.ID, "error", err)
		}
	}
	return rule, nil
}

func (s serverRemediationOperationsService) UpdateRule(id string, rule remediation.Rule) (*remediation.Rule, error) {
	if s.deps == nil || s.deps.Remediation == nil {
		return nil, errRemediationUnavailable
	}
	if err := s.deps.Remediation.UpdateRule(id, rule); err != nil {
		return nil, err
	}
	updated, _ := s.deps.Remediation.GetRule(id)
	return updated, nil
}

func (s serverRemediationOperationsService) DeleteRule(id string) error {
	if s.deps == nil || s.deps.Remediation == nil {
		return errRemediationUnavailable
	}
	return s.deps.Remediation.DeleteRule(id)
}

func (s serverRemediationOperationsService) GetRule(id string) (*remediation.Rule, bool, error) {
	if s.deps == nil || s.deps.Remediation == nil {
		return nil, false, errRemediationUnavailable
	}
	rule, ok := s.deps.Remediation.GetRule(id)
	return rule, ok, nil
}

func (s serverRemediationOperationsService) EnableRule(id string) error {
	if s.deps == nil || s.deps.Remediation == nil {
		return errRemediationUnavailable
	}
	return s.deps.Remediation.EnableRule(id)
}

func (s serverRemediationOperationsService) DisableRule(id string) error {
	if s.deps == nil || s.deps.Remediation == nil {
		return errRemediationUnavailable
	}
	return s.deps.Remediation.DisableRule(id)
}

func (s serverRemediationOperationsService) ListExecutions(limit int) ([]*remediation.Execution, error) {
	if s.deps == nil {
		return nil, errRemediationUnavailable
	}
	if s.deps.RemediationExecutor != nil {
		return s.deps.RemediationExecutor.ListExecutions(context.Background(), limit), nil
	}
	if s.deps.Remediation == nil {
		return nil, errRemediationUnavailable
	}
	return s.deps.Remediation.ListExecutions(limit), nil
}

func (s serverRemediationOperationsService) GetExecution(id string) (*remediation.Execution, bool, error) {
	if s.deps == nil {
		return nil, false, errRemediationUnavailable
	}
	if s.deps.RemediationExecutor != nil {
		execution, ok := s.deps.RemediationExecutor.GetExecution(context.Background(), id)
		return execution, ok, nil
	}
	if s.deps.Remediation == nil {
		return nil, false, errRemediationUnavailable
	}
	execution, ok := s.deps.Remediation.GetExecution(id)
	return execution, ok, nil
}

func (s serverRemediationOperationsService) ApproveExecution(ctx context.Context, id, approverID string) error {
	if s.deps == nil || s.deps.RemediationExecutor == nil {
		return errRemediationExecutorUnavailable
	}
	return s.deps.RemediationExecutor.Approve(ctx, id, approverID)
}

func (s serverRemediationOperationsService) RejectExecution(ctx context.Context, id, rejecterID, reason string) error {
	if s.deps == nil || s.deps.RemediationExecutor == nil {
		return errRemediationExecutorUnavailable
	}
	return s.deps.RemediationExecutor.Reject(ctx, id, rejecterID, reason)
}

var _ remediationOperationsService = serverRemediationOperationsService{}
