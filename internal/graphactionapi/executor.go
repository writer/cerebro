package graphactionapi

import (
	"context"
	"fmt"
	"strings"

	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/graphactions"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourcehttp/accessapprovalsclient"
)

type Executor struct {
	Service          *graphactions.Service
	NewService       func() (*graphactions.Service, error)
	AuthorizeFinding func(context.Context, string) error
	BumpFinding      func(context.Context, *ports.FindingRecord)
	BeforeLink       func(context.Context, *ports.FindingRecord, *graphactions.GraphAction, string) error
}

func (e Executor) Execute(ctx context.Context, input graphactions.Input) (*graphactions.Result, error) {
	input.FindingID = strings.TrimSpace(input.FindingID)
	if input.FindingID == "" {
		return nil, fmt.Errorf("%w: finding_id is required", graphactions.ErrInvalidRequest)
	}
	if e.AuthorizeFinding != nil {
		if err := e.AuthorizeFinding(ctx, input.FindingID); err != nil {
			return nil, err
		}
	}
	service, err := e.service()
	if err != nil {
		return nil, err
	}
	result, err := service.Execute(ctx, input)
	if err != nil {
		return nil, err
	}
	if result.Finding != nil && e.BumpFinding != nil && !result.DryRun {
		e.BumpFinding(ctx, result.Finding)
	}
	return result, nil
}

func (e Executor) Reconcile(ctx context.Context, input graphactions.ReconcileInput) (*graphactions.Result, error) {
	input.FindingID = strings.TrimSpace(input.FindingID)
	if input.FindingID == "" {
		return nil, fmt.Errorf("%w: finding_id is required", graphactions.ErrInvalidRequest)
	}
	if e.AuthorizeFinding != nil {
		if err := e.AuthorizeFinding(ctx, input.FindingID); err != nil {
			return nil, err
		}
	}
	service, err := e.service()
	if err != nil {
		return nil, err
	}
	result, err := service.Reconcile(ctx, input)
	if err != nil {
		return nil, err
	}
	if result.Finding != nil && e.BumpFinding != nil {
		e.BumpFinding(ctx, result.Finding)
	}
	return result, nil
}

func (e Executor) service() (*graphactions.Service, error) {
	service := e.Service
	if service == nil && e.NewService != nil {
		var err error
		service, err = e.NewService()
		if err != nil {
			return nil, err
		}
	}
	if service == nil {
		return nil, graphactions.ErrNotConfigured
	}
	if e.BeforeLink == nil {
		return service, nil
	}
	copy := *service
	copy.BeforeLink = e.BeforeLink
	return &copy, nil
}

func AccessApprovalsConfigured(cfg config.AccessApprovalsActionConfig) bool {
	return strings.TrimSpace(cfg.BaseURL) != "" && strings.TrimSpace(cfg.BearerToken) != ""
}

func NewServiceIfConfigured(cfg config.GraphActionsConfig, findings graphactions.FindingWorkflow, providers map[string]graphactions.ActionProvider) (*graphactions.Service, error) {
	merged := make(map[string]graphactions.ActionProvider, len(providers)+1)
	for provider, actionProvider := range providers {
		if strings.TrimSpace(provider) != "" && actionProvider != nil {
			merged[strings.TrimSpace(provider)] = actionProvider
		}
	}
	if AccessApprovalsConfigured(cfg.AccessApprovals) {
		client, err := accessapprovalsclient.New(cfg.AccessApprovals)
		if err != nil {
			return nil, err
		}
		merged[graphactions.ProviderAccessApprovals] = graphactions.AccessApprovalsProvider{Client: client}
	}
	if len(merged) == 0 {
		return nil, nil
	}
	return &graphactions.Service{
		Findings:  findings,
		Providers: merged,
	}, nil
}

func NewAccessApprovalsServiceIfConfigured(cfg config.AccessApprovalsActionConfig, findings graphactions.FindingWorkflow) (*graphactions.Service, error) {
	return NewServiceIfConfigured(config.GraphActionsConfig{AccessApprovals: cfg}, findings, nil)
}

func NewAccessApprovalsService(cfg config.AccessApprovalsActionConfig, findings graphactions.FindingWorkflow) (*graphactions.Service, error) {
	service, err := NewServiceIfConfigured(config.GraphActionsConfig{AccessApprovals: cfg}, findings, nil)
	if err != nil {
		return nil, err
	}
	if service == nil {
		return nil, graphactions.ErrNotConfigured
	}
	return service, nil
}
