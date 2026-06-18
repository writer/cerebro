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
	result, err := service.Execute(ctx, input)
	if err != nil {
		return nil, err
	}
	if result.Finding != nil && e.BumpFinding != nil {
		e.BumpFinding(ctx, result.Finding)
	}
	return result, nil
}

func AccessApprovalsConfigured(cfg config.AccessApprovalsActionConfig) bool {
	return strings.TrimSpace(cfg.BaseURL) != "" && strings.TrimSpace(cfg.BearerToken) != ""
}

func NewAccessApprovalsService(cfg config.AccessApprovalsActionConfig, findings graphactions.FindingWorkflow) (*graphactions.Service, error) {
	client, err := accessapprovalsclient.New(cfg)
	if err != nil {
		return nil, err
	}
	return &graphactions.Service{Findings: findings, Client: client}, nil
}
