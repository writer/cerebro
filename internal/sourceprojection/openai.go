package sourceprojection

import (
	"errors"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

var errOpenAIRustProjectionRequired = errors.New("openai projection requires Rust authority")

func openAIRustProjectionRequired(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errOpenAIRustProjectionRequired
}

var (
	openAIAPIKeyProjections             = openAIRustProjectionRequired
	openAIAuditProjections              = openAIRustProjectionRequired
	openAIGovernanceControlProjections  = openAIRustProjectionRequired
	openAIGroupProjections              = openAIRustProjectionRequired
	openAIGroupRoleProjections          = openAIRustProjectionRequired
	openAIGroupUserProjections          = openAIRustProjectionRequired
	openAIInviteProjections             = openAIRustProjectionRequired
	openAIProjectEntitlementProjections = openAIRustProjectionRequired
	openAIProjectGroupProjections       = openAIRustProjectionRequired
	openAIProjectGroupRoleProjections   = openAIRustProjectionRequired
	openAIProjectProjections            = openAIRustProjectionRequired
	openAIProjectUserProjections        = openAIRustProjectionRequired
	openAIProjectUserRoleProjections    = openAIRustProjectionRequired
	openAIRoleProjections               = openAIRustProjectionRequired
	openAIServiceAccountProjections     = openAIRustProjectionRequired
	openAIUsageMetricProjections        = openAIRustProjectionRequired
	openAIUserProjections               = openAIRustProjectionRequired
	openAIUserRoleProjections           = openAIRustProjectionRequired
)
