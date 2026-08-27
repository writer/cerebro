package sourceprojection

import (
	"errors"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

var errLangChainRustProjectionRequired = errors.New("langchain projection requires Rust authority")

func langChainCredentialProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errLangChainRustProjectionRequired
}

func langChainAuditProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errLangChainRustProjectionRequired
}

// langChainDatasetProjections and langChainFeedbackProjections previously
// dispatched straight to the shared genericInventoryProjections helper
// (still used by kubernetes, langfuse, writer, pagerduty, snyk, etc.). They
// get their own langchain-only fail-closed wrappers so the shared helper is
// left untouched (precedent: the Datadog retirement, #2747).
func langChainDatasetProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errLangChainRustProjectionRequired
}

func langChainFeedbackProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errLangChainRustProjectionRequired
}

func langChainOrganizationProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errLangChainRustProjectionRequired
}

func langChainOrganizationMemberProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errLangChainRustProjectionRequired
}

func langChainProjectProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errLangChainRustProjectionRequired
}

func langChainRoleProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errLangChainRustProjectionRequired
}

func langChainUsageMetricProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errLangChainRustProjectionRequired
}

func langChainServiceAccountProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errLangChainRustProjectionRequired
}

func langChainGovernanceControlProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errLangChainRustProjectionRequired
}

func langChainWorkspaceProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errLangChainRustProjectionRequired
}

func langChainWorkspaceMemberProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errLangChainRustProjectionRequired
}
