package sourceprojection

import (
	"errors"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

var errDatadogRustProjectionRequired = errors.New("datadog projection requires Rust authority")

func datadogUserProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errDatadogRustProjectionRequired
}

func datadogTaggedResourceProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errDatadogRustProjectionRequired
}

func datadogIncidentProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errDatadogRustProjectionRequired
}

func datadogAuditEventProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errDatadogRustProjectionRequired
}

// datadogRoleProjections and datadogTeamProjections previously dispatched
// straight to the shared genericInventoryProjections helper (still used by
// kubernetes, langchain, langfuse, writer, pagerduty, snyk, etc.). They get
// their own datadog-only fail-closed wrappers so the shared helper is left
// untouched (precedent: the Cloudflare retirement, #2747).
func datadogRoleProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errDatadogRustProjectionRequired
}

func datadogTeamProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errDatadogRustProjectionRequired
}
