package sourceprojection

import (
	"errors"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

var errApigeeRustProjectionRequired = errors.New("apigee projection requires Rust authority")

func apigeeOrganizationsProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errApigeeRustProjectionRequired
}

func apigeeAPIProxiesProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errApigeeRustProjectionRequired
}

func apigeeDeploymentsProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errApigeeRustProjectionRequired
}

func apigeeDevelopersProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errApigeeRustProjectionRequired
}

func apigeeAppsProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errApigeeRustProjectionRequired
}
