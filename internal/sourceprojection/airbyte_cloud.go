package sourceprojection

import (
	"errors"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

var errAirbyteCloudRustProjectionRequired = errors.New("airbyte_cloud projection requires Rust authority")

func airbyteCloudUsersProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errAirbyteCloudRustProjectionRequired
}

func airbyteCloudOrganizationsProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errAirbyteCloudRustProjectionRequired
}

func airbyteCloudSourcesProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errAirbyteCloudRustProjectionRequired
}

func airbyteCloudPermissionsProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errAirbyteCloudRustProjectionRequired
}

func airbyteCloudConnectionsProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errAirbyteCloudRustProjectionRequired
}
