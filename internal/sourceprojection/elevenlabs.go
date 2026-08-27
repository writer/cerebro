package sourceprojection

import (
	"errors"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

var errElevenlabsRustProjectionRequired = errors.New("elevenlabs projection requires Rust authority")

func elevenlabsModelCatalogProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errElevenlabsRustProjectionRequired
}

func elevenlabsVoicesProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errElevenlabsRustProjectionRequired
}

func elevenlabsServiceAccountsProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errElevenlabsRustProjectionRequired
}

func elevenlabsServiceAccountApiKeysProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errElevenlabsRustProjectionRequired
}

func elevenlabsWebhooksProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errElevenlabsRustProjectionRequired
}

func elevenlabsAuthConnectionsProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errElevenlabsRustProjectionRequired
}
