package sourceprojection

import (
	"errors"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

var errMicrosoftEntraIdRustProjectionRequired = errors.New("microsoft_entra_id projection requires Rust authority")

func microsoftEntraIdUsersProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errMicrosoftEntraIdRustProjectionRequired
}

func microsoftEntraIdGroupsProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errMicrosoftEntraIdRustProjectionRequired
}

func microsoftEntraIdAuditEventsProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errMicrosoftEntraIdRustProjectionRequired
}
