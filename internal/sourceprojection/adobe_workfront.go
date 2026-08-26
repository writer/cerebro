package sourceprojection

import (
	"errors"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

var errAdobeWorkfrontRustProjectionRequired = errors.New("adobe_workfront projection requires Rust authority")

func adobeWorkfrontUsersProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errAdobeWorkfrontRustProjectionRequired
}

func adobeWorkfrontGroupsProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errAdobeWorkfrontRustProjectionRequired
}

func adobeWorkfrontProjectsProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errAdobeWorkfrontRustProjectionRequired
}

func adobeWorkfrontDocumentsProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errAdobeWorkfrontRustProjectionRequired
}

func adobeWorkfrontAuditEventsProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errAdobeWorkfrontRustProjectionRequired
}
