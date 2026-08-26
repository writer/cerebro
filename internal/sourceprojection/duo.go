package sourceprojection

import (
	"errors"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

var errDuoRustProjectionRequired = errors.New("duo projection requires Rust authority")

func duoUserProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errDuoRustProjectionRequired
}

func duoGroupProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errDuoRustProjectionRequired
}

func duoAdministratorProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errDuoRustProjectionRequired
}

func duoEndpointProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errDuoRustProjectionRequired
}

func duoPhoneProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errDuoRustProjectionRequired
}

func duoTokenProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errDuoRustProjectionRequired
}

func duoWebAuthnCredentialProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errDuoRustProjectionRequired
}

func duoRoleProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errDuoRustProjectionRequired
}

func duoApplicationProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errDuoRustProjectionRequired
}

func duoAuditEventProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errDuoRustProjectionRequired
}

func duoAuthenticationLogProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errDuoRustProjectionRequired
}
