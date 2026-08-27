package sourceprojection

import (
	"errors"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

var errHashicorpVaultRustProjectionRequired = errors.New("hashicorp_vault projection requires Rust authority")

func hashicorpVaultUsersProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errHashicorpVaultRustProjectionRequired
}

func hashicorpVaultSecretsProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errHashicorpVaultRustProjectionRequired
}

func hashicorpVaultAuditEventsProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errHashicorpVaultRustProjectionRequired
}
