package sourceprojection

import (
	"errors"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

var errApi2cartRustProjectionRequired = errors.New("api2cart projection requires Rust authority")

func api2cartAttributeGroupListJsonProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errApi2cartRustProjectionRequired
}

func api2cartAttributeAttributesetListJsonProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errApi2cartRustProjectionRequired
}
