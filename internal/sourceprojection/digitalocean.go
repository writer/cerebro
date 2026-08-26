package sourceprojection

import (
	"errors"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

var errDigitalOceanRustProjectionRequired = errors.New("digitalocean projection requires Rust authority")

func digitaloceanDropletsProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errDigitalOceanRustProjectionRequired
}

func digitaloceanVPCsProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errDigitalOceanRustProjectionRequired
}

func digitaloceanFirewallsProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errDigitalOceanRustProjectionRequired
}
