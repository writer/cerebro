package sourceprojection

import (
	"errors"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

var errAbuseipdbRustProjectionRequired = errors.New("abuseipdb projection requires Rust authority")

func abuseipdbReportsProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errAbuseipdbRustProjectionRequired
}

func abuseipdbIpAddressesProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errAbuseipdbRustProjectionRequired
}
