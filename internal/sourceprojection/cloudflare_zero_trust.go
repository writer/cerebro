package sourceprojection

import (
	"errors"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

var errCloudflareZeroTrustRustProjectionRequired = errors.New("cloudflare_zero_trust projection requires Rust authority")

func cloudflareZeroTrustUsersProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errCloudflareZeroTrustRustProjectionRequired
}

func cloudflareZeroTrustGroupsProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errCloudflareZeroTrustRustProjectionRequired
}

func cloudflareZeroTrustRolesProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errCloudflareZeroTrustRustProjectionRequired
}

func cloudflareZeroTrustApplicationsProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errCloudflareZeroTrustRustProjectionRequired
}

func cloudflareZeroTrustAuditEventsProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errCloudflareZeroTrustRustProjectionRequired
}
