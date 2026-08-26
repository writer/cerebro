package sourceprojection

import (
	"errors"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

var errCloudflareRustProjectionRequired = errors.New("cloudflare projection requires Rust authority")

func cloudflareAccountProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errCloudflareRustProjectionRequired
}

func cloudflareMemberProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errCloudflareRustProjectionRequired
}

func cloudflareRoleProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errCloudflareRustProjectionRequired
}

func cloudflareZoneProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errCloudflareRustProjectionRequired
}

func cloudflareDNSRecordProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errCloudflareRustProjectionRequired
}

func cloudflareAuditLogProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errCloudflareRustProjectionRequired
}

func cloudflareLoadBalancerProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errCloudflareRustProjectionRequired
}

func cloudflareAccountScopedInventoryProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errCloudflareRustProjectionRequired
}

func cloudflareZoneScopedInventoryProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errCloudflareRustProjectionRequired
}

// cloudflareDNSRecordRetractions previously removed obsolete dns_record-to-zone
// links when a DNS record was observed as reassigned to a different zone. DNS
// record projection (entities and links alike) is now Rust-authoritative, and
// (*Service).ProjectRecordsContext already fails closed on cloudflare.dns_record
// before (*Service).ProjectRetractions can run in the production dispatch path
// (see ProjectWithDelta), so this hook is unreachable there. It is called
// unconditionally for every event kind regardless of registry, though, so it
// stays registered as a permanent no-op rather than erroring, to avoid
// tripping up unrelated registries (e.g. catalog-runtime template tests) that
// still route cloudflare.dns_record through a generic projector.
func cloudflareDNSRecordRetractions(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedLink, error) {
	return nil, nil
}
