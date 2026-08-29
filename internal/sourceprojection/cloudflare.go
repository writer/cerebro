package sourceprojection

import (
	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

// cloudflareDNSRecordRetractions previously removed obsolete dns_record-to-zone
// links when a DNS record was observed as reassigned to a different zone. DNS
// record projection (entities and links alike) is now Rust-authoritative, and
// the built-in registry fails closed on every cloudflare kind before
// (*Service).ProjectRetractions can run. This hook is called unconditionally
// for every event kind regardless of registry, though, so it stays registered
// as a permanent no-op rather than erroring, to avoid tripping up unrelated
// registries (e.g. catalog-runtime template tests) that still route
// cloudflare.dns_record through a generic projector.
func cloudflareDNSRecordRetractions(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedLink, error) {
	return nil, nil
}
