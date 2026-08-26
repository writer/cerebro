package sourceprojection

import (
	"errors"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestCloudflareGoProjectionFailsClosedForRustAuthoritativeFamilies(t *testing.T) {
	for _, kind := range []string{
		"cloudflare.access_application",
		"cloudflare.access_group",
		"cloudflare.account",
		"cloudflare.account_ruleset",
		"cloudflare.audit_log",
		"cloudflare.dns_record",
		"cloudflare.gateway_rule",
		"cloudflare.load_balancer",
		"cloudflare.load_balancer_pool",
		"cloudflare.member",
		"cloudflare.role",
		"cloudflare.worker_script",
		"cloudflare.zone",
		"cloudflare.zone_access_application",
		"cloudflare.zone_access_group",
		"cloudflare.zone_ruleset",
	} {
		t.Run(kind, func(t *testing.T) {
			entities, links, err := ProjectEvent(&cerebrov1.EventEnvelope{
				Id:       "event-1",
				TenantId: "tenant",
				SourceId: "cloudflare",
				Kind:     kind,
			})
			if !errors.Is(err, errCloudflareRustProjectionRequired) {
				t.Fatalf("ProjectEvent() error = %v", err)
			}
			if len(entities) != 0 || len(links) != 0 {
				t.Fatalf("Go projection produced entities=%d links=%d", len(entities), len(links))
			}
		})
	}
}

// TestCloudflareDNSRecordRetractionsIsNoOp covers the DNS-record zone
// reassignment retraction hook, which is wired independently of the family
// dispatch table above (see (*Service).ProjectRetractions) and is called
// unconditionally for every event regardless of registry. Now that DNS record
// projection is Rust-authoritative, it must never compute retractions itself.
func TestCloudflareDNSRecordRetractionsIsNoOp(t *testing.T) {
	event := &cerebrov1.EventEnvelope{
		Id:       "event-1",
		TenantId: "tenant",
		SourceId: "cloudflare",
		Kind:     "cloudflare.dns_record",
		Attributes: map[string]string{
			"record_id":        "dns-1",
			"zone_id":          "zone-2",
			"previous_zone_id": "zone-1",
		},
	}
	links, err := cloudflareDNSRecordRetractions(event)
	if err != nil {
		t.Fatalf("cloudflareDNSRecordRetractions() error = %v", err)
	}
	if len(links) != 0 {
		t.Fatalf("Go retraction produced links=%d, want none", len(links))
	}
}
