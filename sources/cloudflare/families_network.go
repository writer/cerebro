package cloudflare

import "github.com/writer/cerebro/sources/internal/jsonapi"

func networkFamilies() []jsonapi.Family {
	return []jsonapi.Family{
		{
			Name:             "zone",
			Path:             "/zones",
			URNKind:          "cloudflare_zone",
			IDKeys:           []string{"id"},
			TimestampKeys:    []string{"created_on", "modified_on"},
			ListKeys:         cloudflareResultListKeys(),
			Attributes:       map[string]string{"zone_id": "id", "account_id": "account.id|account_id", "name": "name", "status": "status", "type": "type", "paused": "paused"},
			StaticAttributes: cloudflareStaticAttributes(),
		},
		{
			Name:             "dns_record",
			Path:             "/zones/{zone_id}/dns_records",
			PathParams:       []string{"zone_id"},
			URNKind:          "cloudflare_dns_record",
			IDKeys:           []string{"id"},
			TimestampKeys:    []string{"created_on", "modified_on"},
			ListKeys:         cloudflareResultListKeys(),
			Attributes:       map[string]string{"record_id": "id", "zone_id": "zone_id", "name": "name", "type": "type", "content": "content", "proxied": "proxied"},
			StaticAttributes: cloudflareStaticAttributes(),
		},
		{
			Name:             "zone_ruleset",
			Path:             "/zones/{zone_id}/rulesets",
			DetailPath:       "/zones/{zone_id}/rulesets/{id}",
			PathParams:       []string{"zone_id"},
			URNKind:          "cloudflare_zone_ruleset",
			IDKeys:           []string{"id"},
			TimestampKeys:    []string{"last_updated"},
			ListKeys:         cloudflareResultListKeys(),
			Attributes:       map[string]string{"ruleset_id": "id", "zone_id": "zone_id", "name": "name", "kind": "kind", "phase": "phase", "version": "version", "last_updated": "last_updated", "rules": "rules"},
			StaticAttributes: cloudflareStaticAttributes(),
		},
		{
			Name:             "load_balancer",
			Path:             "/zones/{zone_id}/load_balancers",
			PathParams:       []string{"zone_id"},
			URNKind:          "cloudflare_load_balancer",
			IDKeys:           []string{"id"},
			TimestampKeys:    []string{"created_on", "modified_on"},
			ListKeys:         cloudflareResultListKeys(),
			Attributes:       map[string]string{"load_balancer_id": "id", "zone_id": "zone_id", "name": "name", "fallback_pool": "fallback_pool", "default_pools": "default_pools", "enabled": "enabled", "proxied": "proxied", "steering_policy": "steering_policy"},
			StaticAttributes: cloudflareStaticAttributes(),
		},
		{
			Name:             "load_balancer_pool",
			Path:             "/accounts/{account_id}/load_balancers/pools",
			PathParams:       []string{"account_id"},
			URNKind:          "cloudflare_load_balancer_pool",
			IDKeys:           []string{"id"},
			TimestampKeys:    []string{"created_on", "modified_on"},
			ListKeys:         cloudflareResultListKeys(),
			Attributes:       map[string]string{"pool_id": "id", "account_id": "account_id", "name": "name", "enabled": "enabled", "origins": "origins", "check_regions": "check_regions", "minimum_origins": "minimum_origins"},
			StaticAttributes: cloudflareStaticAttributes(),
		},
	}
}
