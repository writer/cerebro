package cloudflare

import "github.com/writer/cerebro/sources/internal/jsonapi"

func accessFamilies() []jsonapi.Family {
	return []jsonapi.Family{
		{
			Name:             "access_application",
			Path:             "/accounts/{account_id}/access/apps",
			PathParams:       []string{"account_id"},
			URNKind:          "cloudflare_access_application",
			IDKeys:           []string{"id"},
			TimestampKeys:    []string{"created_at", "updated_at"},
			ListKeys:         cloudflareResultListKeys(),
			Attributes:       map[string]string{"application_id": "id", "account_id": "account_id", "name": "name", "domain": "domain", "type": "type", "aud": "aud", "session_duration": "session_duration", "policies": "policies", "allowed_idps": "allowed_idps", "auto_redirect_to_identity": "auto_redirect_to_identity"},
			StaticAttributes: cloudflareStaticAttributes(),
		},
		{
			Name:             "zone_access_application",
			Path:             "/zones/{zone_id}/access/apps",
			PathParams:       []string{"zone_id"},
			URNKind:          "cloudflare_zone_access_application",
			IDKeys:           []string{"id"},
			TimestampKeys:    []string{"created_at", "updated_at"},
			ListKeys:         cloudflareResultListKeys(),
			Attributes:       map[string]string{"application_id": "id", "zone_id": "zone_id", "name": "name", "domain": "domain", "type": "type", "aud": "aud", "session_duration": "session_duration", "policies": "policies", "allowed_idps": "allowed_idps", "auto_redirect_to_identity": "auto_redirect_to_identity"},
			StaticAttributes: cloudflareStaticAttributes(),
		},
		{
			Name:             "access_group",
			Path:             "/accounts/{account_id}/access/groups",
			PathParams:       []string{"account_id"},
			URNKind:          "cloudflare_access_group",
			IDKeys:           []string{"id"},
			TimestampKeys:    []string{"created_at", "updated_at"},
			ListKeys:         cloudflareResultListKeys(),
			Attributes:       map[string]string{"group_id": "id", "account_id": "account_id", "name": "name", "include": "include", "exclude": "exclude", "require": "require"},
			StaticAttributes: cloudflareStaticAttributes(),
		},
		{
			Name:             "zone_access_group",
			Path:             "/zones/{zone_id}/access/groups",
			PathParams:       []string{"zone_id"},
			URNKind:          "cloudflare_zone_access_group",
			IDKeys:           []string{"id"},
			TimestampKeys:    []string{"created_at", "updated_at"},
			ListKeys:         cloudflareResultListKeys(),
			Attributes:       map[string]string{"group_id": "id", "zone_id": "zone_id", "name": "name", "include": "include", "exclude": "exclude", "require": "require"},
			StaticAttributes: cloudflareStaticAttributes(),
		},
		{
			Name:             "gateway_rule",
			Path:             "/accounts/{account_id}/gateway/rules",
			PathParams:       []string{"account_id"},
			URNKind:          "cloudflare_gateway_rule",
			IDKeys:           []string{"id"},
			TimestampKeys:    []string{"created_at", "updated_at"},
			ListKeys:         cloudflareResultListKeys(),
			Attributes:       map[string]string{"rule_id": "id", "account_id": "account_id", "name": "name", "action": "action", "traffic": "traffic", "enabled": "enabled", "precedence": "precedence", "filters": "filters", "rule_settings": "rule_settings"},
			StaticAttributes: cloudflareStaticAttributes(),
		},
	}
}
