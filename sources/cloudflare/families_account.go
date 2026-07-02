package cloudflare

import "github.com/writer/cerebro/sources/internal/jsonapi"

func accountFamilies() []jsonapi.Family {
	return []jsonapi.Family{
		{
			Name:             "account",
			Path:             "/accounts",
			URNKind:          "cloudflare_account",
			IDKeys:           []string{"id"},
			ListKeys:         cloudflareResultListKeys(),
			Attributes:       map[string]string{"account_id": "id", "name": "name", "type": "type"},
			StaticAttributes: cloudflareStaticAttributes(),
		},
		{
			Name:             "member",
			Path:             "/accounts/{account_id}/members",
			PathParams:       []string{"account_id"},
			URNKind:          "cloudflare_member",
			IDKeys:           []string{"id"},
			TimestampKeys:    []string{"created_on", "modified_on"},
			ListKeys:         cloudflareResultListKeys(),
			Attributes:       map[string]string{"member_id": "id", "account_id": "account.id|account_id", "email": "user.email|email", "status": "status", "roles": "roles"},
			StaticAttributes: cloudflareStaticAttributes(),
		},
		{
			Name:             "role",
			Path:             "/accounts/{account_id}/roles",
			DetailPath:       "/accounts/{account_id}/roles/{id}",
			PathParams:       []string{"account_id"},
			URNKind:          "cloudflare_role",
			IDKeys:           []string{"id"},
			ListKeys:         cloudflareResultListKeys(),
			Attributes:       map[string]string{"role_id": "id", "name": "name", "description": "description", "permissions": "permissions", "permission_groups": "permission_groups"},
			StaticAttributes: cloudflareStaticAttributes(),
		},
		{
			Name:             "account_ruleset",
			Path:             "/accounts/{account_id}/rulesets",
			DetailPath:       "/accounts/{account_id}/rulesets/{id}",
			PathParams:       []string{"account_id"},
			URNKind:          "cloudflare_account_ruleset",
			IDKeys:           []string{"id"},
			TimestampKeys:    []string{"last_updated"},
			ListKeys:         cloudflareResultListKeys(),
			Attributes:       map[string]string{"ruleset_id": "id", "account_id": "account_id", "name": "name", "kind": "kind", "phase": "phase", "version": "version", "last_updated": "last_updated", "rules": "rules"},
			StaticAttributes: cloudflareStaticAttributes(),
		},
		{
			Name:             "worker_script",
			Path:             "/accounts/{account_id}/workers/scripts",
			PathParams:       []string{"account_id"},
			URNKind:          "cloudflare_worker_script",
			IDKeys:           []string{"id"},
			TimestampKeys:    []string{"created_on", "modified_on"},
			ListKeys:         cloudflareResultListKeys(),
			Attributes:       map[string]string{"script_id": "id", "account_id": "account_id", "created_on": "created_on", "modified_on": "modified_on", "compatibility_date": "compatibility_date", "tags": "tags", "bindings": "bindings", "placement": "placement", "resource_name": "id|name"},
			StaticAttributes: cloudflareStaticAttributes(),
		},
		{
			Name:             "audit_log",
			Path:             "/accounts/{account_id}/audit_logs",
			PathParams:       []string{"account_id"},
			URNKind:          "cloudflare_audit_log",
			IDKeys:           []string{"id"},
			TimestampKeys:    []string{"when", "timestamp"},
			ListKeys:         cloudflareResultListKeys(),
			Attributes:       map[string]string{"audit_id": "id", "account_id": "account.id|account_id", "action": "action.type|action", "actor_email": "actor.email", "actor_ip": "actor.ip", "resource_id": "resource.id", "resource_type": "resource.type", "zone_id": "zone.id|zone_id"},
			StaticAttributes: cloudflareStaticAttributes(),
		},
	}
}
