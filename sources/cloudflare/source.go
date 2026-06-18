package cloudflare

import (
	"context"
	"embed"
	"fmt"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/sources/internal/jsonapi"
)

//go:embed catalog.yaml
var catalogFS embed.FS

const sourceID = "cloudflare"

type Source struct{ inner *jsonapi.Source }

func New() (*Source, error) {
	spec, err := loadSpec()
	if err != nil {
		return nil, err
	}
	inner, err := jsonapi.New(spec, jsonapi.Options{
		SourceID:        sourceID,
		DefaultBaseURL:  "https://api.cloudflare.com/client/v4",
		DefaultFamily:   "account",
		RequireTenantID: true,
		TokenScheme:     "Bearer",
		Families:        cloudflareFamilies(),
	})
	if err != nil {
		return nil, err
	}
	return &Source{inner: inner}, nil
}

func (s *Source) Spec() *cerebrov1.SourceSpec { return s.inner.Spec() }
func (s *Source) Check(ctx context.Context, cfg sourcecdk.Config) error {
	return s.inner.Check(ctx, cfg)
}
func (s *Source) Discover(ctx context.Context, cfg sourcecdk.Config) ([]sourcecdk.URN, error) {
	return s.inner.Discover(ctx, cfg)
}
func (s *Source) Read(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	return s.inner.Read(ctx, cfg, cursor)
}
func loadSpec() (*cerebrov1.SourceSpec, error) {
	specBytes, err := catalogFS.ReadFile("catalog.yaml")
	if err != nil {
		return nil, fmt.Errorf("read catalog: %w", err)
	}
	spec, err := sourcecdk.LoadCatalog(specBytes)
	if err != nil {
		return nil, fmt.Errorf("load catalog: %w", err)
	}
	return spec, nil
}

func cloudflareFamilies() []jsonapi.Family {
	families := []jsonapi.Family{
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
		{
			Name:             "worker_script",
			Path:             "/accounts/{account_id}/workers/scripts",
			PathParams:       []string{"account_id"},
			URNKind:          "cloudflare_worker_script",
			IDKeys:           []string{"id"},
			TimestampKeys:    []string{"created_on", "modified_on"},
			ListKeys:         cloudflareResultListKeys(),
			Attributes:       map[string]string{"script_id": "id", "account_id": "account_id", "created_on": "created_on", "modified_on": "modified_on", "compatibility_date": "compatibility_date", "tags": "tags", "bindings": "bindings", "placement": "placement"},
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
	for i := range families {
		families[i].CursorParam = "page"
		families[i].PageSizeParams = []string{"per_page"}
	}
	return families
}

func cloudflareResultListKeys() []string {
	return []string{"result"}
}

func cloudflareStaticAttributes() map[string]string {
	return map[string]string{"source_product": "cloudflare"}
}
