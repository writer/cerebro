package tailscale

import (
	"context"
	"embed"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/sources/internal/jsonapi"
)

//go:embed catalog.yaml
var catalogFS embed.FS

const sourceID = "tailscale"

type Source struct{ inner *jsonapi.Source }

func New() (*Source, error) {
	spec, err := loadSpec()
	if err != nil {
		return nil, err
	}
	inner, err := jsonapi.New(spec, jsonapi.Options{
		SourceID:        sourceID,
		DefaultBaseURL:  "https://api.tailscale.com/api/v2",
		DefaultFamily:   "device",
		RequireTenantID: true,
		TokenScheme:     "Bearer",
		Families: []jsonapi.Family{
			{Name: "tailnet", Path: "/tailnet/-/settings", URNKind: "tailscale_tailnet", IDKeys: []string{"id", "tailnet", "organization"}, Singleton: true, RequireID: false, Attributes: map[string]string{"tailnet": "id|tailnet|organization", "devices_approval_on": "devicesApprovalOn", "users_approval_on": "usersApprovalOn", "network_flow_logging_on": "networkFlowLoggingOn", "regional_routing_on": "regionalRoutingOn", "max_key_duration_days": "maxKeyDurationDays"}, StaticAttributes: map[string]string{"source_product": "tailscale"}},
			{Name: "user", Path: "/tailnet/-/users", URNKind: "tailscale_user", IDKeys: []string{"id", "user_id", "loginName"}, TimestampKeys: []string{"created", "lastSeen"}, Attributes: map[string]string{"user_id": "id|user_id", "login_name": "loginName|login_name|email", "email": "email|loginName", "display_name": "displayName|display_name", "role": "role", "status": "status", "type": "type", "last_seen_at": "lastSeen|last_seen"}, StaticAttributes: map[string]string{"source_product": "tailscale"}},
			{Name: "device", Path: "/tailnet/-/devices", URNKind: "tailscale_device", IDKeys: []string{"id", "nodeId", "device_id"}, TimestampKeys: []string{"lastSeen", "created"}, Attributes: map[string]string{"device_id": "id|nodeId|device_id", "node_id": "nodeId|id", "name": "name", "hostname": "hostname", "os": "os", "user_id": "user", "owner_email": "user", "authorized": "authorized", "is_external": "isExternal|is_external", "key_expiry_disabled": "keyExpiryDisabled|key_expiry_disabled", "update_available": "updateAvailable|update_available", "blocks_incoming_connections": "blocksIncomingConnections|blocks_incoming_connections", "tags": "tags", "last_seen_at": "lastSeen|last_seen", "client_version": "clientVersion|client_version"}, StaticAttributes: map[string]string{"source_product": "tailscale"}},
			{Name: "group", Path: "/tailnet/-/acl", URNKind: "tailscale_group", IDKeys: []string{"id", "name"}, MapRecords: map[string]string{"groups": "members"}, Attributes: map[string]string{"group_id": "id|name", "name": "name", "members": "members"}, StaticAttributes: map[string]string{"source_product": "tailscale"}},
			{Name: "tag", Path: "/tailnet/-/acl", URNKind: "tailscale_tag", IDKeys: []string{"id", "name"}, MapRecords: map[string]string{"tagOwners": "owners"}, Attributes: map[string]string{"tag_id": "id|name", "name": "name", "owners": "owners"}, StaticAttributes: map[string]string{"source_product": "tailscale"}},
			{Name: "service", Path: "/tailnet/-/vip-services", URNKind: "tailscale_service", IDKeys: []string{"id", "service_id", "name"}, ListKeys: []string{"vipServices", "services"}, Attributes: map[string]string{"service_id": "id|service_id|name", "name": "name", "addresses": "addrs|addresses", "ports": "ports", "tags": "tags", "comment": "comment"}, StaticAttributes: map[string]string{"source_product": "tailscale"}},
			{Name: "grant", Path: "/tailnet/-/acl", URNKind: "tailscale_grant", IDKeys: []string{"id", "grant_id"}, RequireID: false, Attributes: map[string]string{"grant_id": "id|grant_id", "sources": "src|sources", "destinations": "dst|destinations", "via": "via", "ip": "ip", "app": "app", "disabled": "disabled"}, StaticAttributes: map[string]string{"source_product": "tailscale"}},
		},
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
	pull, err := s.inner.Read(ctx, cfg, cursor)
	if err != nil {
		return pull, err
	}
	return enrichTailnetSettingsIdentity(pull, cfg), nil
}
func loadSpec() (*cerebrov1.SourceSpec, error) {
	return sourcecdk.LoadSpecFromFS(catalogFS, "catalog.yaml")
}

func enrichTailnetSettingsIdentity(pull sourcecdk.Pull, cfg sourcecdk.Config) sourcecdk.Pull {
	tailnet := tailscaleTailnetConfigIdentity(cfg)
	if tailnet == "" {
		return pull
	}
	for _, event := range pull.Events {
		if event == nil || event.Kind != "tailscale.tailnet" {
			continue
		}
		if event.Attributes == nil {
			event.Attributes = map[string]string{}
		}
		if tailscaleTailnetPlaceholder(event.Attributes["tailnet"]) {
			event.Attributes["tailnet"] = tailnet
		}
		if tailscaleTailnetPlaceholder(event.Attributes["external_id"]) {
			event.Attributes["external_id"] = tailnet
		}
	}
	return pull
}

func tailscaleTailnetConfigIdentity(cfg sourcecdk.Config) string {
	for _, key := range []string{"tailnet", "organization", "tenant_id"} {
		value, _ := cfg.Lookup(key)
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}

func tailscaleTailnetPlaceholder(value string) bool {
	value = strings.TrimSpace(value)
	return value == "" || value == "tailnet"
}
