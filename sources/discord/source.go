package discord

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/sources/internal/jsonapi"
)

//go:embed catalog.yaml
var catalogFS embed.FS

const (
	sourceID               = "discord"
	defaultFamily          = familyAuditLog
	defaultBaseURLTemplate = "https://discord.com/api/v10"
	tokenScheme            = "Bot"
	familyAuditLog         = "audit_log"
	familyMember           = "member"
	familyRole             = "role"
	familyPermission       = "permission"
)

var templateKeys = []string{"application_id", "guild_id", "api_key"}

type Source struct {
	spec   *cerebrov1.SourceSpec
	inners map[string]*jsonapi.Source
}

func New() (*Source, error) {
	spec, err := loadSpec()
	if err != nil {
		return nil, err
	}
	families := []jsonapi.Family{
		{
			Name:             familyAuditLog,
			Path:             "/guilds/${config.guild_id}/audit-logs",
			URNKind:          "discord_audit_log",
			IDKeys:           []string{"id"},
			RequireID:        true,
			PageFirstCursor:  "0",
			CursorParam:      "after",
			PageSizeParams:   []string{"limit"},
			ListKeys:         []string{"audit_log_entries"},
			Config:           jsonapi.FamilyConfig{LastItemCursorKeys: []string{"id"}},
			TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
			Attributes:       map[string]string{"actor_id": "user_id", "event_type": "action_type", "id": "id", "provider_id": "id", "resource_id": "target_id", "source_event_id": "id"},
			StaticAttributes: map[string]string{"record_class": "audit_event", "schema": "audit_log", "source_system": "discord"},
		},
		{
			Name:             familyMember,
			Path:             "/guilds/${config.guild_id}/members",
			URNKind:          "discord_member",
			IDKeys:           []string{"user.id"},
			RequireID:        true,
			PageFirstCursor:  "0",
			CursorParam:      "after",
			PageSizeParams:   []string{"limit"},
			Config:           jsonapi.FamilyConfig{LastItemCursorKeys: []string{"user.id"}},
			TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
			Attributes:       map[string]string{"avatar": "avatar|user.avatar", "communication_disabled_until": "communication_disabled_until", "deaf": "deaf", "display_name": "nick|user.global_name|user.username", "flags": "flags", "global_name": "user.global_name", "id": "user.id", "joined_at": "joined_at", "login": "user.username", "mute": "mute", "name": "nick|user.global_name|user.username", "pending": "pending", "provider_id": "user.id", "resource_id": "user.id", "resource_name": "nick|user.global_name|user.username", "roles": "roles", "source_event_id": "user.id", "user_id": "user.id", "username": "user.username"},
			StaticAttributes: map[string]string{"record_class": "identity_user", "schema": "member", "source_system": "discord"},
		},
		{
			Name:             familyRole,
			Path:             "/guilds/${config.guild_id}/roles",
			DisablePageSize:  true,
			URNKind:          "discord_role",
			IDKeys:           []string{"id"},
			RequireID:        true,
			TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
			Attributes:       map[string]string{"description": "description|summary", "domain": "domain|tenant_domain|organization_domain", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "group_email": "group_email|email", "group_id": "group_id|id", "group_name": "group_name|name|display_name", "id": "id", "name": "name", "observed_at": "observed_at|updated_at|last_seen_at", "provider_id": "id", "resource_id": "resource_id|id|metadata.resource_id", "resource_name": "name|display_name|hostname|metadata.resource_name", "resource_type": "resource_type|type|metadata.resource_type", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
			StaticAttributes: map[string]string{"record_class": "identity_group", "schema": "role", "source_system": "discord"},
		},
		{
			Name:             familyPermission,
			Path:             "/applications/${config.application_id}/guilds/${config.guild_id}/commands/permissions",
			DisablePageSize:  true,
			URNKind:          "discord_permission",
			IDKeys:           []string{"id"},
			RequireID:        true,
			TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
			Attributes:       map[string]string{"application_id": "application_id", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "guild_id": "guild_id", "id": "id", "name": "application_id", "observed_at": "observed_at|updated_at|last_seen_at", "resource_id": "id", "resource_name": "application_id", "resource_type": "permission", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
			StaticAttributes: map[string]string{"record_class": "asset", "schema": "permission", "source_system": "discord"},
		},
	}
	inners := make(map[string]*jsonapi.Source, len(families))
	for _, family := range families {
		family := family
		inner, err := jsonapi.New(spec, jsonapi.Options{
			SourceID:        sourceID,
			DefaultFamily:   family.Name,
			RequireTenantID: true,
			AuthModel:       "api_key",
			TokenScheme:     tokenScheme,
			ResponseError: func(body []byte) error {
				return validateResponseEnvelope(family.Name, body)
			},
			Families: []jsonapi.Family{family},
		})
		if err != nil {
			return nil, err
		}
		inners[family.Name] = inner
	}
	return &Source{spec: spec, inners: inners}, nil
}

func (s *Source) Spec() *cerebrov1.SourceSpec {
	if s == nil {
		return nil
	}
	return s.spec
}

func (s *Source) Check(ctx context.Context, cfg sourcecdk.Config) error {
	runtimeCfg, err := s.runtimeConfig(ctx, cfg)
	if err != nil {
		return err
	}
	inner, err := s.innerFor(runtimeCfg)
	if err != nil {
		return err
	}
	return inner.Check(ctx, runtimeCfg)
}

func (s *Source) Discover(ctx context.Context, cfg sourcecdk.Config) ([]sourcecdk.URN, error) {
	runtimeCfg, err := s.runtimeConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	inner, err := s.innerFor(runtimeCfg)
	if err != nil {
		return nil, err
	}
	return inner.Discover(ctx, runtimeCfg)
}

func (s *Source) Read(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	runtimeCfg, err := s.runtimeConfig(ctx, cfg)
	if err != nil {
		return sourcecdk.Pull{}, err
	}
	inner, err := s.innerFor(runtimeCfg)
	if err != nil {
		return sourcecdk.Pull{}, err
	}
	family := strings.TrimSpace(sourcecdk.ConfigValue(runtimeCfg, "family"))
	if family == "" {
		family = defaultFamily
	}
	if family == familyAuditLog || family == familyMember {
		if token := strings.TrimSpace(sourcecdk.CursorToken(cursor)); token != "" {
			if _, err := positiveSnowflake(token); err != nil {
				return sourcecdk.Pull{}, fmt.Errorf("discord %s after cursor: %w", family, err)
			}
		}
	}
	if family == familyPermission {
		for _, field := range []string{"application_id", "guild_id"} {
			if _, err := positiveSnowflake(sourcecdk.ConfigValue(runtimeCfg, field)); err != nil {
				return sourcecdk.Pull{}, fmt.Errorf("discord permission config %s: %w", field, err)
			}
		}
	}
	pull, err := inner.Read(ctx, runtimeCfg, cursor)
	if err != nil {
		return sourcecdk.Pull{}, err
	}
	if err := adjustProviderCursor(family, &pull); err != nil {
		return sourcecdk.Pull{}, err
	}
	if err := validatePermissionScope(family, runtimeCfg, &pull); err != nil {
		return sourcecdk.Pull{}, err
	}
	return pull, nil
}

func adjustProviderCursor(family string, pull *sourcecdk.Pull) error {
	if pull == nil {
		return nil
	}
	if family == "" {
		family = defaultFamily
	}
	switch family {
	case familyAuditLog:
		var previous uint64
		for index, event := range pull.Events {
			id, err := positiveSnowflake(event.Attributes["provider_id"])
			if err != nil {
				return fmt.Errorf("discord audit_log provider_id: %w", err)
			}
			if index > 0 && id <= previous {
				return fmt.Errorf("discord audit_log after page must be strictly ascending")
			}
			previous = id
		}
	case familyMember:
		if pull.NextCursor == nil {
			return nil
		}
		var highest uint64
		for _, event := range pull.Events {
			id, err := positiveSnowflake(event.Attributes["provider_id"])
			if err != nil {
				return fmt.Errorf("discord member user.id: %w", err)
			}
			if id > highest {
				highest = id
			}
		}
		if highest == 0 {
			return fmt.Errorf("discord member full page has no resumable user.id")
		}
		pull.NextCursor = &cerebrov1.SourceCursor{Opaque: strconv.FormatUint(highest, 10)}
	}
	return nil
}

func positiveSnowflake(value string) (uint64, error) {
	trimmed := strings.TrimSpace(value)
	id, err := strconv.ParseUint(trimmed, 10, 64)
	if err != nil || id == 0 {
		return 0, fmt.Errorf("must be a positive string snowflake")
	}
	return id, nil
}

func validatePermissionScope(family string, cfg sourcecdk.Config, pull *sourcecdk.Pull) error {
	if family != familyPermission || pull == nil {
		return nil
	}
	expectedApplication := strings.TrimSpace(sourcecdk.ConfigValue(cfg, "application_id"))
	expectedGuild := strings.TrimSpace(sourcecdk.ConfigValue(cfg, "guild_id"))
	for index, event := range pull.Events {
		if event.Attributes["application_id"] != expectedApplication {
			return fmt.Errorf("discord permission record %d application_id does not match request scope", index)
		}
		if event.Attributes["guild_id"] != expectedGuild {
			return fmt.Errorf("discord permission record %d guild_id does not match request scope", index)
		}
	}
	return nil
}

func (s *Source) innerFor(cfg sourcecdk.Config) (*jsonapi.Source, error) {
	family := strings.TrimSpace(sourcecdk.ConfigValue(cfg, "family"))
	if family == "" {
		family = defaultFamily
	}
	inner := s.inners[family]
	if inner == nil {
		return nil, fmt.Errorf("discord family %q is unsupported", family)
	}
	return inner, nil
}

func validateResponseEnvelope(family string, body []byte) error {
	var root any
	if err := json.Unmarshal(body, &root); err != nil {
		return fmt.Errorf("decode discord %s response: %w", family, err)
	}
	switch family {
	case familyAuditLog:
		object, ok := root.(map[string]any)
		if !ok {
			return fmt.Errorf("discord audit_log response must be an object envelope")
		}
		_, ok = object["audit_log_entries"].([]any)
		if !ok {
			return fmt.Errorf("discord audit_log response must contain audit_log_entries")
		}
	case familyMember, familyRole, familyPermission:
		var ok bool
		_, ok = root.([]any)
		if !ok {
			return fmt.Errorf("discord %s response must be a bare array", family)
		}
	default:
		return fmt.Errorf("discord family %q is unsupported", family)
	}
	return nil
}

func (s *Source) runtimeConfig(_ context.Context, cfg sourcecdk.Config) (sourcecdk.Config, error) {
	return sourcecdk.ResolveBaseURLConfig(sourceID, defaultBaseURLTemplate, cfg, templateKeys)
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

func (s *Source) allowLoopbackForTest() {
	if s == nil {
		return
	}
	for _, inner := range s.inners {
		inner.AllowLoopbackBaseURL = true
	}
}
