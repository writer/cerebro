package files_com

import (
	"context"
	"embed"
	"fmt"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/sources/internal/jsonapi"
)

//go:embed catalog.yaml
var catalogFS embed.FS

const (
	sourceID                             = "files_com"
	defaultFamily                        = familyExternalEvent
	defaultHealthPath                    = "/external_events"
	defaultBaseURLTemplate               = "//app.files.com/api/rest/v1"
	tokenHeader                          = ""
	tokenScheme                          = "Token"
	familyExternalEvent                  = "external_event"
	familyApiKey                         = "api_key"
	familyGroup                          = "group"
	familyGroupUser                      = "group_user"
	familyActionNotificationExportResult = "action_notification_export_result"
	familyPermission                     = "permission"
	familyLogin                          = "login"
	familySiteApiKey                     = "site_api_key"
	familyUserApiKey                     = "user_api_key"
	familyExavaultReserved               = "exavault_reserved"
	familyUserGroup                      = "user_group"
	familyUser                           = "user"
)

var templateKeys = []string{"api_key"}

type Source struct {
	inner         *jsonapi.Source
	allowLoopback bool
}

func New() (*Source, error) {
	spec, err := loadSpec()
	if err != nil {
		return nil, err
	}
	inner, err := jsonapi.New(spec, jsonapi.Options{
		SourceID:        sourceID,
		DefaultFamily:   defaultFamily,
		RequireTenantID: true,
		AuthModel:       "api_key",
		TokenHeader:     tokenHeader,
		TokenScheme:     tokenScheme,
		Families: []jsonapi.Family{
			{
				Name:             familyExternalEvent,
				Path:             "/external_events",
				URNKind:          "files_external_event",
				IDKeys:           []string{"id", "body", "event_id", "uuid", "request_id"},
				CursorParam:      "cursor",
				PageSizeParams:   []string{"per_page"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"actor_email": "actor_email|actor.email|email|user.email", "actor_id": "actor_id|actor.id|actorId|user_id|user.id", "actor_name": "actor_name|actor.name|username|user.name", "event_type": "event_type|event_name|action|type", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "id", "name": "display|event_type|body", "observed_at": "when|observed_at|updated_at|last_seen_at|created_at", "outcome_result": "status|success|failure_type", "provider_id": "id", "resource_email": "resource_email|target_email|target.email", "resource_id": "resource_id|target_id|target.id|resource.id|object_id|path|destination", "resource_name": "resource_name|target_name|target.name|resource.name|object_name|path|display|destination", "resource_type": "resource_type|target_type|target.type|object_type|interface", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "source_ip": "source_ip|ip", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "audit_event", "schema": "external_event", "source_system": "files_com"},
			},
			{
				Name:             familyApiKey,
				Path:             "/api_keys",
				URNKind:          "files_api_key",
				IDKeys:           []string{"id", "name", "secret_id", "key", "sid"},
				CursorParam:      "cursor",
				PageSizeParams:   []string{"per_page"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "id", "name": "name", "observed_at": "observed_at|updated_at|last_seen_at", "resource_id": "resource_id|id|metadata.resource_id", "resource_name": "name|display_name|hostname|metadata.resource_name", "resource_type": "resource_type|type|metadata.resource_type", "resource_urn": "resource_urn|urn|metadata.resource_urn", "secret_created_at": "created_at|created|date_created", "secret_id": "id", "secret_last_rotated_at": "secret_last_rotated_at|last_rotated_at|last_rotated|rotated_at", "secret_name": "name", "secret_rotation_enabled": "secret_rotation_enabled|rotation_enabled|auto_rotate", "secret_status": "secret_status|status|state", "secret_type": "api_key", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "secret", "schema": "api_key", "source_system": "files_com"},
			},
			{
				Name:             familyGroup,
				Path:             "/groups",
				URNKind:          "files_group",
				IDKeys:           []string{"id", "name", "group_id", "group_email", "email"},
				CursorParam:      "cursor",
				PageSizeParams:   []string{"per_page"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"description": "description|summary", "domain": "domain|tenant_domain|organization_domain", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "group_email": "group_email|email", "group_id": "group_id|id", "group_name": "group_name|name|display_name", "id": "id", "name": "name", "observed_at": "observed_at|updated_at|last_seen_at", "provider_id": "id", "resource_id": "resource_id|id|metadata.resource_id", "resource_name": "name|display_name|hostname|metadata.resource_name", "resource_type": "resource_type|type|metadata.resource_type", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "identity_group", "schema": "group", "source_system": "files_com"},
			},
			{
				Name:             familyGroupUser,
				Path:             "/group_users",
				URNKind:          "files_group_user",
				IDKeys:           []string{"id", "user_id", "group_id", "username", "email", "primary_email", "login"},
				CursorParam:      "cursor",
				PageSizeParams:   []string{"per_page"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"created_at": "created_at|created|profile.created_at", "department": "department|profile.department", "display_name": "display_name|username|name|profile.display_name|profile.name", "domain": "domain|tenant_domain|organization_domain", "email": "email|primary_email|profile.email", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "group_id": "group_id", "group_name": "group_name", "id": "id", "job_title": "job_title|title|profile.title", "last_login_at": "last_login_at|last_login|last_seen_at", "login": "username|login|email|profile.login", "manager": "manager|profile.manager", "name": "username|name", "observed_at": "observed_at|updated_at|last_seen_at", "primary_email": "primary_email|email|profile.email", "provider_id": "id", "resource_id": "resource_id|id|metadata.resource_id", "resource_name": "username|name|display_name|hostname|metadata.resource_name", "resource_type": "resource_type|type|metadata.resource_type", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "status": "status|state|lifecycle_state", "tenant_id": "tenant_id|metadata.tenant_id", "user_id": "user_id|uid"},
				StaticAttributes: map[string]string{"record_class": "identity_user", "schema": "group_user", "source_system": "files_com"},
			},
			{
				Name:             familyActionNotificationExportResult,
				Path:             "/action_notification_export_results",
				URNKind:          "files_action_notification_export_result",
				IDKeys:           []string{"id", "created_at", "alert_id", "sid", "incident_id", "uuid"},
				CursorParam:      "cursor",
				PageSizeParams:   []string{"per_page"},
				TimestampKeys:    []string{"when", "observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"alert_description": "description|summary|message|body", "alert_fired_at": "fired_at|triggered_at|created_at|occurred_at|timestamp", "alert_id": "id", "alert_name": "message|name|display|subject", "alert_resolved_at": "resolved_at|closed_at|acknowledged_at", "alert_severity": "severity|alert_severity|risk_level", "alert_source": "request_url|url|source|alert_source|monitor|check", "alert_status": "status", "alert_type": "alert_type|type|category|kind", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "id", "name": "message|name|display|subject", "observed_at": "observed_at|updated_at|last_seen_at", "resource_id": "resource_id|id|metadata.resource_id", "resource_name": "resource_name|path|folder|message|name|display_name|hostname|metadata.resource_name", "resource_type": "resource_type|type|metadata.resource_type", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"alert_type": "action_notification_export_result", "record_class": "alert", "resource_type": "action_notification_export_result", "schema": "action_notification_export_result", "source_system": "files_com"},
			},
			{
				Name:             familyPermission,
				Path:             "/permissions",
				URNKind:          "files_permission",
				IDKeys:           []string{"id", "path", "username", "group_id", "user_id"},
				CursorParam:      "cursor",
				PageSizeParams:   []string{"per_page"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "group_id": "group_id", "id": "id", "name": "path|username|group_name", "observed_at": "observed_at|updated_at|last_seen_at", "resource_id": "id|path", "resource_name": "path|username|group_name", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id", "user_id": "user_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "resource_type": "permission", "schema": "permission", "source_system": "files_com"},
			},
			{
				Name:             familyLogin,
				Path:             "/history/login",
				URNKind:          "files_login",
				IDKeys:           []string{"id", "username", "event_id", "uuid", "request_id"},
				CursorParam:      "cursor",
				PageSizeParams:   []string{"per_page"},
				TimestampKeys:    []string{"when", "observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"actor_email": "actor_email|actor.email|email|user.email", "actor_id": "actor_id|actor.id|actorId|user_id|user.id", "actor_name": "username|actor_name|actor.name|user.name", "event_type": "action|event_type|event_name|type|interface", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "id", "name": "username|display", "observed_at": "when|observed_at|updated_at|last_seen_at", "outcome_result": "failure_type", "provider_id": "id", "resource_email": "resource_email|target_email|target.email", "resource_id": "resource_id|target_id|target.id|resource.id|object_id|path|destination", "resource_name": "resource_name|target_name|target.name|resource.name|object_name|path|display|destination", "resource_type": "interface|resource_type|target_type|target.type|object_type", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "source_ip": "source_ip|ip", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "audit_event", "schema": "login", "source_system": "files_com"},
			},
			{
				Name:             familySiteApiKey,
				Path:             "/site/api_keys",
				URNKind:          "files_site_api_key",
				IDKeys:           []string{"id", "name", "secret_id", "key", "sid"},
				CursorParam:      "cursor",
				PageSizeParams:   []string{"per_page"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "id", "name": "name", "observed_at": "observed_at|updated_at|last_seen_at", "resource_id": "resource_id|id|metadata.resource_id", "resource_name": "name|display_name|hostname|metadata.resource_name", "resource_type": "resource_type|type|metadata.resource_type", "resource_urn": "resource_urn|urn|metadata.resource_urn", "secret_created_at": "created_at|created|date_created", "secret_id": "id", "secret_last_rotated_at": "secret_last_rotated_at|last_rotated_at|last_rotated|rotated_at", "secret_name": "name", "secret_rotation_enabled": "secret_rotation_enabled|rotation_enabled|auto_rotate", "secret_status": "secret_status|status|state", "secret_type": "api_key", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "secret", "schema": "site_api_key", "source_system": "files_com"},
			},
			{
				Name:             familyUserApiKey,
				Path:             "/user/api_keys",
				URNKind:          "files_user_api_key",
				IDKeys:           []string{"id", "name", "secret_id", "key", "sid"},
				CursorParam:      "cursor",
				PageSizeParams:   []string{"per_page"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "id", "name": "name", "observed_at": "observed_at|updated_at|last_seen_at", "resource_id": "resource_id|id|metadata.resource_id", "resource_name": "name|display_name|hostname|metadata.resource_name", "resource_type": "resource_type|type|metadata.resource_type", "resource_urn": "resource_urn|urn|metadata.resource_urn", "secret_created_at": "created_at|created|date_created", "secret_id": "id", "secret_last_rotated_at": "secret_last_rotated_at|last_rotated_at|last_rotated|rotated_at", "secret_name": "name", "secret_rotation_enabled": "secret_rotation_enabled|rotation_enabled|auto_rotate", "secret_status": "secret_status|status|state", "secret_type": "api_key", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "secret", "schema": "user_api_key", "source_system": "files_com"},
			},
			{
				Name:             familyExavaultReserved,
				Path:             "/ip_addresses/exavault-reserved",
				URNKind:          "files_exavault_reserved",
				IDKeys:           []string{"id", "associated_with", "group_id"},
				CursorParam:      "cursor",
				PageSizeParams:   []string{"per_page"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "group_id": "group_id", "id": "id", "name": "associated_with|id", "observed_at": "observed_at|updated_at|last_seen_at", "resource_id": "resource_id|id|metadata.resource_id", "resource_name": "associated_with|name|display_name|hostname|metadata.resource_name", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "resource_type": "ip_address_range", "schema": "exavault_reserved", "source_system": "files_com"},
			},
			{
				Name:             familyUserGroup,
				Path:             "/user/groups",
				URNKind:          "files_user_group",
				IDKeys:           []string{"id", "group_id", "name", "group_email", "email"},
				CursorParam:      "cursor",
				PageSizeParams:   []string{"per_page"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"description": "notes|description|summary", "domain": "domain|tenant_domain|organization_domain", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "group_email": "group_email|email", "group_id": "group_id|id", "group_name": "group_name|name|display_name", "id": "id", "name": "name|group_name", "observed_at": "observed_at|updated_at|last_seen_at", "provider_id": "id", "resource_id": "resource_id|id|metadata.resource_id", "resource_name": "name|group_name|display_name|hostname|metadata.resource_name", "resource_type": "resource_type|type|metadata.resource_type", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "identity_group", "schema": "user_group", "source_system": "files_com"},
			},
			{
				Name:             familyUser,
				Path:             "/users",
				URNKind:          "files_user",
				IDKeys:           []string{"id", "name", "user_id", "email", "primary_email", "login"},
				CursorParam:      "cursor",
				PageSizeParams:   []string{"per_page"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"created_at": "created_at|created|profile.created_at", "department": "department|profile.department", "display_name": "display_name|name|profile.display_name|profile.name", "domain": "domain|tenant_domain|organization_domain", "email": "email|primary_email|profile.email", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "id", "job_title": "job_title|title|profile.title", "last_login_at": "last_login_at|last_login|last_seen_at", "login": "login|username|email|profile.login", "manager": "manager|profile.manager", "name": "name", "observed_at": "observed_at|updated_at|last_seen_at", "primary_email": "primary_email|email|profile.email", "provider_id": "id", "resource_id": "resource_id|id|metadata.resource_id", "resource_name": "name|display_name|hostname|metadata.resource_name", "resource_type": "resource_type|type|metadata.resource_type", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "status": "status|state|lifecycle_state", "tenant_id": "tenant_id|metadata.tenant_id", "user_id": "user_id|id|uid"},
				StaticAttributes: map[string]string{"record_class": "identity_user", "schema": "user", "source_system": "files_com"},
			},
		},
	})
	if err != nil {
		return nil, err
	}
	return &Source{inner: inner}, nil
}

func (s *Source) Spec() *cerebrov1.SourceSpec {
	if s == nil || s.inner == nil {
		return nil
	}
	return s.inner.Spec()
}

func (s *Source) Check(ctx context.Context, cfg sourcecdk.Config) error {
	runtimeCfg, err := s.runtimeConfig(ctx, cfg)
	if err != nil {
		return err
	}
	if err := s.checkHealth(ctx, runtimeCfg); err != nil {
		return err
	}
	return s.inner.Check(ctx, runtimeCfg)
}

func (s *Source) Discover(ctx context.Context, cfg sourcecdk.Config) ([]sourcecdk.URN, error) {
	runtimeCfg, err := s.runtimeConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return s.inner.Discover(ctx, runtimeCfg)
}

func (s *Source) Read(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	runtimeCfg, err := s.runtimeConfig(ctx, cfg)
	if err != nil {
		return sourcecdk.Pull{}, err
	}
	return s.inner.Read(ctx, runtimeCfg, cursor)
}

func (s *Source) runtimeConfig(_ context.Context, cfg sourcecdk.Config) (sourcecdk.Config, error) {
	return sourcecdk.ResolveBaseURLConfig(sourceID, defaultBaseURLTemplate, cfg, templateKeys)
}

func (s *Source) checkHealth(ctx context.Context, cfg sourcecdk.Config) error {
	path := firstNonEmpty(sourcecdk.ConfigValue(cfg, "health_path"), defaultHealthPath)
	return s.inner.CheckPath(ctx, cfg, path, nil)
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

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func (s *Source) allowLoopbackForTest() {
	if s != nil && s.inner != nil {
		s.inner.AllowLoopbackBaseURL = true
		s.allowLoopback = true
	}
}
