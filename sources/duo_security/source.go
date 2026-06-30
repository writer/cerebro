package duo_security

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
	sourceID                  = "duo_security"
	defaultFamily             = familyUsers
	defaultHealthPath         = "/admin/v1/users"
	defaultBaseURLTemplate    = "${config.base_url}"
	tokenHeader               = ""
	familyUsers               = "users"
	familyGroups              = "groups"
	familyAdministrators      = "administrators"
	familyPhones              = "phones"
	familyHardwareTokens      = "hardware_tokens"
	familyWebAuthnCredentials = "webauthn_credentials"
	familyBypassCodes         = "bypass_codes"
	familyEndpoints           = "endpoints"
	familyRoles               = "roles"
	familyApplications        = "applications"
	familyAuditEvents         = "audit_events"
	familyAuthenticationLogs  = "authentication_logs"
)

var templateKeys = []string{"base_url", "client_id", "client_secret"}

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
		AuthModel:       "duo_hmac",
		TokenHeader:     tokenHeader,
		Families: []jsonapi.Family{
			{
				Name:             familyUsers,
				Path:             "/admin/v1/users",
				URNKind:          "runtime_users",
				IDKeys:           []string{"user_id", "id", "username", "email", "primary_email", "login"},
				CursorParam:      "offset",
				NextCursorKeys:   []string{"metadata.next_offset"},
				PageSizeParams:   []string{"limit"},
				ListKeys:         []string{"response"},
				TimestampKeys:    []string{"last_login", "created", "observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"created_at": "created_at|created|profile.created_at", "department": "department|profile.department", "display_name": "realname|name|username", "domain": "domain|tenant_domain|organization_domain", "email": "email", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "job_title": "job_title|title|profile.title", "last_login_at": "last_login_at|last_login|last_seen_at", "login": "username|login|email|profile.login", "manager": "manager|profile.manager", "observed_at": "observed_at|updated_at|last_seen_at|last_login|created", "primary_email": "email|primary_email|profile.email", "resource_id": "resource_id|user_id|id|metadata.resource_id", "resource_name": "realname|name|username|display_name|hostname|metadata.resource_name", "resource_type": "resource_type|type|metadata.resource_type", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|user_id|id|metadata.event_id", "status": "status", "tenant_id": "tenant_id|metadata.tenant_id", "user_id": "user_id|id"},
				StaticAttributes: map[string]string{"record_class": "identity_user", "schema": "users", "source_system": "duo_security"},
			},
			{
				Name:             familyGroups,
				Path:             "/admin/v1/groups",
				URNKind:          "runtime_groups",
				IDKeys:           []string{"group_id", "id", "name", "group_email", "email"},
				CursorParam:      "offset",
				NextCursorKeys:   []string{"metadata.next_offset"},
				PageSizeParams:   []string{"limit"},
				ListKeys:         []string{"response"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"description": "desc|description|summary", "domain": "domain|tenant_domain|organization_domain", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "group_email": "group_email|email", "group_id": "group_id|id", "group_name": "name", "observed_at": "observed_at|updated_at|last_seen_at", "resource_id": "resource_id|group_id|id|metadata.resource_id", "resource_name": "name|display_name|hostname|metadata.resource_name", "resource_type": "resource_type|type|metadata.resource_type", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|group_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "identity_group", "schema": "groups", "source_system": "duo_security"},
			},
			{
				Name:             familyAdministrators,
				Path:             "/admin/v1/admins",
				URNKind:          "runtime_users",
				IDKeys:           []string{"admin_id", "id", "email", "name"},
				CursorParam:      "offset",
				NextCursorKeys:   []string{"metadata.next_offset"},
				PageSizeParams:   []string{"limit"},
				ListKeys:         []string{"response"},
				TimestampKeys:    []string{"last_login", "created", "observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"created_at": "created_at|created", "display_name": "name|realname|email", "email": "email", "last_login_at": "last_login|last_login_at", "login": "email|username", "observed_at": "observed_at|updated_at|last_seen_at|last_login|created", "resource_id": "admin_id|id", "resource_name": "name|email", "resource_type": "resource_type|type", "resource_urn": "resource_urn|urn|metadata.resource_urn", "role": "role", "source_event_id": "event_id|admin_id|id|metadata.event_id", "status": "status", "tenant_id": "tenant_id|metadata.tenant_id", "user_id": "admin_id|id"},
				StaticAttributes: map[string]string{"record_class": "identity_user", "resource_type": "duo_administrator", "schema": "administrators", "source_system": "duo_security"},
			},
			{
				Name:             familyPhones,
				Path:             "/admin/v1/phones",
				URNKind:          "runtime_mfa_factors",
				IDKeys:           []string{"phone_id", "id", "number", "name"},
				CursorParam:      "offset",
				NextCursorKeys:   []string{"metadata.next_offset"},
				PageSizeParams:   []string{"limit"},
				ListKeys:         []string{"response"},
				TimestampKeys:    []string{"last_seen", "last_seen_at", "created", "created_at"},
				Attributes:       map[string]string{"activated": "activated", "capabilities": "capabilities", "encrypted": "encrypted", "last_seen_at": "last_seen|last_seen_at", "model": "model", "name": "name", "number": "number", "phone_id": "phone_id|id", "platform": "platform", "screenlock": "screenlock", "source_event_id": "event_id|phone_id|id|metadata.event_id", "tampered": "tampered", "tenant_id": "tenant_id|metadata.tenant_id", "user_id": "user_id|user.user_id|users.0.user_id"},
				StaticAttributes: map[string]string{"factor_type": "phone", "record_class": "mfa_factor", "resource_type": "phone", "schema": "phones", "source_system": "duo_security"},
			},
			{
				Name:             familyHardwareTokens,
				Path:             "/admin/v1/tokens",
				URNKind:          "runtime_mfa_factors",
				IDKeys:           []string{"token_id", "id", "serial"},
				CursorParam:      "offset",
				NextCursorKeys:   []string{"metadata.next_offset"},
				PageSizeParams:   []string{"limit"},
				ListKeys:         []string{"response"},
				TimestampKeys:    []string{"last_seen", "last_seen_at", "created", "created_at"},
				Attributes:       map[string]string{"last_seen_at": "last_seen|last_seen_at", "serial": "serial", "source_event_id": "event_id|token_id|id|serial|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id", "token_id": "token_id|id", "totp_step": "totp_step", "type": "type", "user_id": "user_id|user.user_id|users.0.user_id"},
				StaticAttributes: map[string]string{"factor_type": "hardware_token", "record_class": "mfa_factor", "resource_type": "hardware_token", "schema": "hardware_tokens", "source_system": "duo_security"},
			},
			{
				Name:             familyWebAuthnCredentials,
				Path:             "/admin/v1/webauthncredentials",
				URNKind:          "runtime_mfa_factors",
				IDKeys:           []string{"webauthnkey", "credential_id", "id", "key"},
				CursorParam:      "offset",
				NextCursorKeys:   []string{"metadata.next_offset"},
				PageSizeParams:   []string{"limit"},
				ListKeys:         []string{"response"},
				TimestampKeys:    []string{"last_used", "last_used_at", "created", "created_at"},
				Attributes:       map[string]string{"credential_id": "webauthnkey|credential_id|id|key", "credential_name": "name|label", "label": "label|name", "last_used_at": "last_used|last_used_at", "source_event_id": "event_id|webauthnkey|credential_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id", "user_id": "user_id|user.user_id|users.0.user_id"},
				StaticAttributes: map[string]string{"factor_type": "webauthn", "record_class": "mfa_factor", "resource_type": "webauthn_credential", "schema": "webauthn_credentials", "source_system": "duo_security"},
			},
			{
				Name:             familyBypassCodes,
				Path:             "/admin/v1/bypass_codes",
				URNKind:          "runtime_bypass_codes",
				IDKeys:           []string{"bypass_code_id", "id", "code_id", "user_id"},
				CursorParam:      "offset",
				NextCursorKeys:   []string{"metadata.next_offset"},
				PageSizeParams:   []string{"limit"},
				ListKeys:         []string{"response"},
				TimestampKeys:    []string{"created", "created_at", "expiration", "expires_at"},
				Attributes:       map[string]string{"created_at": "created|created_at", "expires_at": "expiration|expires_at", "resource_id": "bypass_code_id|code_id|id|user_id", "resource_name": "name|user_id|bypass_code_id|id", "resource_type": "resource_type|type", "source_event_id": "event_id|bypass_code_id|code_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id", "user_id": "user_id|user.user_id"},
				Config:           jsonapi.FamilyConfig{EncodeURNID: true, ResourceURNKind: "runtime_bypass_codes"},
				StaticAttributes: map[string]string{"record_class": "secret", "resource_type": "bypass_code", "schema": "bypass_codes", "source_system": "duo_security"},
			},
			{
				Name:             familyEndpoints,
				Path:             "/admin/v1/endpoints",
				URNKind:          "runtime_endpoints",
				IDKeys:           []string{"epkey", "endpoint_id", "id", "hostname"},
				CursorParam:      "offset",
				NextCursorKeys:   []string{"metadata.next_offset"},
				PageSizeParams:   []string{"limit"},
				ListKeys:         []string{"response"},
				TimestampKeys:    []string{"last_seen", "last_seen_at", "created", "created_at"},
				Attributes:       map[string]string{"browser": "browser", "disk_encryption_status": "disk_encryption_status", "endpoint_id": "epkey|endpoint_id|id", "hostname": "hostname|computer_name", "last_seen_at": "last_seen|last_seen_at", "os": "os|platform", "os_version": "os_version|platform_version", "source_event_id": "event_id|epkey|endpoint_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "endpoint_device", "resource_type": "endpoint", "schema": "endpoints", "source_system": "duo_security"},
			},
			{
				Name:             familyRoles,
				Path:             "/admin/v1/admin_roles",
				URNKind:          "runtime_roles",
				IDKeys:           []string{"role_id", "id", "name", "policy_id", "key", "control_id"},
				DisablePageSize:  true,
				ListKeys:         []string{"response"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "observed_at": "observed_at|updated_at|last_seen_at", "policy_created_at": "created_at|created|date_created", "policy_description": "description|summary|body", "policy_id": "role_id|id", "policy_name": "name", "policy_severity": "severity|risk|priority", "policy_status": "status", "policy_type": "role", "resource_id": "resource_id|role_id|id|metadata.resource_id", "resource_name": "name|display_name|hostname|metadata.resource_name", "resource_type": "resource_type|type|metadata.resource_type", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|role_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "policy", "schema": "roles", "source_system": "duo_security"},
			},
			{
				Name:             familyApplications,
				Path:             "/admin/v3/integrations",
				AuthModel:        "duo_hmac_v5",
				URNKind:          "runtime_applications",
				IDKeys:           []string{"integration_key", "integration_id", "ikey", "id", "name", "urn", "resource_urn"},
				CursorParam:      "offset",
				NextCursorKeys:   []string{"metadata.next_offset"},
				PageSizeParams:   []string{"limit"},
				ListKeys:         []string{"response"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "integration_key|integration_id|ikey|id", "name": "name", "observed_at": "observed_at|updated_at|last_seen_at", "resource_id": "integration_key|integration_id|ikey|id", "resource_name": "name", "resource_type": "type|application", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|integration_key|integration_id|ikey|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				Config:           jsonapi.FamilyConfig{EncodeURNID: true, ResourceURNKind: "runtime_applications"},
				StaticAttributes: map[string]string{"record_class": "asset", "schema": "applications", "source_system": "duo_security"},
			},
			{
				Name:             familyAuditEvents,
				Path:             "/admin/v2/logs/activity",
				URNKind:          "runtime_audit_events",
				IDKeys:           []string{"txid", "id", "name", "event_id", "uuid", "request_id"},
				CursorParam:      "next_offset",
				NextCursorKeys:   []string{"response.metadata.next_offset"},
				PageSizeParams:   []string{"limit"},
				ListKeys:         []string{"response.items"},
				TimestampKeys:    []string{"ts", "isotimestamp", "observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"actor_email": "actor_email|actor.email|user.email", "actor_id": "actor.key|actor_id|actor.id|user.key|user.id|user.name", "actor_name": "actor.name|actor_name|user.name", "event_type": "event_type|action.name|action|type", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "txid|id", "observed_at": "isotimestamp|ts|observed_at|updated_at|last_seen_at", "resource_email": "resource_email|target_email|target.email", "resource_id": "target.key|resource_id|application.key|access_device.epkey", "resource_name": "target.name|resource_name|application.name|access_device.hostname|resource.name|object_name", "resource_type": "target.type|resource_type|application.type", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "txid|event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				Config:           jsonapi.FamilyConfig{ConfigQuery: map[string]string{"mintime": "mintime", "maxtime": "maxtime"}},
				StaticAttributes: map[string]string{"record_class": "audit_event", "schema": "audit_events", "source_system": "duo_security"},
			},
			{
				Name:             familyAuthenticationLogs,
				Path:             "/admin/v2/logs/authentication",
				URNKind:          "runtime_audit_events",
				IDKeys:           []string{"txid", "id", "event_id", "uuid"},
				CursorParam:      "next_offset",
				NextCursorKeys:   []string{"response.metadata.next_offset"},
				PageSizeParams:   []string{"limit"},
				ListKeys:         []string{"response.authlogs"},
				TimestampKeys:    []string{"isotimestamp", "timestamp", "ts", "observed_at", "created_at"},
				Attributes:       map[string]string{"actor_email": "email|user.email", "actor_id": "user.key|user_id|username|user.name", "actor_name": "username|user.name|email", "event_type": "event_type|eventtype|factor|result", "id": "txid|id", "observed_at": "isotimestamp|timestamp|ts", "resource_id": "application.key|application.name|access_device.epkey|txid", "resource_name": "application.name|access_device.hostname|host", "resource_type": "application.type|type", "source_event_id": "txid|event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				Config:           jsonapi.FamilyConfig{ConfigQuery: map[string]string{"mintime": "mintime", "maxtime": "maxtime"}},
				StaticAttributes: map[string]string{"record_class": "audit_event", "schema": "authentication_logs", "source_system": "duo_security"},
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
	runtimeCfg, err := sourcecdk.ResolveBaseURLConfig(sourceID, defaultBaseURLTemplate, cfg, templateKeys)
	if err != nil {
		return sourcecdk.Config{}, err
	}
	family := strings.TrimSpace(sourcecdk.ConfigValue(runtimeCfg, "family"))
	if family == "" {
		family = defaultFamily
	}
	if family == familyAuditEvents || family == familyAuthenticationLogs {
		if strings.TrimSpace(sourcecdk.ConfigValue(runtimeCfg, "mintime")) == "" || strings.TrimSpace(sourcecdk.ConfigValue(runtimeCfg, "maxtime")) == "" {
			return sourcecdk.Config{}, fmt.Errorf("%w: mintime and maxtime are required for %s", sourcecdk.ErrInvalidConfig, family)
		}
	}
	return runtimeCfg, nil
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
