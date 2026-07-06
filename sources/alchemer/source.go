package alchemer

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
	sourceID               = "alchemer"
	defaultFamily          = familyAccountUsers
	defaultHealthPath      = "/v5/account?api_token=${config.api_token}&api_token_secret=${config.api_token_secret}"
	defaultBaseURLTemplate = "${config.base_url}"
	familyAccount          = "account"
	familyAccountUsers     = "account_users"
	familyAccountTeams     = "account_teams"
	familySurveys          = "surveys"
	familyContactLists     = "contact_lists"
	familySSOIntegrations  = "sso_integrations"
)

var templateKeys = []string{"base_url", "api_token", "api_token_secret"}

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
		AuthModel:       "none",
		Families: []jsonapi.Family{
			{
				Name:             familyAccount,
				Path:             "/v5/account",
				URNKind:          "alchemer_account",
				IDKeys:           []string{"id", "organization"},
				ListKeys:         []string{"data"},
				Singleton:        true,
				RequireID:        true,
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "observed_at": "date_created|updated_at|observed_at", "resource_id": "id", "resource_name": "organization|name", "resource_type": "account", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "resource_type": "account", "schema": "account", "source_system": "alchemer"},
				Config:           jsonapi.FamilyConfig{ConfigQuery: alchemerAuthQuery(), ResourceURNKind: "alchemer_account"},
			},
			{
				Name:             familyAccountUsers,
				Path:             "/v5/accountuser",
				URNKind:          "alchemer_account_users",
				IDKeys:           []string{"id", "email", "username"},
				CursorParam:      "page",
				PageFirstCursor:  "1",
				PageSizeParams:   []string{"resultsperpage"},
				ListKeys:         []string{"data"},
				TimestampKeys:    []string{"last_login", "created_at", "updated_at"},
				Attributes:       map[string]string{"display_name": "username|name", "email": "email", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "last_login_at": "last_login", "license": "license", "observed_at": "last_login|updated_at|observed_at", "resource_id": "id", "resource_name": "username|email", "resource_type": "account_user", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "status": "status", "tenant_id": "tenant_id|metadata.tenant_id", "user_id": "id"},
				StaticAttributes: map[string]string{"record_class": "identity_user", "schema": "account_users", "source_system": "alchemer"},
				Config:           jsonapi.FamilyConfig{ConfigQuery: alchemerAuthQuery(), DefaultPageSize: 100},
			},
			{
				Name:             familyAccountTeams,
				Path:             "/v5/accountteams",
				URNKind:          "alchemer_account_teams",
				IDKeys:           []string{"id", "team_name", "name"},
				CursorParam:      "page",
				PageFirstCursor:  "1",
				PageSizeParams:   []string{"resultsperpage"},
				ListKeys:         []string{"data"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "observed_at": "updated_at|observed_at", "resource_id": "id", "resource_name": "team_name|name", "resource_type": "account_team", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "resource_type": "account_team", "schema": "account_teams", "source_system": "alchemer"},
				Config:           jsonapi.FamilyConfig{ConfigQuery: alchemerAuthQuery(), DefaultPageSize: 100, ResourceURNKind: "alchemer_account_team"},
			},
			{
				Name:             familySurveys,
				Path:             "/v5/survey",
				URNKind:          "alchemer_surveys",
				IDKeys:           []string{"id", "title", "name"},
				CursorParam:      "page",
				PageFirstCursor:  "1",
				PageSizeParams:   []string{"resultsperpage"},
				ListKeys:         []string{"data"},
				TimestampKeys:    []string{"modified_on", "created_on", "date_modified", "date_created"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "observed_at": "modified_on|date_modified|created_on|date_created|observed_at", "resource_id": "id", "resource_name": "title|name", "resource_type": "survey", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "status": "status", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "resource_type": "survey", "schema": "surveys", "source_system": "alchemer"},
				Config:           jsonapi.FamilyConfig{ConfigQuery: alchemerAuthQuery(), DefaultPageSize: 100, ResourceURNKind: "alchemer_survey"},
			},
			{
				Name:             familyContactLists,
				Path:             "/v5/contactlist",
				URNKind:          "alchemer_contact_lists",
				IDKeys:           []string{"id", "list_name", "name"},
				CursorParam:      "page",
				PageFirstCursor:  "1",
				PageSizeParams:   []string{"resultsperpage"},
				ListKeys:         []string{"data"},
				TimestampKeys:    []string{"date_modified", "date_modifed", "date_created"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "observed_at": "date_modified|date_modifed|date_created|observed_at", "resource_id": "id", "resource_name": "list_name|name", "resource_type": "contact_list", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "resource_type": "contact_list", "schema": "contact_lists", "source_system": "alchemer"},
				Config:           jsonapi.FamilyConfig{ConfigQuery: alchemerAuthQuery(), DefaultPageSize: 100, ResourceURNKind: "alchemer_contact_list"},
			},
			{
				Name:             familySSOIntegrations,
				Path:             "/v5/sso",
				URNKind:          "alchemer_sso_integrations",
				IDKeys:           []string{"id", "name", "entity_id"},
				CursorParam:      "page",
				PageFirstCursor:  "1",
				PageSizeParams:   []string{"resultsperpage"},
				ListKeys:         []string{"data"},
				MapRecords:       map[string]string{"data": "sso_integration"},
				TimestampKeys:    []string{"sso_integration.dModified", "sso_integration.created", "dModified", "created"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "sso_integration.evidence_cas.commit_id|sso_integration.evidence_cas_commit_id|evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "sso_integration.evidence_cas.digest|sso_integration.evidence_cas_digest|evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "sso_integration.evidence_cas.merkle_root|sso_integration.evidence_cas_merkle_root|evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "sso_integration.evidence_cas.ref_type|sso_integration.evidence_cas_ref_type|evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "sso_integration.evidence_cas.uri|sso_integration.evidence_cas_uri|evidence_cas.uri|evidence_cas_uri|uri", "observed_at": "sso_integration.dModified|sso_integration.created|dModified|created|observed_at", "policy_id": "sso_integration.id|id", "policy_name": "sso_integration.name|sso_integration.entity_id|name", "policy_status": "sso_integration.status|status", "policy_type": "sso_integration", "resource_id": "sso_integration.id|id", "resource_name": "sso_integration.name|sso_integration.entity_id|name", "resource_type": "sso_integration", "resource_urn": "sso_integration.resource_urn|sso_integration.urn|sso_integration.metadata.resource_urn|resource_urn|urn|metadata.resource_urn", "source_event_id": "sso_integration.event_id|sso_integration.id|event_id|id|metadata.event_id", "tenant_id": "sso_integration.tenant_id|sso_integration.metadata.tenant_id|tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"policy_type": "sso_integration", "record_class": "policy", "schema": "sso_integrations", "source_system": "alchemer"},
				Config:           jsonapi.FamilyConfig{ConfigQuery: alchemerAuthQuery(), DefaultPageSize: 100},
			},
		},
	})
	if err != nil {
		return nil, err
	}
	return &Source{inner: inner}, nil
}

func alchemerAuthQuery() map[string]string {
	return map[string]string{"api_token": "api_token", "api_token_secret": "api_token_secret"}
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
