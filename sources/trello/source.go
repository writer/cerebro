package trello

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

const (
	sourceID               = "trello"
	defaultFamily          = familyUsers
	defaultBaseURLTemplate = "https://api.trello.com"
	familyUsers            = "users"
	familyGroups           = "groups"
	familyWorkspaces       = "workspaces"
	familyDocuments        = "documents"
	familyAuditEvents      = "audit_events"
)

var templateKeys = []string{"api_key", "token"}

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
				Name:             familyUsers,
				Path:             "/1/members/me",
				URNKind:          "trello_users",
				IDKeys:           []string{"id", "name", "user_id", "email", "primary_email", "login"},
				DisablePageSize:  true,
				Singleton:        true,
				TimestampKeys:    []string{"dateLastActivity"},
				Attributes:       map[string]string{"display_name": "fullName|username", "email": "email", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "login": "username|email", "observed_at": "dateLastActivity", "primary_email": "email", "resource_id": "id", "resource_name": "fullName|username", "resource_urn": "resource_urn|urn", "source_event_id": "id", "status": "status", "tenant_id": "tenant_id", "user_id": "id"},
				Config:           trelloRequestConfig(""),
				StaticAttributes: map[string]string{"record_class": "identity_user", "schema": "users", "source_system": "trello"},
			},
			{
				Name:             familyGroups,
				Path:             "/1/members/me",
				URNKind:          "trello_groups",
				IDKeys:           []string{"id", "name", "group_id", "group_email", "email"},
				DisablePageSize:  true,
				ListKeys:         []string{"organizations"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"description": "desc|description", "domain": "associatedDomain|domain", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "group_email": "email", "group_id": "id", "group_name": "displayName|name", "observed_at": "dateLastActivity", "resource_id": "id", "resource_name": "displayName|name", "resource_urn": "resource_urn|urn", "source_event_id": "id", "tenant_id": "tenant_id"},
				Config:           trelloRequestConfigWithStatic("", map[string]string{"organizations": "all"}),
				StaticAttributes: map[string]string{"record_class": "identity_group", "schema": "groups", "source_system": "trello"},
			},
			{
				Name:             familyWorkspaces,
				Path:             "/1/members/me/boards",
				URNKind:          "trello_workspaces",
				IDKeys:           []string{"id", "name", "urn", "resource_urn"},
				DisablePageSize:  true,
				TimestampKeys:    []string{"dateLastActivity", "dateLastView"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "id", "name": "name", "observed_at": "dateLastActivity|dateLastView", "resource_id": "id", "resource_name": "name", "resource_urn": "resource_urn|urn", "source_event_id": "id", "tenant_id": "tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "resource_type": "trello_board", "schema": "workspaces", "source_system": "trello"},
				Config:           trelloRequestConfig("trello_board"),
			},
			{
				Name:             familyDocuments,
				Path:             "/1/boards/${config.board_id}/cards",
				URNKind:          "trello_documents",
				IDKeys:           []string{"id", "name", "urn", "resource_urn"},
				DisablePageSize:  true,
				TimestampKeys:    []string{"dateLastActivity", "due"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "id", "name": "name", "observed_at": "dateLastActivity|due", "resource_id": "id", "resource_name": "name", "resource_urn": "resource_urn|urn", "source_event_id": "id", "tenant_id": "tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "resource_type": "trello_card", "schema": "documents", "source_system": "trello"},
				Config:           trelloRequestConfig("trello_card"),
			},
			{
				Name:             familyAuditEvents,
				Path:             "/1/members/${config.member_id}/actions",
				URNKind:          "trello_audit_events",
				IDKeys:           []string{"id", "name", "event_id", "uuid", "request_id"},
				DisablePageSize:  true,
				TimestampKeys:    []string{"date"},
				Attributes:       map[string]string{"actor_email": "memberCreator.email", "actor_id": "idMemberCreator|memberCreator.id", "actor_name": "memberCreator.fullName|memberCreator.username", "event_type": "type", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "id", "observed_at": "date", "resource_email": "data.card.email|data.board.email", "resource_id": "data.card.id|data.board.id|data.list.id", "resource_name": "data.card.name|data.board.name|data.list.name", "resource_type": "type", "resource_urn": "resource_urn|urn", "source_event_id": "id", "tenant_id": "tenant_id"},
				StaticAttributes: map[string]string{"record_class": "audit_event", "schema": "audit_events", "source_system": "trello"},
				Config:           trelloRequestConfigWithStatic("", map[string]string{"filter": "all"}),
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

func trelloRequestConfig(resourceURNKind string) jsonapi.FamilyConfig {
	return jsonapi.FamilyConfig{
		ConfigAttributes: map[string]string{"tenant_id": "tenant_id"},
		ConfigQuery:      map[string]string{"key": "api_key", "token": "token"},
		ResourceURNKind:  resourceURNKind,
	}
}

func trelloRequestConfigWithStatic(resourceURNKind string, query map[string]string) jsonapi.FamilyConfig {
	config := trelloRequestConfig(resourceURNKind)
	config.StaticQuery = query
	return config
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
	if s != nil && s.inner != nil {
		s.inner.AllowLoopbackBaseURL = true
		s.allowLoopback = true
	}
}
