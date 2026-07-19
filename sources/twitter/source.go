package twitter

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
	sourceID               = "twitter"
	defaultFamily          = familyListMembership
	defaultHealthPath      = "/2/users/${config.id}/list_memberships"
	defaultBaseURLTemplate = "https://api.twitter.com"
	tokenHeader            = ""
	tokenScheme            = "Bearer"
	familyListMembership   = "list_membership"
	familyMember           = "member"
	familyJob              = "job"
	familyDmEvent          = "dm_event"
)

var templateKeys = []string{"id", "token"}

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
		AuthModel:       "bearer_token",
		TokenHeader:     tokenHeader,
		TokenScheme:     tokenScheme,
		Families: []jsonapi.Family{
			{
				Name:             familyListMembership,
				Path:             "/2/users/${config.id}/list_memberships",
				URNKind:          "twitter_list_membership",
				IDKeys:           []string{"id", "name", "membership_id", "group_id", "member_id", "user_id", "email"},
				CursorParam:      "pagination_token",
				NextCursorKeys:   []string{"meta.next_token"},
				PageSizeParams:   []string{"max_results"},
				ListKeys:         []string{"data"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"group_id": "id", "group_name": "name", "id": "id", "name": "name", "provider_id": "id", "resource_id": "id", "resource_name": "name", "source_event_id": "id"},
				StaticAttributes: map[string]string{"member_type": "user", "record_class": "group_membership", "resource_type": "list", "role": "member", "schema": "list_membership", "source_system": "twitter"},
				Config: jsonapi.FamilyConfig{ConfigAttributes: map[string]string{
					"member_id":      "id",
					"member_user_id": "id",
					"tenant_id":      "tenant_id",
				}},
			},
			{
				Name:             familyMember,
				Path:             "/2/lists/${config.id}/members",
				URNKind:          "twitter_member",
				IDKeys:           []string{"id", "name", "user_id", "email", "primary_email", "login"},
				CursorParam:      "pagination_token",
				NextCursorKeys:   []string{"meta.next_token"},
				PageSizeParams:   []string{"max_results"},
				ListKeys:         []string{"data"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"display_name": "name|username", "id": "id", "login": "username", "name": "name|username", "provider_id": "id", "resource_id": "id", "resource_name": "name|username", "source_event_id": "id", "user_id": "id"},
				StaticAttributes: map[string]string{"record_class": "identity_user", "resource_type": "user", "schema": "member", "source_system": "twitter"},
				Config:           jsonapi.FamilyConfig{ConfigAttributes: map[string]string{"tenant_id": "tenant_id"}},
			},
			{
				Name:             familyJob,
				Path:             "/2/compliance/jobs",
				URNKind:          "twitter_job",
				IDKeys:           []string{"id", "name", "policy_id", "key", "control_id"},
				ListKeys:         []string{"data"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"id": "id", "name": "type", "observed_at": "created_at", "policy_created_at": "created_at", "policy_id": "id", "policy_name": "type", "policy_status": "status", "policy_type": "type", "provider_id": "id", "resource_id": "id", "resource_name": "type", "source_event_id": "id"},
				StaticAttributes: map[string]string{"record_class": "policy", "resource_type": "compliance_job", "schema": "job", "source_system": "twitter"},
				Config: jsonapi.FamilyConfig{
					ConfigAttributes: map[string]string{"tenant_id": "tenant_id"},
					StaticQuery:      map[string]string{"type": "tweets"},
				},
				DisablePageSize: true,
			},
			{
				Name:             familyDmEvent,
				Path:             "/2/dm_events",
				URNKind:          "twitter_dm_event",
				IDKeys:           []string{"id", "attachments", "event_id", "uuid", "request_id"},
				PageSizeParams:   []string{"max_results"},
				ListKeys:         []string{"data"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"actor_email": "actor_email|actor.email|email|user.email", "actor_id": "actor_id|actor.id|actorId|user_id|user.id", "actor_name": "actor_name|actor.name|user.name", "event_type": "event_type|event_name|action|type", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "id", "name": "attachments", "observed_at": "observed_at|updated_at|last_seen_at", "provider_id": "id", "resource_email": "resource_email|target_email|target.email", "resource_id": "resource_id|target_id|target.id|resource.id|object_id", "resource_name": "resource_name|target_name|target.name|resource.name|object_name", "resource_type": "resource_type|target_type|target.type|object_type", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "audit_event", "schema": "dm_event", "source_system": "twitter"},
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
