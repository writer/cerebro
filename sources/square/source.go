package square

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
	sourceID                       = "square"
	defaultFamily                  = familyActivity
	defaultHealthPath              = "/v2/gift-cards/activities"
	defaultBaseURLTemplate         = "https://connect.squareup.com"
	tokenHeader                    = ""
	tokenScheme                    = "Bearer"
	familyActivity                 = "activity"
	familyBankAccount              = "bank_account"
	familyGroup                    = "group"
	familyTeamMemberBookingProfile = "team_member_booking_profile"
)

var templateKeys = []string{"oauth_client_reference"}

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
		SourceID:                    sourceID,
		DefaultFamily:               defaultFamily,
		RequireTenantID:             true,
		AuthModel:                   "oauth_authorization_code",
		TokenHeader:                 tokenHeader,
		TokenScheme:                 tokenScheme,
		OAuthTokenURL:               "https://connect.squareup.com/oauth2/token",
		OAuthScopes:                 []string{"APPOINTMENTS_BUSINESS_SETTINGS_READ", "APPOINTMENTS_READ", "BANK_ACCOUNTS_READ", "CASH_DRAWER_READ", "CUSTOMERS_READ", "DEVICE_CREDENTIAL_MANAGEMENT", "DISPUTES_READ", "EMPLOYEES_READ", "GIFTCARDS_READ", "INVENTORY_READ", "INVOICES_READ", "ITEMS_READ", "LOYALTY_READ", "MERCHANT_PROFILE_READ", "ONLINE_STORE_SITE_READ", "ONLINE_STORE_SNIPPETS_READ", "ORDERS_READ", "PAYMENTS_READ", "SETTLEMENTS_READ", "SUBSCRIPTIONS_READ", "TIMECARDS_READ", "TIMECARDS_SETTINGS_READ"},
		OAuthTokenRequestAuthMethod: "client_secret_basic",
		Families: []jsonapi.Family{
			{
				Name:             familyActivity,
				Path:             "/v2/gift-cards/activities",
				URNKind:          "squareup_activity",
				IDKeys:           []string{"category", "event_id", "id", "uuid", "request_id"},
				CursorParam:      "cursor",
				PageSizeParams:   []string{"limit"},
				ListKeys:         []string{"errors"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"actor_email": "actor_email|actor.email|email|user.email", "actor_id": "actor_id|actor.id|actorId|user_id|user.id", "actor_name": "actor_name|actor.name|user.name", "event_type": "event_type|event_name|action|type", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "category", "name": "category", "observed_at": "observed_at|updated_at|last_seen_at", "provider_id": "category", "resource_email": "resource_email|target_email|target.email", "resource_id": "resource_id|target_id|target.id|resource.id|object_id", "resource_name": "resource_name|target_name|target.name|resource.name|object_name", "resource_type": "resource_type|target_type|target.type|object_type", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "audit_event", "schema": "activity", "source_system": "square"},
			},
			{
				Name:             familyBankAccount,
				Path:             "/v2/bank-accounts",
				URNKind:          "squareup_bank_account",
				IDKeys:           []string{"id", "account_number_suffix", "user_id", "email", "primary_email", "login"},
				CursorParam:      "cursor",
				PageSizeParams:   []string{"limit"},
				ListKeys:         []string{"bank_accounts"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"created_at": "created_at|created|profile.created_at", "department": "department|profile.department", "display_name": "display_name|name|profile.display_name|profile.name", "domain": "domain|tenant_domain|organization_domain", "email": "email|primary_email|profile.email", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "id", "job_title": "job_title|title|profile.title", "last_login_at": "last_login_at|last_login|last_seen_at", "login": "login|username|email|profile.login", "manager": "manager|profile.manager", "name": "account_number_suffix", "observed_at": "observed_at|updated_at|last_seen_at", "primary_email": "primary_email|email|profile.email", "provider_id": "id", "resource_id": "resource_id|id|metadata.resource_id", "resource_name": "name|display_name|hostname|metadata.resource_name", "resource_type": "resource_type|type|metadata.resource_type", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "status": "status|state|lifecycle_state", "tenant_id": "tenant_id|metadata.tenant_id", "user_id": "user_id|id|uid"},
				StaticAttributes: map[string]string{"record_class": "identity_user", "schema": "bank_account", "source_system": "square"},
			},
			{
				Name:             familyGroup,
				Path:             "/v2/customers/groups",
				URNKind:          "squareup_group",
				IDKeys:           []string{"id", "name", "group_id", "group_email", "email"},
				CursorParam:      "cursor",
				PageSizeParams:   []string{"limit"},
				ListKeys:         []string{"groups"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"description": "description|summary", "domain": "domain|tenant_domain|organization_domain", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "group_email": "group_email|email", "group_id": "group_id|id", "group_name": "group_name|name|display_name", "id": "id", "name": "name", "observed_at": "observed_at|updated_at|last_seen_at", "provider_id": "id", "resource_id": "resource_id|id|metadata.resource_id", "resource_name": "name|display_name|hostname|metadata.resource_name", "resource_type": "resource_type|type|metadata.resource_type", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "identity_group", "schema": "group", "source_system": "square"},
			},
			{
				Name:             familyTeamMemberBookingProfile,
				Path:             "/v2/bookings/team-member-booking-profiles",
				URNKind:          "squareup_team_member_booking_profile",
				IDKeys:           []string{"description", "display_name", "membership_id", "id", "group_id", "member_id", "user_id", "email"},
				CursorParam:      "cursor",
				PageSizeParams:   []string{"limit"},
				ListKeys:         []string{"team_member_booking_profiles"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "group_email": "group_email|group.email", "group_id": "group_id|group.id|groupId", "group_name": "group_name|group.name", "id": "description", "member_email": "member_email|user_email|email|member.email|user.email", "member_id": "member_id|member.id|user_id|user.id|id", "member_name": "member_name|name|member.name|user.name", "member_type": "member_type|type|member.type", "member_user_id": "member_user_id|user_id|user.id|member.id", "name": "display_name", "observed_at": "observed_at|updated_at|last_seen_at", "provider_id": "description", "resource_id": "resource_id|id|metadata.resource_id", "resource_name": "name|display_name|hostname|metadata.resource_name", "resource_type": "resource_type|type|metadata.resource_type", "resource_urn": "resource_urn|urn|metadata.resource_urn", "role": "role|membership_role", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "group_membership", "schema": "team_member_booking_profile", "source_system": "square"},
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
