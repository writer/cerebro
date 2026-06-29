package avaza

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
	sourceID               = "avaza"
	defaultFamily          = familyProjectmember
	defaultHealthPath      = "/api/ProjectMember"
	defaultBaseURLTemplate = "https://api.avaza.com"
	tokenHeader            = ""
	tokenScheme            = "Bearer"
	familyProjectmember    = "projectmember"
	familyLookup           = "lookup"
	familyUserprofile      = "userprofile"
	familyWebhook          = "webhook"
	familyBill             = "bill"
	familyBillpayment      = "billpayment"
	familyCompany          = "company"
	familyContact          = "contact"
	familyCreditnote       = "creditnote"
	familyCurrency         = "currency"
	familyEstimate         = "estimate"
	familyExpense          = "expense"
)

var templateKeys = []string{"token"}

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
				Name:             familyProjectmember,
				Path:             "/api/ProjectMember",
				URNKind:          "avaza_projectmember",
				IDKeys:           []string{"Email", "user_id", "id", "email", "primary_email", "login"},
				ListKeys:         []string{"ProjectMembers"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"created_at": "created_at|created|profile.created_at", "department": "department|profile.department", "display_name": "display_name|name|profile.display_name|profile.name", "domain": "domain|tenant_domain|organization_domain", "email": "email|primary_email|profile.email", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "Email", "job_title": "job_title|title|profile.title", "last_login_at": "last_login_at|last_login|last_seen_at", "login": "login|username|email|profile.login", "manager": "manager|profile.manager", "name": "Email", "observed_at": "observed_at|updated_at|last_seen_at", "primary_email": "primary_email|email|profile.email", "provider_id": "Email", "resource_id": "resource_id|id|metadata.resource_id", "resource_name": "name|display_name|hostname|metadata.resource_name", "resource_type": "resource_type|type|metadata.resource_type", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "status": "status|state|lifecycle_state", "tenant_id": "tenant_id|metadata.tenant_id", "user_id": "user_id|id|uid"},
				StaticAttributes: map[string]string{"record_class": "identity_user", "schema": "projectmember", "source_system": "avaza"},
			},
			{
				Name:             familyLookup,
				Path:             "/api/ExpenseGroup/Lookup",
				URNKind:          "avaza_lookup",
				IDKeys:           []string{"Name", "id", "urn", "resource_urn", "name"},
				PageSizeParams:   []string{"pageSize"},
				ListKeys:         []string{"ExpenseGroups"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "Name", "name": "Name", "observed_at": "observed_at|updated_at|last_seen_at", "resource_id": "Name", "resource_name": "Name", "resource_type": "lookup", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "schema": "lookup", "source_system": "avaza"},
			},
			{
				Name:             familyUserprofile,
				Path:             "/api/UserProfile",
				URNKind:          "avaza_userprofile",
				IDKeys:           []string{"Email", "user_id", "id", "email", "primary_email", "login"},
				ListKeys:         []string{"Users"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"created_at": "created_at|created|profile.created_at", "department": "department|profile.department", "display_name": "display_name|name|profile.display_name|profile.name", "domain": "domain|tenant_domain|organization_domain", "email": "email|primary_email|profile.email", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "Email", "job_title": "job_title|title|profile.title", "last_login_at": "last_login_at|last_login|last_seen_at", "login": "login|username|email|profile.login", "manager": "manager|profile.manager", "name": "Email", "observed_at": "observed_at|updated_at|last_seen_at", "primary_email": "primary_email|email|profile.email", "provider_id": "Email", "resource_id": "resource_id|id|metadata.resource_id", "resource_name": "name|display_name|hostname|metadata.resource_name", "resource_type": "resource_type|type|metadata.resource_type", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "status": "status|state|lifecycle_state", "tenant_id": "tenant_id|metadata.tenant_id", "user_id": "user_id|id|uid"},
				StaticAttributes: map[string]string{"record_class": "identity_user", "schema": "userprofile", "source_system": "avaza"},
			},
			{
				Name:             familyWebhook,
				Path:             "/api/Webhook",
				URNKind:          "avaza_webhook",
				IDKeys:           []string{"EventCode", "id", "urn", "resource_urn", "name"},
				ListKeys:         []string{"Webhooks"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "EventCode", "name": "EventCode", "observed_at": "observed_at|updated_at|last_seen_at", "resource_id": "EventCode", "resource_name": "EventCode", "resource_type": "webhook", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "schema": "webhook", "source_system": "avaza"},
			},
			{
				Name:             familyBill,
				Path:             "/api/Bill",
				URNKind:          "avaza_bill",
				IDKeys:           []string{"AccountIDFK", "Subject", "id", "urn", "resource_urn", "name"},
				PageSizeParams:   []string{"pageSize"},
				ListKeys:         []string{"Bills"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "AccountIDFK", "name": "Subject", "observed_at": "observed_at|updated_at|last_seen_at", "resource_id": "AccountIDFK", "resource_name": "Subject", "resource_type": "bill", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "schema": "bill", "source_system": "avaza"},
			},
			{
				Name:             familyBillpayment,
				Path:             "/api/BillPayment",
				URNKind:          "avaza_billpayment",
				IDKeys:           []string{"AccountIDFK", "id", "urn", "resource_urn", "name"},
				PageSizeParams:   []string{"pageSize"},
				ListKeys:         []string{"Payments"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "AccountIDFK", "name": "AccountIDFK", "observed_at": "observed_at|updated_at|last_seen_at", "resource_id": "AccountIDFK", "resource_name": "AccountIDFK", "resource_type": "billpayment", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "schema": "billpayment", "source_system": "avaza"},
			},
			{
				Name:             familyCompany,
				Path:             "/api/Company",
				URNKind:          "avazapany",
				IDKeys:           []string{"BillingAddress", "id", "urn", "resource_urn", "name"},
				PageSizeParams:   []string{"pageSize"},
				ListKeys:         []string{"Companies"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "BillingAddress", "name": "BillingAddress", "observed_at": "observed_at|updated_at|last_seen_at", "resource_id": "BillingAddress", "resource_name": "BillingAddress", "resource_type": "company", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "schema": "company", "source_system": "avaza"},
			},
			{
				Name:             familyContact,
				Path:             "/api/Contact",
				URNKind:          "avaza_contact",
				IDKeys:           []string{"Email", "id", "urn", "resource_urn", "name"},
				PageSizeParams:   []string{"pageSize"},
				ListKeys:         []string{"Contacts"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "Email", "name": "Email", "observed_at": "observed_at|updated_at|last_seen_at", "resource_id": "Email", "resource_name": "Email", "resource_type": "contact", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "schema": "contact", "source_system": "avaza"},
			},
			{
				Name:             familyCreditnote,
				Path:             "/api/CreditNote",
				URNKind:          "avaza_creditnote",
				IDKeys:           []string{"Balance", "id", "urn", "resource_urn", "name"},
				PageSizeParams:   []string{"pageSize"},
				ListKeys:         []string{"CreditNotes"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "Balance", "name": "Balance", "observed_at": "observed_at|updated_at|last_seen_at", "resource_id": "Balance", "resource_name": "Balance", "resource_type": "creditnote", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "schema": "creditnote", "source_system": "avaza"},
			},
			{
				Name:             familyCurrency,
				Path:             "/api/Currency",
				URNKind:          "avaza_currency",
				IDKeys:           []string{"Name", "id", "urn", "resource_urn", "name"},
				ListKeys:         []string{"Currencies"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "Name", "name": "Name", "observed_at": "observed_at|updated_at|last_seen_at", "resource_id": "Name", "resource_name": "Name", "resource_type": "currency", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "schema": "currency", "source_system": "avaza"},
			},
			{
				Name:             familyEstimate,
				Path:             "/api/Estimate",
				URNKind:          "avaza_estimate",
				IDKeys:           []string{"AccountIDFK", "Subject", "id", "urn", "resource_urn", "name"},
				PageSizeParams:   []string{"pageSize"},
				ListKeys:         []string{"Estimates"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "AccountIDFK", "name": "Subject", "observed_at": "observed_at|updated_at|last_seen_at", "resource_id": "AccountIDFK", "resource_name": "Subject", "resource_type": "estimate", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "schema": "estimate", "source_system": "avaza"},
			},
			{
				Name:             familyExpense,
				Path:             "/api/Expense",
				URNKind:          "avaza_expense",
				IDKeys:           []string{"Email", "id", "urn", "resource_urn", "name"},
				PageSizeParams:   []string{"pageSize"},
				ListKeys:         []string{"Expenses"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "Email", "name": "Email", "observed_at": "observed_at|updated_at|last_seen_at", "resource_id": "Email", "resource_name": "Email", "resource_type": "expense", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "schema": "expense", "source_system": "avaza"},
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
