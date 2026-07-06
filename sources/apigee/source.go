package apigee

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
	sourceID               = "apigee"
	defaultFamily          = familyOrganizations
	defaultHealthPath      = "/v1/organizations/${config.organization}"
	defaultBaseURLTemplate = "https://apigee.googleapis.com"
	tokenHeader            = ""
	tokenScheme            = "Bearer"
	familyOrganizations    = "organizations"
	familyAPIProxies       = "api_proxies"
	familyDeployments      = "deployments"
	familyDevelopers       = "developers"
	familyApps             = "apps"
)

var templateKeys = []string{"organization", "token"}

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
				Name:             familyOrganizations,
				Path:             "/v1/organizations",
				URNKind:          "apigee_organizations",
				IDKeys:           []string{"organization", "name", "projectId", "project_id"},
				ListKeys:         []string{"organizations"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       assetAttributes("organization|name|projectId|project_id", "organization|name|projectId|project_id", "apigee_organization"),
				StaticAttributes: map[string]string{"record_class": "asset", "schema": "organizations", "source_system": "apigee", "resource_type": "apigee_organization"},
				DisablePageSize:  true,
			},
			{
				Name:             familyAPIProxies,
				Path:             "/v1/organizations/${config.organization}/apis",
				URNKind:          "apigee_api_proxies",
				IDKeys:           []string{"name", "id", "resource_urn"},
				ListKeys:         []string{"proxies"},
				TimestampKeys:    []string{"observed_at", "updated_at", "lastModifiedAt", "createdAt"},
				Attributes:       assetAttributes("name", "name|displayName|display_name", "apigee_api_proxy"),
				StaticAttributes: map[string]string{"record_class": "asset", "schema": "api_proxies", "source_system": "apigee", "resource_type": "apigee_api_proxy"},
				Config: jsonapi.FamilyConfig{
					ConfigAttributes: map[string]string{"organization": "organization"},
					StaticQuery:      map[string]string{"includeRevisions": "true", "includeMetaData": "true"},
				},
				DisablePageSize: true,
			},
			{
				Name:             familyDeployments,
				Path:             "/v1/organizations/${config.organization}/deployments",
				URNKind:          "apigee_deployments",
				IDKeys:           []string{"id", "name", "apiProxy", "revision"},
				ListKeys:         []string{"deployments"},
				TimestampKeys:    []string{"observed_at", "updated_at", "lastModifiedAt", "createdAt"},
				Attributes:       deploymentAttributes(),
				StaticAttributes: map[string]string{"record_class": "deployment", "schema": "deployments", "source_system": "apigee", "resource_type": "apigee_deployment"},
				Config:           jsonapi.FamilyConfig{ConfigAttributes: map[string]string{"organization": "organization"}},
				DisablePageSize:  true,
			},
			{
				Name:             familyDevelopers,
				Path:             "/v1/organizations/${config.organization}/developers",
				URNKind:          "apigee_developers",
				IDKeys:           []string{"email", "developerId", "userName", "id"},
				CursorParam:      "startKey",
				PageSizeParams:   []string{"count"},
				ListKeys:         []string{"developer"},
				TimestampKeys:    []string{"observed_at", "updated_at", "lastModifiedAt", "createdAt"},
				Attributes:       developerAttributes(),
				StaticAttributes: map[string]string{"record_class": "identity_user", "schema": "developers", "source_system": "apigee"},
				Config: jsonapi.FamilyConfig{
					ConfigAttributes:   map[string]string{"organization": "organization"},
					LastItemCursorKeys: []string{"email"},
				},
			},
			{
				Name:             familyApps,
				Path:             "/v1/organizations/${config.organization}/apps",
				URNKind:          "apigee_apps",
				IDKeys:           []string{"appId", "name", "id"},
				CursorParam:      "pageToken",
				NextCursorKeys:   []string{"nextPageToken"},
				PageSizeParams:   []string{"pageSize"},
				ListKeys:         []string{"app"},
				TimestampKeys:    []string{"observed_at", "updated_at", "lastModifiedAt", "createdAt"},
				Attributes:       assetAttributes("appId|name", "name|displayName|display_name", "apigee_app"),
				StaticAttributes: map[string]string{"record_class": "asset", "schema": "apps", "source_system": "apigee", "resource_type": "apigee_app"},
				Config: jsonapi.FamilyConfig{
					ConfigAttributes: map[string]string{"organization": "organization"},
					StaticQuery:      map[string]string{"expand": "true"},
				},
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

func assetAttributes(idPath, namePath, resourceType string) map[string]string {
	return map[string]string{
		"evidence_cas_commit_id":   "evidence_cas.commit_id|evidence_cas_commit_id|commit_id",
		"evidence_cas_digest":      "evidence_cas.digest|evidence_cas_digest|digest",
		"evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root",
		"evidence_cas_ref_type":    "evidence_cas.ref_type|evidence_cas_ref_type|ref_type",
		"evidence_cas_uri":         "evidence_cas.uri|evidence_cas_uri|uri",
		"id":                       idPath,
		"name":                     namePath,
		"observed_at":              "observed_at|updated_at|last_seen_at|createdAt|lastModifiedAt",
		"resource_id":              idPath,
		"resource_name":            namePath,
		"resource_type":            "resource_type|type|kind",
		"resource_urn":             "resource_urn|urn|metadata.resource_urn",
		"source_event_id":          "event_id|id|metadata.event_id",
		"tenant_id":                "tenant_id|metadata.tenant_id",
		"organization":             "organization|org|metadata.organization",
		"project_id":               "projectId|project_id",
		"status":                   "status|state",
		"resource_kind":            resourceType,
	}
}

func deploymentAttributes() map[string]string {
	return map[string]string{
		"deployment_branch":        "branch|ref|git_branch|head_branch",
		"deployment_commit_sha":    "revision|commit_sha|commit|sha|git_sha",
		"deployment_created_at":    "created_at|created|date_created",
		"deployment_environment":   "environment|env|stage|target",
		"deployment_id":            "id|name|apiProxy",
		"deployment_name":          "name|apiProxy",
		"deployment_status":        "state|status",
		"deployment_updated_at":    "updated_at|updated|last_modified",
		"deployment_url":           "url|deployment_url|endpoint|domain|basePath",
		"evidence_cas_commit_id":   "evidence_cas.commit_id|evidence_cas_commit_id|commit_id",
		"evidence_cas_digest":      "evidence_cas.digest|evidence_cas_digest|digest",
		"evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root",
		"evidence_cas_ref_type":    "evidence_cas.ref_type|evidence_cas_ref_type|ref_type",
		"evidence_cas_uri":         "evidence_cas.uri|evidence_cas_uri|uri",
		"observed_at":              "observed_at|updated_at|last_seen_at|createdAt|lastModifiedAt",
		"resource_id":              "apiProxy|name|id",
		"resource_name":            "name|apiProxy",
		"resource_type":            "resource_type|type|metadata.resource_type",
		"resource_urn":             "resource_urn|urn|metadata.resource_urn",
		"source_event_id":          "event_id|id|metadata.event_id",
		"tenant_id":                "tenant_id|metadata.tenant_id",
		"organization":             "organization|org|metadata.organization",
		"service_account":          "serviceAccount",
	}
}

func developerAttributes() map[string]string {
	return map[string]string{
		"created_at":               "createdAt|created_at|created|profile.created_at",
		"department":               "department|profile.department",
		"display_name":             "displayName|name|userName|email",
		"domain":                   "domain|tenant_domain|organization_domain",
		"email":                    "email",
		"evidence_cas_commit_id":   "evidence_cas.commit_id|evidence_cas_commit_id|commit_id",
		"evidence_cas_digest":      "evidence_cas.digest|evidence_cas_digest|digest",
		"evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root",
		"evidence_cas_ref_type":    "evidence_cas.ref_type|evidence_cas_ref_type|ref_type",
		"evidence_cas_uri":         "evidence_cas.uri|evidence_cas_uri|uri",
		"job_title":                "job_title|title|profile.title",
		"last_login_at":            "last_login_at|last_login|last_seen_at",
		"login":                    "userName|login|username|email|profile.login",
		"manager":                  "manager|profile.manager",
		"observed_at":              "observed_at|updated_at|last_seen_at|createdAt|lastModifiedAt",
		"primary_email":            "email|primary_email|profile.email",
		"resource_id":              "developerId|email",
		"resource_name":            "displayName|name|email|metadata.resource_name",
		"resource_type":            "resource_type|type|metadata.resource_type",
		"resource_urn":             "resource_urn|urn|metadata.resource_urn",
		"source_event_id":          "event_id|id|metadata.event_id",
		"status":                   "status",
		"tenant_id":                "tenant_id|metadata.tenant_id",
		"user_id":                  "email|developerId|id",
		"organization":             "organization|org|metadata.organization",
	}
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
