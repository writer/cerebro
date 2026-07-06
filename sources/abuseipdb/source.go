package abuseipdb

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
	sourceID               = "abuseipdb"
	defaultFamily          = familyIpAddresses
	defaultHealthPath      = "/blacklist"
	defaultBaseURLTemplate = "https://api.abuseipdb.com/api/v2"
	tokenHeader            = "Key"
	tokenScheme            = ""
	familyReports          = "reports"
	familyIpAddresses      = "ip_addresses"
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
				Name:             familyReports,
				Path:             "/reports",
				URNKind:          "abuseipdb_reports",
				IDKeys:           []string{"_record_id", "reportedAt"},
				CursorParam:      "page",
				NextCursorKeys:   []string{"data.nextPageUrl"},
				PageSizeParams:   []string{"perPage"},
				PageFirstCursor:  "1",
				ListKeys:         []string{"data.results"},
				TimestampKeys:    []string{"reportedAt"},
				Attributes:       map[string]string{"description": "comment", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "finding_id": "_record_id|reportedAt", "observed_at": "reportedAt", "resource_id": "ipAddress|metadata.ip_address", "resource_name": "ipAddress|metadata.ip_address", "resource_type": "abuseipdb_report", "resource_urn": "resource_urn|urn|metadata.resource_urn", "severity": "severity|abuseConfidenceScore|risk|priority", "source_event_id": "_record_id|event_id|reportedAt|metadata.event_id", "status": "status|state", "tenant_id": "tenant_id|metadata.tenant_id", "title": "comment"},
				StaticAttributes: map[string]string{"record_class": "finding", "resource_type": "abuseipdb_report", "schema": "reports", "severity": "reported", "source_system": "abuseipdb", "status": "observed"},
				Config: jsonapi.FamilyConfig{
					ConfigQuery:      map[string]string{"ipAddress": "ip_address", "maxAgeInDays": "max_age_in_days"},
					ConfigAttributes: map[string]string{"resource_id": "ip_address"},
					IDTemplate:       "${reportedAt}:${reporterId}",
					DefaultPageSize:  25,
					ResourceURNKind:  "abuseipdb_ip_address",
				},
			},
			{
				Name:             familyIpAddresses,
				Path:             "/blacklist",
				URNKind:          "abuseipdb_ip_addresses",
				IDKeys:           []string{"ipAddress", "id", "urn", "resource_urn", "name"},
				CursorParam:      "cursor",
				NextCursorKeys:   []string{"next_cursor"},
				PageSizeParams:   []string{"limit"},
				ListKeys:         []string{"data"},
				TimestampKeys:    []string{"lastReportedAt", "observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "observed_at": "lastReportedAt|observed_at|updated_at|last_seen_at", "resource_id": "ipAddress|id", "resource_name": "ipAddress|name|display_name|hostname|metadata.resource_name", "resource_type": "resource_type|type|kind", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|ipAddress|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "resource_type": "ip_address", "schema": "ip_addresses", "source_system": "abuseipdb"},
				Config: jsonapi.FamilyConfig{
					StaticQuery:     map[string]string{"confidenceMinimum": "90"},
					ConfigQuery:     map[string]string{"confidenceMinimum": "confidence_minimum", "ipVersion": "ip_version"},
					DefaultPageSize: 100,
					IdentityKeys:    []string{"abuseConfidenceScore", "countryCode"},
					ResourceURNKind: "abuseipdb_ip_address",
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
