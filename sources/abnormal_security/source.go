package abnormal_security

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
	sourceID               = "abnormal_security"
	defaultFamily          = familyResources
	defaultHealthPath      = "/users"
	defaultBaseURLTemplate = "${config.base_url}"
	tokenHeader            = ""
	tokenScheme            = "Bearer"
	familyResources        = "resources"
	familyThreats          = "threats"
	familyCases            = "cases"
	familyPostureCatalog   = "posture_catalog"
	familyAuditEvents      = "audit_events"
)

var templateKeys = []string{"base_url", "token"}

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
				Name:             familyResources,
				Path:             "/resources",
				URNKind:          "abnormal_security_resources",
				IDKeys:           []string{"resourceId", "id", "name", "urn", "resource_urn"},
				CursorParam:      "pageNumber",
				NextCursorKeys:   []string{"nextPageNumber"},
				PageSizeParams:   []string{"pageSize"},
				ListKeys:         []string{"resources"},
				TimestampKeys:    []string{"updated_at", "created_at", "last_seen_at", "observed_at"},
				Attributes:       map[string]string{"description": "description", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "resourceId|id", "name": "name", "observed_at": "updated_at|created_at|last_seen_at|observed_at", "resource_id": "resourceId|id", "resource_name": "name", "resource_type": "resource", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|resourceId|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "schema": "resources", "source_system": "abnormal_security"},
			},
			{
				Name:             familyThreats,
				Path:             "/threats",
				URNKind:          "abnormal_security_threats",
				IDKeys:           []string{"threatId", "id", "finding_id", "resource_urn"},
				CursorParam:      "pageNumber",
				NextCursorKeys:   []string{"nextPageNumber"},
				PageSizeParams:   []string{"pageSize"},
				ListKeys:         []string{"threats"},
				TimestampKeys:    []string{"receivedTime", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"description": "description|summary", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "finding_id": "threatId|id", "observed_at": "receivedTime|updated_at|last_seen_at|created_at", "resource_id": "resource_id|recipientAddress|recipient.address", "resource_name": "recipientAddress|recipient.address|name|display_name|hostname|metadata.resource_name", "resource_type": "email_threat", "resource_urn": "resource_urn|urn|metadata.resource_urn", "severity": "severity|severity_level|attackType", "source_event_id": "event_id|threatId|id|metadata.event_id", "status": "status|remediationStatus", "tenant_id": "tenant_id|metadata.tenant_id", "title": "title|subject|attackType"},
				StaticAttributes: map[string]string{"record_class": "finding", "schema": "threats", "source_system": "abnormal_security"},
			},
			{
				Name:             familyCases,
				Path:             "/cases",
				URNKind:          "abnormal_security_cases",
				IDKeys:           []string{"caseId", "id", "finding_id", "resource_urn"},
				CursorParam:      "pageNumber",
				NextCursorKeys:   []string{"nextPageNumber"},
				PageSizeParams:   []string{"pageSize"},
				ListKeys:         []string{"cases"},
				TimestampKeys:    []string{"last_modified", "first_observed", "created", "updated_at"},
				Attributes:       map[string]string{"description": "description|summary", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "finding_id": "caseId|id", "observed_at": "last_modified|first_observed|created|updated_at", "resource_id": "affectedEmployee|affected_employee|resource_id", "resource_name": "affectedEmployee|affected_employee|name|display_name|metadata.resource_name", "resource_type": "abnormal_case", "resource_urn": "resource_urn|urn|metadata.resource_urn", "severity": "severity_level|severity", "source_event_id": "event_id|caseId|id|metadata.event_id", "status": "case_status|status|remediation_status", "tenant_id": "tenant|tenant_id|metadata.tenant_id", "title": "description|severity"},
				StaticAttributes: map[string]string{"record_class": "finding", "schema": "cases", "source_system": "abnormal_security"},
			},
			{
				Name:             familyPostureCatalog,
				Path:             "/spm-v2/posture-catalog",
				URNKind:          "abnormal_security_posture_catalog",
				IDKeys:           []string{"id", "name", "policy_id", "key", "control_id"},
				CursorParam:      "pageNumber",
				NextCursorKeys:   []string{"metadata.next_page|nextPageNumber"},
				PageSizeParams:   []string{"pageSize"},
				ListKeys:         []string{"data"},
				TimestampKeys:    []string{"updated_at", "created_at", "observed_at", "last_seen_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "observed_at": "updated_at|created_at|observed_at|last_seen_at", "policy_created_at": "created_at|created|date_created", "policy_description": "description|insight|remediation_steps|summary|body", "policy_id": "id", "policy_name": "name", "policy_severity": "risk_level|severity|risk|priority", "policy_status": "status", "policy_type": "posture_catalog", "resource_id": "id|resource_id|metadata.resource_id", "resource_name": "name|display_name|hostname|metadata.resource_name", "resource_type": "posture", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "policy", "schema": "posture_catalog", "source_system": "abnormal_security"},
			},
			{
				Name:             familyAuditEvents,
				Path:             "/auditlogs",
				URNKind:          "abnormal_security_audit_events",
				IDKeys:           []string{"id", "event_id", "timestamp", "uuid", "request_id"},
				CursorParam:      "pageNumber",
				NextCursorKeys:   []string{"nextPageNumber"},
				PageSizeParams:   []string{"pageSize"},
				ListKeys:         []string{"auditLogs"},
				TimestampKeys:    []string{"timestamp", "observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"actor_email": "user.email|actor_email", "actor_id": "user.email|actor_id", "actor_name": "user.name|actor_name|actor.name", "event_type": "action|event_type", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "id|event_id|timestamp", "observed_at": "timestamp|observed_at|updated_at|last_seen_at", "resource_email": "resource_email|target_email|target.email", "resource_id": "actionDetails.message_id|resource_id", "resource_name": "actionDetails.request_url|resource_name|target_name|target.name|resource.name|object_name", "resource_type": "category|resource_type", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|timestamp|metadata.event_id", "tenant_id": "tenantName|tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "audit_event", "schema": "audit_events", "source_system": "abnormal_security"},
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
