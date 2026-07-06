package adobe_workfront

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
	sourceID               = "adobe_workfront"
	defaultFamily          = familyUsers
	defaultHealthPath      = "/info"
	defaultBaseURLTemplate = "${config.base_url}"
	tokenHeader            = "apiKey"
	tokenScheme            = ""
	familyUsers            = "users"
	familyGroups           = "groups"
	familyProjects         = "projects"
	familyDocuments        = "documents"
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
		AuthModel:       "api_key",
		TokenHeader:     tokenHeader,
		TokenScheme:     tokenScheme,
		Families: []jsonapi.Family{
			{
				Name:             familyUsers,
				Path:             "/user/search",
				URNKind:          "adobe_workfront_users",
				IDKeys:           []string{"ID", "id", "name", "emailAddr", "username"},
				CursorParam:      "$$FIRST",
				PageFirstCursor:  "0",
				PageSizeParams:   []string{"$$LIMIT"},
				ListKeys:         []string{"data"},
				TimestampKeys:    []string{"lastLoginDate", "lastUpdateDate", "entryDate", "observed_at"},
				Attributes:       map[string]string{"created_at": "entryDate|created_at", "department": "homeGroup.name|department", "display_name": "name", "email": "emailAddr|email", "job_title": "title", "last_login_at": "lastLoginDate", "login": "username|emailAddr", "manager": "manager.name|managerID", "observed_at": "lastUpdateDate|entryDate", "primary_email": "emailAddr|email", "resource_id": "ID|id", "resource_name": "name", "resource_type": "user", "source_event_id": "ID|id", "status": "isActive|status", "tenant_id": "tenant_id|metadata.tenant_id", "user_id": "ID|id"},
				StaticAttributes: map[string]string{"record_class": "identity_user", "schema": "users", "source_system": "adobe_workfront"},
			},
			{
				Name:             familyGroups,
				Path:             "/group/search",
				URNKind:          "adobe_workfront_groups",
				IDKeys:           []string{"ID", "id", "name"},
				CursorParam:      "$$FIRST",
				PageFirstCursor:  "0",
				PageSizeParams:   []string{"$$LIMIT"},
				ListKeys:         []string{"data"},
				TimestampKeys:    []string{"lastUpdateDate", "entryDate", "observed_at"},
				Attributes:       map[string]string{"description": "description", "group_id": "ID|id", "group_name": "name", "observed_at": "lastUpdateDate|entryDate", "resource_id": "ID|id", "resource_name": "name", "resource_type": "group", "source_event_id": "ID|id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "identity_group", "schema": "groups", "source_system": "adobe_workfront"},
			},
			{
				Name:             familyProjects,
				Path:             "/proj/search",
				URNKind:          "adobe_workfront_projects",
				IDKeys:           []string{"ID", "id", "name"},
				CursorParam:      "$$FIRST",
				PageFirstCursor:  "0",
				PageSizeParams:   []string{"$$LIMIT"},
				ListKeys:         []string{"data"},
				TimestampKeys:    []string{"lastUpdateDate", "entryDate", "actualStartDate", "observed_at"},
				Attributes:       map[string]string{"id": "ID|id", "name": "name", "observed_at": "lastUpdateDate|entryDate", "owner_id": "ownerID", "resource_id": "ID|id", "resource_name": "name", "resource_type": "project", "source_event_id": "ID|id", "status": "status", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "schema": "projects", "source_system": "adobe_workfront"},
			},
			{
				Name:             familyDocuments,
				Path:             "/docu/search",
				URNKind:          "adobe_workfront_documents",
				IDKeys:           []string{"ID", "id", "name"},
				CursorParam:      "$$FIRST",
				PageFirstCursor:  "0",
				PageSizeParams:   []string{"$$LIMIT"},
				ListKeys:         []string{"data"},
				TimestampKeys:    []string{"lastModDate", "entryDate", "observed_at"},
				Attributes:       map[string]string{"doc_obj_code": "docObjCode", "download_url": "downloadURL", "file_type": "fileType", "id": "ID|id", "name": "name", "observed_at": "lastModDate|entryDate", "resource_id": "ID|id", "resource_name": "name", "resource_type": "document", "source_event_id": "ID|id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "schema": "documents", "source_system": "adobe_workfront"},
			},
			{
				Name:             familyAuditEvents,
				Path:             "/jrnle/search",
				URNKind:          "adobe_workfront_audit_events",
				IDKeys:           []string{"ID", "id", "objID"},
				CursorParam:      "$$FIRST",
				PageFirstCursor:  "0",
				PageSizeParams:   []string{"$$LIMIT"},
				ListKeys:         []string{"data"},
				TimestampKeys:    []string{"entryDate", "lastUpdateDate", "observed_at"},
				Attributes:       map[string]string{"actor_id": "userID|enteredByID", "event_type": "fieldName|eventType|objObjCode", "field_name": "fieldName", "id": "ID|id", "new_value": "newTextVal|newDateVal|newNumberVal", "observed_at": "entryDate|lastUpdateDate", "old_value": "oldTextVal|oldDateVal|oldNumberVal", "resource_id": "objID", "resource_name": "objectName|name", "resource_type": "objObjCode|resource_type", "source_event_id": "ID|id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "audit_event", "schema": "audit_events", "source_system": "adobe_workfront"},
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
