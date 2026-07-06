package airbrake

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
	sourceID                = "airbrake"
	defaultFamily           = familyProjects
	defaultHealthPath       = "/api/v4/projects"
	defaultBaseURLTemplate  = "https://api.airbrake.io"
	familyProjects          = "projects"
	familyGroups            = "groups"
	familyDeploys           = "deploys"
	familySourceMaps        = "source_maps"
	familyProjectActivities = "project_activities"
)

var templateKeys = []string{"token", "project_id", "group_id"}

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
			airbrakeAssetFamily(familyProjects, "/api/v4/projects", "airbrake_projects", "airbrake_project", []string{"id", "name"}, []string{"deployAt", "updatedAt", "createdAt"}, []string{"projects"}, map[string]string{"id": "id", "name": "name", "resource_id": "id", "resource_name": "name", "resource_type": "airbrake_project", "source_event_id": "id"}),
			{
				Name:           familyGroups,
				Path:           "/api/v4/groups",
				URNKind:        "airbrake_groups",
				IDKeys:         []string{"id", "groupId"},
				CursorParam:    "start",
				NextCursorKeys: []string{"end"},
				PageSizeParams: []string{"limit"},
				ListKeys:       []string{"groups"},
				TimestampKeys:  []string{"lastNoticeAt", "createdAt", "updatedAt"},
				Attributes: map[string]string{
					"description":     "errors.0.message|errors[0].message",
					"finding_id":      "id",
					"observed_at":     "lastNoticeAt|createdAt",
					"resource_id":     "projectId",
					"resource_name":   "context.environment|projectId",
					"resource_type":   "airbrake_project",
					"resource_urn":    "resource_urn",
					"severity":        "context.severity|severity",
					"source_event_id": "id",
					"status":          "resolved",
					"tenant_id":       "tenant_id|metadata.tenant_id",
					"title":           "errors.0.type|errors[0].type|id",
				},
				StaticAttributes: map[string]string{"record_class": "finding", "resource_type": "airbrake_project", "schema": "groups", "severity": "error", "source_system": "airbrake"},
				Config:           airbrakeQueryConfig(),
			},
			airbrakeAssetFamily(familyDeploys, "/api/v4/projects/${config.project_id}/deploys", "airbrake_deploys", "airbrake_deploy", []string{"id", "deployId", "revision", "version"}, []string{"createdAt", "deployAt"}, []string{"deploys"}, map[string]string{"id": "id|deployId|revision", "name": "version|revision", "resource_id": "id|deployId|revision", "resource_name": "version|revision", "resource_type": "airbrake_deploy", "source_event_id": "id|deployId|revision", "repository": "repository", "revision": "revision", "version": "version", "actor_email": "email", "actor_name": "username"}),
			airbrakeAssetFamily(familySourceMaps, "/api/v4/projects/${config.project_id}/sourcemaps", "airbrake_source_maps", "airbrake_source_map", []string{"id", "name"}, []string{"usedAt", "createdAt", "updatedAt"}, []string{"sourcemaps"}, map[string]string{"id": "id", "name": "name", "resource_id": "id", "resource_name": "name", "resource_type": "airbrake_source_map", "source_event_id": "id", "pattern": "pattern", "used_at": "usedAt"}),
			{
				Name:           familyProjectActivities,
				Path:           "/api/v4/projects/${config.project_id}/activities",
				URNKind:        "airbrake_project_activities",
				IDKeys:         []string{"id", "trackableId", "createdAt"},
				PageSizeParams: []string{"limit"},
				ListKeys:       []string{"activities"},
				TimestampKeys:  []string{"createdAt", "updatedAt"},
				Attributes: map[string]string{
					"actor_id":        "userId",
					"actor_name":      "userName",
					"event_type":      "activity",
					"id":              "id|trackableId",
					"observed_at":     "createdAt",
					"resource_id":     "trackableId",
					"resource_name":   "trackableType|trackableId",
					"resource_type":   "trackableType",
					"source_event_id": "id|trackableId|createdAt",
					"tenant_id":       "tenant_id|metadata.tenant_id",
				},
				StaticAttributes: map[string]string{"record_class": "audit_event", "schema": "project_activities", "source_system": "airbrake"},
				Config:           airbrakeQueryConfig(),
			},
		},
	})
	if err != nil {
		return nil, err
	}
	return &Source{inner: inner}, nil
}

func airbrakeAssetFamily(name, path, urnKind, resourceType string, idKeys []string, timestampKeys []string, listKeys []string, attrs map[string]string) jsonapi.Family {
	return jsonapi.Family{
		Name:             name,
		Path:             path,
		URNKind:          urnKind,
		IDKeys:           idKeys,
		PageSizeParams:   []string{"limit"},
		ListKeys:         listKeys,
		TimestampKeys:    timestampKeys,
		Attributes:       attrs,
		StaticAttributes: map[string]string{"record_class": "asset", "resource_type": resourceType, "schema": name, "source_system": "airbrake"},
		Config:           airbrakeQueryConfig(),
	}
}

func airbrakeQueryConfig() jsonapi.FamilyConfig {
	return jsonapi.FamilyConfig{ConfigQuery: map[string]string{"key": "token"}}
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
