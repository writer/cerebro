package datadog

import (
	"context"
	"embed"
	"fmt"
	"net/http"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/sources/internal/jsonapi"
)

//go:embed catalog.yaml
var catalogFS embed.FS

const (
	sourceID          = "datadog"
	defaultBaseURL    = "https://api.datadoghq.com"
	defaultFamily     = familyUsers
	defaultHealthPath = "/api/v1/validate"

	familyUsers      = "users"
	familyRoles      = "roles"
	familyTeams      = "teams"
	familyMonitors   = "monitors"
	familySLOs       = "slos"
	familyDashboards = "dashboards"
	familyIncidents  = "incidents"
	familyAudit      = "audit_events"
)

var (
	configHeaders = map[string]string{
		"DD-API-KEY":         "api_key",
		"DD-APPLICATION-KEY": "application_key",
	}
	staticAttributes = map[string]string{
		"source_product": "datadog",
		"source_system":  "datadog",
	}
)

type Source struct {
	inner *jsonapi.Source
}

func New() (*Source, error) {
	spec, err := loadSpec()
	if err != nil {
		return nil, err
	}
	inner, err := jsonapi.New(spec, jsonapi.Options{
		SourceID:        sourceID,
		DefaultBaseURL:  defaultBaseURL,
		DefaultFamily:   defaultFamily,
		RequireTenantID: true,
		AuthModel:       "none",
		ConfigHeaders:   configHeaders,
		Families:        datadogFamilies(),
	})
	if err != nil {
		return nil, err
	}
	return &Source{inner: inner}, nil
}

func (s *Source) Spec() *cerebrov1.SourceSpec { return s.inner.Spec() }

func (s *Source) Check(ctx context.Context, cfg sourcecdk.Config) error {
	if err := validateConfig(cfg); err != nil {
		return err
	}
	healthPath := strings.TrimSpace(sourcecdk.ConfigValue(cfg, "health_path"))
	if healthPath == "" {
		healthPath = defaultHealthPath
	}
	return s.inner.CheckPath(ctx, cfg, healthPath, []int{http.StatusOK})
}

func (s *Source) Discover(ctx context.Context, cfg sourcecdk.Config) ([]sourcecdk.URN, error) {
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}
	return s.inner.Discover(ctx, cfg)
}

func (s *Source) Read(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	if err := validateConfig(cfg); err != nil {
		return sourcecdk.Pull{}, err
	}
	return s.inner.Read(ctx, cfg, cursor)
}

func (s *Source) allowLoopbackForTest() { s.inner.AllowLoopbackBaseURL = true }

func validateConfig(cfg sourcecdk.Config) error {
	for _, key := range []string{"api_key", "application_key"} {
		if strings.TrimSpace(sourcecdk.ConfigValue(cfg, key)) == "" {
			return fmt.Errorf("%w: %s %s is required", sourcecdk.ErrInvalidConfig, sourceID, key)
		}
	}
	return nil
}

func datadogFamilies() []jsonapi.Family {
	return []jsonapi.Family{
		datadogV2Family(familyUsers, "/api/v2/users", "datadog_users", []string{"id"}, []string{"attributes.modified_at", "attributes.created_at"}, map[string]string{
			"user_id":     "id",
			"email":       "attributes.email",
			"name":        "attributes.name|attributes.handle",
			"handle":      "attributes.handle",
			"status":      "attributes.status",
			"disabled":    "attributes.disabled",
			"verified":    "attributes.verified",
			"created_at":  "attributes.created_at",
			"modified_at": "attributes.modified_at",
		}),
		datadogV2Family(familyRoles, "/api/v2/roles", "datadog_roles", []string{"id"}, []string{"attributes.modified_at", "attributes.created_at"}, map[string]string{
			"role_id":     "id",
			"name":        "attributes.name",
			"description": "attributes.description",
			"created_at":  "attributes.created_at",
			"modified_at": "attributes.modified_at",
		}),
		datadogV2Family(familyTeams, "/api/v2/team", "datadog_teams", []string{"id"}, []string{"attributes.modified_at", "attributes.created_at"}, map[string]string{
			"team_id":     "id",
			"name":        "attributes.name",
			"handle":      "attributes.handle",
			"description": "attributes.description",
			"hidden":      "attributes.hidden",
			"avatar":      "attributes.avatar",
			"banner":      "attributes.banner",
			"created_at":  "attributes.created_at",
			"modified_at": "attributes.modified_at",
		}),
		datadogV1PageFamily(familyMonitors, "/api/v1/monitor", "datadog_monitors", []string{"id"}, []string{"modified", "created"}, map[string]string{
			"monitor_id":    "id",
			"name":          "name",
			"type":          "type",
			"query":         "query",
			"state":         "overall_state",
			"overall_state": "overall_state",
			"priority":      "priority",
			"creator_id":    "creator.id|creator.handle|created_by.id",
			"creator_email": "creator.email|creator.handle|created_by.email",
			"tags":          "tags",
			"created_at":    "created",
			"modified_at":   "modified",
		}),
		datadogOffsetFamily(familySLOs, "/api/v1/slo", "datadog_slos", []string{"id"}, []string{"modified_at", "created_at"}, map[string]string{
			"slo_id":       "id",
			"name":         "name",
			"type":         "type",
			"target":       "target_threshold",
			"warning":      "warning_threshold",
			"monitor_ids":  "monitor_ids",
			"creator_id":   "creator.id",
			"creator_name": "creator.name|creator.handle",
			"tags":         "tags",
			"created_at":   "created_at",
			"modified_at":  "modified_at",
		}, []string{"data"}),
		datadogDashboardFamily(familyDashboards, "/api/v1/dashboard", "datadog_dashboards", []string{"id"}, []string{"modified_at", "created_at"}, map[string]string{
			"dashboard_id":  "id",
			"title":         "title",
			"description":   "description",
			"author_handle": "author_handle",
			"author_name":   "author_name",
			"is_read_only":  "is_read_only",
			"layout_type":   "layout_type",
			"tags":          "tags",
			"created_at":    "created_at",
			"modified_at":   "modified_at",
		}, []string{"dashboards"}),
		datadogIncidentFamily(familyIncidents, "/api/v2/incidents", "datadog_incidents", []string{"id"}, []string{"attributes.modified", "attributes.created", "attributes.created_at"}, map[string]string{
			"incident_id":        "id",
			"title":              "attributes.title",
			"state":              "attributes.state",
			"severity":           "attributes.severity",
			"customer_impact":    "attributes.customer_impacted",
			"commander_user_id":  "relationships.commander_user.data.id|attributes.commander_user.id|attributes.commander_user_id",
			"created_by_user_id": "relationships.created_by_user.data.id|attributes.created_by_user.id|attributes.created_by_user_id",
			"created_by_email":   "attributes.created_by_user.email",
			"commander_email":    "attributes.commander_user.email",
			"team_id":            "relationships.teams.data.id|attributes.team_id",
			"service":            "attributes.service|attributes.services",
			"tags":               "attributes.tags",
			"created_at":         "attributes.created|attributes.created_at",
			"modified_at":        "attributes.modified|attributes.modified_at",
			"resolved_at":        "attributes.resolved",
		}),
		datadogAuditFamily(familyAudit, "/api/v2/audit/events", "datadog_audit_events", []string{"id"}, []string{"attributes.timestamp", "attributes.date_happened"}, map[string]string{
			"audit_id":       "id",
			"event_type":     "attributes.evt.name|attributes.event_type|attributes.action",
			"action":         "attributes.evt.name|attributes.action",
			"actor_id":       "attributes.usr.id|attributes.actor.id|attributes.user.id",
			"actor_email":    "attributes.usr.email|attributes.actor.email|attributes.user.email",
			"actor_name":     "attributes.usr.name|attributes.actor.name|attributes.user.name",
			"resource_id":    "attributes.resource.id|attributes.target.id|attributes.resource_id",
			"resource_name":  "attributes.resource.name|attributes.target.name|attributes.resource_name",
			"resource_type":  "attributes.resource.type|attributes.target.type|attributes.resource_type",
			"service":        "attributes.service",
			"tags":           "attributes.tags",
			"timestamp":      "attributes.timestamp|attributes.date_happened",
			"date_happened":  "attributes.date_happened|attributes.timestamp",
			"source_message": "attributes.message",
		}),
	}
}

func datadogV2Family(name string, path string, urnKind string, idKeys []string, timestampKeys []string, attrs map[string]string) jsonapi.Family {
	family := datadogListFamily(name, path, urnKind, idKeys, timestampKeys, attrs, []string{"data"})
	family.CursorParam, family.NextCursorKeys, family.PageSizeParams = "page[cursor]", []string{"meta.page.after", "meta.page.cursor"}, []string{"page[size]"}
	return family
}

func datadogIncidentFamily(name string, path string, urnKind string, idKeys []string, timestampKeys []string, attrs map[string]string) jsonapi.Family {
	family := datadogListFamily(name, path, urnKind, idKeys, timestampKeys, attrs, []string{"data"})
	family.CursorParam, family.NextCursorKeys, family.PageSizeParams = "page[offset]", []string{"meta.pagination.next_offset"}, []string{"page[size]"}
	return family
}

func datadogAuditFamily(name string, path string, urnKind string, idKeys []string, timestampKeys []string, attrs map[string]string) jsonapi.Family {
	family := datadogListFamily(name, path, urnKind, idKeys, timestampKeys, attrs, []string{"data"})
	family.CursorParam, family.NextCursorKeys, family.PageSizeParams = "page[cursor]", []string{"meta.page.after", "meta.page.cursor", "links.next"}, []string{"page[limit]"}
	return family
}

func datadogV1PageFamily(name string, path string, urnKind string, idKeys []string, timestampKeys []string, attrs map[string]string) jsonapi.Family {
	family := datadogListFamily(name, path, urnKind, idKeys, timestampKeys, attrs, nil)
	family.CursorParam, family.PageFirstCursor, family.PageSizeParams = "page", "0", []string{"page_size"}
	return family
}

func datadogOffsetFamily(name string, path string, urnKind string, idKeys []string, timestampKeys []string, attrs map[string]string, listKeys []string) jsonapi.Family {
	family := datadogListFamily(name, path, urnKind, idKeys, timestampKeys, attrs, listKeys)
	family.CursorParam, family.PageSizeParams = "offset", []string{"limit"}
	family.Config.TotalKeys = []string{"metadata.page.total_count"}
	family.Config.OffsetKeys = []string{"metadata.page.offset"}
	family.Config.LimitKeys = []string{"metadata.page.limit"}
	return family
}

func datadogDashboardFamily(name string, path string, urnKind string, idKeys []string, timestampKeys []string, attrs map[string]string, listKeys []string) jsonapi.Family {
	family := datadogListFamily(name, path, urnKind, idKeys, timestampKeys, attrs, listKeys)
	family.CursorParam, family.PageFirstCursor, family.PageSizeParams = "start", "0", []string{"count"}
	return family
}

func datadogListFamily(name string, path string, urnKind string, idKeys []string, timestampKeys []string, attrs map[string]string, listKeys []string) jsonapi.Family {
	return jsonapi.Family{
		Name:             name,
		Path:             path,
		URNKind:          urnKind,
		IDKeys:           idKeys,
		TimestampKeys:    timestampKeys,
		Attributes:       attrs,
		StaticAttributes: staticAttributes,
		ListKeys:         listKeys,
		RequireID:        true,
	}
}

func loadSpec() (*cerebrov1.SourceSpec, error) {
	return sourcecdk.LoadSpecFromFS(catalogFS, "catalog.yaml")
}
