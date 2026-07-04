package addigy

import (
	"context"
	"embed"
	"net/http"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/sources/internal/jsonapi"
)

//go:embed catalog.yaml
var catalogFS embed.FS

const (
	sourceID               = "addigy"
	defaultFamily          = familyDevices
	defaultBaseURLTemplate = "https://api.addigy.com/api/v2"

	familyDevices     = "devices"
	familyUsers       = "users"
	familyGroups      = "groups"
	familyPolicies    = "policies"
	familyAuditEvents = "audit_events"
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
		DefaultBaseURL:  defaultBaseURLTemplate,
		DefaultFamily:   defaultFamily,
		RequireTenantID: true,
		AuthModel:       "api_key",
		TokenHeader:     "x-api-key",
		Families: []jsonapi.Family{
			deviceFamily(),
			organizationUsersFamily(),
			endUserGroupsFamily(),
			policiesFamily(),
			auditEventsFamily(),
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
	return s.inner.Check(ctx, cfg)
}

func (s *Source) Discover(ctx context.Context, cfg sourcecdk.Config) ([]sourcecdk.URN, error) {
	return s.inner.Discover(ctx, cfg)
}

func (s *Source) Read(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	return s.inner.Read(ctx, cfg, cursor)
}

func loadSpec() (*cerebrov1.SourceSpec, error) {
	return sourcecdk.LoadSpecFromFS(catalogFS, "catalog.yaml")
}

func deviceFamily() jsonapi.Family {
	return pagedFamily(jsonapi.Family{
		Name:           familyDevices,
		Path:           "/devices",
		URNKind:        "addigy_devices",
		IDKeys:         []string{"agentid", "device_uuid", "facts.serial_number.value"},
		TimestampKeys:  []string{"audit_date", "agent_audit_date", "updated_at", "created_at"},
		ListKeys:       []string{"items"},
		PageSizeParams: []string{"per_page"},
		Attributes: map[string]string{
			"id":            "agentid|device_uuid|facts.serial_number.value",
			"resource_id":   "agentid|device_uuid|facts.serial_number.value|_record_id",
			"resource_name": "facts.device_name.value|facts.host_name.value|facts.serial_number.value|agentid",
			"serial_number": "facts.serial_number.value",
		},
		StaticAttributes: staticAttributes(familyDevices, "asset", "device"),
		Config: jsonapi.FamilyConfig{
			JSONBody: jsonapi.JSONBodyConfig{
				Static: map[string]string{"sort_direction": "asc", "sort_field": "serial_number"},
				Config: map[string]string{"desired_fact_identifiers[]": "desired_fact_identifiers"},
			},
		},
	})
}

func organizationUsersFamily() jsonapi.Family {
	return pagedFamily(jsonapi.Family{
		Name:       familyUsers,
		Path:       "/o/${config.organization_id}/users/query",
		PathParams: []string{"organization_id"},
		URNKind:    "addigy_users",
		IDKeys:     []string{"email", "name"},
		ListKeys:   []string{"items"},
		Attributes: map[string]string{
			"addigy_role":   "addigy_role",
			"display_name":  "name",
			"email":         "email",
			"primary_email": "email",
			"resource_id":   "email|name|_record_id",
			"resource_name": "name|email",
			"user_id":       "email|name|_record_id",
		},
		StaticAttributes: staticAttributes(familyUsers, "identity_user", "user"),
		Config: jsonapi.FamilyConfig{JSONBody: jsonapi.JSONBodyConfig{
			Static: map[string]string{"sort_direction": "asc", "sort_field": "email"},
		}},
	})
}

func endUserGroupsFamily() jsonapi.Family {
	return pagedFamily(jsonapi.Family{
		Name:       familyGroups,
		Path:       "/o/${config.organization_id}/end-users/groups/query",
		PathParams: []string{"organization_id"},
		URNKind:    "addigy_groups",
		IDKeys:     []string{"id", "external_id", "display_name", "displayName"},
		ListKeys:   []string{"items"},
		Attributes: map[string]string{
			"external_id":   "external_id|id",
			"group_id":      "id|external_id|display_name|displayName|_record_id",
			"group_name":    "display_name|displayName|name|id",
			"resource_id":   "id|external_id|display_name|displayName|_record_id",
			"resource_name": "display_name|displayName|name|id",
		},
		StaticAttributes: staticAttributes(familyGroups, "identity_group", "group"),
		Config: jsonapi.FamilyConfig{JSONBody: jsonapi.JSONBodyConfig{
			Static: map[string]string{"sort_direction": "asc", "sort_field": "displayName"},
		}},
	})
}

func policiesFamily() jsonapi.Family {
	return jsonapi.Family{
		Name:             familyPolicies,
		Path:             "/oa/policies/query",
		URNKind:          "addigy_policies",
		IDKeys:           []string{"policyId", "id", "name"},
		TimestampKeys:    []string{"created_at", "updated_at", "meta.created", "meta.last_modified"},
		StaticAttributes: policyStaticAttributes(),
		Attributes: map[string]string{
			"policy_id":     "policyId|id|name|_record_id",
			"policy_name":   "name|policyId|id",
			"resource_id":   "policyId|id|name|_record_id",
			"resource_name": "name|policyId|id",
		},
		Config: jsonapi.FamilyConfig{
			Method: http.MethodPost,
			JSONBody: jsonapi.JSONBodyConfig{
				SendEmpty: true,
			},
			DefaultPageSize: 100,
		},
		DisablePageSize: true,
	}
}

func auditEventsFamily() jsonapi.Family {
	return pagedFamily(jsonapi.Family{
		Name:          familyAuditEvents,
		Path:          "/system-events/search",
		URNKind:       "addigy_audit_events",
		IDKeys:        []string{"event_id", "id", "uuid"},
		TimestampKeys: []string{"date", "audit_date", "agent_audit_date", "created_at", "updated_at"},
		ListKeys:      []string{"items"},
		Attributes: map[string]string{
			"actor_id":        "action_sender.identifier|action_sender.name",
			"actor_name":      "action_sender.name",
			"event_type":      "action.name|source|level",
			"id":              "event_id|id|uuid|_record_id",
			"observed_at":     "date|audit_date|created_at|updated_at",
			"resource_id":     "action.entity.identifier|action_receiver.identifier|_record_id",
			"resource_name":   "action.entity.name|action_receiver.name|action.entity.identifier",
			"resource_type":   "action.entity.type|action_receiver.type",
			"result":          "result.status",
			"source_event_id": "event_id|id|uuid|_record_id",
		},
		StaticAttributes: staticAttributes(familyAuditEvents, "audit_event", "addigy_resource"),
		Config: jsonapi.FamilyConfig{
			JSONBody: jsonapi.JSONBodyConfig{
				Static: map[string]string{"sort_direction": "asc"},
				Config: map[string]string{
					"from_date_time": "audit_start_time",
					"to_date_time":   "audit_end_time",
				},
			},
		},
	})
}

func pagedFamily(family jsonapi.Family) jsonapi.Family {
	family.CursorParam = "page"
	family.PageFirstCursor = "1"
	family.Config.Method = http.MethodPost
	family.Config.CursorContainers = append(family.Config.CursorContainers, "metadata")
	family.Config.JSONBody.CursorParam = "page"
	family.Config.JSONBody.SizeParam = "per_page"
	if family.Config.DefaultPageSize == 0 {
		family.Config.DefaultPageSize = 100
	}
	return family
}

func staticAttributes(schema string, recordClass string, resourceType string) map[string]string {
	return map[string]string{
		"record_class":  recordClass,
		"resource_type": resourceType,
		"schema":        schema,
		"source_system": sourceID,
	}
}

func policyStaticAttributes() map[string]string {
	attrs := staticAttributes(familyPolicies, "policy", "policy")
	attrs["policy_status"] = "configured"
	attrs["policy_type"] = "device_policy"
	return attrs
}

func (s *Source) allowLoopbackForTest() {
	if s != nil && s.inner != nil {
		s.inner.AllowLoopbackBaseURL = true
	}
}
