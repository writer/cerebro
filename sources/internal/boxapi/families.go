package boxapi

import (
	"strings"

	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/sources/internal/jsonapi"
)

const (
	SourceID               = "box"
	DefaultFamily          = FamilyUsers
	DefaultHealthPath      = "/users/me"
	DefaultBaseURLTemplate = "https://api.box.com/2.0"
	TokenScheme            = "Bearer"
	FamilyUsers            = "users"
	FamilyContentAssets    = "content_assets"
	FamilyGroups           = "groups"
	FamilyGroupMemberships = "group_memberships"
	FamilyAuditEvents      = "audit_events"
)

var TemplateKeys = []string{"client_id", "client_secret", "enterprise_id", "box_subject_id"}

func Families() []jsonapi.Family {
	return []jsonapi.Family{
		boxUsersFamily(),
		boxContentAssetsFamily(),
		boxGroupsFamily(),
		boxGroupMembershipsFamily(),
		boxAuditEventsFamily(),
	}
}

func PathParamValues(cfg sourcecdk.Config) (string, []string) {
	if familyName(cfg) != FamilyGroupMemberships {
		return "", nil
	}
	values := configListValues(cfg, "group_ids", "group_id")
	if len(values) == 0 {
		return "", nil
	}
	return "group_id", values
}

func boxUsersFamily() jsonapi.Family {
	return boxMarkerFamily(jsonapi.Family{
		Name:          FamilyUsers,
		Path:          "/users",
		URNKind:       "runtime_users",
		IDKeys:        []string{"id", "user_id", "email", "primary_email", "login"},
		ListKeys:      []string{"entries"},
		TimestampKeys: []string{"modified_at", "created_at", "observed_at", "updated_at", "last_seen_at"},
		Attributes: map[string]string{
			"user_id":                  "user_id|id|uid",
			"source_event_id":          "id|event_id",
			"email":                    "login|email|primary_email|profile.email",
			"primary_email":            "login|primary_email|email|profile.email",
			"login":                    "login|username|email|profile.login",
			"display_name":             "name|display_name|profile.display_name|profile.name",
			"department":               "department|profile.department",
			"job_title":                "job_title|title|profile.title",
			"status":                   "status|state|lifecycle_state",
			"created_at":               "created_at|created|profile.created_at",
			"last_login_at":            "last_login_at|last_login|last_seen_at",
			"resource_id":              "id|resource_id|metadata.resource_id",
			"resource_name":            "name|display_name|metadata.resource_name",
			"resource_type":            "type|resource_type|metadata.resource_type",
			"resource_urn":             "resource_urn|urn|metadata.resource_urn",
			"observed_at":              "modified_at|observed_at|updated_at|last_seen_at",
			"evidence_cas_uri":         "evidence_cas.uri|evidence_cas_uri|uri",
			"evidence_cas_digest":      "evidence_cas.digest|evidence_cas_digest|digest",
			"evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root",
			"evidence_cas_ref_type":    "evidence_cas.ref_type|evidence_cas_ref_type|ref_type",
			"evidence_cas_commit_id":   "evidence_cas.commit_id|evidence_cas_commit_id|commit_id",
		},
		StaticAttributes: boxStaticAttributes("users", "identity_user", "identity_user"),
		Config:           jsonapi.FamilyConfig{ResourceURNKind: "runtime_users"},
	})
}

func boxContentAssetsFamily() jsonapi.Family {
	return boxMarkerFamily(jsonapi.Family{
		Name:          FamilyContentAssets,
		Path:          "/folders/0/items",
		URNKind:       "runtime_content_assets",
		IDKeys:        []string{"id", "urn", "resource_urn", "name"},
		ListKeys:      []string{"entries"},
		TimestampKeys: []string{"modified_at", "created_at", "observed_at", "updated_at", "last_seen_at"},
		Attributes: map[string]string{
			"source_event_id":          "id|event_id",
			"resource_id":              "id|resource_id|metadata.resource_id",
			"resource_name":            "name|display_name|metadata.resource_name",
			"resource_type":            "type|resource_type|metadata.resource_type",
			"resource_urn":             "resource_urn|urn|metadata.resource_urn",
			"observed_at":              "modified_at|observed_at|updated_at|last_seen_at",
			"owner_id":                 "owned_by.id|owner.id",
			"owner_email":              "owned_by.login|owned_by.email|owner.email",
			"owner_name":               "owned_by.name|owner.name",
			"evidence_cas_uri":         "evidence_cas.uri|evidence_cas_uri|uri",
			"evidence_cas_digest":      "evidence_cas.digest|evidence_cas_digest|digest",
			"evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root",
			"evidence_cas_ref_type":    "evidence_cas.ref_type|evidence_cas_ref_type|ref_type",
			"evidence_cas_commit_id":   "evidence_cas.commit_id|evidence_cas_commit_id|commit_id",
		},
		StaticAttributes: boxStaticAttributes("content_assets", "asset", "box_content"),
		Config:           jsonapi.FamilyConfig{ResourceURNKind: "runtime_content_assets"},
	})
}

func boxGroupsFamily() jsonapi.Family {
	return boxOffsetFamily(jsonapi.Family{
		Name:          FamilyGroups,
		Path:          "/groups",
		URNKind:       "box_groups",
		IDKeys:        []string{"id", "name"},
		ListKeys:      []string{"entries"},
		TimestampKeys: []string{"modified_at", "created_at"},
		Attributes: map[string]string{
			"group_id":        "id",
			"source_event_id": "id",
			"group_name":      "name",
			"group_type":      "type",
			"description":     "description",
			"resource_id":     "id",
			"resource_name":   "name",
			"resource_type":   "type",
			"observed_at":     "modified_at|created_at",
		},
		StaticAttributes: boxStaticAttributes("groups", "identity_group", "group"),
		Config: jsonapi.FamilyConfig{
			ResourceURNKind: "box_groups",
			TotalKeys:       []string{"total_count"},
			OffsetKeys:      []string{"offset"},
			LimitKeys:       []string{"limit"},
		},
	})
}

func boxGroupMembershipsFamily() jsonapi.Family {
	return boxOffsetFamily(jsonapi.Family{
		Name:       FamilyGroupMemberships,
		Path:       "/groups/{group_id}/memberships",
		PathParams: []string{"group_id"},
		URNKind:    "box_group_memberships",
		IDKeys:     []string{"id", "user.id", "user.login"},
		ListKeys:   []string{"entries"},
		Attributes: map[string]string{
			"membership_id":   "id",
			"source_event_id": "id|user.id",
			"group_id":        "group_id",
			"group_name":      "group.name",
			"member_id":       "user.id",
			"member_user_id":  "user.id",
			"member_email":    "user.login|user.email",
			"member_name":     "user.name",
			"member_type":     "user.type",
			"role":            "role",
			"resource_id":     "user.id",
			"resource_name":   "user.name|user.login",
			"resource_type":   "user.type",
			"observed_at":     "modified_at|created_at",
		},
		StaticAttributes: boxStaticAttributes("group_memberships", "identity_group_membership", "user"),
		Config: jsonapi.FamilyConfig{
			IdentityKeys:     []string{"group_id"},
			ResourceURNKind:  "runtime_users",
			ConfigAttributes: map[string]string{"group_id": "group_id"},
			TotalKeys:        []string{"total_count"},
			OffsetKeys:       []string{"offset"},
			LimitKeys:        []string{"limit"},
		},
	})
}

func boxAuditEventsFamily() jsonapi.Family {
	return jsonapi.Family{
		Name:           FamilyAuditEvents,
		Path:           "/events",
		URNKind:        "runtime_audit_events",
		IDKeys:         []string{"event_id", "id", "uuid", "request_id"},
		CursorParam:    "stream_position",
		NextCursorKeys: []string{"next_stream_position"},
		PageSizeParams: []string{"limit"},
		ListKeys:       []string{"entries"},
		TimestampKeys:  []string{"created_at", "observed_at", "updated_at", "last_seen_at"},
		Attributes: map[string]string{
			"source_event_id":          "event_id|id|metadata.event_id",
			"event_type":               "event_type|event_name|action|type",
			"actor_id":                 "created_by.id|actor_id|actor.id|actorId|user_id|user.id",
			"actor_email":              "created_by.login|created_by.email|actor_email|actor.email|email|user.email",
			"actor_name":               "created_by.name|actor_name|actor.name|user.name",
			"resource_id":              "source.id|resource_id|target_id|target.id|resource.id|object_id",
			"resource_name":            "source.name|resource_name|target_name|target.name|resource.name|object_name",
			"resource_type":            "source.type|resource_type|target_type|target.type|object_type",
			"resource_email":           "source.login|resource_email|target_email|target.email",
			"resource_urn":             "resource_urn|urn|metadata.resource_urn",
			"observed_at":              "created_at|observed_at|updated_at|last_seen_at",
			"evidence_cas_uri":         "evidence_cas.uri|evidence_cas_uri|uri",
			"evidence_cas_digest":      "evidence_cas.digest|evidence_cas_digest|digest",
			"evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root",
			"evidence_cas_ref_type":    "evidence_cas.ref_type|evidence_cas_ref_type|ref_type",
			"evidence_cas_commit_id":   "evidence_cas.commit_id|evidence_cas_commit_id|commit_id",
		},
		StaticAttributes: boxStaticAttributes("audit_events", "audit_event", "box_event"),
		Config:           jsonapi.FamilyConfig{StaticQuery: map[string]string{"stream_type": "admin_logs_streaming"}},
	}
}

func boxMarkerFamily(family jsonapi.Family) jsonapi.Family {
	family.CursorParam = "marker"
	family.NextCursorKeys = []string{"next_marker"}
	family.PageSizeParams = []string{"limit"}
	if family.Config.StaticQuery == nil {
		family.Config.StaticQuery = map[string]string{}
	}
	family.Config.StaticQuery["usemarker"] = "true"
	return family
}

func boxOffsetFamily(family jsonapi.Family) jsonapi.Family {
	family.CursorParam = "offset"
	family.PageFirstCursor = "0"
	family.PageSizeParams = []string{"limit"}
	return family
}

func boxStaticAttributes(schema string, recordClass string, resourceType string) map[string]string {
	return map[string]string{
		"record_class":  recordClass,
		"resource_type": resourceType,
		"schema":        schema,
		"source_system": "box",
	}
}

func configListValues(cfg sourcecdk.Config, keys ...string) []string {
	values := []string{}
	for _, key := range keys {
		for _, value := range strings.Split(sourcecdk.ConfigValue(cfg, key), ",") {
			if value = strings.TrimSpace(value); value != "" {
				values = append(values, value)
			}
		}
	}
	return values
}

func familyName(cfg sourcecdk.Config) string {
	if family := strings.TrimSpace(sourcecdk.ConfigValue(cfg, "family")); family != "" {
		return family
	}
	return DefaultFamily
}
