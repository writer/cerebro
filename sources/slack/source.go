package slack

import (
	"context"
	"embed"
	"net/http"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/sources/internal/jsonapi"
	"github.com/writer/cerebro/sources/internal/slackapi"
)

//go:embed catalog.yaml
var catalogFS embed.FS

const (
	sourceID              = slackapi.SourceID
	defaultFamily         = familyUser
	familyTeam            = "team"
	familyUser            = "user"
	familyChannel         = "channel"
	familyUserGroup       = "user_group"
	familyChannelMember   = slackapi.FamilyChannelMember
	familyUserGroupMember = slackapi.FamilyUserGroupMember
	familyAccessLog       = "access_log"
	familyAuditLog        = slackapi.FamilyAuditLog

	slackNextCursor      = "response_metadata.next_cursor"
	defaultWebAPIBaseURL = slackapi.DefaultWebAPIBaseURL
)

type Source struct{ inner *jsonapi.Source }

func New() (*Source, error) {
	spec, err := loadSpec()
	if err != nil {
		return nil, err
	}
	inner, err := jsonapi.New(spec, jsonapi.Options{
		SourceID:        sourceID,
		DefaultBaseURL:  defaultWebAPIBaseURL,
		DefaultFamily:   defaultFamily,
		RequireTenantID: true,
		TokenScheme:     "Bearer",
		ResponseError:   slackapi.ResponseError,
		Families:        slackFamilies(),
	})
	if err != nil {
		return nil, err
	}
	return &Source{inner: inner}, nil
}

func (s *Source) Spec() *cerebrov1.SourceSpec { return s.inner.Spec() }
func (s *Source) Check(ctx context.Context, cfg sourcecdk.Config) error {
	if slackapi.CustomFamily(sourcecdk.ConfigValue(cfg, "family")) {
		_, err := slackapi.Read(ctx, cfg, nil, s.slackOptions(1))
		return err
	}
	return s.inner.Check(ctx, cfg)
}
func (s *Source) Discover(ctx context.Context, cfg sourcecdk.Config) ([]sourcecdk.URN, error) {
	if slackapi.CustomFamily(sourcecdk.ConfigValue(cfg, "family")) {
		return slackapi.Discover(ctx, cfg, s.slackOptions(slackapi.PageSize(cfg, 100)))
	}
	return s.inner.Discover(ctx, cfg)
}
func (s *Source) Read(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	if slackapi.CustomFamily(sourcecdk.ConfigValue(cfg, "family")) {
		return slackapi.Read(ctx, cfg, cursor, s.slackOptions(slackapi.PageSize(cfg, 100)))
	}
	return s.inner.Read(ctx, cfg, cursor)
}
func loadSpec() (*cerebrov1.SourceSpec, error) {
	return sourcecdk.LoadSpecFromFS(catalogFS, "catalog.yaml")
}

func (s *Source) slackOptions(pageSize int) slackapi.Options {
	return slackapi.Options{
		AllowLoopback: s != nil && s.inner != nil && s.inner.AllowLoopbackBaseURL,
		PageSize:      pageSize,
	}
}

func slackFamilies() []jsonapi.Family {
	return []jsonapi.Family{
		slackTeamFamily(),
		slackUserFamily(),
		slackChannelFamily(),
		slackUserGroupFamily(),
		slackAccessLogFamily(),
	}
}

func slackTeamFamily() jsonapi.Family {
	return slackPagedFamily(jsonapi.Family{
		Name:     familyTeam,
		Method:   http.MethodPost,
		Path:     "/auth.teams.list",
		URNKind:  "slack_team",
		IDKeys:   []string{"id", "team_id"},
		ListKeys: []string{"teams"},
		Attributes: map[string]string{
			"team_id": "id|team_id",
			"name":    "name",
			"domain":  "domain",
		},
		StaticAttributes: slackStaticAttributes(),
	})
}

func slackUserFamily() jsonapi.Family {
	return slackPagedFamily(jsonapi.Family{
		Name:          familyUser,
		Path:          "/users.list",
		URNKind:       "slack_user",
		IDKeys:        []string{"id", "user_id"},
		TimestampKeys: []string{"updated"},
		ListKeys:      []string{"members"},
		Attributes: map[string]string{
			"user_id":             "id|user_id",
			"team_id":             "team_id",
			"email":               "profile.email|email",
			"real_name":           "real_name|profile.real_name",
			"name":                "name",
			"deleted":             "deleted",
			"is_admin":            "is_admin",
			"is_owner":            "is_owner",
			"is_primary_owner":    "is_primary_owner",
			"is_bot":              "is_bot",
			"is_restricted":       "is_restricted",
			"is_ultra_restricted": "is_ultra_restricted",
			"has_2fa":             "has_2fa",
			"has_mfa":             "has_2fa",
			"two_factor_type":     "two_factor_type",
		},
		StaticAttributes: slackStaticAttributes(),
	})
}

func slackChannelFamily() jsonapi.Family {
	return slackPagedFamily(jsonapi.Family{
		Name:          familyChannel,
		Path:          "/conversations.list",
		URNKind:       "slack_channel",
		IDKeys:        []string{"id", "channel_id"},
		TimestampKeys: []string{"updated", "created"},
		Attributes: map[string]string{
			"channel_id":      "id|channel_id",
			"team_id":         "context_team_id",
			"shared_team_ids": "shared_team_ids|internal_team_ids",
			"name":            "name",
			"is_private":      "is_private",
			"is_archived":     "is_archived",
			"creator":         "creator",
			"num_members":     "num_members",
		},
		StaticAttributes: slackStaticAttributes(),
		Config: jsonapi.FamilyConfig{StaticQuery: map[string]string{
			"exclude_archived": "false",
			"types":            "public_channel,private_channel",
		}},
	})
}

func slackUserGroupFamily() jsonapi.Family {
	return jsonapi.Family{
		Name:            familyUserGroup,
		Path:            "/usergroups.list",
		URNKind:         "slack_user_group",
		IDKeys:          []string{"id", "group_id"},
		ListKeys:        []string{"usergroups"},
		TimestampKeys:   []string{"date_update", "date_create"},
		DisablePageSize: true,
		Attributes: map[string]string{
			"group_id":    "id|group_id",
			"team_id":     "team_id",
			"handle":      "handle",
			"name":        "name",
			"description": "description",
			"is_disabled": "is_disabled",
		},
		StaticAttributes: slackStaticAttributes(),
	}
}

func slackAccessLogFamily() jsonapi.Family {
	return jsonapi.Family{
		Name:            familyAccessLog,
		Path:            "/team.accessLogs",
		URNKind:         "slack_access_log",
		ListKeys:        []string{"logins"},
		CursorParam:     "page",
		PageFirstCursor: "1",
		PageSizeParams:  []string{"count"},
		TimestampKeys:   []string{"date_last", "date_first"},
		Attributes: map[string]string{
			"actor_id":      "user_id",
			"actor_name":    "username",
			"user_id":       "user_id",
			"username":      "username",
			"ip_address":    "ip",
			"user_agent":    "user_agent",
			"isp":           "isp",
			"country":       "country",
			"region":        "region",
			"login_count":   "count",
			"first_seen_at": "date_first",
			"last_seen_at":  "date_last",
		},
		StaticAttributes: map[string]string{
			"event_type":     "team_access",
			"source_product": "slack",
		},
		Config: jsonapi.FamilyConfig{ConfigQuery: map[string]string{"before": "before"}},
	}
}

func slackPagedFamily(family jsonapi.Family) jsonapi.Family {
	family.NextCursorKeys = []string{slackNextCursor}
	family.PageSizeParams = []string{"limit"}
	return family
}

func slackStaticAttributes() map[string]string {
	return map[string]string{"source_product": "slack"}
}
