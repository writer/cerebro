package slack

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

const sourceID = "slack"

type Source struct{ inner *jsonapi.Source }

func New() (*Source, error) {
	spec, err := loadSpec()
	if err != nil {
		return nil, err
	}
	inner, err := jsonapi.New(spec, jsonapi.Options{
		SourceID:        sourceID,
		DefaultBaseURL:  "https://slack.com/api",
		DefaultFamily:   "user",
		RequireTenantID: true,
		TokenScheme:     "Bearer",
		Families: []jsonapi.Family{
			{Name: "team", Path: "/auth.teams.list", URNKind: "slack_team", IDKeys: []string{"id", "team_id"}, Attributes: map[string]string{"team_id": "id|team_id", "name": "name", "domain": "domain"}, StaticAttributes: map[string]string{"source_product": "slack"}},
			{Name: "user", Path: "/users.list", URNKind: "slack_user", IDKeys: []string{"id", "user_id"}, TimestampKeys: []string{"updated"}, ListKeys: []string{"members"}, Attributes: map[string]string{"user_id": "id|user_id", "team_id": "team_id", "email": "profile.email|email", "real_name": "real_name|profile.real_name", "name": "name", "deleted": "deleted", "is_admin": "is_admin", "is_owner": "is_owner", "is_primary_owner": "is_primary_owner", "has_2fa": "has_2fa", "has_mfa": "has_2fa"}, StaticAttributes: map[string]string{"source_product": "slack"}},
			{Name: "channel", Path: "/conversations.list", URNKind: "slack_channel", IDKeys: []string{"id", "channel_id"}, TimestampKeys: []string{"updated", "created"}, Attributes: map[string]string{"channel_id": "id|channel_id", "name": "name", "is_private": "is_private", "is_archived": "is_archived", "creator": "creator", "num_members": "num_members"}, StaticAttributes: map[string]string{"source_product": "slack"}},
			{Name: "user_group", Path: "/usergroups.list", URNKind: "slack_user_group", IDKeys: []string{"id", "group_id"}, TimestampKeys: []string{"date_update", "date_create"}, Attributes: map[string]string{"group_id": "id|group_id", "team_id": "team_id", "handle": "handle", "name": "name", "description": "description", "is_disabled": "is_disabled"}, StaticAttributes: map[string]string{"source_product": "slack"}},
		},
	})
	if err != nil {
		return nil, err
	}
	return &Source{inner: inner}, nil
}

func (s *Source) Spec() *cerebrov1.SourceSpec { return s.inner.Spec() }
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
