package jumpcloud

import (
	"context"
	"embed"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/sources/internal/jsonapi"
)

//go:embed catalog.yaml
var catalogFS embed.FS

const (
	sourceID                       = "jumpcloud"
	defaultFamily                  = familyUsers
	defaultHealthPath              = "/systemusers?limit=1&skip=0"
	defaultBaseURLTemplate         = "https://console.jumpcloud.com/api"
	defaultInsightsBaseURLTemplate = "https://api.jumpcloud.com/insights/directory/v1"
	tokenHeader                    = "x-api-key"
	tokenScheme                    = ""
	familyUsers                    = "users"
	familyGroups                   = "groups"
	familySystems                  = "systems"
	familyApplications             = "applications"
	familySystemGroups             = "system_groups"
	familyGroupMembers             = "group_members"
	familyAuditEvents              = "audit_events"
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
		ConfigHeaders:   map[string]string{"x-org-id": "org_id"},
		Families:        jumpCloudFamilies(),
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
	if familyName(runtimeCfg) == familyAuditEvents {
		return s.checkAuditEvents(ctx, runtimeCfg)
	}
	if param, values := jumpCloudPathParamValues(runtimeCfg); param != "" {
		return s.inner.CheckPathParamValues(ctx, runtimeCfg, param, values)
	}
	path := firstNonEmpty(sourcecdk.ConfigValue(runtimeCfg, "health_path"), defaultHealthPath)
	if err := s.inner.CheckPath(ctx, runtimeCfg, path, nil); err != nil {
		return err
	}
	return s.inner.Check(ctx, runtimeCfg)
}

func (s *Source) Discover(ctx context.Context, cfg sourcecdk.Config) ([]sourcecdk.URN, error) {
	runtimeCfg, err := s.runtimeConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if familyName(runtimeCfg) == familyAuditEvents {
		return s.discoverAuditEvents(ctx, runtimeCfg)
	}
	if param, values := jumpCloudPathParamValues(runtimeCfg); param != "" {
		return s.discoverGroupMembers(ctx, runtimeCfg, param, values)
	}
	return s.inner.Discover(ctx, runtimeCfg)
}

func (s *Source) Read(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	return s.ReadWithCheckpoint(ctx, cfg, cursor, nil)
}

func (s *Source) ReadWithCheckpoint(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor, checkpoint *cerebrov1.SourceCheckpoint) (sourcecdk.Pull, error) {
	runtimeCfg, err := s.runtimeConfig(ctx, cfg)
	if err != nil {
		return sourcecdk.Pull{}, err
	}
	if familyName(runtimeCfg) == familyAuditEvents {
		return s.readAuditEvents(ctx, runtimeCfg, cursor, checkpoint)
	}
	if param, values := jumpCloudPathParamValues(runtimeCfg); param != "" {
		return s.inner.ReadPathParamValuesWithCheckpoint(ctx, runtimeCfg, cursor, checkpoint, param, values)
	}
	return s.inner.ReadWithCheckpoint(ctx, runtimeCfg, cursor, checkpoint)
}

func (s *Source) runtimeConfig(_ context.Context, cfg sourcecdk.Config) (sourcecdk.Config, error) {
	return sourcecdk.ResolveBaseURLConfig(sourceID, defaultBaseURLTemplate, cfg, templateKeys)
}

func loadSpec() (*cerebrov1.SourceSpec, error) {
	return sourcecdk.LoadSpecFromFS(catalogFS, "catalog.yaml")
}

func jumpCloudPathParamValues(cfg sourcecdk.Config) (string, []string) {
	if familyName(cfg) != familyGroupMembers {
		return "", nil
	}
	return "group_id", configListValues(cfg, "group_ids", "user_group_ids", "group_id", "user_group_id")
}

func (s *Source) discoverGroupMembers(ctx context.Context, cfg sourcecdk.Config, param string, values []string) ([]sourcecdk.URN, error) {
	pull, err := s.inner.ReadPathParamValuesWithCheckpoint(ctx, cfg, nil, nil, param, values)
	if err != nil {
		return nil, err
	}
	seen := map[sourcecdk.URN]struct{}{}
	urns := []sourcecdk.URN{}
	for _, event := range pull.Events {
		attrs := event.GetAttributes()
		groupID := firstNonEmpty(attrs["group_id"], sourcecdk.ConfigValue(cfg, "group_id"))
		memberID := firstNonEmpty(attrs["member_user_id"], attrs["member_id"], attrs["resource_id"], attrs["source_event_id"])
		if groupID == "" && memberID == "" {
			memberID = event.GetId()
		}
		urn, err := sourcecdk.URNForEscaped(event.GetTenantId(), "jumpcloud_group_members", groupID, memberID)
		if err != nil {
			return nil, err
		}
		if _, ok := seen[urn]; ok {
			continue
		}
		seen[urn] = struct{}{}
		urns = append(urns, urn)
	}
	return urns, nil
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
	return defaultFamily
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
