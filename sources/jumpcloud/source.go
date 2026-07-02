package jumpcloud

import (
	"context"
	"embed"
	"fmt"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/sources/internal/jsonapi"
	"github.com/writer/cerebro/sources/internal/jumpcloudapi"
)

const groupMemberDiscoveryPageLimit = 1000

//go:embed catalog.yaml
var catalogFS embed.FS

const (
	sourceID               = jumpcloudapi.SourceID
	defaultFamily          = jumpcloudapi.DefaultFamily
	defaultHealthPath      = "/systemusers?limit=1&skip=0"
	defaultBaseURLTemplate = jumpcloudapi.DefaultBaseURLTemplate
	tokenScheme            = ""
	familyUsers            = jumpcloudapi.FamilyUsers
	familyGroups           = jumpcloudapi.FamilyGroups
	familySystems          = jumpcloudapi.FamilySystems
	familyApplications     = jumpcloudapi.FamilyApplications
	familySystemGroups     = jumpcloudapi.FamilySystemGroups
	familyGroupMembers     = jumpcloudapi.FamilyGroupMembers
	familyAuditEvents      = jumpcloudapi.FamilyAuditEvents
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
		TokenHeader:     jumpcloudapi.TokenHeader,
		TokenScheme:     tokenScheme,
		ConfigHeaders:   map[string]string{"x-org-id": "org_id"},
		Families:        jumpcloudapi.Families(),
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
	if jumpcloudapi.FamilyName(runtimeCfg) == familyAuditEvents {
		return jumpcloudapi.CheckAuditEvents(ctx, runtimeCfg, s != nil && s.allowLoopback)
	}
	if param, values := jumpCloudPathParamValues(runtimeCfg); param != "" {
		return s.inner.CheckPathParamValues(ctx, runtimeCfg, param, values)
	}
	path := jumpcloudapi.FirstNonEmpty(sourcecdk.ConfigValue(runtimeCfg, "health_path"), defaultHealthPath)
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
	if jumpcloudapi.FamilyName(runtimeCfg) == familyAuditEvents {
		return jumpcloudapi.DiscoverAuditEvents(ctx, runtimeCfg, s != nil && s.allowLoopback)
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
	if jumpcloudapi.FamilyName(runtimeCfg) == familyAuditEvents {
		return jumpcloudapi.ReadAuditEvents(ctx, runtimeCfg, cursor, checkpoint, s != nil && s.allowLoopback)
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
	if jumpcloudapi.FamilyName(cfg) != familyGroupMembers {
		return "", nil
	}
	return "group_id", jumpcloudapi.ConfigListValues(cfg, "group_ids", "user_group_ids", "group_id", "user_group_id")
}

func (s *Source) discoverGroupMembers(ctx context.Context, cfg sourcecdk.Config, param string, values []string) ([]sourcecdk.URN, error) {
	seen := map[sourcecdk.URN]struct{}{}
	urns := []sourcecdk.URN{}
	var cursor *cerebrov1.SourceCursor
	for pages := 0; pages < groupMemberDiscoveryPageLimit; pages++ {
		pull, err := s.inner.ReadPathParamValuesWithCheckpoint(ctx, cfg, cursor, nil, param, values)
		if err != nil {
			return nil, err
		}
		for _, event := range pull.Events {
			attrs := event.GetAttributes()
			groupID := jumpcloudapi.FirstNonEmpty(attrs["group_id"], sourcecdk.ConfigValue(cfg, "group_id"))
			memberID := jumpcloudapi.FirstNonEmpty(attrs["member_user_id"], attrs["member_id"], attrs["resource_id"], attrs["source_event_id"])
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
		cursor = pull.NextCursor
		if cursor == nil {
			return urns, nil
		}
	}
	return nil, fmt.Errorf("jumpcloud group member discovery exceeded %d pages", groupMemberDiscoveryPageLimit)
}

func (s *Source) allowLoopbackForTest() {
	if s != nil && s.inner != nil {
		s.inner.AllowLoopbackBaseURL = true
		s.allowLoopback = true
	}
}
