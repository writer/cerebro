package fivetran

import (
	"context"
	"embed"
	"fmt"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/sources/internal/fivetranapi"
	"github.com/writer/cerebro/sources/internal/jsonapi"
)

//go:embed catalog.yaml
var catalogFS embed.FS

const (
	sourceID               = fivetranapi.SourceID
	defaultFamily          = fivetranapi.DefaultFamily
	defaultHealthPath      = fivetranapi.DefaultHealthPath
	defaultBaseURLTemplate = fivetranapi.DefaultBaseURLTemplate
)

type Source struct{ inner *jsonapi.Source }

func New() (*Source, error) {
	spec, err := loadSpec()
	if err != nil {
		return nil, err
	}
	inner, err := jsonapi.New(spec, jsonapi.Options{
		SourceID:        sourceID,
		DefaultFamily:   defaultFamily,
		RequireTenantID: true,
		AuthModel:       "basic",
		Families:        fivetranapi.Families(),
	})
	if err != nil {
		return nil, err
	}
	return &Source{inner: inner}, nil
}

func (s *Source) Spec() *cerebrov1.SourceSpec { return s.inner.Spec() }

func (s *Source) Check(ctx context.Context, cfg sourcecdk.Config) error {
	runtimeCfg, err := s.runtimeConfig(ctx, cfg)
	if err != nil {
		return err
	}
	if param, values := fivetranapi.PathParamValues(runtimeCfg); param != "" {
		values, err = s.resolvePathParamValues(ctx, runtimeCfg, param, values)
		if err != nil {
			return err
		}
		if len(values) == 0 {
			return nil
		}
		return s.inner.CheckPathParamValues(ctx, runtimeCfg, param, values)
	}
	path := fivetranapi.FirstNonEmpty(sourcecdk.ConfigValue(runtimeCfg, "health_path"), defaultHealthPath)
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
	if param, values := fivetranapi.PathParamValues(runtimeCfg); param != "" {
		values, err = s.resolvePathParamValues(ctx, runtimeCfg, param, values)
		if err != nil {
			return nil, err
		}
		if len(values) == 0 {
			return nil, nil
		}
		return s.discoverScoped(ctx, runtimeCfg, param, values)
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
	if param, values := fivetranapi.PathParamValues(runtimeCfg); param != "" {
		values, innerCursor, err := s.readPathParamState(ctx, runtimeCfg, cursor, param, values)
		if err != nil {
			return sourcecdk.Pull{}, err
		}
		if len(values) == 0 {
			return sourcecdk.Pull{}, nil
		}
		pull, err := s.inner.ReadPathParamValuesWithCheckpoint(ctx, runtimeCfg, innerCursor, checkpoint, param, values)
		if err != nil {
			return sourcecdk.Pull{}, err
		}
		if len(fivetranapi.CompactStrings(values)) > 0 && len(fivetranapi.CompactStrings(fivetranapi.ConfiguredPathParamValues(runtimeCfg, param))) == 0 {
			pull.NextCursor = fivetranapi.EncodePathParamCursor(param, values, pull.NextCursor)
		}
		return pull, nil
	}
	return s.inner.ReadWithCheckpoint(ctx, runtimeCfg, cursor, checkpoint)
}

func (s *Source) runtimeConfig(_ context.Context, cfg sourcecdk.Config) (sourcecdk.Config, error) {
	return sourcecdk.ResolveBaseURLConfig(sourceID, defaultBaseURLTemplate, cfg, []string{"base_url"})
}

func loadSpec() (*cerebrov1.SourceSpec, error) {
	return sourcecdk.LoadSpecFromFS(catalogFS, "catalog.yaml")
}

func (s *Source) discoverScoped(ctx context.Context, cfg sourcecdk.Config, param string, values []string) ([]sourcecdk.URN, error) {
	if len(values) == 0 {
		return nil, fmt.Errorf("%w: fivetran %s requires at least one %s", sourcecdk.ErrInvalidConfig, fivetranapi.FamilyName(cfg), param)
	}
	return s.inner.DiscoverPathParamValues(ctx, cfg, param, values)
}

func (s *Source) resolvePathParamValues(ctx context.Context, cfg sourcecdk.Config, param string, values []string) ([]string, error) {
	values = fivetranapi.CompactStrings(values)
	if len(values) > 0 {
		return values, nil
	}
	parentFamily, parentAttribute := fivetranapi.ParentFamilyForParam(param)
	if parentFamily == "" || parentAttribute == "" {
		return nil, nil
	}
	parentCfg := fivetranapi.ConfigWithValue(cfg, "family", parentFamily)
	ids := []string{}
	var cursor *cerebrov1.SourceCursor
	for page := 0; page < 1000; page++ {
		pull, err := s.inner.Read(ctx, parentCfg, cursor)
		if err != nil {
			return nil, fmt.Errorf("discover fivetran %s values from %s: %w", param, parentFamily, err)
		}
		for _, event := range pull.Events {
			if event == nil {
				continue
			}
			if value := fivetranapi.FirstNonEmpty(event.Attributes[parentAttribute]); value != "" {
				ids = append(ids, value)
			}
		}
		if sourcecdk.CursorToken(pull.NextCursor) == "" {
			return fivetranapi.CompactStrings(ids), nil
		}
		cursor = pull.NextCursor
	}
	return nil, fmt.Errorf("fivetran %s parent fanout exceeded page limit", param)
}

func (s *Source) readPathParamState(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor, param string, values []string) ([]string, *cerebrov1.SourceCursor, error) {
	values = fivetranapi.CompactStrings(values)
	if len(values) > 0 {
		return values, cursor, nil
	}
	if values, innerCursor, ok := fivetranapi.DecodePathParamCursor(cursor, param); ok {
		return values, innerCursor, nil
	}
	values, err := s.resolvePathParamValues(ctx, cfg, param, nil)
	if err != nil {
		return nil, nil, err
	}
	return values, cursor, nil
}

func (s *Source) allowLoopbackForTest() {
	if s != nil && s.inner != nil {
		s.inner.AllowLoopbackBaseURL = true
	}
}
