package langfuse

import (
	"context"
	"embed"
	"errors"
	"net/http"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/sources/internal/jsonapi"
)

//go:embed catalog.yaml
var catalogFS embed.FS

const sourceID = "langfuse"

type Source struct {
	inner          *jsonapi.Source
	legacyFallback *jsonapi.Source
}

func New() (*Source, error) {
	spec, err := loadSpec()
	if err != nil {
		return nil, err
	}
	options := jsonapi.Options{
		SourceID:               sourceID,
		DefaultBaseURL:         "https://cloud.langfuse.com",
		DefaultFamily:          "project",
		RequireTenantID:        true,
		AuthModel:              "basic",
		ConfigurableAuthModels: []string{"basic", "bearer_token"},
		Families:               langfuseFamilies(),
		DoNotRetryStatuses:     []int{http.StatusNotImplemented},
	}
	inner, err := jsonapi.New(spec, options)
	if err != nil {
		return nil, err
	}
	options.Families = langfuseLegacyFallbackFamilies()
	legacyFallback, err := jsonapi.New(spec, options)
	if err != nil {
		return nil, err
	}
	return &Source{inner: inner, legacyFallback: legacyFallback}, nil
}

func (s *Source) Spec() *cerebrov1.SourceSpec { return s.inner.Spec() }
func (s *Source) Check(ctx context.Context, cfg sourcecdk.Config) error {
	if err := validateMetricsQuery(cfg); err != nil {
		return err
	}
	err := s.inner.Check(ctx, cfg)
	if !isLangfuseV2Fallback(cfg, err) {
		return err
	}
	s.syncFallbackTransport()
	return s.legacyFallback.Check(ctx, cfg)
}
func (s *Source) Discover(ctx context.Context, cfg sourcecdk.Config) ([]sourcecdk.URN, error) {
	if err := validateMetricsQuery(cfg); err != nil {
		return nil, err
	}
	urns, err := s.inner.Discover(ctx, cfg)
	if !isLangfuseV2Fallback(cfg, err) {
		return urns, err
	}
	s.syncFallbackTransport()
	return s.legacyFallback.Discover(ctx, cfg)
}
func (s *Source) Read(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	if err := validateMetricsQuery(cfg); err != nil {
		return sourcecdk.Pull{}, err
	}
	family, _ := cfg.Lookup("family")
	family = strings.TrimSpace(family)
	if legacyCursor, ok := langfuseLegacyCursor(family, cursor); ok {
		s.syncFallbackTransport()
		pull, err := s.legacyFallback.Read(ctx, cfg, legacyCursor)
		return markLangfuseLegacyCursor(pull), err
	}
	pull, err := s.inner.Read(ctx, cfg, cursor)
	if !isLangfuseV2Fallback(cfg, err) || strings.TrimSpace(sourcecdk.CursorToken(cursor)) != "" {
		return pull, err
	}
	s.syncFallbackTransport()
	pull, err = s.legacyFallback.Read(ctx, cfg, nil)
	return markLangfuseLegacyCursor(pull), err
}

const langfuseLegacyCursorPrefix = "langfuse-v1:"

type statusCodeError interface{ StatusCode() int }

func isLangfuseV2Fallback(cfg sourcecdk.Config, err error) bool {
	if err == nil {
		return false
	}
	family, _ := cfg.Lookup("family")
	if family = strings.TrimSpace(family); family != "observation" && family != "metric" {
		return false
	}
	var statusErr statusCodeError
	return errors.As(err, &statusErr) && statusErr.StatusCode() == http.StatusNotImplemented
}

func (s *Source) syncFallbackTransport() {
	if s != nil && s.inner != nil && s.legacyFallback != nil {
		s.legacyFallback.AllowLoopbackBaseURL = s.inner.AllowLoopbackBaseURL
	}
}

func langfuseLegacyCursor(family string, cursor *cerebrov1.SourceCursor) (*cerebrov1.SourceCursor, bool) {
	if family != "observation" && family != "metric" {
		return nil, false
	}
	token := strings.TrimSpace(sourcecdk.CursorToken(cursor))
	if !strings.HasPrefix(token, langfuseLegacyCursorPrefix) {
		return nil, false
	}
	return &cerebrov1.SourceCursor{Opaque: strings.TrimPrefix(token, langfuseLegacyCursorPrefix)}, true
}

func markLangfuseLegacyCursor(pull sourcecdk.Pull) sourcecdk.Pull {
	if pull.NextCursor != nil {
		if token := strings.TrimSpace(pull.NextCursor.GetOpaque()); token != "" {
			pull.NextCursor.Opaque = langfuseLegacyCursorPrefix + token
		}
	}
	return pull
}

func validateMetricsQuery(cfg sourcecdk.Config) error {
	family, _ := cfg.Lookup("family")
	if strings.TrimSpace(family) != "metric" {
		return nil
	}
	raw, _ := cfg.Lookup("metrics_query")
	return jsonapi.ValidateMetricsQuery(raw, jsonapi.MetricsQueryLimits{
		AllowedViews:      map[string]bool{"observations": true, "scores-numeric": true, "scores-boolean": true, "scores-categorical": true},
		RequiredDimension: "name",
		MaxBytes:          16 << 10,
		MaxMetrics:        16,
		MaxInterval:       31 * 24 * time.Hour,
	})
}

func loadSpec() (*cerebrov1.SourceSpec, error) {
	return sourcecdk.LoadSpecFromFS(catalogFS, "catalog.yaml")
}
